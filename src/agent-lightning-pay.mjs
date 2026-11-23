// Unified HTTP 402 + direct payment runner for v2 Passkey PRF Agent Wallets.
//
// Supported HTTP 402 protocols:
//   1. `l402`  — `WWW-Authenticate: L402 macaroon="...", invoice="lnbc..."` (or `LSAT`)
//                -> pays BOLT11 via Arkade Intents, retries `Authorization: L402 <macaroon>:<preimage>`
//   2. `mpp-lightning` — `WWW-Authenticate: Payment ...` (`method="lightning"`, `intent="charge"`)
//                -> pays BOLT11 via Arkade Intents, retries `Authorization: Payment <Credential>`
//   3. `x402`  — `PAYMENT-REQUIRED` header or JSON `{ x402Version, accepts }`
//                -> co-signs ERC-1271 SafeMessage over EIP-3009 / Permit2 from 2-of-4 Base Safe
//   4. `mpp-evm` — `WWW-Authenticate: Payment ...` (`method="evm"`, `intent="charge"`)
//                -> co-signs exact-amount Safe -> Agent EOA USDC hop, then pays via `mppx`
import { isUtf8 } from "node:buffer";
import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import { decodePaymentResponseHeader } from "@x402/core/http";
import { Challenge, Credential, Receipt } from "mppx";
import { privateKeyToAccount } from "viem/accounts";
import { BASE_CHAIN_ID, BASE_USDC_ADDRESS, TEMPO_CHAIN_IDS } from "./agent-safe-v2.mjs";
import { MERCHANT_HEADERS, requestShape } from "./agent-kernel-runtime.mjs";
import { parseChallenge, payWithSafe, quoteOffer, selectOffer } from "./safe-pay.mjs";
import { parseMppChallenges, payMppCharge, quoteMppOffer, selectMppOffer } from "./safe-pay-mpp.mjs";
import { parseSolanaChallenge, payWithSolana, quoteSolanaOffer, readSolanaUsdcBalance, solanaSignerFromAgentKey } from "./safe-pay-solana.mjs";

const denied = new BlockList();
// Tempo has no gas coin: the Agent EOA pays its transferWithMemo fee in the token
// itself (~$0.0003 at 0.6 gwei), so keep a $0.03 buffer on the Agent EOA.
const TEMPO_HOP_FEE_RESERVE_UNITS = 30_000n;
const TEMPO_MAINNET_CHAIN_ID = 4217;
const RELAY_FEE_ESTIMATE_UNITS = 40_000n;
for (const [ip, bits] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
]) {
  denied.addSubnet(ip, bits, "ipv4");
}

function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === "function") {
    const val = headers.get(name);
    return val === null ? undefined : val;
  }
  const v = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(v) ? v.join(", ") : v;
}

export function validateMerchantHttpsUrl(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) {
    throw new Error("invalid_merchant_url");
  }
  const u = new URL(value);
  if (
    u.protocol !== "https:" ||
    u.username ||
    u.password ||
    u.hash ||
    u.port ||
    u.href !== value ||
    isIP(u.hostname) ||
    !/^[a-z0-9.-]+$/.test(u.hostname) ||
    !u.hostname.includes(".") ||
    /(^|\.)(localhost|local|internal|home|lan|test|invalid)$/.test(u.hostname)
  ) {
    throw new Error("invalid_merchant_url");
  }
  return u;
}

export async function defaultPinnedMerchantFetch(url, { headers = {}, shape = requestShape() } = {}) {
  const u = validateMerchantHttpsUrl(url);
  const answers = await Promise.race([
    lookup(u.hostname, { all: true, family: 4 }),
    new Promise((_, reject) => {
      const t = setTimeout(() => reject(new Error("dns_timeout")), 10_000);
      t.unref?.();
    }),
  ]);
  if (!answers.length || !answers.every((a) => a.family === 4 && !denied.check(a.address, "ipv4"))) {
    throw new Error("nonpublic_merchant");
  }
  const pinned = answers[0];
  return new Promise((resolve, reject) => {
    let timer;
    const req = httpsRequest(
      u,
      {
        method: shape.method,
        agent: false,
        maxHeaderSize: 49_152,
        headers: { ...MERCHANT_HEADERS, ...shape.headers, ...headers },
        lookup: (_host, options, cb) =>
          options.all ? cb(null, [pinned]) : cb(null, pinned.address, 4),
      },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          const err = new Error("merchant_redirect_forbidden");
          res.destroy(err);
          req.destroy(err);
          return;
        }
        if (res.headers["content-encoding"] && res.headers["content-encoding"] !== "identity") {
          const err = new Error("encoded_body_unsupported");
          res.destroy(err);
          req.destroy(err);
          return;
        }
        const chunks = [];
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size > 262_144) {
            req.destroy(new Error("merchant_body_too_large"));
            res.destroy();
          } else {
            chunks.push(chunk);
          }
        });
        res.on("error", reject);
        res.on("end", () => {
          clearTimeout(timer);
          resolve({
            status: res.statusCode,
            headers: res.headers,
            bytes: Buffer.concat(chunks),
          });
        });
      },
    );
    timer = setTimeout(() => req.destroy(new Error("merchant_timeout")), 25_000);
    timer.unref?.();
    req.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    req.end(shape.bytes ?? undefined);
  });
}

function formatResourceBody(response) {
  const type = getHeader(response.headers, "content-type") || "application/octet-stream";
  const text = /^(text\/|application\/(json|[^;]+\+json))/.test(type) && isUtf8(response.bytes);
  return {
    content_type: type,
    encoding: text ? "utf8" : "base64",
    body: response.bytes.toString(text ? "utf8" : "base64"),
    size_bytes: response.bytes.length,
  };
}

/**
 * Parse L402 / LSAT `WWW-Authenticate` header:
 *   `L402 macaroon="...", invoice="lnbc..."` or `LSAT token="...", invoice="lnbc..."`
 */
export function parseL402Challenge(headers) {
  const raw = getHeader(headers, "www-authenticate");
  if (typeof raw !== "string" || !raw.trim()) return null;
  const schemeMatch = /(?:^|,)\s*(L402|LSAT)\s+([^,]+(?:\s*,\s*[a-zA-Z0-9_-]+\s*=\s*(?:"[^"]*"|[^\s,]+))*)/i.exec(raw);
  if (!schemeMatch) return null;
  const scheme = schemeMatch[1].toUpperCase();
  const paramsRaw = raw.slice(schemeMatch.index + schemeMatch[0].indexOf(schemeMatch[1]) + schemeMatch[1].length);
  const params = {};
  const paramRe = /([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^\s,]+))/g;
  let m;
  while ((m = paramRe.exec(paramsRaw)) !== null) {
    params[m[1].toLowerCase()] = m[2] !== undefined ? m[2] : m[3];
  }
  const macaroon = params.macaroon || params.token;
  const invoice = params.invoice;
  if (!macaroon || !invoice) return null;
  return {
    protocol: "l402",
    scheme,
    macaroon: macaroon.trim(),
    invoice: invoice.trim(),
  };
}

/**
 * Parse Lightning MPP challenges from `WWW-Authenticate: Payment ...`
 */
export function parseLightningMppChallenges(headers) {
  const raw = getHeader(headers, "www-authenticate");
  if (typeof raw !== "string" || !/^\s*Payment\s/i.test(raw)) return [];
  let list;
  try {
    list = Challenge.deserializeList(raw);
  } catch {
    return [];
  }
  const out = [];
  for (const [index, challenge] of list.entries()) {
    const method = String(challenge.method || "").toLowerCase();
    const intent = String(challenge.intent || "charge").toLowerCase();
    if (!["lightning", "bolt11", "bitcoin-lightning"].includes(method) || intent !== "charge") {
      continue;
    }
    const req = challenge.request || {};
    const md = req.methodDetails || {};
    const invoice = req.invoice || req.paymentRequest || req.bolt11 || md.invoice || md.bolt11;
    if (typeof invoice !== "string" || !invoice.trim()) continue;
    out.push({
      protocol: "mpp-lightning",
      index,
      challenge,
      method: challenge.method,
      intent: challenge.intent,
      invoice: invoice.trim(),
      amountSats: req.amount && /^[0-9]+$/.test(String(req.amount)) ? Number(req.amount) : null,
      expires: challenge.expires ?? null,
    });
  }
  return out;
}

let cachedBtcUsd = { rate: null, at: 0 };

export async function defaultGetBtcUsdRate(fetchImpl = fetch) {
  const now = Date.now();
  if (cachedBtcUsd.rate && now - cachedBtcUsd.at < 60_000) {
    return cachedBtcUsd.rate;
  }
  try {
    const res = await fetchImpl("https://api.coinbase.com/v2/prices/BTC-USD/spot", {
      signal: AbortSignal.timeout(3000),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return cachedBtcUsd.rate;
    const json = await res.json();
    const rate = Number(json?.data?.amount);
    if (Number.isFinite(rate) && rate > 1000) {
      cachedBtcUsd = { rate, at: now };
      return rate;
    }
  } catch {
    // Fall back to cached rate or conservative bound.
  }
  return cachedBtcUsd.rate;
}

export function usdUnitsToMaxSats(maxAmountUnits, btcUsd) {
  // Conservative upper BTC/USD bound ($150k) if spot price is unavailable so a USD cap is never loosened.
  const rate = Number.isFinite(btcUsd) && btcUsd > 1000 ? btcUsd : 150_000;
  const usd = Number(maxAmountUnits) / 1e6;
  return BigInt(Math.max(0, Math.floor((usd / rate) * 1e8)));
}

export function satsToMaxUsdUnits(maxSats, btcUsd) {
  // Conservative lower BTC/USD bound ($30k) if spot price is unavailable so a sats cap is never loosened.
  const rate = Number.isFinite(btcUsd) && btcUsd > 1000 ? btcUsd : 30_000;
  const btc = Number(maxSats) / 1e8;
  return BigInt(Math.max(0, Math.floor(btc * rate * 1e6)));
}

/**
 * Detect which 402 payment protocol(s) a merchant response offers.
 */
export function classifyHttp402Response({
  headers,
  bodyText = "",
  prefer,
  decodeBolt11,
  balances = null,
  capHint = null,
}) {
  const candidates = [];

  const l402 = parseL402Challenge(headers);
  if (l402) {
    let facts = null;
    try {
      facts = decodeBolt11 ? decodeBolt11(l402.invoice) : null;
    } catch {
      facts = null;
    }
    candidates.push({
      kind: "l402",
      rail: "lightning",
      l402,
      invoice: l402.invoice,
      amountSats: facts?.amountSats ?? null,
      paymentHash: facts?.paymentHash ?? null,
      expiresAt: facts?.expiresAt ?? null,
    });
  }

  const lnMpp = parseLightningMppChallenges(headers);
  if (lnMpp.length > 0) {
    const offer = lnMpp[0];
    let facts = null;
    try {
      facts = decodeBolt11 ? decodeBolt11(offer.invoice) : null;
    } catch {
      facts = null;
    }
    candidates.push({
      kind: "mpp-lightning",
      rail: "lightning",
      offer,
      invoice: offer.invoice,
      amountSats: facts?.amountSats ?? offer.amountSats ?? null,
      paymentHash: facts?.paymentHash ?? null,
      expiresAt: facts?.expiresAt ?? null,
    });
  }

  if (
    typeof getHeader(headers, "payment-required") === "string" ||
    (() => {
      try {
        const j = JSON.parse(bodyText);
        return Boolean(j && (j.x402Version === 1 || j.x402Version === 2));
      } catch {
        return false;
      }
    })()
  ) {
    try {
      const { required, offers } = parseChallenge({ headers, bodyText });
      const x402Prefer =
        prefer && ["exact", "upto", "exact:eip3009", "exact:permit2", "upto:permit2"].includes(String(prefer))
          ? prefer
          : undefined;
      const offer = selectOffer(offers, { chainIds: [BASE_CHAIN_ID], prefer: x402Prefer });
      candidates.push({
        kind: "x402",
        rail: "usdc",
        required,
        offer,
        amountUnits: offer.amount,
      });
    } catch {
      // Ignore if x402 offers are for unsupported chains.
    }
  }

  const solana = parseSolanaChallenge({ headers, bodyText });
  if (solana) {
    const offer = solana.offers[0];
    candidates.push({ kind: "x402-solana", rail: "solana-usdc", required: solana.required, offer, amountUnits: offer.amount });
  }

  if (/^\s*Payment\s/i.test(getHeader(headers, "www-authenticate") || "")) {
    try {
      const evmOffers = parseMppChallenges({ headers });
      const mppPrefer =
        prefer && ["mpp", "mpp:evm", "charge", "session"].includes(String(prefer))
          ? prefer
          : undefined;
      const offer = selectMppOffer(evmOffers, { chainIds: [BASE_CHAIN_ID, ...TEMPO_CHAIN_IDS], prefer: mppPrefer });
      const paidOffers = evmOffers.filter((o) => BigInt(o.amount) > 0n);
      const paidFallback =
        BigInt(offer.amount) === 0n && paidOffers.length > 0
          ? selectMppOffer(paidOffers, { chainIds: [BASE_CHAIN_ID, ...TEMPO_CHAIN_IDS], prefer: mppPrefer })
          : null;
      candidates.push({
        kind: "mpp-evm",
        rail: "usdc",
        offer,
        ...(paidFallback ? { paidFallback } : {}),
        amountUnits: offer.amount,
      });
    } catch {
      // Ignore if MPP challenges are for unsupported chains.
    }
  }

  if (candidates.length === 0) return null;

  const pref = String(prefer || "").toLowerCase();
  if (pref === "lightning" || pref === "l402" || pref === "btc" || pref === "mpp:lightning") {
    const ln = candidates.find(
      (c) =>
        (pref === "l402" && c.kind === "l402") ||
        (pref === "mpp:lightning" && c.kind === "mpp-lightning") ||
        c.rail === "lightning",
    );
    if (ln) return ln;
  }
  if (pref === "solana") return candidates.find((c) => c.kind === "x402-solana") || candidates[0];
  if (pref === "usdc" || pref === "x402" || pref === "mpp" || pref === "mpp:evm") {
    const evm = candidates.find(
      (c) =>
        (pref === "x402" && (c.kind === "x402" || c.kind === "x402-solana")) ||
        ((pref === "mpp" || pref === "mpp:evm") && c.kind === "mpp-evm") ||
        (pref === "usdc" && (c.rail === "usdc" || c.rail === "solana-usdc")),
    );
    if (evm) return evm;
  }

  // Dual-rail endpoint with no explicit `prefer`: pick whichever rail already holds
  // sufficient native balance so we avoid unnecessary cross-rail swap fees. If both
  // rails are funded and caller passed a currency-specific cap (`max_amount` -> usdc,
  // `max_sats` -> lightning), honor that cap hint.
  if (balances && candidates.length > 1) {
    const sats = BigInt(balances.sats ?? 0n);
    const usdcUnits = BigInt(balances.usdcUnits ?? 0n);
    const funded = candidates.filter((c) => {
      if (c.rail === "lightning") {
        return c.amountSats !== null && sats >= BigInt(c.amountSats);
      }
      // A Tempo MPP offer is paid from the Safe's token balance on Tempo, which the
      // caller's Base-USDC balance snapshot does not know: never exclude it here.
      if (c.kind === "mpp-evm" && TEMPO_CHAIN_IDS.includes(Number(c.offer?.chainId))) {
        return true;
      }
      const available = c.rail === "solana-usdc" ? BigInt(balances.solanaUsdcUnits ?? 0n) : usdcUnits;
      return c.amountUnits !== undefined && available >= BigInt(c.amountUnits);
    });
    if (funded.length > 0) {
      if (capHint) {
        const hinted = funded.find((c) => c.rail === capHint || (capHint === "usdc" && c.rail === "solana-usdc"));
        if (hinted) return hinted;
      }
      return funded[0];
    }
  }

  return candidates[0];
}

export function createPrfHttp402Payer({
  safeRuntime,
  arkadeRuntime,
  merchantFetch = defaultPinnedMerchantFetch,
  ensureRailFunded = null,
  getBtcUsdRate = defaultGetBtcUsdRate,
  solanaRpcUrl,
} = {}) {
  async function payHttpResource({
    walletRecord,
    secrets,
    url,
    method = "GET",
    body,
    contentType,
    prefer,
    maxAmountUnits,
    maxSats,
    dryRun = false,
    opId,
  }) {
    validateMerchantHttpsUrl(url);
    const shape = requestShape({ method, body, contentType });
    const first = await merchantFetch(url, { headers: {}, shape });
    if (first.status !== 402) {
      return {
        status: first.status >= 200 && first.status < 300 ? "done" : "failed",
        paid: false,
        http_status: first.status,
        resource: formatResourceBody(first),
      };
    }

    const bodyText = isUtf8(first.bytes) ? first.bytes.toString("utf8") : "";
    let prefBalances = null;
    if (!prefer && safeRuntime && arkadeRuntime) {
      const [uRes, aRes, sRes] = await Promise.allSettled([
        safeRuntime.readUsdcBalanceUnits(walletRecord.safeAddress),
        arkadeRuntime.readBalance(walletRecord),
        solanaSignerFromAgentKey(secrets.agentEthPrivHex).then((signer) => readSolanaUsdcBalance({ owner: signer.address, ...(solanaRpcUrl ? { rpcUrl: solanaRpcUrl } : {}) })),
      ]);
      prefBalances = {
        usdcUnits: uRes.status === "fulfilled" ? uRes.value : 0n,
        sats: aRes.status === "fulfilled" ? aRes.value.sats : 0n,
        solanaUsdcUnits: sRes.status === "fulfilled" ? sRes.value : 0n,
      };
    }

    const capHint =
      maxAmountUnits !== undefined && maxAmountUnits !== null && (maxSats === undefined || maxSats === null)
        ? "usdc"
        : maxSats !== undefined && maxSats !== null && (maxAmountUnits === undefined || maxAmountUnits === null)
          ? "lightning"
          : null;

    const selected = classifyHttp402Response({
      headers: first.headers,
      bodyText,
      prefer,
      decodeBolt11: arkadeRuntime?.decodeBolt11,
      balances: prefBalances,
      capHint,
    });
    if (!selected) {
      throw new Error("no_payable_402_challenge");
    }

    const needsCrossCap =
      (selected.rail === "lightning" && maxAmountUnits !== undefined && maxAmountUnits !== null) ||
      ((selected.rail === "usdc" || selected.rail === "solana-usdc") && maxSats !== undefined && maxSats !== null);
    const btcUsd = needsCrossCap ? await getBtcUsdRate().catch(() => null) : null;

    function isLightningOverCap(amountSats) {
      if (amountSats === null || amountSats === undefined) return false;
      if (maxSats !== undefined && maxSats !== null && BigInt(amountSats) > BigInt(maxSats)) {
        return true;
      }
      if (maxAmountUnits !== undefined && maxAmountUnits !== null) {
        const maxSatsFromUsd = usdUnitsToMaxSats(maxAmountUnits, btcUsd);
        if (BigInt(amountSats) > maxSatsFromUsd) return true;
      }
      return false;
    }

    function isUsdcOverCap(amountUnits) {
      if (maxAmountUnits !== undefined && maxAmountUnits !== null && BigInt(amountUnits) > BigInt(maxAmountUnits)) {
        return true;
      }
      if (maxSats !== undefined && maxSats !== null) {
        const maxUnitsFromSats = satsToMaxUsdUnits(maxSats, btcUsd);
        if (BigInt(amountUnits) > maxUnitsFromSats) return true;
      }
      return false;
    }

    if (dryRun) {
      if (selected.rail === "lightning") {
        const bal = prefBalances ? { sats: prefBalances.sats } : await arkadeRuntime.readBalance(walletRecord);
        const nativePayable =
          selected.amountSats !== null ? bal.sats >= BigInt(selected.amountSats) : false;
        let crossRail = false;
        if (!nativePayable && safeRuntime && ensureRailFunded) {
          const usdcBal =
            prefBalances?.usdcUnits ??
            (await safeRuntime.readUsdcBalanceUnits(walletRecord.safeAddress).catch(() => 0n));
          if (usdcBal > 0n) crossRail = true;
        }
        const overCap = isLightningOverCap(selected.amountSats);
        return {
          status: "done",
          dry_run: true,
          protocol: selected.kind,
          rail: "lightning",
          ...(crossRail ? { cross_rail: true, funded_from: "usdc" } : {}),
          ...(selected.amountSats !== null
            ? { price: { amount: String(selected.amountSats), currency: "sats" } }
            : {}),
          over_cap: overCap,
          quote: {
            protocol: selected.kind,
            invoice: selected.invoice,
            amount_sats: selected.amountSats,
            payment_hash: selected.paymentHash,
            expires_at: selected.expiresAt,
          },
          available_sats: bal.sats.toString(),
          payable: (nativePayable || crossRail) && !overCap,
        };
      }
      if (selected.kind === "x402-solana") {
        const solanaBal = prefBalances?.solanaUsdcUnits ?? await solanaSignerFromAgentKey(secrets.agentEthPrivHex)
          .then((signer) => readSolanaUsdcBalance({ owner: signer.address, ...(solanaRpcUrl ? { rpcUrl: solanaRpcUrl } : {}) }));
        const overCap = isUsdcOverCap(selected.amountUnits);
        return { status: "done", dry_run: true, protocol: "x402", rail: "solana-usdc",
          amount_units: selected.amountUnits, over_cap: overCap, quote: quoteSolanaOffer(selected.offer),
          available_units: solanaBal.toString(), payable: solanaBal >= BigInt(selected.amountUnits) && !overCap };
      }
      const quoteTarget =
        selected.kind === "mpp-evm" && BigInt(selected.offer.amount) === 0n && selected.paidFallback
          ? selected.paidFallback
          : selected.offer;
      const quoteIsTempo =
        selected.kind === "mpp-evm" && TEMPO_CHAIN_IDS.includes(Number(quoteTarget?.chainId));
      const quoteAmountUnits = quoteTarget?.amount ?? selected.amountUnits;
      const requiredUnits = quoteIsTempo && BigInt(quoteAmountUnits) > 0n
        ? BigInt(quoteAmountUnits) + TEMPO_HOP_FEE_RESERVE_UNITS
        : BigInt(quoteAmountUnits);
      let usdcBal;
      if (quoteIsTempo) {
        const readTok = typeof safeRuntime?.readTokenBalanceUnits === "function"
          ? safeRuntime.readTokenBalanceUnits
          : null;
        const eoaAddr = secrets?.agentEthPrivHex
          ? privateKeyToAccount(
              secrets.agentEthPrivHex.startsWith("0x") ? secrets.agentEthPrivHex : `0x${secrets.agentEthPrivHex}`,
            ).address
          : walletRecord.agentEthEoa;
        const [eoaBal, safeTempoBal] = readTok
          ? await Promise.all([
              eoaAddr ? readTok(eoaAddr, quoteTarget.asset, Number(quoteTarget.chainId)).catch(() => 0n) : 0n,
              readTok(walletRecord.safeAddress, quoteTarget.asset, Number(quoteTarget.chainId)).catch(() => 0n),
            ])
          : [0n, 0n];
        usdcBal = eoaBal >= safeTempoBal ? eoaBal : safeTempoBal;
      } else {
        usdcBal =
          prefBalances?.usdcUnits ??
          (await safeRuntime.readUsdcBalanceUnits(walletRecord.safeAddress));
      }
      const nativePayable = usdcBal >= requiredUnits;
      let crossRail = false;
      let fundedFrom = null;
      if (!nativePayable && ensureRailFunded) {
        if (quoteIsTempo && Number(quoteTarget.chainId) === TEMPO_MAINNET_CHAIN_ID) {
          const baseBal =
            prefBalances?.usdcUnits ??
            (await safeRuntime.readUsdcBalanceUnits(walletRecord.safeAddress).catch(() => 0n));
          if (baseBal >= requiredUnits + RELAY_FEE_ESTIMATE_UNITS) {
            crossRail = true;
            fundedFrom = "base_usdc";
          } else if (arkadeRuntime) {
            const arkBal =
              prefBalances?.sats ??
              (await arkadeRuntime.readBalance(walletRecord).then((b) => b.sats).catch(() => 0n));
            if (arkBal > 0n) {
              crossRail = true;
              fundedFrom = "arkade";
            }
          }
        } else if (!quoteIsTempo && arkadeRuntime) {
          const arkBal =
            prefBalances?.sats ??
            (await arkadeRuntime.readBalance(walletRecord).then((b) => b.sats).catch(() => 0n));
          if (arkBal > 0n) {
            crossRail = true;
            fundedFrom = "arkade";
          }
        }
      }
      const overCap = isUsdcOverCap(quoteAmountUnits);
      const q = selected.kind === "x402" ? quoteOffer(selected.offer) : quoteMppOffer(quoteTarget);
      return {
        status: "done",
        dry_run: true,
        protocol: selected.kind,
        rail: "usdc",
        ...(crossRail ? { cross_rail: true, funded_from: fundedFrom || "arkade" } : {}),
        amount_units: quoteAmountUnits,
        over_cap: overCap,
        quote: q,
        available_units: usdcBal.toString(),
        payable: (nativePayable || crossRail) && !overCap,
      };
    }

    if (selected.rail === "lightning") {
      if (!arkadeRuntime) throw new Error("arkade_runtime_unavailable");
      if (isLightningOverCap(selected.amountSats)) {
        const err = new Error("invoice_exceeds_max_sats");
        err.code = "over_max_amount";
        err.invoiceSats = selected.amountSats;
        if (maxSats !== undefined && maxSats !== null) err.maxSats = Number(maxSats);
        if (maxAmountUnits !== undefined && maxAmountUnits !== null) err.maxUnits = String(maxAmountUnits);
        throw err;
      }

      let bridged = null;
      if (ensureRailFunded && selected.amountSats !== null) {
        const currentSats =
          prefBalances?.sats ??
          (await arkadeRuntime.readBalance(walletRecord).then((b) => b.sats).catch(() => 0n));
        const feeBuffer = BigInt(Math.max(100, Math.ceil(selected.amountSats * 0.03)));
        if (currentSats < BigInt(selected.amountSats) + feeBuffer) {
          bridged = await ensureRailFunded({
            walletRecord,
            secrets,
            targetRail: "lightning",
            neededSats: Number(BigInt(selected.amountSats) + feeBuffer),
            maxAmountUnits,
            maxSats,
            opId,
          });
        }
      }

      const paidLn = await arkadeRuntime.payBolt11Invoice({
        walletRecord,
        agentBtcPrivHex: secrets.agentBtcPrivHex,
        bolt11: selected.invoice,
        maxSats,
        opId,
      });
      if (!paidLn.preimageHex) {
        return {
          status: "pending",
          protocol: selected.kind,
          rail: "lightning",
          ...(bridged ? { funded_from: "usdc", bridged } : {}),
          payment_hash: paidLn.paymentHash,
          amount_sats: paidLn.amountSats,
          fee_sats: paidLn.feeSats,
          ark_txid: paidLn.arkTxid,
        };
      }

      const authHeader =
        selected.kind === "l402"
          ? `${selected.l402.scheme} ${selected.l402.macaroon}:${paidLn.preimageHex}`
          : Credential.serialize(
              Credential.from({
                challenge: selected.offer.challenge,
                payload: { preimage: paidLn.preimageHex },
              }),
            );

      const second = await merchantFetch(url, {
        headers: { Authorization: authHeader },
        shape,
      });
      return {
        status: second.status >= 200 && second.status < 300 ? "done" : "failed",
        paid: true,
        protocol: selected.kind,
        rail: "lightning",
        ...(bridged ? { funded_from: "usdc", bridged } : {}),
        http_status: second.status,
        amount_sats: paidLn.amountSats,
        fee_sats: paidLn.feeSats,
        total_sats: paidLn.totalSats,
        payment_hash: paidLn.paymentHash,
        preimage: paidLn.preimageHex,
        ark_txid: paidLn.arkTxid,
        resource: formatResourceBody(second),
      };
    }

    if (selected.kind === "x402-solana") {
      if (isUsdcOverCap(selected.amountUnits)) {
        const err = new Error("invoice_exceeds_max_amount");
        err.code = "over_max_amount";
        err.invoiceUnits = selected.amountUnits;
        if (maxAmountUnits !== undefined && maxAmountUnits !== null) err.maxUnits = String(maxAmountUnits);
        if (maxSats !== undefined && maxSats !== null) err.maxSats = Number(maxSats);
        throw err;
      }
      const signed = await payWithSolana({ offer: selected.offer, required: selected.required, agentEthPrivateKeyHex: secrets.agentEthPrivHex, ...(solanaRpcUrl ? { rpcUrl: solanaRpcUrl } : {}) });
      const second = await merchantFetch(url, { headers: signed.headers, shape });
      let receipt = null;
      const receiptHeader = getHeader(second.headers, "payment-response") || getHeader(second.headers, "x-payment-response");
      if (typeof receiptHeader === "string") {
        try { receipt = decodePaymentResponseHeader(receiptHeader); } catch { receipt = null; }
      }
      return { status: second.status >= 200 && second.status < 300 ? "done" : "failed", paid: true,
        protocol: "x402", rail: "solana-usdc", http_status: second.status, amount_units: selected.offer.amount,
        asset: selected.offer.asset, solana_address: signed.payerAddress, tx_hash: receipt?.transaction || null,
        resource: formatResourceBody(second) };
    }

    // EVM Base USDC rail (`x402` or `mpp-evm`)
    if (!safeRuntime) throw new Error("safe_runtime_unavailable");
    if (isUsdcOverCap(selected.amountUnits)) {
      const err = new Error("invoice_exceeds_max_amount");
      err.code = "over_max_amount";
      err.invoiceUnits = selected.amountUnits;
      if (maxAmountUnits !== undefined && maxAmountUnits !== null) err.maxUnits = String(maxAmountUnits);
      if (maxSats !== undefined && maxSats !== null) err.maxSats = Number(maxSats);
      throw err;
    }

    const selectedIsTempo =
      selected.kind === "mpp-evm" && TEMPO_CHAIN_IDS.includes(Number(selected.offer?.chainId));
    let bridged = null;
    if (ensureRailFunded && !selectedIsTempo) {
      const currentUsdc =
        prefBalances?.usdcUnits ??
        (await safeRuntime.readUsdcBalanceUnits(walletRecord.safeAddress).catch(() => 0n));
      if (currentUsdc < BigInt(selected.amountUnits)) {
        bridged = await ensureRailFunded({
          walletRecord,
          secrets,
          targetRail: "usdc",
          neededUsdcUnits: BigInt(selected.amountUnits),
          maxAmountUnits,
          maxSats,
          opId,
        });
      }
    }

    const safeWalletRow = {
      cred_id_b64u: walletRecord.credIdB64u,
      slot_index: walletRecord.slotIndex,
      main_eoa: walletRecord.mainEoa,
      passkey_signer_address: walletRecord.passkeySignerAddress,
      agent_eoa: walletRecord.agentEthEoa,
      cosigner_eoa: walletRecord.cosignerEoa,
      safe_address: walletRecord.safeAddress,
    };

    if (selected.kind === "x402") {
      await safeRuntime.ensureSafeDeployed(safeWalletRow);
      const signed = await payWithSafe({
        offer: selected.offer,
        required: selected.required,
        safe: walletRecord.safeAddress,
        readContract: (args) => safeRuntime.publicClient.readContract(args),
        signTypedData: async (typedData) => {
          if (selected.offer.method === "permit2") {
            await safeRuntime.ensurePermit2Allowance({
              walletRecord: safeWalletRow,
              agentEthPrivateKeyHex: secrets.agentEthPrivHex,
              requiredUnits: BigInt(selected.offer.amount),
              opId: `${opId}:permit2`,
            });
          }
          const combinedSignature = await safeRuntime.signSafeTypedData({
            walletRecord: safeWalletRow,
            agentEthPrivateKeyHex: secrets.agentEthPrivHex,
            typedData,
            opId: `${opId}:x402:${createHash("sha256")
              .update(JSON.stringify(typedData, (_k, v) => (typeof v === "bigint" ? v.toString() : v)))
              .digest("hex")
              .slice(0, 12)}`,
          });
          return combinedSignature;
        },
      });

      const second = await merchantFetch(url, {
        headers: signed.headers,
        shape,
      });
      let receipt = null;
      const receiptHeader =
        getHeader(second.headers, "payment-response") ||
        getHeader(second.headers, "x-payment-response");
      if (typeof receiptHeader === "string") {
        try {
          receipt = decodePaymentResponseHeader(receiptHeader);
        } catch {
          receipt = null;
        }
      }
      return {
        status: second.status >= 200 && second.status < 300 ? "done" : "failed",
        paid: true,
        protocol: "x402",
        rail: "usdc",
        ...(bridged ? { funded_from: "arkade", bridged } : {}),
        http_status: second.status,
        amount_units: selected.offer.amount,
        asset: BASE_USDC_ADDRESS,
        tx_hash: receipt?.transaction || null,
        resource: formatResourceBody(second),
      };
    }

    // `mpp-evm`: exact-amount hop from 2-of-4 Safe -> Agent EOA, then stock `mppx`
    const agentAccount = privateKeyToAccount(
      secrets.agentEthPrivHex.startsWith("0x")
        ? secrets.agentEthPrivHex
        : `0x${secrets.agentEthPrivHex}`,
    );

    async function runMppOffer(offer, hopSuffix) {
      const offerChainId = Number(offer.chainId);
      const offerIsTempo = TEMPO_CHAIN_IDS.includes(offerChainId);
      const offerAmountUnits = BigInt(offer.amount);
      if (offerAmountUnits > 0n && isUsdcOverCap(offer.amount)) {
        const err = new Error("invoice_exceeds_max_amount");
        err.code = "over_max_amount";
        err.invoiceUnits = offer.amount;
        if (maxAmountUnits !== undefined && maxAmountUnits !== null) err.maxUnits = String(maxAmountUnits);
        if (maxSats !== undefined && maxSats !== null) err.maxSats = Number(maxSats);
        throw err;
      }
      let hopAmountOverride = null;
      let skipHop = false;
      if (offerIsTempo && offerAmountUnits > 0n) {
        const readTok = typeof safeRuntime.readTokenBalanceUnits === "function"
          ? safeRuntime.readTokenBalanceUnits
          : null;
        const neededOnEoa = offerAmountUnits + TEMPO_HOP_FEE_RESERVE_UNITS;
        const eoaBal = readTok
          ? await readTok(agentAccount.address, offer.asset, offerChainId).catch(() => 0n)
          : 0n;
        if (eoaBal >= neededOnEoa) {
          skipHop = true;
        } else {
          const shortfall = neededOnEoa - eoaBal;
          const safeTempoBal = readTok
            ? await readTok(walletRecord.safeAddress, offer.asset, offerChainId).catch(() => null)
            : null;
          if (safeTempoBal !== null && safeTempoBal >= shortfall) {
            hopAmountOverride = shortfall;
          } else if (offerChainId === TEMPO_MAINNET_CHAIN_ID && ensureRailFunded) {
            bridged = await ensureRailFunded({
              walletRecord,
              secrets,
              targetRail: "tempo",
              recipient: agentAccount.address,
              token: offer.asset,
              chainId: offerChainId,
              neededUnits: shortfall,
              neededTotalUnits: neededOnEoa,
              maxAmountUnits,
              maxSats,
              opId: `${opId}:${hopSuffix}`,
            });
            skipHop = true;
          } else if (safeTempoBal !== null) {
            const err = new Error(
              `insufficient_tempo_balance: Safe ${walletRecord.safeAddress} holds ${safeTempoBal} units (Agent EOA holds ${eoaBal}) of ${offer.asset} on Tempo (chain ${offerChainId}), need ${neededOnEoa} (${offerAmountUnits} payment + ${TEMPO_HOP_FEE_RESERVE_UNITS} fee reserve).`,
            );
            err.code = "insufficient_tempo_balance";
            throw err;
          }
        }
      }
      let hopTxHash = null;
      let rawRes = null;
      const { response, receipt } = await payMppCharge({
        offer,
        agent: agentAccount,
        evmAuthorization:
          offer.asset?.toLowerCase() === BASE_USDC_ADDRESS.toLowerCase()
            ? { name: "USD Coin", version: "2" }
            : undefined,
        feeReserve: offerIsTempo ? TEMPO_HOP_FEE_RESERVE_UNITS : 0n,
        hop: skipHop
          ? null
          : async (_token, amount) => {
              const hopped = await safeRuntime.transferToken({
                walletRecord: safeWalletRow,
                agentEthPrivateKeyHex: secrets.agentEthPrivHex,
                to: agentAccount.address,
                amountUnits: hopAmountOverride ?? amount,
                opId: `${opId}:${hopSuffix}`,
                chainId: offerChainId,
                token: offer.asset,
              });
              hopTxHash = hopped.txHash;
            },
        getClient: (chainId) => safeRuntime.clientForChain(chainId),
        fetchPaid: async (credentialHeader) => {
          const res = await merchantFetch(url, {
            headers: credentialHeader ? { Authorization: credentialHeader } : {},
            shape,
          });
          rawRes = res;
          return new Response(res.bytes, {
            status: res.status,
            headers: Object.entries(res.headers || {}).filter(([, v]) => typeof v === "string"),
          });
        },
      });
      return { response, receipt, hopTxHash, rawRes, offer };
    }

    let attempt = await runMppOffer(selected.offer, "mpp-hop");
    // Credit-proof flow (e.g. treg.to): first challenge has amount=0 (free EIP-712
    // wallet proof to spend prepaid credit). If the server replies 402 with a paid
    // charge challenge (credit_insufficient), settle that paid challenge once.
    if (
      BigInt(selected.offer.amount) === 0n &&
      attempt.response.status === 402 &&
      attempt.rawRes &&
      /^\s*Payment\s/i.test(getHeader(attempt.rawRes.headers, "www-authenticate") || "")
    ) {
      const mppPrefer =
        prefer && ["mpp", "mpp:evm", "charge", "session"].includes(String(prefer))
          ? prefer
          : undefined;
      const followOffers = parseMppChallenges({ headers: attempt.rawRes.headers }).filter(
        (o) => BigInt(o.amount) > 0n,
      );
      if (followOffers.length > 0) {
        const paidOffer = selectMppOffer(followOffers, {
          chainIds: [BASE_CHAIN_ID, ...TEMPO_CHAIN_IDS],
          prefer: mppPrefer,
        });
        attempt = await runMppOffer(paidOffer, "mpp-hop-paid");
      }
    }

    const { response: second, receipt, hopTxHash, rawRes: secondRaw, offer: finalOffer } = attempt;

    return {
      status: second.status >= 200 && second.status < 300 ? "done" : "failed",
      paid: true,
      protocol: "mpp",
      rail: "usdc",
      ...(bridged ? { funded_from: bridged.from || "arkade", bridged } : {}),
      http_status: second.status,
      amount_units: finalOffer.amount,
      asset: finalOffer.asset,
      tx_hash: receipt?.reference || hopTxHash || null,
      hop_tx_hash: hopTxHash,
      resource: secondRaw ? formatResourceBody(secondRaw) : null,
    };
  }

  return {
    payHttpResource,
  };
}
