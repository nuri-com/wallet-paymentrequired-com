// Stateless SwapKit MCP client (`https://swapkit.nuri.com/mcp`) + Bitcoin/BIP21/XMR
// destination helpers for cross-rail (`USDC <-> Lightning/Arkade`) and on-chain Bitcoin
// (`bc1...`) payments inside the 4-action MCP `wallet` tool.
import { randomBytes } from "node:crypto";
import { decimalToUnits } from "./wallet-units.mjs";

export const DEFAULT_SWAPKIT_MCP_URL = "https://swapkit.nuri.com/mcp";

const ONCHAIN_BTC_RE = /^(?:bc1[a-z0-9]{11,87}|tb1[a-z0-9]{11,87}|bcrt1[a-z0-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/;
const MONERO_ADDR_RE = /^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93,104}$/;
const BTC_DECIMAL_RE = /^(0|[1-9][0-9]{0,7})(\.[0-9]{1,8})?$/;

const SETTLED_STATUSES = new Set(["COMPLETED", "completed", "settled", "done", "DONE", "SUCCESS"]);
const FAILED_STATUSES = new Set(["FAILED", "EXPIRED", "REFUNDED", "CANCELED", "CANCELLED", "failed", "expired", "refunded", "canceled"]);

export function isOnchainBtcAddress(value) {
  return typeof value === "string" && ONCHAIN_BTC_RE.test(value.trim());
}

export function isMoneroAddress(value) {
  return typeof value === "string" && MONERO_ADDR_RE.test(value.trim());
}

export function btcDecimalToSats(value) {
  const raw = typeof value === "number" ? value.toFixed(8).replace(/\.?0+$/, "") : String(value ?? "").trim();
  if (!BTC_DECIMAL_RE.test(raw)) {
    throw new Error("invalid_btc_amount");
  }
  const [whole, frac = ""] = raw.split(".");
  const sats = BigInt(whole) * 100_000_000n + BigInt(frac.padEnd(8, "0").slice(0, 8));
  if (sats <= 0n || sats > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("invalid_btc_amount");
  }
  return Number(sats);
}

/**
 * Parse a BIP21 `bitcoin:` payment URI (`bitcoin:bc1...?amount=0.0005&lightning=lnbc...`).
 */
export function parseBip21Uri(raw) {
  if (typeof raw !== "string" || !/^bitcoin:/i.test(raw.trim())) return null;
  const trimmed = raw.trim();
  const withoutScheme = trimmed.slice("bitcoin:".length);
  const qIdx = withoutScheme.indexOf("?");
  const addrPart = (qIdx === -1 ? withoutScheme : withoutScheme.slice(0, qIdx)).replace(/^\/+/, "").trim();
  const params = new URLSearchParams(qIdx === -1 ? "" : withoutScheme.slice(qIdx + 1));

  let lightning = null;
  let amountSats = null;
  for (const [k, v] of params.entries()) {
    const key = k.toLowerCase();
    const val = v.trim();
    if (key === "lightning" && /^ln(?:bc|tb|bcrt|tbs)[0-9a-z]+$/i.test(val)) {
      lightning = val;
    } else if (key === "amount" && val) {
      amountSats = btcDecimalToSats(val);
    }
  }
  const address = isOnchainBtcAddress(addrPart) ? addrPart : null;
  if (!address && !lightning) return null;
  return { address, amountSats, lightning };
}

export function usdcAmountToUnitsCeil(amount) {
  const raw = typeof amount === "number" ? amount.toFixed(6) : String(amount ?? "").trim();
  const match = /^([0-9]+)(?:\.([0-9]+))?$/.exec(raw);
  if (!match) throw new Error(`invalid_usdc_amount:${raw}`);
  const whole = match[1];
  const frac = match[2] || "";
  const base = BigInt(decimalToUnits(`${whole}.${frac.slice(0, 6).padEnd(6, "0")}`, 6));
  const extra = frac.length > 6 && /[1-9]/.test(frac.slice(6)) ? 1n : 0n;
  return base + extra;
}

export function extractSwapFunding(intent) {
  if (!intent || typeof intent !== "object") {
    throw new Error("swapkit_invalid_intent");
  }
  const provider = intent.provider || intent.routedVia || intent.track?.provider || null;
  const swapId = intent.id ?? intent.track?.id ?? null;
  const fund = intent.fund || {};
  const actions = Array.isArray(intent.actions) ? intent.actions : [];
  const lnAction = actions.find((a) => a?.type === "pay_lightning_invoice" && a?.invoice);
  const sendAction = actions.find((a) => a?.type === "send_asset" && a?.to);

  const payInvoice = lnAction?.invoice || fund.payInvoice || null;
  const sendToAddress = sendAction?.to || fund.sendToAddress || null;
  const depositAmount = sendAction?.amount ?? lnAction?.amountBtc ?? fund.amount ?? null;
  const settleAmount = intent.receive?.amount ?? null;
  const settleTxid =
    intent.details?.settleTxns?.[0]?.txid ||
    intent.details?.settleTxns?.[0]?.hash ||
    intent.details?.settleTxns?.[0] ||
    intent.receipt?.txid ||
    null;

  return {
    provider,
    swapId,
    status: intent.status || "AWAITING_FUNDING",
    payInvoice,
    sendToAddress,
    depositAmount,
    settleAmount,
    settleTxid: typeof settleTxid === "string" ? settleTxid : null,
    raw: intent,
  };
}

export function extractProviderMinFromRoute(route, fromAsset) {
  const unavail = Array.isArray(route?.unavailable) ? route.unavailable : [];
  for (const u of unavail) {
    if (u?.code === "below_provider_min" && u?.limits?.min != null) {
      const minNum = Number(u.limits.min);
      if (Number.isFinite(minNum) && minNum > 0) {
        return {
          provider: u.provider,
          min: minNum,
          unit: u.limits.unit || fromAsset,
          asset: u.limits.asset || fromAsset,
        };
      }
    }
  }
  const best = route?.bestExecutable || route?.best;
  if (best?.limits?.min != null && Number.isFinite(Number(best.limits.min))) {
    return {
      provider: best.provider,
      min: Number(best.limits.min),
      unit: best.limits.unit || fromAsset,
      asset: best.limits.asset || fromAsset,
    };
  }
  return null;
}

export function createSwapkitClient({
  url = process.env.SWAPKIT_MCP_URL || DEFAULT_SWAPKIT_MCP_URL,
  fetchImpl = fetch,
} = {}) {
  const endpoint = String(url || DEFAULT_SWAPKIT_MCP_URL).trim();

  async function callTool(name, args, { signal } = {}) {
    const res = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: randomBytes(6).toString("hex"),
        method: "tools/call",
        params: { name, arguments: args },
      }),
      signal,
    });
    const text = await res.text();
    let rpc = null;
    try {
      const dataLine = text.split("\n").find((l) => l.startsWith("data: "));
      rpc = JSON.parse(dataLine ? dataLine.slice(6) : text);
    } catch {
      throw new Error(`swapkit_invalid_response:${res.status}`);
    }
    if (!res.ok || !rpc || rpc.error) {
      throw new Error(rpc?.error?.message || `swapkit_http_${res.status}`);
    }
    const toolRes = rpc.result || {};
    const contentText = toolRes.content?.find?.((c) => c?.type === "text")?.text;
    let parsed = toolRes.structuredContent;
    if (parsed === undefined && typeof contentText === "string") {
      try {
        parsed = JSON.parse(contentText);
      } catch {
        parsed = { error: contentText };
      }
    }
    if (toolRes.isError) {
      throw new Error(parsed?.error || contentText || "swapkit_tool_error");
    }
    return parsed ?? {};
  }

  async function routeSwap({ from, to, amount, sats, side = "settle", liveOnly = true, signal }) {
    return await callTool(
      "swap_route",
      {
        from,
        to,
        ...(sats !== undefined ? { sats: Number(sats) } : {}),
        ...(amount !== undefined ? { amount: Number(amount) } : {}),
        ...(side ? { side } : {}),
        liveOnly,
      },
      { signal },
    );
  }

  async function createSwap({
    provider = "auto",
    from,
    to,
    amount,
    sats,
    side = "settle",
    settleTarget,
    refundAddress,
    walletCapabilities,
    customOrderId,
    simulate = false,
    signal,
  }) {
    const intent = await callTool(
      "swap_create",
      {
        provider,
        from,
        to,
        settleTarget,
        ...(refundAddress ? { refundAddress } : {}),
        ...(sats !== undefined ? { sats: Number(sats) } : {}),
        ...(amount !== undefined ? { amount: Number(amount) } : {}),
        ...(side ? { side } : {}),
        ...(Array.isArray(walletCapabilities) ? { walletCapabilities } : {}),
        ...(customOrderId ? { customOrderId: String(customOrderId).slice(0, 64) } : {}),
        ...(simulate ? { simulate: true } : {}),
      },
      { signal },
    );
    return extractSwapFunding(intent);
  }

  async function getSwapStatus({ provider, id, signal }) {
    const intent = await callTool("swap_status", { provider, id }, { signal });
    return extractSwapFunding(intent);
  }

  async function pollUntilSettled({
    provider,
    id,
    timeoutMs = 45_000,
    intervalMs = 2_000,
    signal,
  }) {
    if (!provider || !id) return { settled: false, status: "pending", order: null };
    const deadline = Date.now() + timeoutMs;
    let last = null;
    while (Date.now() <= deadline) {
      try {
        last = await getSwapStatus({ provider, id, signal });
        if (SETTLED_STATUSES.has(last.status)) {
          return { settled: true, status: "done", order: last, settleTxid: last.settleTxid };
        }
        if (FAILED_STATUSES.has(last.status)) {
          return { settled: false, status: "failed", order: last };
        }
      } catch {
        // Transient poll error; keep polling until timeout.
      }
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    return { settled: false, status: "pending", order: last, settleTxid: last?.settleTxid || null };
  }

  return {
    endpoint,
    callTool,
    routeSwap,
    createSwap,
    getSwapStatus,
    pollUntilSettled,
  };
}
