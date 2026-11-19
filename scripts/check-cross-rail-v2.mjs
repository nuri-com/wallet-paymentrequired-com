// Offline E2E test for cross-rail auto-bridging (USDC <-> Lightning/Arkade),
// on-chain Bitcoin (`bc1...` + BIP21 `bitcoin:...`), chained Passkey `create_url`,
// smart dual-rail 402 selection, universal `to`, and Monero -> SwapKit redirect.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { bech32, hex } from "@scure/base";
import { getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  AGENT_DERIVATION_VERSION,
  AGENT_GRANT_REPLY_FORMAT,
  AGENT_REPLY_SALT_DOMAIN,
  agentGrantProofMessage,
  deriveAgentWallet,
} from "../src/agent-grant-crypto.mjs";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { decodeBolt11 } from "@arkade-os/swap/advanced";
import { createMcpWalletTool, WALLET_TOOL } from "../src/mcp-wallet-tool.mjs";
import { instructions } from "../src/mcp-instructions.mjs";
import {
  resolveWalletOrigin,
  serviceIndexHtml,
  walletLlmsTxt,
  walletSkillMd,
} from "../src/service-index.mjs";
import {
  btcDecimalToSats,
  isMoneroAddress,
  isOnchainBtcAddress,
  parseBip21Uri,
} from "../src/agent-swapkit-v2.mjs";

const vector = JSON.parse(
  readFileSync(new URL("../test/fixtures/agent-grant-vector.json", import.meta.url), "utf8"),
);

const MAIN_WALLET = privateKeyToAccount("0x3333333333333333333333333333333333333333333333333333333333333333");
const COSIGNER_EOA = "0x4444444444444444444444444444444444444444";
const COSIGNER_BTC_PUB33 = hex.encode(secp256k1.getPublicKey(new Uint8Array(32).fill(0x45), true));
const SWAPKIT_USDC_DEPOSIT = getAddress("0x7777777777777777777777777777777777777777");
const TEST_CRED_ID = "Y3Jvc3MtcmFpbC10ZXN0LWNyZWQtaWQ";

function intToWordsBE(num, len) {
  const out = new Array(len).fill(0);
  let n = BigInt(num);
  for (let i = len - 1; i >= 0; i -= 1) {
    out[i] = Number(n & 31n);
    n >>= 5n;
  }
  return out;
}

function makeBolt11(amountSats, preimageHex) {
  const preimage = hex.decode(preimageHex);
  const paymentHash = sha256(preimage);
  const hrp = `lnbc${BigInt(amountSats) * 10n}n`;
  const tsWords = intToWordsBE(Math.floor(Date.now() / 1000), 7);
  const phWords = bech32.toWords(paymentHash);
  const expWords = intToWordsBE(3600, 2);
  const sigWords = bech32.toWords(new Uint8Array(65).fill(0x42));
  const words = [
    ...tsWords,
    1,
    ...intToWordsBE(phWords.length, 2),
    ...phWords,
    6,
    ...intToWordsBE(expWords.length, 2),
    ...expWords,
    ...sigWords,
  ];
  return {
    invoice: bech32.encode(hrp, words, 2000),
    paymentHash: hex.encode(paymentHash),
    preimageHex,
  };
}

function encryptGrant({ prfBytes, sessionId, replyPubkey, index = 0, policy }) {
  const derived = deriveAgentWallet(prfBytes, index);
  const ephSk = new Uint8Array(32).fill(0x19);
  const ephPubXonly = hex.encode(schnorr.getPublicKey(ephSk));
  const shared = secp256k1.getSharedSecret(ephSk, `02${replyPubkey.toLowerCase()}`, true).slice(1);
  const key = hkdf(sha256, shared, new TextEncoder().encode(AGENT_REPLY_SALT_DOMAIN), new TextEncoder().encode(sessionId), 32);
  const nonce = new Uint8Array(24).fill(0x27);
  const aad = new TextEncoder().encode(
    JSON.stringify({
      format: AGENT_GRANT_REPLY_FORMAT,
      session_id: sessionId,
      index: derived.public.index,
      agent_eth_eoa: getAddress(derived.public.agent_eth_eoa),
      agent_btc_public_key_33_hex: derived.public.agent_btc_public_key_33_hex,
      policy,
    }),
  );
  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      format: AGENT_GRANT_REPLY_FORMAT,
      derivation_version: AGENT_DERIVATION_VERSION,
      index: derived.public.index,
      agent_eth_private_key_hex: hex.encode(derived.secrets.agent_eth_private_key),
      agent_btc_private_key_hex: hex.encode(derived.secrets.agent_btc_private_key),
      public: derived.public,
      policy,
    }),
  );
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return {
    ephemeral_pubkey: ephPubXonly,
    nonce_b64u: Buffer.from(nonce).toString("base64url"),
    ciphertext_b64u: Buffer.from(ciphertext).toString("base64url"),
    agent_public: derived.public,
    policy,
  };
}

// 1. Unit checks for BIP21, BTC address, Monero address, decimal BTC -> sats, instructions
{
  assert.equal(isOnchainBtcAddress("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"), true);
  assert.equal(isOnchainBtcAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), true);
  assert.equal(isOnchainBtcAddress("0x5b090a84e864d7B3C84bc398109a6712E5649Ca8"), false);
  assert.equal(isMoneroAddress("4" + "A".repeat(94)), true);
  assert.equal(isMoneroAddress("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"), false);
  assert.equal(btcDecimalToSats("0.00025"), 25_000);
  assert.equal(btcDecimalToSats(0.0005), 50_000);

  const bip = parseBip21Uri("bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.00025");
  assert.equal(bip.address, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
  assert.equal(bip.amountSats, 25_000);
  assert.equal(bip.lightning, null);

  const sampleInv = makeBolt11(1000, "11".repeat(32)).invoice;
  const bipLn = parseBip21Uri(`bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.00001&lightning=${sampleInv}`);
  assert.equal(bipLn.lightning, sampleInv);

  const walletInst = instructions(["wallet"]);
  assert.ok(walletInst.includes("wallet_key"));
  assert.ok(!walletInst.includes("Hold a session"));
  assert.ok(walletInst.includes("swapkit.nuri.com/mcp"));
  assert.ok(walletInst.includes("NEVER pass companion MCP URLs like swapkit.nuri.com/mcp or XMR addresses into wallet pay"));
  assert.ok(walletInst.includes("create_url"));
  assert.ok(walletInst.includes("NEW request_id and a higher max_amount"));
  assert.deepEqual(WALLET_TOOL.inputSchema.properties.action.enum, ["balance", "receive", "pay", "history"]);
  const { outputSchema: _omitOut, ...wireWalletTool } = WALLET_TOOL;
  const approxStaticTokens = Math.ceil((walletInst.length + JSON.stringify(wireWalletTool).length) / 4);
  assert.ok(
    approxStaticTokens / 64000 <= 0.0235,
    `static MCP footprint ${((approxStaticTokens / 64000) * 100).toFixed(3)}% exceeds 2.35% of 64k`,
  );

  // Host-aware origin resolution & inline script syntax
  assert.equal(resolveWalletOrigin("agent.nuri.com"), "https://agent.nuri.com");
  assert.equal(resolveWalletOrigin("wallet.paymentrequired.com"), "https://wallet.paymentrequired.com");
  assert.equal(resolveWalletOrigin("wallet.nuri.com:443"), "https://wallet.nuri.com");
  assert.equal(resolveWalletOrigin("nuriwallet.com"), "https://nuriwallet.com");
  assert.equal(resolveWalletOrigin({ headers: { "x-forwarded-host": "agent.nuri.com, 10.0.0.1", host: "127.0.0.1:8798" } }), "https://agent.nuri.com");
  assert.equal(resolveWalletOrigin({ headers: { "x-forwarded-host": "nuriwallet.com, 10.0.0.1", host: "127.0.0.1:8798" } }), "https://nuriwallet.com");
  assert.equal(resolveWalletOrigin("evil.example.com"), "https://wallet.paymentrequired.com");
  const homeHtml = serviceIndexHtml("wallet", { origin: "https://agent.nuri.com" });
  const scriptMatch = homeHtml.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(scriptMatch, "homepage must include inline setup widget script");
  new Function(scriptMatch[1]); // verify valid JS syntax offline
  assert.ok(homeHtml.includes('id="tt"'), "homepage must include dark/light theme toggle");
  assert.ok(homeHtml.includes("A real money account"), "homepage must use unified Nuri design");
  assert.ok(homeHtml.includes("calls.nuri.com"), "homepage must link live calls.nuri.com companion");
  assert.ok(scriptMatch[1].includes('to: "https://mail.paymentrequired.com/v1/create_inbox"'), "test payment must pass to:");
  assert.ok(!scriptMatch[1].includes('target: "https://mail.paymentrequired.com'), "test payment must not pass unknown field target:");
  assert.ok(scriptMatch[1].includes("body: { request_id: reqId }"), "test payment must pass mail request_id body");
  assert.ok(walletLlmsTxt("https://agent.nuri.com").split("\n").length <= 40);
  assert.ok(walletSkillMd("https://agent.nuri.com").includes("mcp_endpoint: https://agent.nuri.com/mcp"));
  assert.ok(walletLlmsTxt("https://nuriwallet.com").split("\n").length <= 40);
  assert.ok(walletSkillMd("https://nuriwallet.com").includes("mcp_endpoint: https://nuriwallet.com/mcp"));
}

// 2. Full cross-rail + on-chain + chained create_url + smart dual-rail 402 E2E
const tmpDir = mkdtempSync(join(tmpdir(), "nuri-cross-rail-"));
const savedEnv = { ...process.env };
process.env.AGENT_KERNEL_ENCRYPTION_KEY = "22".repeat(32);

try {
  const sessions = new Map();
  let safeUsdcUnits = 0n;
  let arkSats = 0n;
  let pendingSwapReceives = new Map(); // invoice -> { rfqId, amountSats, funded }
  const swapOrders = new Map();
  let swapSeq = 0;

  const connectClient = {
    origin: "https://connect.nuri.com",
    async startAgentGrant({ replyPubkey, index, policy }) {
      const id = `sess_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
      const approvalUrl = `https://connect.nuri.com/sign/${id}`;
      sessions.set(id, { status: "pending", replyPubkey, index, policy, approvalUrl });
      return { session_id: id, approval_url: approvalUrl, expires_at: new Date(Date.now() + 600_000).toISOString() };
    },
    async startWalletCreate({ returnUrl }) {
      return {
        session_id: "create_sess_1",
        approval_url: `https://connect.nuri.com/create/create_sess_1?return_url=${encodeURIComponent(returnUrl)}`,
      };
    },
    async readAgentGrantResult({ sessionId }) {
      return sessions.get(sessionId);
    },
  };

  const cosignerClient = {
    async registerGrant({ main_eoa, index = 0 }) {
      return {
        grant: {
          cosigner_eoa: COSIGNER_EOA,
          cosigner_btc_pk33: COSIGNER_BTC_PUB33,
          aggregated_btc_xonly: "aa".repeat(32),
          main_eoa,
          index,
        },
      };
    },
  };

  const transfers = [];
  const safeRuntime = {
    publicClient: {
      readContract: async () => 0n,
    },
    async readUsdcBalanceUnits() {
      return safeUsdcUnits;
    },
    async ensureSafeDeployed() {
      return { deployed: true, txHash: null };
    },
    async signSafeTypedData() {
      return "0x" + "99".repeat(65);
    },
    async transferUsdc({ to, amountUnits }) {
      const amt = BigInt(amountUnits);
      assert.ok(safeUsdcUnits >= amt, `Safe USDC insufficient: ${safeUsdcUnits} < ${amt}`);
      safeUsdcUnits -= amt;
      const txHash = `0x${createHash("sha256").update(`usdc:${to}:${amt}:${transfers.length}`).digest("hex")}`;
      transfers.push({ rail: "usdc", to, amountUnits: amt, txHash });
      // If funded a SwapKit deposit order, settle it immediately!
      for (const order of swapOrders.values()) {
        if (order.sendToAddress && getAddress(order.sendToAddress) === getAddress(to) && order.status === "AWAITING_FUNDING") {
          order.status = "COMPLETED";
          order.settleTxid = `btc_tx_${order.swapId}`;
          // If settling to our own Arkade lightning receive invoice, mark it lockup-funded!
          const rec = pendingSwapReceives.get(order.settleTarget);
          if (rec) rec.funded = true;
        }
      }
      return { txHash };
    },
  };

  const preimages = new Map();
  const arkadeRuntime = {
    decodeBolt11,
    async deriveWalletScript() {
      return { address: "ark1qtestwallet00000000000000000000000000000000000000000000000000000" };
    },
    async readBalance() {
      return { address: "ark1qtestwallet00000000000000000000000000000000000000000000000000000", sats: arkSats };
    },
    async createLightningReceive({ amountSats }) {
      const rfqId = createHash("sha256").update(`recv:${amountSats}:${pendingSwapReceives.size}`).digest("hex");
      const pre = createHash("sha256").update(`pre:${rfqId}`).digest("hex");
      const b = makeBolt11(amountSats + 50, pre);
      pendingSwapReceives.set(b.invoice, { rfqId, expectedAmountSats: amountSats, funded: false });
      return {
        rfqId,
        invoice: b.invoice,
        paymentHash: b.paymentHash,
        payAmountSats: amountSats + 50,
        expectedAmountSats: amountSats,
        feeSats: 50,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        lockupAddress: "ark1qlockup",
        swapPkScriptHex: "5120" + "11".repeat(32),
        payoutAddress: "ark1qtestwallet00000000000000000000000000000000000000000000000000000",
        quoteJson: "{}",
      };
    },
    async claimLightningReceive({ receiveRecord }) {
      const rec = [...pendingSwapReceives.values()].find((r) => r.rfqId === receiveRecord.rfqId);
      if (!rec || !rec.funded) return { status: "pending" };
      if (!rec.claimed) {
        rec.claimed = true;
        arkSats += BigInt(rec.expectedAmountSats);
      }
      return { status: "claimed", claimTxid: `claim_${rec.rfqId.slice(0, 12)}`, claimedSats: rec.expectedAmountSats };
    },
    async payBolt11Invoice({ bolt11, maxSats }) {
      const facts = decodeBolt11(bolt11);
      const total = facts.amountSats + 30;
      if (maxSats && total > maxSats) {
        const e = new Error("over");
        e.code = "over_max_amount";
        throw e;
      }
      if (arkSats < BigInt(total)) {
        throw new Error(`insufficient_arkade_sats:${arkSats}:${total}`);
      }
      arkSats -= BigInt(total);
      const isPendingOnly = pendingBolt11Hashes.has(facts.paymentHash);
      const pre = isPendingOnly ? null : preimages.get(facts.paymentHash) || "ab".repeat(32);
      const arkTxid = `ark_${createHash("sha256").update(`ln:${bolt11}:${transfers.length}`).digest("hex").slice(0, 24)}`;
      transfers.push({ rail: "lightning", paymentHash: facts.paymentHash, totalSats: total, arkTxid });

      // If this BOLT11 belongs to a SwapKit deposit order, settle it!
      for (const order of swapOrders.values()) {
        if (order.payInvoice === bolt11 && order.status === "AWAITING_FUNDING") {
          order.status = "COMPLETED";
          order.settleTxid = `settle_${order.swapId}`;
          if (order.to === "USDC_BASE") {
            const settleUnits = BigInt(Math.round(Number(order.settleAmount) * 1_000_000));
            // If settling into our own Safe, credit Safe balance!
            if (order.settleTarget && walletSafeAddr && getAddress(order.settleTarget) === getAddress(walletSafeAddr)) {
              safeUsdcUnits += settleUnits;
            }
          }
        }
      }

      return {
        status: isPendingOnly ? "pending" : "done",
        paymentHash: facts.paymentHash,
        ...(pre ? { preimageHex: pre } : {}),
        amountSats: facts.amountSats,
        feeSats: 30,
        totalSats: total,
        arkTxid,
        swapPkScriptHex: "5120" + "22".repeat(32),
      };
    },
    async checkLightningSendFate({ paymentHash }) {
      const settledPre = settledPendingSendPreimages.get(paymentHash);
      if (settledPre) return { fate: "claimed", preimageHex: settledPre };
      return { fate: "pending", preimageHex: null };
    },
  };

  // Synthetic SwapKit client mirroring live BitcoinVN limits ($5 min, 1 BTC = $65,000)
  const BTC_USD = 65_000;
  const swapkitClient = {
    async routeSwap({ from, to, amount, sats, side = "settle" }) {
      if (from === "USDC_BASE" && to === "BTC_LN") {
        const usd = side === "deposit" ? Number(amount) : (Number(sats) / 1e8) * BTC_USD;
        if (usd < 5) {
          return {
            bestExecutable: null,
            unavailable: [{ provider: "bitcoinvn", code: "below_provider_min", limits: { min: 5, unit: "USDC", asset: "USDC_BASE", rate: 1 / BTC_USD } }],
          };
        }
        const btc = side === "deposit" ? (usd / BTC_USD).toFixed(8) : (Number(sats) / 1e8).toFixed(8);
        return {
          bestExecutable: { provider: "bitcoinvn", execution: "live", depositAmount: (usd * 1.02).toFixed(6), settleAmount: btc },
        };
      }
      if (from === "BTC_LN" && to === "USDC_BASE") {
        const usd = Number(amount);
        if (usd < 5) {
          return {
            bestExecutable: null,
            unavailable: [{ provider: "bitcoinvn", code: "below_provider_min", limits: { min: 5 / BTC_USD, unit: "BTC", asset: "BTC_LN", rate: 1 / BTC_USD } }],
          };
        }
        return {
          bestExecutable: { provider: "bitcoinvn", execution: "live", depositAmount: ((usd / BTC_USD) * 1.02).toFixed(8), settleAmount: String(usd) },
        };
      }
      return { bestExecutable: { provider: "bitcoinvn", execution: "live", depositAmount: "15.0", settleAmount: "0.00025" } };
    },
    async createSwap({ from, to, amount, sats, settleTarget }) {
      swapSeq += 1;
      const swapId = `sk_${swapSeq}`;
      if (from === "USDC_BASE") {
        const targetSats = sats ?? Math.round((Number(amount) / BTC_USD) * 1e8);
        const depositUsd = Number(((targetSats / 1e8) * BTC_USD * 1.02).toFixed(6));
        const order = {
          provider: "bitcoinvn",
          swapId,
          status: "AWAITING_FUNDING",
          from,
          to,
          settleTarget,
          sendToAddress: SWAPKIT_USDC_DEPOSIT,
          depositAmount: depositUsd,
          settleAmount: targetSats / 1e8,
        };
        swapOrders.set(swapId, order);
        return order;
      }
      // from === "BTC_LN"
      const depSats =
        to === "BTC"
          ? Math.ceil(Number(sats) * 1.02)
          : Math.ceil((Number(amount) / BTC_USD) * 1e8 * 1.02);
      const pre = createHash("sha256").update(`sk_pre_${swapId}`).digest("hex");
      const inv = makeBolt11(depSats, pre);
      preimages.set(inv.paymentHash, pre);
      const order = {
        provider: "bitcoinvn",
        swapId,
        status: "AWAITING_FUNDING",
        from,
        to,
        settleTarget,
        payInvoice: inv.invoice,
        depositAmount: depSats / 1e8,
        settleAmount: to === "BTC" ? Number(sats) / 1e8 : Number(amount),
      };
      swapOrders.set(swapId, order);
      return order;
    },
    async getSwapStatus({ id }) {
      return swapOrders.get(id);
    },
    async pollUntilSettled({ id }) {
      const o = swapOrders.get(id);
      return { settled: o.status === "COMPLETED", status: o.status === "COMPLETED" ? "done" : "pending", order: o, settleTxid: o.settleTxid };
    },
  };

  // Synthetic L402, x402, and dual-rail HTTP 402 endpoints
  const l402Inv = makeBolt11(500, "55".repeat(32));
  preimages.set(l402Inv.paymentHash, l402Inv.preimageHex);
  const dualLnInv = makeBolt11(400, "66".repeat(32));
  preimages.set(dualLnInv.paymentHash, dualLnInv.preimageHex);

  const merchantFetch = async (url, { headers = {} } = {}) => {
    if (url === "https://l402-only.example.com/data") {
      if (headers.Authorization === `L402 mac1:${l402Inv.preimageHex}`) {
        return { status: 200, headers: { "content-type": "application/json" }, bytes: Buffer.from(JSON.stringify({ ok: "l402-paid-from-usdc" })) };
      }
      return { status: 402, headers: { "www-authenticate": `L402 macaroon="mac1", invoice="${l402Inv.invoice}"` }, bytes: Buffer.from("{}") };
    }
    if (url === "https://x402-only.example.com/ai") {
      if (headers["PAYMENT-SIGNATURE"] || headers["payment-signature"]) {
        const receipt = Buffer.from(JSON.stringify({ success: true, transaction: "0x" + "77".repeat(32) })).toString("base64");
        return {
          status: 200,
          headers: { "content-type": "application/json", "payment-response": receipt },
          bytes: Buffer.from(JSON.stringify({ answer: "x402-paid-from-btc" })),
        };
      }
      const req = {
        x402Version: 2,
        resource: { url },
        accepts: [{
          scheme: "exact",
          network: "eip155:8453",
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          amount: "50000",
          payTo: "0x2222222222222222222222222222222222222222",
          maxTimeoutSeconds: 300,
          extra: { name: "USD Coin", version: "2", assetTransferMethod: "eip3009" },
        }],
      };
      return { status: 402, headers: { "payment-required": Buffer.from(JSON.stringify(req)).toString("base64") }, bytes: Buffer.from("{}") };
    }
    if (url === "https://dual.example.com/auto") {
      if (headers["PAYMENT-SIGNATURE"] || headers["payment-signature"]) {
        return { status: 200, headers: { "content-type": "application/json" }, bytes: Buffer.from(JSON.stringify({ paid_via: "x402" })) };
      }
      const req = {
        x402Version: 2,
        resource: { url },
        accepts: [{
          scheme: "exact",
          network: "eip155:8453",
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          amount: "20000",
          payTo: "0x2222222222222222222222222222222222222222",
          maxTimeoutSeconds: 300,
          extra: { name: "USD Coin", version: "2", assetTransferMethod: "eip3009" },
        }],
      };
      return {
        status: 402,
        headers: {
          "www-authenticate": `L402 macaroon="mac2", invoice="${dualLnInv.invoice}"`,
          "payment-required": Buffer.from(JSON.stringify(req)).toString("base64"),
        },
        bytes: Buffer.from("{}"),
      };
    }
    throw new Error(`unexpected merchant url: ${url}`);
  };

  const pendingBolt11Hashes = new Set();
  const settledPendingSendPreimages = new Map();
  let walletSafeAddr = null;
  const walletTool = createMcpWalletTool({
    accountFlow: { authorized: async () => null },
    chainId: 8453,
    path: join(tmpDir, "cross.sqlite"),
    consolidate: false,
    merchantFetch,
    prfOptions: {
      connectClient,
      cosignerClient,
      safeRuntime,
      arkadeRuntime,
      swapkitClient,
      getBtcUsdRate: async () => BTC_USD,
      bridgeTimeoutMs: 5_000,
      bridgePollIntervalMs: 50,
      autoClaimIntervalMs: 25,
      autoClaimTtlMs: 5_000,
    },
  });

  // A. Missing wallet_key on pay -> clean connect_required!
  const noKeyPay = await walletTool.call({ action: "pay", to: "https://x402-only.example.com/ai" });
  assert.equal(noKeyPay.ok, false);
  assert.equal(noKeyPay.status, "connect_required");

  // B. Step-1 Onboarding returns chained `create_url` with `return_url=<approval_url>` AND `approval_url`!
  const start = await walletTool.call({ action: "balance", request_id: "ob-1" });
  assert.equal(start.status, "connect_required");
  assert.ok(start.create_url.includes("/create/create_sess_1?return_url="));
  assert.ok(start.create_url.includes(encodeURIComponent(start.approval_url)));

  const sid = start.approval_url.split("/").pop();
  const s = sessions.get(sid);
  const enc = encryptGrant({ prfBytes: hex.decode(vector.prf_hex), sessionId: sid, replyPubkey: s.replyPubkey, index: 0, policy: s.policy });
  const sig = await MAIN_WALLET.signMessage({ message: agentGrantProofMessage({ sessionId: sid, replyPubkey: s.replyPubkey, reply: enc }) });
  s.status = "approved";
  s.wallet = { eth_user_eoa: MAIN_WALLET.address, cred_id_b64u: TEST_CRED_ID };
  s.result = { ...enc, address: MAIN_WALLET.address, signature: sig };

  const fin = await walletTool.call({ action: "balance", request_id: "ob-1" });
  assert.equal(fin.ok, true);
  const walletKey = fin.wallet_key;
  walletSafeAddr = fin.address;

  // C. Wallet holds ONLY 15.00 Base USDC (0 sats)!
  safeUsdcUnits = 15_000_000n;
  arkSats = 0n;

  // C1. Dual-rail 402 URL with NO `prefer` and universal `to: "https://..."` -> auto-picks `x402` (zero swap fee!)
  const autoDual = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "https://dual.example.com/auto",
    request_id: "dual-auto-1",
  });
  assert.equal(autoDual.ok, true, JSON.stringify(autoDual));
  assert.equal(autoDual.protocol, "x402");
  assert.equal(autoDual.funded_from, undefined);

  // C2. Direct BOLT11 (>= $5 min -> 10,000 sats ≈ $6.50) paid directly from Base USDC via SwapKit!
  const bigBolt = makeBolt11(10_000, "71".repeat(32));
  const paidBigBolt = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: bigBolt.invoice,
    request_id: "usdc-to-big-bolt",
  });
  assert.equal(paidBigBolt.ok, true, JSON.stringify(paidBigBolt));
  assert.equal(paidBigBolt.rail, "lightning");
  assert.equal(paidBigBolt.funded_from, "usdc");
  assert.ok(paidBigBolt.swap_id);

  // C3. Small L402 HTTPS API (500 sats < $5 min) paid from Base USDC via automatic self-bridge into Arkade + preimage unlock!
  safeUsdcUnits = 10_000_000n;
  arkSats = 0n;
  const paidL402FromUsdc = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "https://l402-only.example.com/data",
    max_sats: 1000,
    request_id: "usdc-to-l402",
  });
  assert.equal(paidL402FromUsdc.ok, true, JSON.stringify(paidL402FromUsdc));
  assert.equal(paidL402FromUsdc.protocol, "l402");
  assert.equal(paidL402FromUsdc.funded_from, "usdc");
  assert.equal(paidL402FromUsdc.preimage, l402Inv.preimageHex);
  assert.equal(JSON.parse(paidL402FromUsdc.resource.body).ok, "l402-paid-from-usdc");
  assert.ok(arkSats > 7_000n, "leftover bridged sats stay in user's own 2-of-2 Arkade custody");

  // D. Wallet holds ONLY 35,000 Arkade sats (0 Base USDC)!
  safeUsdcUnits = 0n;
  arkSats = 35_000n;

  // D1. x402 HTTPS API ($0.05) paid from Arkade sats via automatic self-bridge into Base Safe USDC!
  const paidX402FromBtc = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "https://x402-only.example.com/ai",
    max_amount: "0.25",
    request_id: "btc-to-x402",
  });
  assert.equal(paidX402FromBtc.ok, true, JSON.stringify(paidX402FromBtc));
  assert.equal(paidX402FromBtc.protocol, "x402");
  assert.equal(paidX402FromBtc.funded_from, "arkade");
  assert.equal(JSON.parse(paidX402FromBtc.resource.body).answer, "x402-paid-from-btc");

  // D2. On-chain Bitcoin `bc1...` & BIP21 `bitcoin:bc1...?amount=0.0002` paid from Arkade sats!
  safeUsdcUnits = 0n;
  arkSats = 35_000n;
  const paidBtc = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.0002",
    request_id: "btc-bip21-1",
  });
  assert.equal(paidBtc.ok, true, JSON.stringify(paidBtc));
  assert.equal(paidBtc.rail, "btc");
  assert.equal(paidBtc.funded_from, "arkade");
  assert.equal(paidBtc.amount_sats, 20_000);

  // D3. On-chain Bitcoin `bc1...` paid from Base USDC (decimal BTC `amount: "0.00025"`)!
  safeUsdcUnits = 25_000_000n;
  arkSats = 0n;
  const paidBtcFromUsdc = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    amount: "0.00025",
    request_id: "btc-from-usdc-1",
  });
  assert.equal(paidBtcFromUsdc.ok, true, JSON.stringify(paidBtcFromUsdc));
  assert.equal(paidBtcFromUsdc.rail, "btc");
  assert.equal(paidBtcFromUsdc.funded_from, "usdc");
  assert.equal(paidBtcFromUsdc.amount_sats, 25_000);

  // E. Monero address gives clean 1-sentence redirect to companion SwapKit MCP server!
  const xmrRes = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "4" + "A".repeat(94),
    request_id: "xmr-redirect",
  });
  assert.equal(xmrRes.ok, false);
  assert.match(xmrRes.error, /swapkit\.nuri\.com\/mcp/);

  // F. Cross-rail cap guard: `max_amount: "0.0001"` MUST block L402 (`500 sats`) with STOP error!
  safeUsdcUnits = 0n;
  arkSats = 10_000n;
  const txBeforeCap = transfers.length;
  const overcapL402 = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "https://l402-only.example.com/data",
    max_amount: "0.0001",
    request_id: "overcap-l402-usd",
  });
  assert.equal(overcapL402.ok, false, JSON.stringify(overcapL402));
  assert.deepEqual(overcapL402.price, { amount: "500", currency: "sats" });
  assert.match(overcapL402.error, /STOP and ask the person first/);
  assert.equal(transfers.length, txBeforeCap, "over-cap L402 must not send any sats");

  // G. Cross-rail cap guard: `max_amount: "0.0001"` MUST block raw BOLT11 (`500 sats`) too!
  const overcapBolt11 = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: l402Inv.invoice,
    max_amount: "0.0001",
    request_id: "overcap-bolt11-usd",
  });
  assert.equal(overcapBolt11.ok, false, JSON.stringify(overcapBolt11));
  assert.deepEqual(overcapBolt11.price, { amount: "500", currency: "sats" });
  assert.match(overcapBolt11.error, /STOP and ask the person first/);
  assert.equal(transfers.length, txBeforeCap, "over-cap BOLT11 must not send any sats");

  // H. Dual-rail `capHint`: when BOTH USDC and sats are funded and caller sets `max_amount`, pick x402!
  safeUsdcUnits = 5_000_000n;
  arkSats = 10_000n;
  const dualWithUsdCap = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "https://dual.example.com/auto",
    max_amount: "0.05",
    request_id: "dual-usd-cap-hint",
  });
  assert.equal(dualWithUsdCap.ok, true, JSON.stringify(dualWithUsdCap));
  assert.equal(dualWithUsdCap.protocol, "x402");
  assert.equal(dualWithUsdCap.rail, "usdc");

  // I. Pending BOLT11 op is saved in history and idempotent replay returns cached pending receipt without double-submitting!
  const pendingInv = makeBolt11(800, "99".repeat(32));
  pendingBolt11Hashes.add(pendingInv.paymentHash);
  arkSats = 10_000n;
  const txBeforePending = transfers.length;
  const firstPending = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: pendingInv.invoice,
    max_sats: 1000,
    request_id: "pending-ln-replay",
  });
  assert.equal(firstPending.ok, true, JSON.stringify(firstPending));
  assert.equal(firstPending.status, "pending");
  assert.equal(transfers.length, txBeforePending + 1);

  const secondPending = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: pendingInv.invoice,
    max_sats: 1000,
    request_id: "pending-ln-replay",
  });
  assert.equal(secondPending.ok, true, JSON.stringify(secondPending));
  assert.equal(secondPending.status, "pending");
  assert.equal(secondPending.receipt?.tx, firstPending.receipt?.tx);
  assert.equal(transfers.length, txBeforePending + 1, "pending replay must NOT re-submit payment");

  const hist = await walletTool.call({ action: "history", wallet_key: walletKey });
  const pendingHistItem = hist.history.find((h) => h.request_id === "pending-ln-replay");
  assert.ok(pendingHistItem, "pending op must appear in history");
  assert.equal(pendingHistItem.status, "pending");
  assert.equal(pendingHistItem.rail, "lightning");

  // J. Once the pending Lightning send settles on-chain/Arkade, replay & history auto-upgrade pending -> done with preimage!
  settledPendingSendPreimages.set(pendingInv.paymentHash, pendingInv.preimageHex);
  const upgradedReplay = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: pendingInv.invoice,
    max_sats: 1000,
    request_id: "pending-ln-replay",
  });
  assert.equal(upgradedReplay.ok, true);
  assert.equal(upgradedReplay.status, "done");
  assert.equal(upgradedReplay.preimage, pendingInv.preimageHex);
  assert.equal(transfers.length, txBeforePending + 1, "upgraded replay must NOT re-submit payment");

  // K. Background pushClaim auto-claimer settles inbound Lightning receives without calling wallet balance!
  const satsBeforeAutoClaim = arkSats;
  const autoRecv = await walletTool.call({
    action: "receive",
    wallet_key: walletKey,
    rail: "lightning",
    amount_sats: 1200,
    request_id: "auto-claim-ln-1",
  });
  assert.equal(autoRecv.ok, true);
  // Simulate payer funding the VHTLC without receiver ever calling wallet balance:
  const pendingRecObj = pendingSwapReceives.get(autoRecv.invoice);
  assert.ok(pendingRecObj, "receive record must exist");
  pendingRecObj.funded = true;
  // Wait for background autoClaimIntervalMs (25ms) watcher to claim it automatically:
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(arkSats, satsBeforeAutoClaim + 1200n, "background pushClaim watcher must auto-claim sats without balance call");
  const histAfterAuto = await walletTool.call({ action: "history", wallet_key: walletKey });
  const claimedHist = histAfterAuto.history.find((h) => h.request_id === "auto-claim-ln-1");
  assert.equal(claimedHist?.status, "done", "auto-claimed receive must be done in history");

  walletTool.close();

  // L. Real HTTP server checks for host-aware GET /, /llms.txt, /skill.md, and GET /mcp 405 hint
  const freePort = await new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => resolve(addr.port));
    });
  });
  const serverEntry = fileURLToPath(new URL("../src/wallet-server.mjs", import.meta.url));
  const child = spawn(process.execPath, [serverEntry], {
    cwd: tmpDir,
    env: {
      PATH: process.env.PATH,
      HOST: "127.0.0.1",
      SERVICE_MODE: "wallet",
      SERVICE_PORT: String(freePort),
      SHORT_LINKS_DB: join(tmpDir, "http-check.sqlite"),
      SERVICE_RPC_SECRET: "33".repeat(20),
      AGENT_COSIGNER_URL: "http://127.0.0.1:1",
      AGENT_COSIGNER_RPC_SECRET: "offline-check-secret",
      AGENT_KERNEL_ENCRYPTION_KEY: "22".repeat(32),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let childStderr = "";
  child.stderr.on("data", (chunk) => { childStderr += chunk.toString(); });
  const httpReq = (path, { method = "GET", headers = {}, body } = {}) =>
    new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: freePort, path, method, headers }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
      });
      req.on("error", reject);
      if (body !== undefined) req.write(body);
      req.end();
    });
  try {
    let healthy = false;
    for (let i = 0; i < 40; i += 1) {
      try {
        const h = await httpReq("/healthz");
        if (h.status === 200) { healthy = true; break; }
      } catch {}
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(healthy, `wallet-server failed to boot for HTTP check: ${childStderr}`);

    for (const [hdrs, expectedHost] of [
      [{ Host: "agent.nuri.com" }, "agent.nuri.com"],
      [{ "X-Forwarded-Host": "agent.nuri.com", Host: "127.0.0.1:8798" }, "agent.nuri.com"],
      [{ Host: "wallet.paymentrequired.com" }, "wallet.paymentrequired.com"],
      [{ Host: "wallet.nuri.com" }, "wallet.nuri.com"],
      [{ Host: "nuriwallet.com" }, "nuriwallet.com"],
      [{ "X-Forwarded-Host": "nuriwallet.com", Host: "127.0.0.1:8798" }, "nuriwallet.com"],
      [{ Host: "evil.example.com" }, "wallet.paymentrequired.com"],
    ]) {
      const origin = `https://${expectedHost}`;
      const home = await httpReq("/", { headers: hdrs });
      assert.equal(home.status, 200);
      assert.match(home.headers["content-type"], /text\/html/);
      assert.equal(home.headers["cross-origin-opener-policy"], "same-origin-allow-popups");
      assert.ok(home.body.includes(`<title>${expectedHost} — Agent Wallet</title>`));
      assert.ok(home.body.includes(`${origin}/mcp`));
      assert.ok(home.body.includes(`${origin}/v1/wallet`));
      assert.ok(home.body.includes(`${origin}/llms.txt`));
      assert.ok(home.body.includes(`${origin}/skill.md`));
      assert.ok(home.body.includes(`${origin}/openapi.json`));
      assert.ok(home.body.includes("Create New Passkey Wallet"));
      assert.ok(home.body.includes("Connect Existing Nuri Passkey"));
      assert.ok(home.body.includes("Create Lightning Funding Invoice (sats)"));
      assert.ok(home.body.includes("Test $0.01 Payment (Create Inbox)"));
      assert.ok(home.body.includes("Copy MCP URL"));
      assert.ok(home.body.includes("Copy Agent Prompt"));
      assert.ok(home.body.includes("Copy cURL"));
      assert.ok(!home.body.includes("Privy v1"), "homepage must not show stale Privy v1 copy");
      assert.ok(!home.body.includes("/bridge/privy"), "homepage must not show legacy /bridge/privy copy");
      assert.ok(!home.body.includes("signer.paymentrequired.com"), "homepage must not show signer.paymentrequired.com clutter");
      assert.ok(!home.body.includes("evil.example.com"), "untrusted Host must never reflect into HTML");

      const llms = await httpReq("/llms.txt", { headers: hdrs });
      assert.equal(llms.status, 200);
      assert.match(llms.headers["content-type"], /text\/plain/);
      assert.ok(llms.body.includes(`# Agent Wallet (${expectedHost})`));
      assert.ok(llms.body.includes(`${origin}/mcp`));
      assert.ok(llms.body.includes(`POST ${origin}/v1/wallet`));
      assert.ok(llms.body.includes(`${origin}/openapi.json`));
      assert.ok(llms.body.includes(`NEVER send the person to \`${origin}/\``));
      assert.ok(llms.body.includes("Create / Connect Agent Wallet"));
      assert.ok(llms.body.includes("0.00025"));
      assert.ok(llms.body.includes("https://mail.paymentrequired.com/v1/create_inbox"));
      assert.ok(llms.body.includes("https://browser.paymentrequired.com/v1/browser/open"));
      assert.ok(llms.body.includes("https://vault.paymentrequired.com"));
      assert.ok(llms.body.includes("https://swapkit.nuri.com/mcp"));
      assert.ok(!llms.body.includes("evil.example.com"));

      const skill = await httpReq("/skill.md", { headers: hdrs });
      assert.equal(skill.status, 200);
      assert.match(skill.headers["content-type"], /text\/markdown/);
      assert.ok(skill.body.includes(`mcp_endpoint: ${origin}/mcp`));
      assert.ok(skill.body.includes(`rest_endpoint: ${origin}/v1/wallet`));
      assert.ok(skill.body.includes(`openapi: ${origin}/openapi.json`));
      assert.ok(skill.body.includes(`# Agent Wallet (${expectedHost})`));
      assert.ok(!skill.body.includes("evil.example.com"));

      const openapi = await httpReq("/openapi.json", { headers: hdrs });
      assert.equal(openapi.status, 200);
      assert.match(openapi.headers["content-type"], /application\/json/);
      const spec = JSON.parse(openapi.body);
      assert.equal(spec.openapi, "3.1.0");
      assert.equal(spec.servers[0].url, origin);
      assert.ok(spec.paths["/v1/wallet"]?.post);
      assert.ok(spec.paths["/v1/balance"]?.post);
      assert.ok(spec.paths["/v1/receive"]?.post);
      assert.ok(spec.paths["/v1/pay"]?.post);
      assert.ok(spec.paths["/v1/history"]?.post);
      assert.ok(!openapi.body.includes("evil.example.com"));

      // Plain web/LLM GET /mcp returns 200 + live setup instructions so web fetchers never treat it as dead
      const mcpGet = await httpReq("/mcp", { headers: hdrs });
      assert.equal(mcpGet.status, 200);
      assert.match(mcpGet.headers["content-type"], /text\/plain/);
      assert.ok(mcpGet.body.includes(`Live Remote MCP Server — ${origin}/mcp`));
      assert.ok(mcpGet.body.includes("Settings -> Connectors"));
      assert.ok(mcpGet.body.includes(`# Agent Wallet (${expectedHost})`));

      // Streamable HTTP MCP SSE probe (Accept: text/event-stream) still receives 405 per MCP spec
      const mcpSse = await httpReq("/mcp", { headers: { ...hdrs, Accept: "text/event-stream" } });
      assert.equal(mcpSse.status, 405);
      const mcpJson = JSON.parse(mcpSse.body);
      assert.equal(mcpJson.hint, `POST JSON-RPC to this URL. Start: ${origin}/llms.txt`);

      const restGet = await httpReq("/v1/wallet", { headers: hdrs });
      assert.equal(restGet.status, 200);
      assert.match(restGet.headers["content-type"], /text\/plain/);
      assert.ok(restGet.body.includes(`${origin}/v1/wallet`));
      assert.ok(restGet.body.includes(`# Agent Wallet (${expectedHost})`));

      const robots = await httpReq("/robots.txt", { headers: hdrs });
      assert.equal(robots.status, 200);
      assert.ok(robots.body.includes(`Sitemap: ${origin}/sitemap.xml`));

      const sitemap = await httpReq("/sitemap.xml", { headers: hdrs });
      assert.equal(sitemap.status, 200);
      assert.ok(sitemap.body.includes(`<loc>${origin}/</loc>`));
      assert.ok(sitemap.body.includes(`<loc>${origin}/llms.txt</loc>`));
    }

    for (const p of ["/", "/llms.txt", "/skill.md", "/openapi.json", "/robots.txt", "/sitemap.xml", "/mcp", "/v1/wallet"]) {
      const headRes = await httpReq(p, { method: "HEAD", headers: { Host: "wallet.nuri.com" } });
      assert.equal(headRes.status, 200);
      assert.equal(headRes.body, "");
    }

    // Plain JSON REST /v1/* tests (zero MCP setup): anonymous balance returns connect_required
    const restAnon = await httpReq("/v1/wallet", {
      method: "POST",
      headers: { Host: "wallet.paymentrequired.com", "Content-Type": "application/json" },
      body: JSON.stringify({ action: "balance" }),
    });
    assert.equal(restAnon.status, 200);
    const restAnonJson = JSON.parse(restAnon.body);
    assert.equal(restAnonJson.status, "connect_required");
    assert.ok(restAnonJson.approval_url);
    assert.ok(restAnonJson.create_url);

    // /v1/balance injects action="balance" automatically and accepts Authorization: Bearer npw1_...
    const restBalBadKey = await httpReq("/v1/balance", {
      method: "POST",
      headers: { Host: "wallet.paymentrequired.com", "Content-Type": "application/json", Authorization: "Bearer npw1_invalid_test_key" },
      body: JSON.stringify({}),
    });
    assert.ok(restBalBadKey.status === 200 || restBalBadKey.status === 400);
    const restBalJson = JSON.parse(restBalBadKey.body);
    assert.ok(restBalJson.status === "connect_required" || restBalJson.ok === false, "invalid Bearer wallet_key must fail cleanly");

    // Non-object body returns 400
    const restArr = await httpReq("/v1/pay", {
      method: "POST",
      headers: { Host: "wallet.paymentrequired.com", "Content-Type": "application/json" },
      body: JSON.stringify(["bad"]),
    });
    assert.equal(restArr.status, 400);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.kill("SIGTERM");
      await exited;
    }
  }

  console.log("cross-rail v2 check ok: background pushClaim auto-claim, pending send fate refresh, chained create_url, universal to, dual-rail auto-pick + capHint, cross-rail max_amount/max_sats guards, pending idempotency replay, USDC->BOLT11, USDC->L402 bridge, Arkade->x402 bridge, bc1/BIP21 from BTC & USDC, Monero->SwapKit redirect, and host-aware /, /llms.txt, /skill.md, /mcp 405 verified");
} finally {
  Object.keys(process.env).forEach((k) => {
    if (!(k in savedEnv)) delete process.env[k];
  });
  Object.assign(process.env, savedEnv);
  rmSync(tmpDir, { recursive: true, force: true });
}
