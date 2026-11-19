// v2 Nuri Passkey PRF + Dual-Rail (2-of-4 Base Safe USDC + 2-of-2 Arkade/Lightning)
// coordinator for the 4-action MCP `wallet` tool (`balance`, `receive`, `pay`, `history`).
import { randomUUID } from "node:crypto";
import { getAddress } from "viem";
import { isValidArkAddress } from "@arkade-os/sdk";
import { createAgentArkadeRuntime } from "./agent-arkade-v2.mjs";
import { createAgentCosignerClient } from "./agent-cosigner-client.mjs";
import {
  createConnectGrantClient,
  decryptAgentGrantReply,
  generateGrantReplyKeypair,
  verifyAgentGrantProof,
} from "./agent-grant-crypto.mjs";
import {
  createPrfHttp402Payer,
  defaultGetBtcUsdRate,
  usdUnitsToMaxSats,
} from "./agent-lightning-pay.mjs";
import {
  BASE_USDC_ADDRESS,
  createAgentSafeRuntime,
  deriveFallbackSecondRecoveryAddress,
  predictAgentSafeAddress,
  predictPasskeySignerAddress,
} from "./agent-safe-v2.mjs";
import {
  PRF_WALLET_KEY_RE,
  isPrfWalletKey,
  openPrfAgentWalletStore,
} from "./prf-agent-wallet-store.mjs";
import {
  btcDecimalToSats,
  createSwapkitClient,
  extractProviderMinFromRoute,
  isMoneroAddress,
  isOnchainBtcAddress,
  parseBip21Uri,
  usdcAmountToUnitsCeil,
} from "./agent-swapkit-v2.mjs";
import { decimalToUnits, unitsToDecimal } from "./wallet-units.mjs";

const ETH_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HTTPS_URL_RE = /^https:\/\/.+/i;
const BOLT11_RE = /^(?:lightning:)?ln(?:bc|tb|bcrt|tbs)[0-9a-z]+$/i;
const LN_ADDRESS_RE = /^(?:lightning:)?[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
const DECIMAL_AMOUNT_RE = /^(0|[1-9][0-9]{0,71})(\.[0-9]{1,6})?$/;

export const DEFAULT_GRANT_POLICY = Object.freeze({
  max_per_tx_usdc: "25",
  daily_limit_usdc: "100",
  max_per_tx_sats: 100000,
  daily_limit_sats: 500000,
});

function formatSatsAsBtc(sats) {
  const s = BigInt(sats);
  const whole = s / 100_000_000n;
  const frac = (s % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}

function parsePositiveSats(value, label = "amount_sats") {
  if (value === undefined || value === null || value === "") return undefined;
  const clean = typeof value === "string" ? value.trim() : value;
  const n = typeof clean === "string" && /^\d+$/.test(clean) ? Number(clean) : Number(clean);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new Error(`${label} must be a positive whole number of satoshis.`);
  }
  return n;
}

function parseUsdcUnits(value, label = "amount") {
  if (value === undefined || value === null || value === "") return undefined;
  const raw =
    typeof value === "number" && Number.isFinite(value)
      ? value.toFixed(6).replace(/\.?0+$/, "")
      : typeof value === "string"
        ? value.trim()
        : null;
  if (raw === null || !DECIMAL_AMOUNT_RE.test(raw)) {
    throw new Error(`${label} must be written like 0.25 or 10.`);
  }
  return decimalToUnits(raw, 6);
}

function toSafeWalletRow(wallet) {
  return {
    cred_id_b64u: wallet.credIdB64u,
    slot_index: wallet.slotIndex,
    main_eoa: wallet.mainEoa,
    passkey_signer_address: wallet.passkeySignerAddress,
    agent_eoa: wallet.agentEthEoa,
    cosigner_eoa: wallet.cosignerEoa,
    safe_address: wallet.safeAddress,
  };
}

export function isPrfCustodyConfigured(env = process.env) {
  return Boolean(
    typeof env.AGENT_COSIGNER_URL === "string" &&
      env.AGENT_COSIGNER_URL.trim() &&
      typeof env.AGENT_COSIGNER_RPC_SECRET === "string" &&
      env.AGENT_COSIGNER_RPC_SECRET.trim() &&
      typeof env.AGENT_KERNEL_ENCRYPTION_KEY === "string" &&
      env.AGENT_KERNEL_ENCRYPTION_KEY.trim(),
  );
}

export function createPrfWalletCoordinator({
  path,
  env = process.env,
  connectClient,
  cosignerClient,
  safeRuntime,
  arkadeRuntime,
  swapkitClient,
  http402Payer,
  merchantFetch,
  getBtcUsdRate,
  fetchImpl = fetch,
  bridgeTimeoutMs = 45_000,
  bridgePollIntervalMs = 2_000,
  autoClaimIntervalMs = 2_500,
  autoClaimTtlMs = 10 * 60_000,
} = {}) {
  const configured = isPrfCustodyConfigured(env) || Boolean(cosignerClient);
  let store = null;
  let connect = connectClient || null;
  let cosigner = cosignerClient || null;
  let safe = safeRuntime || null;
  let arkade = arkadeRuntime || null;
  let swapkit = swapkitClient || null;
  let payer = http402Payer || null;
  let closed = false;
  const activeReceiveWatchers = new Map();

  function ensureStore() {
    if (!store) {
      store = openPrfAgentWalletStore({
        path,
        encryptionKey: env.AGENT_KERNEL_ENCRYPTION_KEY,
      });
    }
    return store;
  }

  function ensureConnect() {
    if (!connect) {
      connect = createConnectGrantClient({
        baseUrl: env.CONNECT_NURI_URL || "https://connect.nuri.com",
        fetchImpl,
      });
    }
    return connect;
  }

  function ensureCosigner() {
    if (!cosigner) {
      cosigner = createAgentCosignerClient({
        baseUrl: env.AGENT_COSIGNER_URL,
        secret: env.AGENT_COSIGNER_RPC_SECRET,
        fetchImpl,
      });
    }
    return cosigner;
  }

  function ensureSafe() {
    if (!safe) {
      safe = createAgentSafeRuntime({
        env,
        cosignerClient: ensureCosigner(),
      });
    }
    return safe;
  }

  function ensureArkade() {
    if (!arkade) {
      arkade = createAgentArkadeRuntime({
        env,
        cosignerClient: ensureCosigner(),
        fetchImpl,
      });
    }
    return arkade;
  }

  function ensureSwapkit() {
    if (!swapkit) {
      swapkit = createSwapkitClient({
        url: env.SWAPKIT_MCP_URL,
        fetchImpl,
      });
    }
    return swapkit;
  }

  async function bridgeUsdcToArkade({ walletRecord, secrets, neededSats, opId }) {
    const db = ensureStore();
    const safeRow = toSafeWalletRow(walletRecord);
    const usdcBal = await ensureSafe().readUsdcBalanceUnits(walletRecord.safeAddress);
    if (usdcBal <= 0n) {
      throw new Error("insufficient_balance_usdc_and_btc");
    }

    const sk = ensureSwapkit();
    const route = await sk.routeSwap({
      from: "USDC_BASE",
      to: "BTC_LN",
      sats: neededSats,
      side: "settle",
      liveOnly: true,
    });

    let targetSats = neededSats;
    if (!route?.bestExecutable) {
      const minInfo = extractProviderMinFromRoute(route, "USDC_BASE");
      const minUsdc = minInfo && minInfo.unit === "USDC" ? minInfo.min : 5;
      const bridgeUsdc = Math.ceil(minUsdc * 1.1 * 100) / 100;
      const minUnits = usdcAmountToUnitsCeil(bridgeUsdc);
      if (usdcBal < minUnits) {
        throw new Error(
          `insufficient_usdc_for_cross_rail_bridge:need_${bridgeUsdc}_usdc_have_${unitsToDecimal(String(usdcBal), 6)}`,
        );
      }
      const depRoute = await sk.routeSwap({
        from: "USDC_BASE",
        to: "BTC_LN",
        amount: bridgeUsdc,
        side: "deposit",
        liveOnly: true,
      });
      const q = depRoute?.bestExecutable || depRoute?.best;
      if (!q?.settleAmount) throw new Error("cross_rail_usdc_to_ln_unavailable");
      targetSats = Math.max(neededSats, btcDecimalToSats(q.settleAmount));
    }

    // Mint our own Arkade Lightning receive invoice so bridged sats land in our 2-of-2 Arkade custody.
    const selfRecv = await ensureArkade().createLightningReceive({
      walletRecord,
      agentBtcPrivHex: secrets.agentBtcPrivHex,
      amountSats: targetSats,
    });
    db.saveLightningReceive({
      rfqId: selfRecv.rfqId,
      walletId: walletRecord.walletId,
      requestId: `${opId}:bridge-recv`,
      paymentHash: selfRecv.paymentHash,
      invoice: selfRecv.invoice,
      payAmountSats: selfRecv.payAmountSats,
      expectedAmountSats: selfRecv.expectedAmountSats,
      feeSats: selfRecv.feeSats,
      expiresAt: selfRecv.expiresAt,
      lockupAddress: selfRecv.lockupAddress,
      swapPkScriptHex: selfRecv.swapPkScriptHex,
      payoutAddress: selfRecv.payoutAddress,
      quoteJson: selfRecv.quoteJson,
    });

    const swap = await sk.createSwap({
      from: "USDC_BASE",
      to: "BTC_LN",
      sats: selfRecv.payAmountSats,
      side: "settle",
      settleTarget: selfRecv.invoice,
      refundAddress: walletRecord.safeAddress,
      walletCapabilities: ["send_asset"],
      customOrderId: `${opId}:u2a`,
    });
    if (!swap.sendToAddress || swap.depositAmount == null) {
      throw new Error("cross_rail_swap_missing_deposit_address");
    }
    const depositUnits = usdcAmountToUnitsCeil(swap.depositAmount);
    if (usdcBal < depositUnits) {
      throw new Error(
        `insufficient_usdc_for_cross_rail_bridge:need_${unitsToDecimal(String(depositUnits), 6)}_have_${unitsToDecimal(String(usdcBal), 6)}`,
      );
    }

    const sent = await ensureSafe().transferUsdc({
      walletRecord: safeRow,
      agentEthPrivateKeyHex: secrets.agentEthPrivHex,
      to: getAddress(swap.sendToAddress),
      amountUnits: depositUnits,
      opId: `${opId}:bridge-usdc`,
    });

    const deadline = Date.now() + bridgeTimeoutMs;
    let claimedSats = null;
    while (Date.now() <= deadline) {
      try {
        const claim = await ensureArkade().claimLightningReceive({
          walletRecord,
          agentBtcPrivHex: secrets.agentBtcPrivHex,
          receiveRecord: {
            rfqId: selfRecv.rfqId,
            expectedAmountSats: selfRecv.expectedAmountSats,
            quoteJson: selfRecv.quoteJson,
          },
        });
        if (claim.status === "claimed") {
          claimedSats = claim.claimedSats ?? selfRecv.expectedAmountSats;
          db.markLightningReceiveClaimed(selfRecv.rfqId, {
            claimTxid: claim.claimTxid || null,
            claimedSats,
          });
          break;
        }
      } catch {
        // Wait for swap settlement and VHTLC lockup.
      }
      await new Promise((r) => setTimeout(r, bridgePollIntervalMs));
    }
    if (claimedSats === null) {
      throw new Error(`cross_rail_bridge_pending:swap_${swap.swapId || "unknown"}`);
    }
    return {
      from: "usdc",
      to: "arkade",
      provider: swap.provider,
      swap_id: swap.swapId,
      deposit_usdc: unitsToDecimal(String(depositUnits), 6),
      deposit_tx: sent.txHash,
      received_sats: claimedSats,
    };
  }

  async function bridgeArkadeToUsdc({ walletRecord, secrets, neededUsdcUnits, opId }) {
    const arkBal = await ensureArkade().readBalance(walletRecord);
    if (arkBal.sats <= 0n) {
      throw new Error("insufficient_balance_usdc_and_btc");
    }

    const prevUsdc = await ensureSafe().readUsdcBalanceUnits(walletRecord.safeAddress).catch(() => 0n);
    const neededUsdcNum = Number(unitsToDecimal(String(neededUsdcUnits), 6));
    const sk = ensureSwapkit();
    // Fast path: skip the extra swap_route MCP round-trip by requesting >= 5.5 USDC directly
    // (above BitcoinVN's live ~$5 min); fall back to routeSwap only if createSwap rejects it.
    let bridgeUsdc = Math.max(neededUsdcNum, 5.5);
    let swap;
    try {
      swap = await sk.createSwap({
        from: "BTC_LN",
        to: "USDC_BASE",
        amount: bridgeUsdc,
        side: "settle",
        settleTarget: walletRecord.safeAddress,
        walletCapabilities: ["pay_lightning_invoice"],
        customOrderId: `${opId}:a2u`,
      });
    } catch {
      const route = await sk.routeSwap({
        from: "BTC_LN",
        to: "USDC_BASE",
        amount: neededUsdcNum,
        side: "settle",
        liveOnly: true,
      });
      if (!route?.bestExecutable) {
        const minInfo = extractProviderMinFromRoute(route, "BTC_LN");
        const rate = route?.unavailable?.find?.((u) => u?.limits?.rate)?.limits?.rate;
        const estimatedMinUsdc =
          minInfo && rate ? Math.ceil((minInfo.min / Number(rate)) * 1.15 * 100) / 100 : 5.5;
        bridgeUsdc = Math.max(neededUsdcNum, Math.max(5.5, estimatedMinUsdc));
      } else {
        bridgeUsdc = neededUsdcNum;
      }
      swap = await sk.createSwap({
        from: "BTC_LN",
        to: "USDC_BASE",
        amount: bridgeUsdc,
        side: "settle",
        settleTarget: walletRecord.safeAddress,
        walletCapabilities: ["pay_lightning_invoice"],
        customOrderId: `${opId}:a2u`,
      });
    }
    if (!swap.payInvoice) {
      throw new Error("cross_rail_swap_missing_lightning_invoice");
    }
    const paidLn = await ensureArkade().payBolt11Invoice({
      walletRecord,
      agentBtcPrivHex: secrets.agentBtcPrivHex,
      bolt11: swap.payInvoice,
      opId: `${opId}:bridge-ln`,
    });

    const deadline = Date.now() + bridgeTimeoutMs;
    let landed = false;
    while (Date.now() <= deadline) {
      const nowUsdc = await ensureSafe().readUsdcBalanceUnits(walletRecord.safeAddress).catch(() => 0n);
      if (nowUsdc >= BigInt(neededUsdcUnits) && nowUsdc > prevUsdc) {
        landed = true;
        break;
      }
      if (swap.provider && swap.swapId) {
        try {
          const st = await sk.getSwapStatus({ provider: swap.provider, id: swap.swapId });
          if (st.status === "FAILED" || st.status === "EXPIRED" || st.status === "REFUNDED") {
            throw new Error(`cross_rail_swap_${st.status.toLowerCase()}`);
          }
        } catch (err) {
          if (String(err?.message || "").startsWith("cross_rail_swap_")) throw err;
        }
      }
      await new Promise((r) => setTimeout(r, bridgePollIntervalMs));
    }
    if (!landed) {
      throw new Error(`cross_rail_bridge_pending:swap_${swap.swapId || "unknown"}`);
    }
    return {
      from: "arkade",
      to: "usdc",
      provider: swap.provider,
      swap_id: swap.swapId,
      paid_sats: paidLn.totalSats,
      ark_txid: paidLn.arkTxid,
      received_usdc: String(bridgeUsdc),
    };
  }

  async function ensureRailFunded({ walletRecord, secrets, targetRail, neededSats, neededUsdcUnits, opId }) {
    if (targetRail === "lightning") {
      return await bridgeUsdcToArkade({ walletRecord, secrets, neededSats, opId });
    }
    return await bridgeArkadeToUsdc({ walletRecord, secrets, neededUsdcUnits, opId });
  }

  const resolveBtcUsdRate = getBtcUsdRate || (() => defaultGetBtcUsdRate(fetchImpl));

  function ensurePayer() {
    if (!payer) {
      payer = createPrfHttp402Payer({
        safeRuntime: ensureSafe(),
        arkadeRuntime: ensureArkade(),
        ensureRailFunded,
        getBtcUsdRate: resolveBtcUsdRate,
        ...(merchantFetch ? { merchantFetch } : {}),
      });
    }
    return payer;
  }

  function stopReceiveWatcher(rfqId) {
    const entry = activeReceiveWatchers.get(rfqId);
    if (!entry) return;
    entry.stopped = true;
    if (entry.timer) clearTimeout(entry.timer);
    activeReceiveWatchers.delete(rfqId);
  }

  async function claimAndRecordReceive(walletRecord, agentBtcPrivHex, rec) {
    if (closed || !store) return false;
    const db = ensureStore();
    const res = await ensureArkade().claimLightningReceive({
      walletRecord,
      agentBtcPrivHex,
      receiveRecord: rec,
    });
    if (res.status !== "claimed") return false;
    db.markLightningReceiveClaimed(rec.rfqId, {
      claimTxid: res.claimTxid || null,
      claimedSats: res.claimedSats ?? rec.expectedAmountSats,
    });
    if (!res.alreadyClaimed) {
      db.recordOperation({
        walletId: walletRecord.walletId,
        requestId: rec.requestId || `ln-recv-${rec.rfqId.slice(0, 16)}`,
        action: "receive",
        rail: "lightning",
        status: "done",
        amountDisplay: `${res.claimedSats ?? rec.expectedAmountSats} sats`,
        summary: {
          kind: "receive",
          rail: "lightning",
          amount_sats: res.claimedSats ?? rec.expectedAmountSats,
          tx: res.claimTxid || null,
        },
        result: res,
      });
    }
    stopReceiveWatcher(rec.rfqId);
    return true;
  }

  // Lightweight in-memory background sweeper for newly minted Lightning receives:
  // polls pushClaim every ~2.5s until claimed/expired so incoming HTLCs settle automatically
  // even if the receiving agent does not poll wallet balance. Key is dropped once done.
  function scheduleReceiveAutoClaim(walletRecord, agentBtcPrivHex, rec) {
    if (closed || !rec?.rfqId || !agentBtcPrivHex || autoClaimIntervalMs <= 0) return;
    if (activeReceiveWatchers.has(rec.rfqId)) return;
    const expiryMs = rec.expiresAt ? Number(rec.expiresAt) * 1000 + 30_000 : Date.now() + autoClaimTtlMs;
    const deadline = Math.min(Date.now() + autoClaimTtlMs, expiryMs);
    const entry = { stopped: false, timer: null };
    activeReceiveWatchers.set(rec.rfqId, entry);

    const tick = async () => {
      if (closed || entry.stopped || !store) {
        stopReceiveWatcher(rec.rfqId);
        return;
      }
      if (Date.now() > deadline) {
        stopReceiveWatcher(rec.rfqId);
        return;
      }
      try {
        const claimed = await claimAndRecordReceive(walletRecord, agentBtcPrivHex, rec);
        if (claimed) return;
      } catch {
        // Non-fatal: invoice still unpaid or transient indexer error.
      }
      if (!closed && !entry.stopped && Date.now() <= deadline) {
        entry.timer = setTimeout(tick, autoClaimIntervalMs);
        entry.timer.unref?.();
      } else {
        stopReceiveWatcher(rec.rfqId);
      }
    };

    entry.timer = setTimeout(tick, autoClaimIntervalMs);
    entry.timer.unref?.();
  }

  async function sweepPendingReceives(walletRecord, agentBtcPrivHex) {
    const db = ensureStore();
    const pending = db.listPendingLightningReceives(walletRecord.walletId);
    if (!pending.length) return [];
    const claimed = [];
    for (const rec of pending) {
      try {
        if (await claimAndRecordReceive(walletRecord, agentBtcPrivHex, rec)) {
          claimed.push(rec.rfqId);
        }
      } catch {
        // Non-fatal: pending invoice may still be unpaid or operator unreachable.
      }
    }
    return claimed;
  }

  async function refreshPendingSendOp(walletId, reqId) {
    const db = ensureStore();
    const op = db.getOperation(walletId, reqId);
    if (!op || op.status !== "pending" || op.action !== "pay") return op;
    const s = op.summary || {};

    if (s.swap_pk_script_hex && s.payment_hash && typeof ensureArkade().checkLightningSendFate === "function") {
      try {
        const fate = await ensureArkade().checkLightningSendFate({
          swapPkScriptHex: s.swap_pk_script_hex,
          paymentHash: s.payment_hash,
        });
        if (fate?.fate === "claimed" && fate.preimageHex) {
          const updatedResult = {
            ...(op.result || {}),
            ok: true,
            status: "done",
            preimage: fate.preimageHex,
          };
          return db.recordOperation({
            walletId,
            requestId: reqId,
            action: op.action,
            rail: op.rail,
            status: "done",
            amountDisplay: op.amountDisplay,
            summary: { ...s, preimage: fate.preimageHex },
            result: updatedResult,
          });
        }
        if (fate?.fate === "refunded") {
          const updatedResult = {
            ...(op.result || {}),
            ok: false,
            status: "failed",
            error: "Payment failed (lightning_send_refunded).",
          };
          return db.recordOperation({
            walletId,
            requestId: reqId,
            action: op.action,
            rail: op.rail,
            status: "failed",
            amountDisplay: op.amountDisplay,
            summary: { ...s, reason: "lightning_send_refunded" },
            result: updatedResult,
          });
        }
      } catch {
        // Non-fatal: indexer check can retry later.
      }
    }

    if (s.swap_provider && s.swap_id && typeof ensureSwapkit().getSwapStatus === "function") {
      try {
        const st = await ensureSwapkit().getSwapStatus({
          provider: s.swap_provider,
          id: s.swap_id,
        });
        const statusUpper = String(st?.status || "").toUpperCase();
        if (["COMPLETED", "SETTLED", "SUCCESS", "FINISHED", "DONE"].includes(statusUpper)) {
          const settleTx = st?.settleTxid || st?.txid || s.tx || null;
          const updatedResult = {
            ...(op.result || {}),
            ok: true,
            status: "done",
            ...(settleTx && op.result?.receipt
              ? { receipt: { ...op.result.receipt, tx: settleTx } }
              : {}),
          };
          return db.recordOperation({
            walletId,
            requestId: reqId,
            action: op.action,
            rail: op.rail,
            status: "done",
            amountDisplay: op.amountDisplay,
            summary: { ...s, tx: settleTx },
            result: updatedResult,
          });
        }
        if (["FAILED", "EXPIRED", "REFUNDED", "CANCELLED"].includes(statusUpper)) {
          const updatedResult = {
            ...(op.result || {}),
            ok: false,
            status: "failed",
            error: `Swap ${statusUpper.toLowerCase()} (${s.swap_id}).`,
          };
          return db.recordOperation({
            walletId,
            requestId: reqId,
            action: op.action,
            rail: op.rail,
            status: "failed",
            amountDisplay: op.amountDisplay,
            summary: { ...s, reason: `swap_${statusUpper.toLowerCase()}` },
            result: updatedResult,
          });
        }
      } catch {
        // Non-fatal: SwapKit status check can retry later.
      }
    }

    return op;
  }

  async function refreshPendingSends(walletId) {
    const db = ensureStore();
    const pending = db
      .listOperations(walletId, { limit: 25 })
      .filter((op) => op.status === "pending" && op.action === "pay")
      .slice(0, 5);
    for (const op of pending) {
      await refreshPendingSendOp(walletId, op.request_id);
    }
  }

  async function readDualBalances(walletRecord, secrets = null) {
    if (secrets?.agentBtcPrivHex) {
      await sweepPendingReceives(walletRecord, secrets.agentBtcPrivHex);
    }
    const [usdcResult, arkResult] = await Promise.allSettled([
      ensureSafe().readUsdcBalanceUnits(walletRecord.safeAddress),
      ensureArkade().readBalance(walletRecord),
    ]);

    const usdcUnits = usdcResult.status === "fulfilled" ? usdcResult.value : 0n;
    const arkadeState =
      arkResult.status === "fulfilled"
        ? arkResult.value
        : {
            address: walletRecord.arkadeAddress || null,
            sats: 0n,
          };

    if (arkadeState.address && arkadeState.address !== walletRecord.arkadeAddress) {
      ensureStore().updateWalletArkadeAddress(walletRecord.walletId, arkadeState.address);
      walletRecord.arkadeAddress = arkadeState.address;
    }

    return {
      available: unitsToDecimal(String(usdcUnits), 6),
      usdc: unitsToDecimal(String(usdcUnits), 6),
      address: walletRecord.safeAddress,
      owner_address: walletRecord.mainEoa,
      sats: Number(arkadeState.sats),
      btc: formatSatsAsBtc(arkadeState.sats),
      ...(arkadeState.address ? { arkade_address: arkadeState.address } : {}),
    };
  }

  function dualBalanceSummary(balances) {
    const usdc = balances.available ?? "0";
    const sats = balances.sats ?? 0;
    const btcAddr = balances.arkade_address ? ` Arkade ${balances.arkade_address}` : "";
    return `Show BOTH rails to the user: Base USDC ${usdc} (${balances.address}) AND Bitcoin ${sats} sats / ${balances.btc || "0"} BTC (${btcAddr ? `${btcAddr.trim()}; ` : ""}Lightning invoice via receive rail="lightning").`;
  }

  async function startOrPollOnboarding({ requestId, slotIndex = 0, policy = DEFAULT_GRANT_POLICY } = {}) {
    const db = ensureStore();
    if (requestId) {
      const existing = db.getGrantSession(requestId);
      if (existing) {
        if (existing.status === "approved" && existing.walletId) {
          const wallet = db.getWalletById(existing.walletId);
          const issuedKey = db.popIssuedGrantWalletKey(requestId);
          let secrets = null;
          if (issuedKey) {
            try {
              secrets = db.unlockWalletSecrets(issuedKey).secrets;
            } catch {
              secrets = null;
            }
          }
          const balances = await readDualBalances(wallet, secrets);
          return {
            ok: true,
            status: "done",
            ...(issuedKey ? { wallet_key: issuedKey } : {}),
            ...balances,
            next: issuedKey
              ? `Save wallet_key and send it on every wallet call. ${dualBalanceSummary(balances)}`
              : `Wallet already connected; use the wallet_key returned earlier. ${dualBalanceSummary(balances)}`,
          };
        }
        if (existing.status === "expired") {
          return {
            ok: false,
            status: "failed",
            error: "That connect link expired. Call wallet balance with new:true to get a fresh link.",
          };
        }

        const polled = await ensureConnect().readAgentGrantResult({
          sessionId: existing.connectSessionId,
        });
        if (polled?.status === "pending") {
          return {
            ok: true,
            status: "connect_required",
            request_id: existing.requestId,
            approval_url: existing.approvalUrl,
            next: 'Open approval_url and sign in with your existing Nuri Passkey to reconnect your exact wallet (new users click "Create Passkey" on that same page). After approval, repeat wallet balance with the same request_id.',
          };
        }
        if (polled?.status !== "approved" || !polled?.result || !polled?.wallet) {
          db.markGrantSessionExpired(existing.requestId);
          return {
            ok: false,
            status: "failed",
            error: "That connect link expired before approval. Call wallet balance with new:true for a fresh link.",
          };
        }

        const replySkHex = db.readGrantSessionReplySk(existing.requestId);
        if (!replySkHex) {
          throw new Error("grant_session_reply_key_missing");
        }
        const mainEoa = getAddress(polled.wallet.eth_user_eoa || polled.result.address);
        const validProof = await verifyAgentGrantProof({
          mainEoa,
          sessionId: existing.connectSessionId,
          replyPubkey: existing.replyPubkey,
          grantResult: polled.result,
        });
        if (!validProof) {
          throw new Error("agent_grant_proof_signature_invalid");
        }

        const decrypted = decryptAgentGrantReply({
          replySkHex,
          sessionId: existing.connectSessionId,
          reply: polled.result,
        });

        const credIdB64u = polled.wallet.cred_id_b64u;
        const credPubkeyB64u = polled.wallet.credential_pubkey_b64u;
        if (!credIdB64u) throw new Error("connect_wallet_missing_cred_id");

        const registered = await ensureCosigner().registerGrant({
          cred_id_b64u: credIdB64u,
          ...(credPubkeyB64u ? { credential_pubkey_b64u: credPubkeyB64u } : {}),
          main_eoa: mainEoa,
          session_id: existing.connectSessionId,
          reply_pubkey: existing.replyPubkey,
          grant_result: polled.result,
        });

        const grant = registered.grant;
        const passkeySignerAddress = grant.passkey_signer_address
          ? getAddress(grant.passkey_signer_address)
          : credPubkeyB64u
            ? predictPasskeySignerAddress(credPubkeyB64u).address
            : deriveFallbackSecondRecoveryAddress({ mainEoa, credIdB64u });

        const agentEthEoa = getAddress(decrypted.public.agent_eth_eoa);
        const agentBtcPub33Hex = String(decrypted.public.agent_btc_public_key_33_hex).toLowerCase();
        const cosignerEoa = getAddress(grant.cosigner_eoa);

        const safePrediction = predictAgentSafeAddress({
          mainEoa,
          passkeySignerAddress,
          agentEoa: agentEthEoa,
          cosignerEoa,
          credIdB64u,
          index: decrypted.index,
        });

        let arkadeAddress = null;
        try {
          const derivedArk = await ensureArkade().deriveWalletScript({
            aggregatedBtcXonlyHex: grant.aggregated_btc_xonly,
            agentBtcPub33Hex,
          });
          arkadeAddress = derivedArk.address;
        } catch {
          arkadeAddress = null;
        }

        const finalized = db.finalizeGrantWallet({
          requestId: existing.requestId,
          credIdB64u,
          slotIndex: decrypted.index,
          mainEoa,
          passkeySignerAddress,
          agentEthEoa,
          cosignerEoa,
          safeAddress: grant.safe_address ? getAddress(grant.safe_address) : safePrediction.safeAddress,
          agentBtcPub33Hex,
          cosignerBtcPub33Hex: grant.cosigner_btc_pk33,
          aggregatedBtcXonlyHex: grant.aggregated_btc_xonly,
          arkadeAddress,
          policy: decrypted.policy || existing.policy || DEFAULT_GRANT_POLICY,
          agentEthPrivHex: decrypted.agent_eth_private_key_hex,
          agentBtcPrivHex: decrypted.agent_btc_private_key_hex,
        });

        const issuedKey = db.popIssuedGrantWalletKey(requestId) || finalized.walletKey;
        const balances = await readDualBalances(finalized.wallet, {
          agentBtcPrivHex: decrypted.agent_btc_private_key_hex,
        });
        return {
          ok: true,
          status: "done",
          wallet_key: issuedKey,
          ...balances,
          next: `Save wallet_key and send it on every later wallet call. ${dualBalanceSummary(balances)}`,
        };
      }
    }

    // Start fresh `agent_grant` session on connect.nuri.com
    const reqId = requestId && typeof requestId === "string" ? requestId.trim() : randomUUID();
    const replyKp = generateGrantReplyKeypair();
    const started = await ensureConnect().startAgentGrant({
      replyPubkey: replyKp.replyPubkey,
      index: slotIndex,
      policy,
    });
    const saved = db.createGrantSession({
      requestId: reqId,
      connectSessionId: started.session_id || started.sessionId,
      slotIndex,
      replyPubkey: replyKp.replyPubkey,
      replySkHex: replyKp.replySkHex,
      policy,
      approvalUrl: started.approval_url || started.approvalUrl,
      expiresAt: started.expires_at ?? started.expiresAt,
    });
    return {
      ok: true,
      status: "connect_required",
      request_id: saved.requestId,
      approval_url: saved.approvalUrl,
      next: 'Open approval_url and sign in with your existing Nuri Passkey to reconnect your exact wallet (new users click "Create Passkey" on that same page). After approval, repeat wallet balance with the same request_id.',
    };
  }

  async function handleBalance(args) {
    if (isPrfWalletKey(args?.wallet_key) && !args?.new) {
      const { wallet, secrets } = ensureStore().unlockWalletSecrets(args.wallet_key);
      await refreshPendingSends(wallet.walletId);
      const balances = await readDualBalances(wallet, secrets);
      return {
        ok: true,
        status: "done",
        ...balances,
        next: `Holdings shown. ${dualBalanceSummary(balances)}`,
      };
    }
    return await startOrPollOnboarding({
      requestId: args?.request_id,
      slotIndex: Number.isSafeInteger(args?.index) ? args.index : 0,
    });
  }

  async function handleReceive(args) {
    const db = ensureStore();
    const { wallet, secrets } = db.unlockWalletSecrets(args.wallet_key);
    await sweepPendingReceives(wallet, secrets.agentBtcPrivHex);

    const requestedRail = String(
      args.rail || (args.amount_sats !== undefined ? "lightning" : "usdc"),
    )
      .trim()
      .toLowerCase();

    if (requestedRail === "usdc") {
      const usdcUnits = await ensureSafe()
        .readUsdcBalanceUnits(wallet.safeAddress)
        .catch(() => 0n);
      return {
        ok: true,
        status: "done",
        rail: "usdc",
        address: wallet.safeAddress,
        available: unitsToDecimal(String(usdcUnits), 6),
        next: `Send Base USDC to ${wallet.safeAddress}, then call wallet balance.`,
      };
    }

    if (requestedRail === "arkade" || requestedRail === "btc") {
      const ark = await ensureArkade().readBalance(wallet);
      if (ark.address && ark.address !== wallet.arkadeAddress) {
        db.updateWalletArkadeAddress(wallet.walletId, ark.address);
      }
      return {
        ok: true,
        status: "done",
        rail: "arkade",
        arkade_address: ark.address,
        sats: Number(ark.sats),
        btc: formatSatsAsBtc(ark.sats),
        next: `Send Arkade sats to ${ark.address}, then call wallet balance.`,
      };
    }

    if (requestedRail === "lightning" || requestedRail === "bolt11") {
      if (args.request_id) {
        const existing = db.getLightningReceiveByRequest(wallet.walletId, args.request_id);
        if (existing) {
          if (existing.status === "claimed") {
            const ark = await ensureArkade().readBalance(wallet);
            return {
              ok: true,
              status: "done",
              rail: "lightning",
              invoice: existing.invoice,
              payment_hash: existing.paymentHash,
              amount_sats: existing.claimedSats ?? existing.expectedAmountSats,
              sats: Number(ark.sats),
              arkade_address: ark.address,
              next: "Lightning payment received and claimed into 2-of-2 Arkade custody.",
            };
          }
          scheduleReceiveAutoClaim(wallet, secrets.agentBtcPrivHex, existing);
          return {
            ok: true,
            status: "pending",
            rail: "lightning",
            request_id: args.request_id,
            invoice: existing.invoice,
            payment_hash: existing.paymentHash,
            amount_sats: existing.payAmountSats,
            expected_sats: existing.expectedAmountSats,
            fee_sats: existing.feeSats,
            expires_at: existing.expiresAt,
            next: "Pay the BOLT11 invoice; incoming sats are auto-claimed automatically once paid (check wallet balance).",
          };
        }
      }

      const amountSats = parsePositiveSats(args.amount_sats, "amount_sats");
      if (!amountSats) {
        return {
          ok: false,
          status: "failed",
          error: "Lightning receive needs amount_sats (for example 1000). Pass amount_sats and try again.",
        };
      }
      const created = await ensureArkade().createLightningReceive({
        walletRecord: wallet,
        agentBtcPrivHex: secrets.agentBtcPrivHex,
        amountSats,
      });
      const recvReqId = args.request_id || `ln-recv-${created.rfqId.slice(0, 16)}`;
      db.saveLightningReceive({
        rfqId: created.rfqId,
        walletId: wallet.walletId,
        requestId: recvReqId,
        paymentHash: created.paymentHash,
        invoice: created.invoice,
        payAmountSats: created.payAmountSats,
        expectedAmountSats: created.expectedAmountSats,
        feeSats: created.feeSats,
        expiresAt: created.expiresAt,
        lockupAddress: created.lockupAddress,
        swapPkScriptHex: created.swapPkScriptHex,
        payoutAddress: created.payoutAddress,
        quoteJson: created.quoteJson,
      });
      const out = {
        ok: true,
        status: "done",
        rail: "lightning",
        request_id: recvReqId,
        invoice: created.invoice,
        payment_hash: created.paymentHash,
        amount_sats: created.payAmountSats,
        expected_sats: created.expectedAmountSats,
        fee_sats: created.feeSats,
        expires_at: created.expiresAt,
        arkade_address: created.payoutAddress,
        next: `Share invoice for ${created.payAmountSats} sats (includes ${created.feeSats} sats fee; you net ${created.expectedAmountSats} sats). Once paid, calling wallet balance automatically sweeps the sats into your balance.`,
      };
      db.recordOperation({
        walletId: wallet.walletId,
        requestId: recvReqId,
        action: "receive",
        rail: "lightning",
        status: "pending",
        amountDisplay: `${created.payAmountSats} sats`,
        summary: {
          kind: "receive",
          rail: "lightning",
          to: created.paymentHash,
          tx: null,
        },
        result: out,
      });
      scheduleReceiveAutoClaim(wallet, secrets.agentBtcPrivHex, {
        rfqId: created.rfqId,
        requestId: recvReqId,
        expectedAmountSats: created.expectedAmountSats,
        expiresAt: created.expiresAt,
        quoteJson: created.quoteJson,
      });
      return out;
    }

    return {
      ok: false,
      status: "failed",
      error: "rail must be usdc, lightning, or arkade.",
    };
  }

  async function payBolt11WithCrossRail({ wallet, secrets, bolt11, maxSats, maxAmountUnits, opId, toLabel }) {
    const cleanInvoice = String(bolt11 || "").trim().replace(/^lightning:/i, "");
    const facts = ensureArkade().decodeBolt11(cleanInvoice);
    if (!facts.amountSats || facts.amountSats <= 0) {
      throw new Error("amountless_bolt11_not_supported");
    }
    if (maxSats !== undefined && maxSats !== null && BigInt(facts.amountSats) > BigInt(maxSats)) {
      const err = new Error("invoice_exceeds_max_sats");
      err.code = "over_max_amount";
      err.invoiceSats = facts.amountSats;
      throw err;
    }
    if (maxAmountUnits !== undefined && maxAmountUnits !== null) {
      const btcUsd = await resolveBtcUsdRate().catch(() => null);
      if (BigInt(facts.amountSats) > usdUnitsToMaxSats(maxAmountUnits, btcUsd)) {
        const err = new Error("invoice_exceeds_max_amount");
        err.code = "over_max_amount";
        err.invoiceSats = facts.amountSats;
        throw err;
      }
    }

    const arkBal = await ensureArkade().readBalance(wallet).catch(() => ({ sats: 0n }));
    const feeBuffer = BigInt(Math.max(100, Math.ceil(facts.amountSats * 0.03)));
    if (arkBal.sats >= BigInt(facts.amountSats) + feeBuffer) {
      const paid = await ensureArkade().payBolt11Invoice({
        walletRecord: wallet,
        agentBtcPrivHex: secrets.agentBtcPrivHex,
        bolt11: cleanInvoice,
        maxSats,
        opId,
      });
      return { mode: "native", paid };
    }

    // Arkade sats insufficient — check Base Safe USDC for automatic cross-rail payment!
    const usdcBal = await ensureSafe().readUsdcBalanceUnits(wallet.safeAddress).catch(() => 0n);
    if (usdcBal <= 0n) {
      // Let native path produce the normal insufficient-sats error if both rails are empty.
      const paid = await ensureArkade().payBolt11Invoice({
        walletRecord: wallet,
        agentBtcPrivHex: secrets.agentBtcPrivHex,
        bolt11: cleanInvoice,
        maxSats,
        opId,
      });
      return { mode: "native", paid };
    }

    const sk = ensureSwapkit();
    const route = await sk.routeSwap({
      from: "USDC_BASE",
      to: "BTC_LN",
      sats: facts.amountSats,
      side: "settle",
      liveOnly: true,
    });

    // Path A: Direct exact USDC_BASE -> BTC_LN payment via SwapKit (when >= provider min)
    if (route?.bestExecutable) {
      const estUnits = usdcAmountToUnitsCeil(route.bestExecutable.depositAmount);
      if (maxAmountUnits !== undefined && estUnits > BigInt(maxAmountUnits)) {
        const err = new Error("invoice_exceeds_max_amount");
        err.code = "over_max_amount";
        throw err;
      }
      if (usdcBal < estUnits) {
        throw new Error(
          `insufficient_usdc_for_lightning_swap:need_${unitsToDecimal(String(estUnits), 6)}_have_${unitsToDecimal(String(usdcBal), 6)}`,
        );
      }
      const swap = await sk.createSwap({
        from: "USDC_BASE",
        to: "BTC_LN",
        sats: facts.amountSats,
        side: "settle",
        settleTarget: cleanInvoice,
        refundAddress: wallet.safeAddress,
        walletCapabilities: ["send_asset"],
        customOrderId: opId,
      });
      if (!swap.sendToAddress || swap.depositAmount == null) {
        throw new Error("cross_rail_swap_missing_deposit_address");
      }
      const depositUnits = usdcAmountToUnitsCeil(swap.depositAmount);
      if (maxAmountUnits !== undefined && depositUnits > BigInt(maxAmountUnits)) {
        const err = new Error("invoice_exceeds_max_amount");
        err.code = "over_max_amount";
        throw err;
      }
      if (usdcBal < depositUnits) {
        throw new Error(
          `insufficient_usdc_for_lightning_swap:need_${unitsToDecimal(String(depositUnits), 6)}_have_${unitsToDecimal(String(usdcBal), 6)}`,
        );
      }
      const sent = await ensureSafe().transferUsdc({
        walletRecord: toSafeWalletRow(wallet),
        agentEthPrivateKeyHex: secrets.agentEthPrivHex,
        to: getAddress(swap.sendToAddress),
        amountUnits: depositUnits,
        opId: `${opId}:ln-usdc`,
      });
      const polled = await sk.pollUntilSettled({
        provider: swap.provider,
        id: swap.swapId,
        timeoutMs: bridgeTimeoutMs,
        intervalMs: bridgePollIntervalMs,
      });
      if (polled.status === "failed") {
        throw new Error(`cross_rail_swap_failed:${swap.swapId || "unknown"}`);
      }
      return {
        mode: "direct_swap",
        status: polled.status,
        depositUsdc: unitsToDecimal(String(depositUnits), 6),
        txHash: sent.txHash,
        swapId: swap.swapId,
        provider: swap.provider,
        amountSats: facts.amountSats,
        paymentHash: facts.paymentHash,
        to: toLabel || facts.paymentHash,
      };
    }

    // Path B: Invoice is below provider min (~$5) — self-bridge minimum tranche from Base Safe USDC
    // into our own 2-of-2 Arkade custody, then pay the exact BOLT11 invoice natively!
    const bridged = await bridgeUsdcToArkade({
      walletRecord: wallet,
      secrets,
      neededSats: Number(BigInt(facts.amountSats) + feeBuffer),
      opId,
    });
    const paid = await ensureArkade().payBolt11Invoice({
      walletRecord: wallet,
      agentBtcPrivHex: secrets.agentBtcPrivHex,
      bolt11: cleanInvoice,
      maxSats,
      opId,
    });
    return { mode: "bridged", paid, bridged };
  }

  async function payOnchainBtc({ wallet, secrets, btcAddress, amountSats, maxSats, maxAmountUnits, opId, reqId }) {
    if (maxSats !== undefined && maxSats !== null && BigInt(amountSats) > BigInt(maxSats)) {
      const err = new Error("btc_payment_exceeds_max_sats");
      err.code = "over_max_amount";
      err.invoiceSats = amountSats;
      throw err;
    }
    if (maxAmountUnits !== undefined && maxAmountUnits !== null) {
      const btcUsd = await resolveBtcUsdRate().catch(() => null);
      if (BigInt(amountSats) > usdUnitsToMaxSats(maxAmountUnits, btcUsd)) {
        const err = new Error("btc_payment_exceeds_max_amount");
        err.code = "over_max_amount";
        err.invoiceSats = amountSats;
        throw err;
      }
    }

    const [arkRes, usdcRes] = await Promise.allSettled([
      ensureArkade().readBalance(wallet),
      ensureSafe().readUsdcBalanceUnits(wallet.safeAddress),
    ]);
    const arkSats = arkRes.status === "fulfilled" ? arkRes.value.sats : 0n;
    const usdcBal = usdcRes.status === "fulfilled" ? usdcRes.value : 0n;
    const sk = ensureSwapkit();

    // Prefer Arkade sats when sufficient (~5% buffer for L1 miner + swap fee), else Base USDC.
    const arkNeededEstimate = BigInt(amountSats) + BigInt(Math.max(1000, Math.ceil(amountSats * 0.05)));
    if (arkSats >= arkNeededEstimate) {
      const swap = await sk.createSwap({
        from: "BTC_LN",
        to: "BTC",
        sats: amountSats,
        side: "settle",
        settleTarget: btcAddress,
        walletCapabilities: ["pay_lightning_invoice"],
        customOrderId: opId,
      });
      if (!swap.payInvoice) {
        throw new Error("onchain_btc_swap_missing_lightning_invoice");
      }
      const paidLn = await ensureArkade().payBolt11Invoice({
        walletRecord: wallet,
        agentBtcPrivHex: secrets.agentBtcPrivHex,
        bolt11: swap.payInvoice,
        maxSats,
        opId: `${opId}:btc-ln`,
      });
      const polled = await sk.pollUntilSettled({
        provider: swap.provider,
        id: swap.swapId,
        timeoutMs: bridgeTimeoutMs,
        intervalMs: bridgePollIntervalMs,
      });
      if (polled.status === "failed") {
        throw new Error(`onchain_btc_swap_failed:${swap.swapId || "unknown"}`);
      }
      const out = {
        ok: true,
        status: polled.status,
        request_id: reqId,
        rail: "btc",
        funded_from: "arkade",
        to: btcAddress,
        amount_sats: amountSats,
        fee_sats: Math.max(0, paidLn.totalSats - amountSats),
        ...(swap.swapId ? { swap_id: swap.swapId } : {}),
        receipt: {
          tx: polled.settleTxid || paidLn.arkTxid,
          amount: `${amountSats} sats`,
          to: btcAddress,
        },
        next:
          polled.status === "done"
            ? "On-chain Bitcoin sent."
            : "Swap funded; on-chain Bitcoin broadcast is processing. Call wallet history or balance to verify.",
      };
      return out;
    }

    if (usdcBal > 0n) {
      const swap = await sk.createSwap({
        from: "USDC_BASE",
        to: "BTC",
        sats: amountSats,
        side: "settle",
        settleTarget: btcAddress,
        refundAddress: wallet.safeAddress,
        walletCapabilities: ["send_asset"],
        customOrderId: opId,
      });
      if (!swap.sendToAddress || swap.depositAmount == null) {
        throw new Error("onchain_btc_swap_missing_usdc_deposit");
      }
      const depositUnits = usdcAmountToUnitsCeil(swap.depositAmount);
      if (maxAmountUnits !== undefined && depositUnits > BigInt(maxAmountUnits)) {
        const err = new Error("invoice_exceeds_max_amount");
        err.code = "over_max_amount";
        throw err;
      }
      if (usdcBal < depositUnits) {
        throw new Error(
          `insufficient_usdc_for_btc_send:need_${unitsToDecimal(String(depositUnits), 6)}_have_${unitsToDecimal(String(usdcBal), 6)}`,
        );
      }
      const sent = await ensureSafe().transferUsdc({
        walletRecord: toSafeWalletRow(wallet),
        agentEthPrivateKeyHex: secrets.agentEthPrivHex,
        to: getAddress(swap.sendToAddress),
        amountUnits: depositUnits,
        opId: `${opId}:btc-usdc`,
      });
      const polled = await sk.pollUntilSettled({
        provider: swap.provider,
        id: swap.swapId,
        timeoutMs: bridgeTimeoutMs,
        intervalMs: bridgePollIntervalMs,
      });
      if (polled.status === "failed") {
        throw new Error(`onchain_btc_swap_failed:${swap.swapId || "unknown"}`);
      }
      const depositDec = unitsToDecimal(String(depositUnits), 6);
      return {
        ok: true,
        status: polled.status,
        request_id: reqId,
        rail: "btc",
        funded_from: "usdc",
        to: btcAddress,
        amount_sats: amountSats,
        ...(swap.swapId ? { swap_id: swap.swapId } : {}),
        receipt: {
          tx: polled.settleTxid || sent.txHash,
          amount: `${amountSats} sats (${depositDec} USDC)`,
          to: btcAddress,
        },
        next:
          polled.status === "done"
            ? "On-chain Bitcoin sent from Base USDC."
            : "USDC swap funded; on-chain Bitcoin payout is processing.",
      };
    }

    throw new Error(
      `insufficient_balance_for_btc_send:need_${amountSats}_sats_have_${arkSats.toString()}_sats_and_0_usdc`,
    );
  }

  async function handlePay(args) {
    const db = ensureStore();
    const { wallet, secrets } = db.unlockWalletSecrets(args.wallet_key);
    const reqId =
      typeof args.request_id === "string" && args.request_id.trim()
        ? args.request_id.trim()
        : randomUUID();

    let prior = db.getOperation(wallet.walletId, reqId);
    if (prior && prior.status === "pending" && !args.dry_run) {
      prior = (await refreshPendingSendOp(wallet.walletId, reqId)) || prior;
    }
    if (prior && (prior.status === "done" || prior.status === "pending") && !args.dry_run) {
      return prior.result;
    }

    const opId = `${wallet.walletId}:${reqId}`;
    const maxAmountUnits =
      args.max_amount !== undefined ? parseUsdcUnits(args.max_amount, "max_amount") : undefined;
    const maxSats =
      args.max_sats !== undefined ? parsePositiveSats(args.max_sats, "max_sats") : undefined;

    try {
      // Universal target resolution: `url` OR `to: "https://..."` both work seamlessly!
      const rawUrl =
        typeof args.url === "string" && args.url.trim()
          ? args.url.trim()
          : typeof args.to === "string" && HTTPS_URL_RE.test(args.to.trim())
            ? args.to.trim()
            : null;

      // Case 1: HTTP 402 URL (`x402`, `EVM MPP`, `L402`, `Lightning MPP`)
      if (rawUrl) {
        const res = await ensurePayer().payHttpResource({
          walletRecord: wallet,
          secrets,
          url: rawUrl,
          method: args.method || "GET",
          body: args.body,
          prefer: args.prefer,
          maxAmountUnits,
          maxSats,
          dryRun: Boolean(args.dry_run),
          opId,
        });

        const dryPrice = res.dry_run
          ? res.price ||
            (res.amount_units !== undefined
              ? { amount: unitsToDecimal(String(res.amount_units), 6), currency: "USDC" }
              : undefined)
          : undefined;

        const out = {
          ok: res.status !== "failed",
          status: res.status,
          request_id: reqId,
          ...(res.http_status !== undefined ? { http_status: res.http_status } : {}),
          ...(res.status === "failed" && res.http_status !== undefined
            ? {
                error: `Endpoint returned HTTP ${res.http_status}${res.paid ? " after payment" : " (not paid)"}. Inspect resource.body for the exact server error.`,
              }
            : {}),
          ...(res.protocol ? { protocol: res.protocol } : {}),
          ...(res.rail ? { rail: res.rail } : {}),
          ...(res.funded_from ? { funded_from: res.funded_from } : {}),
          ...(res.cross_rail ? { cross_rail: true } : {}),
          ...(res.bridged ? { bridged: res.bridged } : {}),
          ...(res.dry_run ? { quote: res.quote, payable: res.payable, ...(dryPrice ? { price: dryPrice } : {}) } : {}),
          ...(res.resource ? { resource: res.resource } : {}),
          ...(res.preimage ? { preimage: res.preimage } : {}),
          ...(res.payment_hash ? { payment_hash: res.payment_hash } : {}),
          ...(res.amount_sats !== undefined ? { amount_sats: res.amount_sats } : {}),
          ...(res.fee_sats !== undefined ? { fee_sats: res.fee_sats } : {}),
          ...(res.tx_hash || res.ark_txid
            ? {
                receipt: {
                  tx: res.tx_hash || res.ark_txid,
                  amount:
                    res.amount_units !== undefined
                      ? `${unitsToDecimal(String(res.amount_units), 6)} USDC`
                      : `${res.amount_sats} sats`,
                  to: rawUrl,
                },
              }
            : {}),
          ...(res.dry_run
            ? {
                next: `Dry run only — nothing was paid. Price is ${dryPrice ? `${dryPrice.amount} ${dryPrice.currency}` : "quoted"}${res.over_cap ? " (exceeds your max_amount/max_sats cap)" : ""}. Call wallet pay without dry_run to pay.`,
              }
            : {}),
        };

        if (!args.dry_run && (out.status === "done" || out.status === "pending")) {
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: res.rail || "usdc",
            status: out.status,
            amountDisplay:
              res.amount_units !== undefined
                ? unitsToDecimal(String(res.amount_units), 6)
                : res.amount_sats !== undefined
                  ? `${res.amount_sats} sats`
                  : null,
            summary: {
              kind: "pay",
              protocol: res.protocol || null,
              to: rawUrl,
              tx: res.tx_hash || res.ark_txid || null,
            },
            result: out,
          });
        }
        return out;
      }

      let target = String(args.invoice || args.to || "").trim();
      if (!target) {
        return {
          ok: false,
          status: "failed",
          error:
            "Provide to (https:// paid API, lnbc... BOLT11, user@domain, bc1.../bitcoin:... on-chain Bitcoin, ark1... Arkade, or 0x... Base USDC).",
        };
      }

      // Redirect Monero (XMR) addresses cleanly to the companion SwapKit MCP server
      if (isMoneroAddress(target)) {
        return {
          ok: false,
          status: "failed",
          error:
            "Monero (XMR) payouts use the companion SwapKit MCP server (https://swapkit.nuri.com/mcp): call swap_create from USDC_BASE or BTC_LN to XMR_MONERO, then pay its deposit with wallet pay.",
        };
      }

      // Unwrap BIP21 `bitcoin:bc1...?amount=...&lightning=...` URIs automatically
      let bip21Sats = undefined;
      const bip21 = parseBip21Uri(target);
      if (bip21) {
        if (bip21.lightning) {
          target = bip21.lightning;
        } else if (bip21.address) {
          target = bip21.address;
          if (bip21.amountSats) bip21Sats = bip21.amountSats;
        }
      }

      // Case 2: Direct BOLT11 invoice (native Arkade OR automatic cross-rail from Base USDC!)
      if (BOLT11_RE.test(target)) {
        const res = await payBolt11WithCrossRail({
          wallet,
          secrets,
          bolt11: target,
          maxSats,
          maxAmountUnits,
          opId,
        });
        if (res.mode === "direct_swap") {
          const out = {
            ok: true,
            status: res.status,
            request_id: reqId,
            rail: "lightning",
            funded_from: "usdc",
            amount_sats: res.amountSats,
            payment_hash: res.paymentHash,
            ...(res.swapId ? { swap_id: res.swapId } : {}),
            receipt: {
              tx: res.txHash,
              amount: `${res.amountSats} sats (${res.depositUsdc} USDC)`,
              to: res.paymentHash,
            },
            next: `Paid ${res.amountSats} sats over Lightning (auto-converted from ${res.depositUsdc} Base USDC).`,
          };
          if (res.status === "done" || res.status === "pending") {
            db.recordOperation({
              walletId: wallet.walletId,
              requestId: reqId,
              action: "pay",
              rail: "lightning",
              status: res.status,
              amountDisplay: `${res.amountSats} sats`,
              summary: {
                kind: "pay",
                to: res.paymentHash,
                tx: res.txHash,
                ...(res.provider ? { swap_provider: res.provider } : {}),
                ...(res.swapId ? { swap_id: res.swapId } : {}),
              },
              result: out,
            });
          }
          return out;
        }
        const paid = res.paid;
        const out = {
          ok: true,
          status: paid.status,
          request_id: reqId,
          rail: "lightning",
          ...(res.bridged ? { funded_from: "usdc", bridged: res.bridged } : {}),
          amount_sats: paid.amountSats,
          fee_sats: paid.feeSats,
          payment_hash: paid.paymentHash,
          ...(paid.preimageHex ? { preimage: paid.preimageHex } : {}),
          receipt: {
            tx: paid.arkTxid,
            amount: `${paid.amountSats} sats`,
            to: paid.paymentHash,
          },
        };
        if (paid.status === "done" || paid.status === "pending") {
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: "lightning",
            status: paid.status,
            amountDisplay: `${paid.amountSats} sats`,
            summary: {
              kind: "pay",
              to: paid.paymentHash,
              tx: paid.arkTxid,
              ...(paid.paymentHash ? { payment_hash: paid.paymentHash } : {}),
              ...(paid.swapPkScriptHex ? { swap_pk_script_hex: paid.swapPkScriptHex } : {}),
            },
            result: out,
          });
        }
        return out;
      }

      // Case 3: Lightning Address (`alice@domain.com`) — native Arkade OR cross-rail from Base USDC!
      if (LN_ADDRESS_RE.test(target)) {
        const sats = parsePositiveSats(args.amount_sats, "amount_sats");
        if (!sats) {
          return {
            ok: false,
            status: "failed",
            error: "Paying a Lightning Address needs amount_sats (for example 500).",
          };
        }
        const bolt11 = await ensureArkade().resolveLightningAddressInvoice({
          lightningAddress: target,
          amountSats: sats,
        });
        const res = await payBolt11WithCrossRail({
          wallet,
          secrets,
          bolt11,
          maxSats: maxSats ?? sats + Math.max(50, Math.ceil(sats * 0.03)),
          maxAmountUnits,
          opId,
          toLabel: target,
        });
        if (res.mode === "direct_swap") {
          const out = {
            ok: true,
            status: res.status,
            request_id: reqId,
            rail: "lightning",
            funded_from: "usdc",
            to: target,
            amount_sats: res.amountSats,
            payment_hash: res.paymentHash,
            ...(res.swapId ? { swap_id: res.swapId } : {}),
            receipt: {
              tx: res.txHash,
              amount: `${res.amountSats} sats (${res.depositUsdc} USDC)`,
              to: target,
            },
          };
          if (res.status === "done" || res.status === "pending") {
            db.recordOperation({
              walletId: wallet.walletId,
              requestId: reqId,
              action: "pay",
              rail: "lightning",
              status: res.status,
              amountDisplay: `${res.amountSats} sats`,
              summary: {
                kind: "pay",
                to: target,
                tx: res.txHash,
                ...(res.provider ? { swap_provider: res.provider } : {}),
                ...(res.swapId ? { swap_id: res.swapId } : {}),
              },
              result: out,
            });
          }
          return out;
        }
        const paid = res.paid;
        const out = {
          ok: true,
          status: paid.status,
          request_id: reqId,
          rail: "lightning",
          ...(res.bridged ? { funded_from: "usdc", bridged: res.bridged } : {}),
          to: target,
          amount_sats: paid.amountSats,
          fee_sats: paid.feeSats,
          payment_hash: paid.paymentHash,
          ...(paid.preimageHex ? { preimage: paid.preimageHex } : {}),
          receipt: {
            tx: paid.arkTxid,
            amount: `${paid.amountSats} sats`,
            to: target,
          },
        };
        if (paid.status === "done" || paid.status === "pending") {
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: "lightning",
            status: paid.status,
            amountDisplay: `${paid.amountSats} sats`,
            summary: {
              kind: "pay",
              to: target,
              tx: paid.arkTxid,
              ...(paid.paymentHash ? { payment_hash: paid.paymentHash } : {}),
              ...(paid.swapPkScriptHex ? { swap_pk_script_hex: paid.swapPkScriptHex } : {}),
            },
            result: out,
          });
        }
        return out;
      }

      // Case 4: On-chain Bitcoin (`bc1...` / `1...` / `3...` / `bitcoin:...`)
      if (isOnchainBtcAddress(target)) {
        const sats =
          parsePositiveSats(args.amount_sats, "amount_sats") ??
          bip21Sats ??
          (args.amount !== undefined && args.amount !== "" ? btcDecimalToSats(args.amount) : undefined);
        if (!sats) {
          return {
            ok: false,
            status: "failed",
            error: "Sending on-chain Bitcoin needs amount_sats (e.g. 25000) or BTC amount (e.g. \"0.00025\").",
          };
        }
        const out = await payOnchainBtc({
          wallet,
          secrets,
          btcAddress: target,
          amountSats: sats,
          maxSats,
          maxAmountUnits,
          opId,
          reqId,
        });
        if (out.status === "done" || out.status === "pending") {
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: "btc",
            status: out.status,
            amountDisplay: `${sats} sats`,
            summary: { kind: "send", to: target, tx: out.receipt?.tx || null },
            result: out,
          });
        }
        return out;
      }

      // Case 5: Arkade native off-chain send (`ark1...` / `tark1...`)
      if (isValidArkAddress(target)) {
        const sats = parsePositiveSats(args.amount_sats, "amount_sats");
        if (!sats) {
          return {
            ok: false,
            status: "failed",
            error: "Sending to an Arkade address needs amount_sats (for example 1000).",
          };
        }
        const sent = await ensureArkade().sendArkade({
          walletRecord: wallet,
          agentBtcPrivHex: secrets.agentBtcPrivHex,
          toArkAddress: target,
          amountSats: sats,
          opId,
        });
        const out = {
          ok: true,
          status: "done",
          request_id: reqId,
          rail: "arkade",
          to: target,
          amount_sats: sats,
          receipt: {
            tx: sent.arkTxid,
            amount: `${sats} sats`,
            to: target,
          },
        };
        db.recordOperation({
          walletId: wallet.walletId,
          requestId: reqId,
          action: "pay",
          rail: "arkade",
          status: "done",
          amountDisplay: `${sats} sats`,
          summary: { kind: "send", to: target, tx: sent.arkTxid },
          result: out,
        });
        return out;
      }

      // Case 6: Base USDC transfer to `0x...` (native Safe OR automatic cross-rail from Arkade sats!)
      if (ETH_ADDRESS_RE.test(target)) {
        const units = parseUsdcUnits(args.amount, "amount");
        if (!units || units <= 0n) {
          return {
            ok: false,
            status: "failed",
            error: "Sending Base USDC to a 0x address needs a positive amount like 1.50.",
          };
        }
        const toAddr = getAddress(target);
        const dec = unitsToDecimal(String(units), 6);
        const usdcBal = await ensureSafe().readUsdcBalanceUnits(wallet.safeAddress).catch(() => 0n);

        if (usdcBal >= BigInt(units)) {
          const sent = await ensureSafe().transferUsdc({
            walletRecord: toSafeWalletRow(wallet),
            agentEthPrivateKeyHex: secrets.agentEthPrivHex,
            to: toAddr,
            amountUnits: units,
            opId,
          });
          const out = {
            ok: true,
            status: "done",
            request_id: reqId,
            rail: "usdc",
            to: toAddr,
            receipt: {
              tx: sent.txHash,
              amount: dec,
              to: toAddr,
            },
          };
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: "usdc",
            status: "done",
            amountDisplay: dec,
            summary: { kind: "send", to: toAddr, tx: sent.txHash },
            result: out,
          });
          return out;
        }

        // Safe USDC insufficient — check Arkade sats for automatic cross-rail USDC payout!
        const arkBal = await ensureArkade().readBalance(wallet).catch(() => ({ sats: 0n }));
        if (arkBal.sats > 0n) {
          const sk = ensureSwapkit();
          const route = await sk.routeSwap({
            from: "BTC_LN",
            to: "USDC_BASE",
            amount: Number(dec),
            side: "settle",
            liveOnly: true,
          });

          // Path A: Direct exact BTC_LN -> USDC_BASE swap to recipient `toAddr`
          if (route?.bestExecutable) {
            const swap = await sk.createSwap({
              from: "BTC_LN",
              to: "USDC_BASE",
              amount: Number(dec),
              side: "settle",
              settleTarget: toAddr,
              walletCapabilities: ["pay_lightning_invoice"],
              customOrderId: opId,
            });
            if (!swap.payInvoice) {
              throw new Error("cross_rail_swap_missing_lightning_invoice");
            }
            const paidLn = await ensureArkade().payBolt11Invoice({
              walletRecord: wallet,
              agentBtcPrivHex: secrets.agentBtcPrivHex,
              bolt11: swap.payInvoice,
              maxSats,
              opId: `${opId}:usdc-ln`,
            });
            const polled = await sk.pollUntilSettled({
              provider: swap.provider,
              id: swap.swapId,
              timeoutMs: bridgeTimeoutMs,
              intervalMs: bridgePollIntervalMs,
            });
            if (polled.status === "failed") {
              throw new Error(`cross_rail_swap_failed:${swap.swapId || "unknown"}`);
            }
            const out = {
              ok: true,
              status: polled.status,
              request_id: reqId,
              rail: "usdc",
              funded_from: "arkade",
              to: toAddr,
              amount_sats: paidLn.totalSats,
              ...(swap.swapId ? { swap_id: swap.swapId } : {}),
              receipt: {
                tx: polled.settleTxid || paidLn.arkTxid,
                amount: dec,
                to: toAddr,
              },
            };
            if (polled.status === "done") {
              db.recordOperation({
                walletId: wallet.walletId,
                requestId: reqId,
                action: "pay",
                rail: "usdc",
                status: "done",
                amountDisplay: dec,
                summary: { kind: "send", to: toAddr, tx: out.receipt.tx },
                result: out,
              });
            }
            return out;
          }

          // Path B: Small USDC transfer (< provider min ~$5) — bridge min tranche to own Safe, then send exact amount!
          const bridged = await bridgeArkadeToUsdc({
            walletRecord: wallet,
            secrets,
            neededUsdcUnits: BigInt(units),
            opId,
          });
          const sent = await ensureSafe().transferUsdc({
            walletRecord: toSafeWalletRow(wallet),
            agentEthPrivateKeyHex: secrets.agentEthPrivHex,
            to: toAddr,
            amountUnits: units,
            opId,
          });
          const out = {
            ok: true,
            status: "done",
            request_id: reqId,
            rail: "usdc",
            funded_from: "arkade",
            bridged,
            to: toAddr,
            receipt: {
              tx: sent.txHash,
              amount: dec,
              to: toAddr,
            },
          };
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: "usdc",
            status: "done",
            amountDisplay: dec,
            summary: { kind: "send", to: toAddr, tx: sent.txHash },
            result: out,
          });
          return out;
        }

        // Neither rail has enough funds
        return {
          ok: false,
          status: "failed",
          error: `Insufficient balance: need ${dec} USDC (have ${unitsToDecimal(String(usdcBal), 6)} USDC and ${arkBal.sats.toString()} sats). Fund the wallet first via wallet receive.`,
        };
      }

      return {
        ok: false,
        status: "failed",
        error:
          "Unrecognized destination. Use an https:// URL, BOLT11 lnbc... invoice, user@domain, bc1.../bitcoin:... on-chain Bitcoin, ark1... address, or 0x... Base address. For other assets like XMR, use https://swapkit.nuri.com/mcp.",
      };
    } catch (err) {
      if (err?.code === "over_max_amount") {
        const price =
          err.invoiceUnits !== undefined
            ? { amount: unitsToDecimal(String(err.invoiceUnits), 6), currency: "USDC" }
            : err.invoiceSats !== undefined
              ? { amount: String(err.invoiceSats), currency: "sats" }
              : undefined;
        const priceLabel = price ? ` (${price.amount} ${price.currency})` : "";
        return {
          ok: false,
          status: "failed",
          ...(price ? { price } : {}),
          error:
            `The invoice${priceLabel} exceeds max_amount. Nothing was paid; STOP and ask the person first, then if they approve, send again with a NEW request_id and a higher max_amount.`,
          next: "Tell the person the exact price and ask before raising max_amount.",
        };
      }
      const msg = String(err?.message || err);
      const rawTgt = String(args.invoice || args.to || "").trim();
      const inferredRail =
        args.invoice || BOLT11_RE.test(rawTgt) || LN_ADDRESS_RE.test(rawTgt)
          ? "lightning"
          : isOnchainBtcAddress(rawTgt) || parseBip21Uri(rawTgt)
            ? "btc"
            : isValidArkAddress(rawTgt)
              ? "arkade"
              : args.amount_sats && !args.amount
                ? "lightning"
                : "usdc";
      const currentOp = db.getOperation(wallet.walletId, reqId);
      if (!currentOp || (currentOp.status !== "done" && currentOp.status !== "pending")) {
        db.recordOperation({
          walletId: wallet.walletId,
          requestId: reqId,
          action: "pay",
          rail: inferredRail,
          status: "failed",
          summary: { kind: "pay", to: rawTgt || null, reason: msg.slice(0, 120) },
          result: { ok: false, status: "failed", error: msg },
        });
      }
      return {
        ok: false,
        status: "failed",
        error: `Payment failed (${msg}).`,
      };
    }
  }

  async function handleHistory(args) {
    const db = ensureStore();
    const { wallet, secrets } = db.unlockWalletSecrets(args.wallet_key);
    await sweepPendingReceives(wallet, secrets.agentBtcPrivHex);
    await refreshPendingSends(wallet.walletId);
    const items = db.listOperations(wallet.walletId, { limit: args.limit || 25 });
    return {
      ok: true,
      status: "done",
      history: items.reverse().map((op) => ({
        request_id: op.request_id,
        kind: op.kind || op.action,
        ...(op.rail ? { rail: op.rail } : {}),
        status: op.status === "done" ? "done" : op.status === "failed" ? "failed" : "pending",
        amount: op.amount ?? null,
        to: op.to ?? null,
        tx: op.tx ?? null,
        ...(op.reason ? { reason: op.reason } : {}),
      })),
      next: "History shown.",
    };
  }

  async function payFeeWithPrfWallet({ walletKey, amountUnits, payTo, reference }) {
    const db = ensureStore();
    const { wallet, secrets } = db.unlockWalletSecrets(walletKey);
    const bal = await ensureSafe().readUsdcBalanceUnits(wallet.safeAddress);
    if (bal < BigInt(amountUnits)) {
      return { status: "insufficient", address: wallet.safeAddress };
    }
    const safeWalletRow = {
      cred_id_b64u: wallet.credIdB64u,
      slot_index: wallet.slotIndex,
      main_eoa: wallet.mainEoa,
      passkey_signer_address: wallet.passkeySignerAddress,
      agent_eoa: wallet.agentEthEoa,
      cosigner_eoa: wallet.cosignerEoa,
      safe_address: wallet.safeAddress,
    };
    const sent = await ensureSafe().transferUsdc({
      walletRecord: safeWalletRow,
      agentEthPrivateKeyHex: secrets.agentEthPrivHex,
      to: getAddress(payTo),
      amountUnits: BigInt(amountUnits),
      opId: `fee:${wallet.walletId}:${reference}`,
    });
    return {
      status: "paid",
      tx: sent.txHash,
      payer: wallet.safeAddress,
      asset: BASE_USDC_ADDRESS,
    };
  }

  function hasPendingGrantSession(requestId) {
    if (!configured || !requestId || typeof requestId !== "string") return false;
    try {
      return Boolean(ensureStore().getGrantSession(requestId.trim()));
    } catch {
      return false;
    }
  }

  function close() {
    closed = true;
    for (const rfqId of [...activeReceiveWatchers.keys()]) {
      stopReceiveWatcher(rfqId);
    }
    store?.close?.();
    store = null;
  }

  return {
    configured,
    walletKeyPattern: PRF_WALLET_KEY_RE,
    hasPendingGrantSession,
    handleBalance,
    handleReceive,
    handlePay,
    handleHistory,
    payFeeWithPrfWallet,
    findLatestWalletByMainEoa: (owner) =>
      configured ? ensureStore().findLatestWalletByMainEoa(owner) : null,
    close,
  };
}
