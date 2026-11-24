// Pure-L1 2-of-2 MuSig2+CSV Agent Wallet + Server-Only Arkade 0-Conf Lightning Fronter.
//
// Architecture (Muun model on Nuri's existing Taproot + Arkade stack):
//   - User/Agent wallets hold ONLY plain L1 Bitcoin UTXOs in:
//       tr(MuSig2(agent, cosigner), and_v(v:pk(agent), older(nuriServerCsv)))
//     No per-wallet Arkade SDK, no client VTXOs, no VTXO renewal, no exit chains.
//     `nuriServerCsv` and `l1_network` are synced live from `nuri-agent-cosigner /healthz`
//     so derived `bc1p...` addresses ALWAYS match the cosigner byte-for-byte.
//   - Outgoing (L1 -> Lightning):
//       1) Micro-credit / Muun `LEND` (tiny sends <= lendMaxSats, backed by confirmed L1 UTXOs,
//          policy-authorized via `/v1/l1/authorize-spend`): server's single Arkade pool pays LN
//          immediately with ZERO L1 tx (zero user custody risk; repaid on next L1 tx via `COLLECT`).
//       2) Normal sends (or collecting prior debt): build L1 key-path P2TR PSBT paying server L1
//          replenish address (+ debt `COLLECT`), co-sign via `/v1/l1/sign-psbt` (atomically locks
//          spent outpoints in SQLite so RBF is impossible), HOLD broadcast until server Arkade
//          obtains verified preimage, persist `broadcast_pending` before broadcast (crash-safe
//          auto-reconciler), then broadcast & seal `mark-broadcast` (0 L1 fee on pre-funding fail!).
//   - Incoming (Lightning -> User L1 `bc1p...`):
//       Server's single Arkade pool issues & claims the BOLT11 invoice (`pushClaim` loop).
//       1) Cancels `debt_sats` first (Muun `FulfillFullDebt` — ZERO L1 tx).
//       2) If remaining + `pending_receive_sats` >= `l1SettleFloorSats`, server L1 hot wallet
//          immediately broadcasts a 0-conf L1 P2TR payout (serialized via pool mutex + local
//          change tracking), persists `done` atomically before non-fatal cosigner trust register.
//       3) Otherwise credits `pending_receive_sats` (auto-swept to L1 once >= floor or applied
//          as instant credit on the next outgoing LN payment).
//   - Direct on-chain BTC sends (`bc1...` / BIP21): native 1-tx L1 MuSig2 spend.
//   - Sovereign unilateral exit: `buildUserCsvRecoveryTx` spends the Tapscript CSV leaf alone.
import { randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import {
  Address,
  NETWORK,
  OutScript,
  Script,
  SigHash,
  TEST_NETWORK,
  Transaction,
  p2tr,
} from "@scure/btc-signer";
import * as musig2 from "@scure/btc-signer/musig2.js";
import {
  ArkAddress,
  DefaultVtxo,
  RestIndexerProvider,
  RestOperatorProvider,
  SingleKey,
  assertValidServerUnrollScript,
  networkFromOperatorInfo,
  resolveEmulatorPubkey,
  selectVirtualCoins,
  signAndSubmitOffchainTx,
  toXOnly,
} from "@arkade-os/sdk";
import { decodeBolt11 } from "@arkade-os/swap/advanced";
import { nostrRfqTransport } from "@arkade-os/swap/nostr";
import {
  deriveLightningReceive,
  lightningReceiveRequest,
  lightningSendContract,
  lightningSendRequest,
  pushClaim,
  readLockupFate,
  unilateralClaimDelay,
  verifyLockupAddress,
  verifyReceiveInvoice,
} from "@arkade-os/swap/protocol";
import {
  DEFAULT_ARKADE_NOSTR_RELAYS,
  DEFAULT_ARKADE_SERVER_URL,
  DEFAULT_ARKADE_SOLVER_PUBKEY,
  DEFAULT_SERVER_DECAY_OFFSET_SECONDS,
  SEQUENCE_GRANULARITY_SECONDS,
  deriveLightningReceiveSecrets,
  resolveLightningAddressInvoice,
  toArkadeTimelock,
} from "./agent-arkade-v2.mjs";

export const DEFAULT_L1_CSV = {
  type: "seconds",
  value: Number(DEFAULT_SERVER_DECAY_OFFSET_SECONDS), // 7776256s (~90d, 512s-aligned)
};
export const P2TR_DUST_SATS = 330;
export const DEFAULT_L1_SETTLE_FLOOR_SATS = 5_000;
export const DEFAULT_LEND_MAX_SATS = 5_000;
export const DEFAULT_MAX_DEBT_SATS = 10_000;
export const DEFAULT_ESPLORA_URL = "https://mempool.space/api";
export const MAX_TRUSTED_ANCESTOR_DEPTH = 20; // safely below Bitcoin Core's 25-ancestor limit

const BIP68_LOCKTIME_GRANULARITY = 9;
const BIP68_LOCKTIME_MASK = 0x0000ffff;
const BIP68_LOCKTIME_TYPE_FLAG = 1 << 22;
const BIP68_SECONDS_MOD = 1 << BIP68_LOCKTIME_GRANULARITY;
const BIP68_SECONDS_MAX = BIP68_LOCKTIME_MASK << BIP68_LOCKTIME_GRANULARITY;
const REGTEST_NETWORK = { bech32: "bcrt", pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef };
const COSIGNER_HEALTH_TTL_MS = 5 * 60_000;
const FEE_CACHE_TTL_MS = 10 * 60_000;
const TRUSTED_GRACE_MS = 30_000;
const DEFAULT_CSV_SAFETY_BLOCKS = 144;
const DEFAULT_CSV_SAFETY_SECONDS = 7 * 24 * 3600;
const MIN_LIGHTNING_SEND_LOCKTIME_WINDOW_SECONDS = 5400;

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex").toLowerCase();
}

function hexToBytes(hex) {
  const clean = String(hex || "").trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid_hex");
  }
  return new Uint8Array(Buffer.from(clean, "hex"));
}

function createKeyedMutex() {
  const tails = new Map();
  return async function withLock(key, fn) {
    const k = String(key);
    const prev = tails.get(k) || Promise.resolve();
    let release;
    const next = new Promise((resolve) => {
      release = resolve;
    });
    const tail = prev.catch(() => {}).then(() => next);
    tails.set(k, tail);
    await prev.catch(() => {});
    try {
      return await fn();
    } finally {
      release();
      if (tails.get(k) === tail) tails.delete(k);
    }
  };
}

export function dustLimitForScriptHex(scriptHex) {
  const s = String(scriptHex || "").trim().toLowerCase().replace(/^0x/, "");
  if (s.startsWith("5120") && s.length === 68) return 330; // P2TR
  if (s.startsWith("0020") && s.length === 68) return 330; // P2WSH
  if (s.startsWith("0014") && s.length === 44) return 294; // P2WPKH
  if (s.startsWith("a914") && s.endsWith("87") && s.length === 46) return 540; // P2SH
  return 546; // P2PKH / other
}

export function normalizeBitcoinNetwork(network = "bitcoin") {
  const n = String(network || "bitcoin").trim().toLowerCase();
  if (n === "bitcoin" || n === "mainnet" || n === "btc") return "bitcoin";
  if (n === "testnet" || n === "testnet3" || n === "testnet4" || n === "signet") return "testnet";
  if (n === "regtest") return "regtest";
  throw new Error(`unsupported_bitcoin_network:${network}`);
}

export function bitcoinNetworkParams(network = "bitcoin") {
  const n = normalizeBitcoinNetwork(network);
  if (n === "bitcoin") return NETWORK;
  if (n === "testnet") return TEST_NETWORK;
  return REGTEST_NETWORK;
}

export function bip68SequenceFromCsv(csv = DEFAULT_L1_CSV) {
  const type = String(csv?.type || "").trim();
  const value = Number(csv?.value);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error("invalid_csv_value");
  }
  if (type === "seconds") {
    if (value > BIP68_SECONDS_MAX || value % BIP68_SECONDS_MOD !== 0) {
      throw new Error("invalid_csv_seconds");
    }
    return BIP68_LOCKTIME_TYPE_FLAG | (value >> BIP68_LOCKTIME_GRANULARITY);
  }
  if (type === "blocks") {
    if (value > BIP68_LOCKTIME_MASK) throw new Error("invalid_csv_blocks");
    return value;
  }
  throw new Error("invalid_csv_type");
}

/**
 * Pure L1 2-of-2 MuSig2 + client-only CSV Taproot wallet address derivation.
 * Byte-identical to `nuri-agent-cosigner` (`deriveAgentL1Taproot`) and consumer Nuri (`nuri-expo`).
 */
export function deriveAgentL1Wallet({
  aggregatedBtcXonlyHex,
  agentBtcPub33Hex,
  nuriServerCsv = DEFAULT_L1_CSV,
  network = "bitcoin",
}) {
  const aggXonly = hexToBytes(aggregatedBtcXonlyHex);
  const clientPub33 = hexToBytes(agentBtcPub33Hex);
  if (aggXonly.length !== 32) throw new Error("invalid_aggregated_btc_xonly");
  if (clientPub33.length !== 33) throw new Error("invalid_agent_btc_pub33");
  const clientXonly = clientPub33.subarray(1);
  const csvSequence = bip68SequenceFromCsv(nuriServerCsv);
  const csvLeafScript = Script.encode([
    clientXonly,
    "CHECKSIGVERIFY",
    csvSequence,
    "CHECKSEQUENCEVERIFY",
  ]);
  const normNet = normalizeBitcoinNetwork(network);
  const out = p2tr(
    aggXonly,
    [{ script: csvLeafScript, leafVersion: 0xc0 }],
    bitcoinNetworkParams(normNet),
    true,
  );
  if (!out?.address || !out?.script || !out?.tapMerkleRoot || !out?.tweakedPubkey) {
    throw new Error("l1_wallet_derivation_failed");
  }
  const controlBlock = out.leaves?.[0]?.controlBlock || null;
  return {
    network: normNet,
    nuriServerCsv,
    address: out.address,
    pkScript: out.script,
    scriptPubKeyHex: bytesToHex(out.script),
    tapMerkleRoot: out.tapMerkleRoot,
    tapMerkleRootHex: bytesToHex(out.tapMerkleRoot),
    tweakedXonly: out.tweakedPubkey,
    tweakedXonlyHex: bytesToHex(out.tweakedPubkey),
    aggregatedXonly: aggXonly,
    clientXonly,
    csvSequence,
    csvLeafScript,
    csvLeafScriptHex: bytesToHex(csvLeafScript),
    csvControlBlock: controlBlock,
    csvControlBlockHex: controlBlock ? bytesToHex(controlBlock) : null,
    tapLeafScript: out.tapLeafScript,
  };
}

/**
 * Sovereign unilateral L1 recovery transaction (zero cosigner, zero Arkade, zero Nostr).
 * Spends confirmed L1 UTXOs via the Tapscript CSV recovery leaf after `nuriServerCsv` elapses:
 *   `<agentXonly> OP_CHECKSIGVERIFY <csvSequence> OP_CHECKSEQUENCEVERIFY`
 */
export function buildUserCsvRecoveryTx({
  agentBtcPrivHex,
  agentBtcPub33Hex,
  aggregatedBtcXonlyHex,
  nuriServerCsv = DEFAULT_L1_CSV,
  utxos,
  toBtcAddress,
  feeRateSatVb = 2,
  network = "bitcoin",
}) {
  if (!Array.isArray(utxos) || utxos.length === 0) {
    throw new Error("csv_recovery_requires_utxos");
  }
  const normNet = normalizeBitcoinNetwork(network);
  const netParams = bitcoinNetworkParams(normNet);
  const l1 = deriveAgentL1Wallet({
    aggregatedBtcXonlyHex,
    agentBtcPub33Hex,
    nuriServerCsv,
    network: normNet,
  });
  const destScript = OutScript.encode(Address(netParams).decode(String(toBtcAddress).trim()));
  const destDust = BigInt(dustLimitForScriptHex(bytesToHex(destScript)));

  // Tapscript spend weight: ~10.5 base + ~107.5 vB per CSV leaf input + 43 vB output
  const estVbytes = Math.ceil(10.5 + utxos.length * 107.5 + 43);
  const feeSats = BigInt(Math.max(1, Math.ceil(estVbytes * Number(feeRateSatVb || 2))));
  const totalIn = utxos.reduce((sum, u) => sum + BigInt(u.value), 0n);
  const outSats = totalIn - feeSats;
  if (outSats < destDust) {
    throw new Error(`csv_recovery_below_dust:${outSats.toString()}<${destDust.toString()}`);
  }

  const tx = new Transaction({ version: 2 });
  const prevScripts = [];
  const prevAmounts = [];
  for (const u of utxos) {
    tx.addInput({
      txid: String(u.txid).toLowerCase(),
      index: Number(u.vout),
      sequence: l1.csvSequence, // BIP-68 relative timelock satisfied after CSV elapses
      witnessUtxo: { script: l1.pkScript, amount: BigInt(u.value) },
      tapLeafScript: l1.tapLeafScript,
    });
    prevScripts.push(l1.pkScript);
    prevAmounts.push(BigInt(u.value));
  }
  tx.addOutput({ script: destScript, amount: outSats });

  const priv = hexToBytes(agentBtcPrivHex);
  try {
    for (let i = 0; i < tx.inputsLength; i += 1) {
      const msg32 = tx.preimageWitnessV1(
        i,
        prevScripts,
        SigHash.DEFAULT,
        prevAmounts,
        undefined,
        l1.csvLeafScript,
        0xc0,
      );
      const sig64 = schnorr.sign(msg32, priv);
      if (!schnorr.verify(sig64, msg32, l1.clientXonly)) {
        throw new Error(`csv_recovery_sig_verify_failed:${i}`);
      }
      tx.updateInput(i, {
        finalScriptWitness: [sig64, l1.csvLeafScript, l1.csvControlBlock],
      });
    }
    return {
      txid: tx.id.toLowerCase(),
      rawHex: bytesToHex(tx.extract()),
      fromAddress: l1.address,
      toAddress: toBtcAddress,
      csvSequence: l1.csvSequence,
      totalInSats: Number(totalIn),
      outputSats: Number(outSats),
      feeSats: Number(feeSats),
      vsize: tx.vsize,
    };
  } finally {
    priv.fill(0);
  }
}

export function estimateP2trVbytes(inputCount, outputCount) {
  return Math.ceil(10.5 + inputCount * 57.5 + outputCount * 43);
}

/**
 * Validated server-side Arkade Lightning send VHTLC lockup derivation matching
 * `@arkade-os/swap@0.1.8` (`lightningSendContract` + `verifyLockupAddress`).
 */
export function derivePoolLightningSendLockup({
  quote,
  paymentHash,
  senderPubkey,
  refundPkScript,
  operatorPubkey,
  emulatorPubkey,
  claimDelay,
  hrp,
  now = Math.floor(Date.now() / 1000),
}) {
  if (!quote?.solver_pubkey) throw new Error("lightning_send_quote_missing_solver_pubkey");
  if (!quote?.refund_locktime || Number(quote.refund_locktime) - now < MIN_LIGHTNING_SEND_LOCKTIME_WINDOW_SECONDS) {
    throw new Error("lightning_send_quote_refund_locktime_too_short");
  }
  if (quote.valid_until && Number(quote.valid_until) <= now) {
    throw new Error("lightning_send_quote_expired");
  }
  const refundWithoutReceiverDelay = Number(quote.profile?.refund_without_receiver_delay);
  if (
    !Number.isSafeInteger(refundWithoutReceiverDelay) ||
    refundWithoutReceiverDelay < claimDelay ||
    refundWithoutReceiverDelay % SEQUENCE_GRANULARITY_SECONDS !== 0
  ) {
    throw new Error("lightning_send_quote_invalid_refund_delay");
  }
  if (refundWithoutReceiverDelay < Number(quote.refund_locktime) - now) {
    throw new Error("lightning_send_quote_refund_before_locktime");
  }
  const receiverPkScriptHex = quote.profile?.receiver_pk_script;
  if (!receiverPkScriptHex) {
    throw new Error("lightning_send_quote_missing_receiver_pk_script");
  }
  const receiverPkScript = hexToBytes(receiverPkScriptHex);
  const solverPubkey = toXOnly(hexToBytes(quote.solver_pubkey), "solver key");
  const normPaymentHash = String(paymentHash || "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normPaymentHash)) {
    throw new Error("invalid_payment_hash");
  }

  const baseParams = {
    solverPubkey,
    refundLocktime: Number(quote.refund_locktime),
    operatorPubkey,
    paymentHash: normPaymentHash,
    claimDelay,
    refundWithoutReceiverDelay,
    emulatorPubkey,
    refundPkScript,
    senderPubkey,
    receiverPkScript,
  };

  const candidates = [];
  for (const legacy of [undefined, "preTimelockedRefund"]) {
    const contract = lightningSendContract(legacy ? { ...baseParams, legacy } : baseParams);
    const address = new ArkAddress(operatorPubkey, contract.tweakedPublicKey, hrp).encode();
    candidates.push({ contract, address, legacy });
  }

  // Note: `@arkade-os/swap` signature is verifyLockupAddress(quote, derivedAddresses)
  const matchedAddress = verifyLockupAddress(
    quote,
    candidates.map((c) => c.address),
  );
  const winner = candidates.find((c) => c.address === matchedAddress) || candidates[0];
  return {
    address: winner.address,
    contract: winner.contract,
    swapPkScript: winner.contract.pkScript,
    swapPkScriptHex: bytesToHex(winner.contract.pkScript),
    legacy: winner.legacy || null,
  };
}

export function createEsploraL1Client({
  baseUrl = DEFAULT_ESPLORA_URL,
  fetchImpl = fetch,
  timeoutMs = 12_000,
} = {}) {
  const origin = String(baseUrl || DEFAULT_ESPLORA_URL).trim().replace(/\/+$/, "");
  let cachedFeeRate = null;
  let cachedFeeRateAt = 0;

  async function req(path, opts = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(`${origin}${path}`, { ...opts, signal: controller.signal });
      if (res.status === 404) return { ok: false, status: 404, res };
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        const err = new Error(`esplora_http_${res.status}:${text.slice(0, 200)}`);
        err.status = res.status;
        err.responseText = text;
        throw err;
      }
      return { ok: true, status: res.status, res };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    origin,
    async listUtxos(address) {
      const { ok, res } = await req(`/address/${encodeURIComponent(address)}/utxo`);
      if (!ok) return [];
      const rows = await res.json();
      return (Array.isArray(rows) ? rows : []).map((u) => ({
        txid: String(u.txid).toLowerCase(),
        vout: Number(u.vout),
        value: Number(u.value),
        confirmed: Boolean(u.status?.confirmed),
        blockHeight: u.status?.confirmed ? Number(u.status.block_height) : null,
        blockTime: u.status?.confirmed ? Number(u.status.block_time) : null,
      }));
    },
    async getOutspend(txid, vout) {
      const { ok, res } = await req(`/tx/${txid}/outspend/${Number(vout)}`);
      if (!ok) return null;
      return res.json();
    },
    async getTx(txid) {
      const { ok, res } = await req(`/tx/${txid}`);
      if (!ok) return null;
      return res.json();
    },
    async getTipHeight() {
      const { ok, res } = await req("/blocks/tip/height");
      if (!ok) return null;
      return Number((await res.text()).trim());
    },
    async estimateFeeRate(targetBlocks = 3) {
      try {
        const { ok, res } = await req("/fee-estimates");
        if (!ok) throw new Error("esplora_fee_estimates_missing");
        const map = await res.json();
        const rate = Number(map?.[String(targetBlocks)] ?? map?.["6"] ?? map?.["1"]);
        if (!Number.isFinite(rate) || rate <= 0) {
          throw new Error("esplora_fee_rate_invalid");
        }
        cachedFeeRate = Math.max(1, Math.ceil(rate));
        cachedFeeRateAt = Date.now();
        return cachedFeeRate;
      } catch (err) {
        if (cachedFeeRate && Date.now() - cachedFeeRateAt < FEE_CACHE_TTL_MS) {
          return cachedFeeRate;
        }
        throw new Error(`l1_fee_estimation_unavailable:${err?.message || err}`);
      }
    },
    async broadcastTx(rawHex) {
      const { res } = await req("/tx", {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: String(rawHex || "").trim(),
      });
      return (await res.text()).trim().toLowerCase();
    },
  };
}

function isAlreadyBroadcastError(err) {
  const msg = String(err?.responseText || err?.message || "").toLowerCase();
  return (
    msg.includes("txn-already-known") ||
    msg.includes("already in block chain") ||
    msg.includes("transaction already in block chain")
  );
}

function isDefinitePreMempoolReject(err) {
  const status = Number(err?.status || 0);
  const msg = String(err?.responseText || err?.message || "").toLowerCase();
  if (status === 400 && !isAlreadyBroadcastError(err)) {
    return (
      msg.includes("dust") ||
      msg.includes("min relay fee") ||
      msg.includes("too-long-mempool-chain") ||
      msg.includes("bad-txns") ||
      msg.includes("non-final") ||
      msg.includes("script failed")
    );
  }
  return false;
}

/**
 * SQLite ledger for Muun-style LEND/COLLECT/FulfillFullDebt, micro-receive accumulator,
 * trusted server-originated 0-conf UTXOs (with ancestor depth), and exactly-once swap journal.
 */
export function openL1FronterLedger(dbPath = ":memory:") {
  const resolved = dbPath || ":memory:";
  if (resolved !== ":memory:") {
    mkdirSync(dirname(resolved), { recursive: true });
  }
  const db = new DatabaseSync(resolved);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA busy_timeout = 5000;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS nuri_l1_fronter_ledger (
      wallet_id TEXT PRIMARY KEY,
      debt_sats INTEGER NOT NULL DEFAULT 0,
      pending_receive_sats INTEGER NOT NULL DEFAULT 0,
      updated_at_ms INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS nuri_l1_fronter_swaps (
      op_id TEXT PRIMARY KEY,
      wallet_id TEXT NOT NULL,
      direction TEXT NOT NULL,
      mode TEXT NOT NULL,
      status TEXT NOT NULL,
      payment_hash TEXT,
      preimage_hex TEXT,
      bolt11 TEXT,
      amount_sats INTEGER NOT NULL,
      fee_sats INTEGER NOT NULL DEFAULT 0,
      service_fee_sats INTEGER NOT NULL DEFAULT 0,
      debt_delta_sats INTEGER NOT NULL DEFAULT 0,
      l1_txid TEXT,
      l1_raw_hex TEXT,
      swap_pk_script_hex TEXT,
      ark_txid TEXT,
      spent_outpoints_json TEXT,
      change_outpoints_json TEXT,
      credit_used_sats INTEGER NOT NULL DEFAULT 0,
      output_padding_sats INTEGER NOT NULL DEFAULT 0,
      error TEXT,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_l1_fronter_swaps_wallet
      ON nuri_l1_fronter_swaps (wallet_id, created_at_ms DESC);

    CREATE INDEX IF NOT EXISTS idx_l1_fronter_swaps_status
      ON nuri_l1_fronter_swaps (status);

    CREATE TABLE IF NOT EXISTS nuri_l1_trusted_utxos (
      outpoint TEXT PRIMARY KEY,
      wallet_id TEXT NOT NULL,
      txid TEXT NOT NULL,
      vout INTEGER NOT NULL,
      amount_sats INTEGER NOT NULL,
      script_pubkey_hex TEXT NOT NULL,
      source_kind TEXT NOT NULL,
      ancestor_depth INTEGER NOT NULL DEFAULT 1,
      spent_by_txid TEXT,
      created_at_ms INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_l1_trusted_utxos_wallet
      ON nuri_l1_trusted_utxos (wallet_id, spent_by_txid);
  `);

  // Safe schema evolution for any existing DB created before columns were added
  for (const [table, col, def] of [
    ["nuri_l1_fronter_swaps", "swap_pk_script_hex", "TEXT"],
    ["nuri_l1_fronter_swaps", "ark_txid", "TEXT"],
    ["nuri_l1_fronter_swaps", "spent_outpoints_json", "TEXT"],
    ["nuri_l1_fronter_swaps", "change_outpoints_json", "TEXT"],
    ["nuri_l1_fronter_swaps", "credit_used_sats", "INTEGER NOT NULL DEFAULT 0"],
    ["nuri_l1_fronter_swaps", "output_padding_sats", "INTEGER NOT NULL DEFAULT 0"],
    ["nuri_l1_fronter_swaps", "service_fee_sats", "INTEGER NOT NULL DEFAULT 0"],
    ["nuri_l1_trusted_utxos", "ancestor_depth", "INTEGER NOT NULL DEFAULT 1"],
  ]) {
    try {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def};`);
    } catch {
      // Column already exists.
    }
  }

  function getLedger(walletId) {
    const row = db
      .prepare("SELECT wallet_id, debt_sats, pending_receive_sats, updated_at_ms FROM nuri_l1_fronter_ledger WHERE wallet_id = ?")
      .get(String(walletId));
    if (!row) {
      return { walletId: String(walletId), debtSats: 0, pendingReceiveSats: 0, updatedAtMs: 0 };
    }
    return {
      walletId: row.wallet_id,
      debtSats: Number(row.debt_sats),
      pendingReceiveSats: Number(row.pending_receive_sats),
      updatedAtMs: Number(row.updated_at_ms),
    };
  }

  function setLedger(walletId, { debtSats, pendingReceiveSats }, nowMs = Date.now()) {
    const debt = Math.trunc(Number(debtSats));
    const pending = Math.trunc(Number(pendingReceiveSats));
    if (!Number.isSafeInteger(debt) || debt < 0) {
      throw new Error(`l1_ledger_negative_debt:${debtSats}`);
    }
    if (!Number.isSafeInteger(pending) || pending < 0) {
      throw new Error(`l1_ledger_negative_pending_receive:${pendingReceiveSats}`);
    }
    db.prepare(`
      INSERT INTO nuri_l1_fronter_ledger (wallet_id, debt_sats, pending_receive_sats, updated_at_ms)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(wallet_id) DO UPDATE SET
        debt_sats = excluded.debt_sats,
        pending_receive_sats = excluded.pending_receive_sats,
        updated_at_ms = excluded.updated_at_ms
    `).run(String(walletId), debt, pending, nowMs);
    return { walletId: String(walletId), debtSats: debt, pendingReceiveSats: pending, updatedAtMs: nowMs };
  }

  function getSwap(opId) {
    return db.prepare("SELECT * FROM nuri_l1_fronter_swaps WHERE op_id = ?").get(String(opId)) || null;
  }

  function listSwapsByStatus(walletId, statuses) {
    const placeholders = statuses.map(() => "?").join(",");
    return db
      .prepare(
        `SELECT * FROM nuri_l1_fronter_swaps WHERE wallet_id = ? AND status IN (${placeholders}) ORDER BY created_at_ms ASC`,
      )
      .all(String(walletId), ...statuses);
  }

  function reserveSwap(row) {
    const now = row.updatedAtMs ?? Date.now();
    const res = db
      .prepare(`
        INSERT INTO nuri_l1_fronter_swaps (
          op_id, wallet_id, direction, mode, status, payment_hash, preimage_hex, bolt11,
          amount_sats, fee_sats, service_fee_sats, debt_delta_sats, l1_txid, l1_raw_hex,
          swap_pk_script_hex, ark_txid, spent_outpoints_json, change_outpoints_json,
          credit_used_sats, output_padding_sats, error, created_at_ms, updated_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(op_id) DO NOTHING
      `)
      .run(
        String(row.opId),
        String(row.walletId),
        String(row.direction),
        String(row.mode),
        String(row.status),
        row.paymentHash ?? null,
        row.preimageHex ?? null,
        row.bolt11 ?? null,
        Math.trunc(Number(row.amountSats || 0)),
        Math.trunc(Number(row.feeSats || 0)),
        Math.trunc(Number(row.serviceFeeSats || 0)),
        Math.trunc(Number(row.debtDeltaSats || 0)),
        row.l1Txid ?? null,
        row.l1RawHex ?? null,
        row.swapPkScriptHex ?? null,
        row.arkTxid ?? null,
        row.spentOutpoints ? JSON.stringify(row.spentOutpoints) : null,
        row.changeOutpoints ? JSON.stringify(row.changeOutpoints) : null,
        Math.trunc(Number(row.creditUsedSats || 0)),
        Math.trunc(Number(row.outputPaddingSats || 0)),
        row.error ?? null,
        row.createdAtMs ?? now,
        now,
      );
    return { reserved: res.changes === 1, swap: getSwap(row.opId) };
  }

  function upsertSwap(row) {
    const now = row.updatedAtMs ?? Date.now();
    db.prepare(`
      INSERT INTO nuri_l1_fronter_swaps (
        op_id, wallet_id, direction, mode, status, payment_hash, preimage_hex, bolt11,
        amount_sats, fee_sats, service_fee_sats, debt_delta_sats, l1_txid, l1_raw_hex,
        swap_pk_script_hex, ark_txid, spent_outpoints_json, change_outpoints_json,
        credit_used_sats, output_padding_sats, error, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(op_id) DO UPDATE SET
        mode = excluded.mode,
        status = excluded.status,
        preimage_hex = COALESCE(excluded.preimage_hex, nuri_l1_fronter_swaps.preimage_hex),
        fee_sats = excluded.fee_sats,
        service_fee_sats = excluded.service_fee_sats,
        debt_delta_sats = excluded.debt_delta_sats,
        l1_txid = COALESCE(excluded.l1_txid, nuri_l1_fronter_swaps.l1_txid),
        l1_raw_hex = COALESCE(excluded.l1_raw_hex, nuri_l1_fronter_swaps.l1_raw_hex),
        swap_pk_script_hex = COALESCE(excluded.swap_pk_script_hex, nuri_l1_fronter_swaps.swap_pk_script_hex),
        ark_txid = COALESCE(excluded.ark_txid, nuri_l1_fronter_swaps.ark_txid),
        spent_outpoints_json = COALESCE(excluded.spent_outpoints_json, nuri_l1_fronter_swaps.spent_outpoints_json),
        change_outpoints_json = COALESCE(excluded.change_outpoints_json, nuri_l1_fronter_swaps.change_outpoints_json),
        credit_used_sats = excluded.credit_used_sats,
        output_padding_sats = excluded.output_padding_sats,
        error = excluded.error,
        updated_at_ms = excluded.updated_at_ms
    `).run(
      String(row.opId),
      String(row.walletId),
      String(row.direction),
      String(row.mode),
      String(row.status),
      row.paymentHash ?? null,
      row.preimageHex ?? null,
      row.bolt11 ?? null,
      Math.trunc(Number(row.amountSats || 0)),
      Math.trunc(Number(row.feeSats || 0)),
      Math.trunc(Number(row.serviceFeeSats || 0)),
      Math.trunc(Number(row.debtDeltaSats || 0)),
      row.l1Txid ?? null,
      row.l1RawHex ?? null,
      row.swapPkScriptHex ?? null,
      row.arkTxid ?? null,
      row.spentOutpoints ? JSON.stringify(row.spentOutpoints) : null,
      row.changeOutpoints ? JSON.stringify(row.changeOutpoints) : null,
      Math.trunc(Number(row.creditUsedSats || 0)),
      Math.trunc(Number(row.outputPaddingSats || 0)),
      row.error ?? null,
      row.createdAtMs ?? now,
      now,
    );
    return getSwap(row.opId);
  }

  function addTrustedUtxo({
    walletId,
    txid,
    vout,
    amountSats,
    scriptPubKeyHex,
    sourceKind = "fronter_payout",
    ancestorDepth = 1,
    nowMs = Date.now(),
  }) {
    const normTxid = String(txid).toLowerCase();
    const outpoint = `${normTxid}:${Number(vout)}`;
    db.prepare(`
      INSERT INTO nuri_l1_trusted_utxos (
        outpoint, wallet_id, txid, vout, amount_sats, script_pubkey_hex, source_kind, ancestor_depth, spent_by_txid, created_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
      ON CONFLICT(outpoint) DO NOTHING
    `).run(
      outpoint,
      String(walletId),
      normTxid,
      Number(vout),
      Math.trunc(Number(amountSats)),
      String(scriptPubKeyHex).toLowerCase(),
      String(sourceKind),
      Math.max(1, Math.trunc(Number(ancestorDepth || 1))),
      nowMs,
    );
    return outpoint;
  }

  function listUnspentTrustedUtxos(walletId) {
    return db
      .prepare(
        "SELECT outpoint, txid, vout, amount_sats, script_pubkey_hex, source_kind, ancestor_depth, created_at_ms FROM nuri_l1_trusted_utxos WHERE wallet_id = ? AND spent_by_txid IS NULL",
      )
      .all(String(walletId))
      .map((r) => ({
        outpoint: r.outpoint,
        txid: r.txid,
        vout: Number(r.vout),
        value: Number(r.amount_sats),
        scriptPubKeyHex: r.script_pubkey_hex,
        sourceKind: r.source_kind,
        ancestorDepth: Number(r.ancestor_depth || 1),
        createdAtMs: Number(r.created_at_ms || 0),
        confirmed: false,
        trusted: true,
      }));
  }

  function markOutpointsSpentLocally(walletId, outpoints, spentByTxid) {
    const stmt = db.prepare(`
      INSERT INTO nuri_l1_trusted_utxos (
        outpoint, wallet_id, txid, vout, amount_sats, script_pubkey_hex, source_kind, ancestor_depth, spent_by_txid, created_at_ms
      ) VALUES (?, ?, ?, ?, 0, '', 'spent_marker', 0, ?, ?)
      ON CONFLICT(outpoint) DO UPDATE SET spent_by_txid = excluded.spent_by_txid
    `);
    const now = Date.now();
    for (const op of outpoints) {
      const [txid, voutStr] = String(op).toLowerCase().split(":");
      stmt.run(op.toLowerCase(), String(walletId), txid, Number(voutStr), String(spentByTxid).toLowerCase(), now);
    }
  }

  function getSpentOutpointsSet(walletId) {
    const rows = db
      .prepare("SELECT outpoint FROM nuri_l1_trusted_utxos WHERE wallet_id = ? AND spent_by_txid IS NOT NULL")
      .all(String(walletId));
    return new Set(rows.map((r) => String(r.outpoint).toLowerCase()));
  }

  function getActiveReservedOutpointsSet(walletId) {
    const rows = db
      .prepare(
        "SELECT spent_outpoints_json FROM nuri_l1_fronter_swaps WHERE wallet_id = ? AND status IN ('paying_ln', 'broadcast_pending') AND spent_outpoints_json IS NOT NULL",
      )
      .all(String(walletId));
    const set = new Set();
    for (const r of rows) {
      try {
        for (const op of JSON.parse(r.spent_outpoints_json)) set.add(String(op).toLowerCase());
      } catch {}
    }
    return set;
  }

  function aggregateTotals() {
    const row = db
      .prepare("SELECT COALESCE(SUM(debt_sats), 0) AS total_debt, COALESCE(SUM(pending_receive_sats), 0) AS total_pending, COUNT(*) AS wallets FROM nuri_l1_fronter_ledger")
      .get();
    const pendingBroadcasts = db
      .prepare("SELECT COUNT(*) AS n FROM nuri_l1_fronter_swaps WHERE status = 'broadcast_pending'")
      .get();
    const swapStats = db
      .prepare(`
        SELECT COALESCE(SUM(service_fee_sats), 0) AS earned_fees,
               COALESCE(SUM(CASE WHEN direction = 'out' THEN 1 ELSE 0 END), 0) AS out_count,
               COALESCE(SUM(CASE WHEN direction = 'in' THEN 1 ELSE 0 END), 0) AS in_count
        FROM nuri_l1_fronter_swaps
        WHERE status = 'done'
      `)
      .get();
    return {
      wallets: Number(row?.wallets || 0),
      totalDebtSats: Number(row?.total_debt || 0),
      totalPendingReceiveSats: Number(row?.total_pending || 0),
      pendingL1Broadcasts: Number(pendingBroadcasts?.n || 0),
      earnedServiceFeeSats: Number(swapStats?.earned_fees || 0),
      completedOutSwaps: Number(swapStats?.out_count || 0),
      completedInSwaps: Number(swapStats?.in_count || 0),
    };
  }

  function runTx(fn) {
    db.exec("BEGIN IMMEDIATE;");
    try {
      const res = fn();
      db.exec("COMMIT;");
      return res;
    } catch (err) {
      db.exec("ROLLBACK;");
      throw err;
    }
  }

  let closed = false;
  return {
    db,
    runTx,
    getLedger,
    setLedger,
    getSwap,
    listSwapsByStatus,
    reserveSwap,
    upsertSwap,
    addTrustedUtxo,
    listUnspentTrustedUtxos,
    markOutpointsSpentLocally,
    getSpentOutpointsSet,
    getActiveReservedOutpointsSet,
    aggregateTotals,
    close() {
      if (closed) return;
      closed = true;
      db.close();
    },
  };
}

/**
 * Single server-side Arkade + L1 liquidity pool used by the 0-conf fronter.
 * One server pool replaces per-user Arkade wallets across every user/agent!
 */
export function createServerArkadeLiquidityPool({
  env = process.env,
  fetchImpl = fetch,
  esplora = null,
  network = "bitcoin",
  arkadeServerUrl = env.ARKADE_SERVER_URL || DEFAULT_ARKADE_SERVER_URL,
  poolArkadePrivKeyHex = env.FRONTER_ARKADE_PRIVKEY_HEX || "",
  poolL1PrivKeyHex = env.FRONTER_L1_PRIVKEY_HEX || env.FRONTER_ARKADE_PRIVKEY_HEX || "",
  poolL1DepositAddress = env.FRONTER_L1_DEPOSIT_ADDRESS || "",
  serviceFeeBps = Number(env.FRONTER_SERVICE_FEE_BPS ?? 25), // 0.25% default
} = {}) {
  const normNet = normalizeBitcoinNetwork(network);
  const netParams = bitcoinNetworkParams(normNet);
  const esploraClient =
    esplora || createEsploraL1Client({ baseUrl: env.FRONTER_ESPLORA_URL || DEFAULT_ESPLORA_URL, fetchImpl });

  const cleanArkPriv = String(poolArkadePrivKeyHex || "").trim().toLowerCase().replace(/^0x/, "");
  const cleanL1Priv = String(poolL1PrivKeyHex || "").trim().toLowerCase().replace(/^0x/, "");
  const hasArkKey = /^[0-9a-f]{64}$/.test(cleanArkPriv);
  const hasL1Key = /^[0-9a-f]{64}$/.test(cleanL1Priv);

  let l1P2tr = null;
  if (hasL1Key) {
    const pubXonly = schnorr.getPublicKey(hexToBytes(cleanL1Priv));
    l1P2tr = p2tr(pubXonly, undefined, netParams);
  }
  const explicitDeposit = String(poolL1DepositAddress || "").trim();
  const depositAddress = explicitDeposit || l1P2tr?.address || null;
  // Respect explicit FRONTER_L1_DEPOSIT_ADDRESS first before falling back to hot wallet!
  const depositScriptHex = explicitDeposit
    ? bytesToHex(OutScript.encode(Address(netParams).decode(explicitDeposit)))
    : l1P2tr
      ? bytesToHex(l1P2tr.script)
      : null;

  const serverUrl = String(arkadeServerUrl || DEFAULT_ARKADE_SERVER_URL).replace(/\/+$/, "");
  const relays = String(env.ARKADE_NOSTR_RELAYS || DEFAULT_ARKADE_NOSTR_RELAYS.join(","))
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const solverPubkey = String(env.ARKADE_SOLVER_PUBKEY || DEFAULT_ARKADE_SOLVER_PUBKEY).trim();
  const operator = new RestOperatorProvider(serverUrl);
  const indexer = new RestIndexerProvider(serverUrl);
  const withPoolLock = createKeyedMutex();

  // In-memory hot-wallet UTXO tracker so concurrent LN->L1 payouts never collide on the same pool UTXO!
  const poolSpentOutpoints = new Set();
  const poolLocalChange = new Map(); // outpoint -> { txid, vout, value, confirmed: false }

  let cachedInfo = null;
  let cachedInfoAt = 0;

  async function getInfo() {
    if (cachedInfo && Date.now() - cachedInfoAt < 60_000) return cachedInfo;
    cachedInfo = await operator.getInfo();
    cachedInfoAt = Date.now();
    return cachedInfo;
  }

  async function withRfq(fn) {
    const transport = nostrRfqTransport({
      relays,
      solverPubkey,
      secretKey: randomBytes(32),
      timeoutMs: 25_000,
    });
    try {
      return await fn(transport);
    } finally {
      await transport.close?.().catch?.(() => {});
    }
  }

  function requireArkKey() {
    if (!hasArkKey) throw new Error("fronter_arkade_pool_not_configured");
    const privBytes = hexToBytes(cleanArkPriv);
    const singleKey = SingleKey.fromPrivateKey(privBytes);
    const xonly = schnorr.getPublicKey(privBytes);
    return { privBytes, singleKey, xonly };
  }

  async function getPoolArkScript() {
    const info = await getInfo();
    const arkNet = networkFromOperatorInfo(info);
    const { singleKey, xonly } = requireArkKey();
    const serverXonly = toXOnly(hexToBytes(info.signerPubkey), "arkade signer");
    const script = new DefaultVtxo.Script({
      pubKey: xonly,
      serverPubKey: serverXonly,
      csvTimelock: toArkadeTimelock(info.unilateralExitDelay),
    });
    return {
      info,
      arkNet,
      singleKey,
      xonly,
      serverXonly,
      script,
      address: script.address(arkNet.hrp, serverXonly).encode(),
      pkScript: script.pkScript,
      pkScriptHex: bytesToHex(script.pkScript),
    };
  }

  function computeServiceFee(amountSats) {
    if (!(serviceFeeBps > 0)) return 0;
    return Math.ceil((Number(amountSats) * serviceFeeBps) / 10_000);
  }

  async function listPoolL1Utxos() {
    if (!l1P2tr) return [];
    const chain = await esploraClient.listUtxos(l1P2tr.address);
    const merged = new Map();
    for (const u of chain) {
      const op = `${u.txid}:${u.vout}`;
      if (poolSpentOutpoints.has(op)) continue;
      merged.set(op, { ...u, outpoint: op });
      if (u.confirmed) poolLocalChange.delete(op);
    }
    for (const [op, ch] of poolLocalChange.entries()) {
      if (poolSpentOutpoints.has(op)) continue;
      if (!merged.has(op)) merged.set(op, { ...ch, outpoint: op });
    }
    return [...merged.values()];
  }

  return {
    configured: Boolean(hasArkKey && depositAddress),
    l1DepositAddress: depositAddress,
    l1DepositScriptHex: depositScriptHex,
    l1HotAddress: l1P2tr?.address || null,

    async getPoolStatus() {
      const out = {
        configured: Boolean(hasArkKey && depositAddress),
        network: normNet,
        l1DepositAddress: depositAddress,
        l1HotAddress: l1P2tr?.address || null,
        l1HotBalanceSats: null,
        arkadeAddress: null,
        arkadeBalanceSats: null,
      };
      if (l1P2tr) {
        try {
          const utxos = await listPoolL1Utxos();
          out.l1HotBalanceSats = utxos.reduce((s, u) => s + Number(u.value), 0);
        } catch {}
      }
      if (hasArkKey) {
        try {
          const pool = await getPoolArkScript();
          out.arkadeAddress = pool.address;
          const { vtxos = [] } = await indexer.getVtxos({ scripts: [pool.pkScriptHex], spendableOnly: true });
          out.arkadeBalanceSats = vtxos
            .filter((v) => !v.isSpent && !v.isSwept && !v.isUnrolled && Number(v.value) > 0)
            .reduce((s, v) => s + Number(v.value), 0);
        } catch {}
      }
      return out;
    },

    async quoteLightningSend({ bolt11 }) {
      const facts = decodeBolt11(bolt11);
      if (!facts.amountSats || facts.amountSats <= 0) {
        throw new Error("amountless_bolt11_not_supported");
      }
      const now = Math.floor(Date.now() / 1000);
      if (facts.expiresAt && now >= facts.expiresAt) {
        throw new Error("bolt11_invoice_expired");
      }
      const pool = await getPoolArkScript();
      const rfqId = randomBytes(32).toString("hex");
      const quote = await withRfq((t) =>
        t.requestQuote(
          lightningSendRequest({
            rfqId,
            invoice: facts.raw,
            refundAddress: pool.address,
            senderPubkey: pool.xonly,
          }),
        ),
      );
      const fundAmountSats = Number(quote.from_amount);
      const invoiceAmountSats = Number(quote.to_amount);
      if (invoiceAmountSats !== facts.amountSats) {
        throw new Error(`solver_quote_amount_mismatch:${invoiceAmountSats}:${facts.amountSats}`);
      }
      if (!Number.isSafeInteger(fundAmountSats) || fundAmountSats < invoiceAmountSats) {
        throw new Error("solver_quote_invalid_from_amount");
      }
      const lnFeeSats = fundAmountSats - invoiceAmountSats;
      const serviceFeeSats = computeServiceFee(invoiceAmountSats);
      return {
        rfqId,
        quote,
        paymentHash: facts.paymentHash,
        invoiceAmountSats,
        lnFeeSats,
        serviceFeeSats,
        totalCostSats: invoiceAmountSats + lnFeeSats + serviceFeeSats,
      };
    },

    async payLightningInvoice({ bolt11, quoteContext = null, pollTimeoutMs = 45_000, pollIntervalMs = 1_000 }) {
      return withPoolLock("arkade_send", async () => {
        const facts = decodeBolt11(bolt11);
        const pool = await getPoolArkScript();
        const ctx = quoteContext || (await this.quoteLightningSend({ bolt11 }));
        const emulatorPubkey = toXOnly(
          hexToBytes(resolveEmulatorPubkey(pool.arkNet, env.ARKADE_EMULATOR_PUBKEY?.trim() || undefined)),
          "emulator key",
        );
        const claimDelay = unilateralClaimDelay(Number(pool.info.unilateralExitDelay));
        const lockup = derivePoolLightningSendLockup({
          quote: ctx.quote,
          paymentHash: facts.paymentHash,
          senderPubkey: pool.xonly,
          refundPkScript: pool.pkScript,
          operatorPubkey: pool.serverXonly,
          emulatorPubkey,
          claimDelay,
          hrp: pool.arkNet.hrp,
          now: Math.floor(Date.now() / 1000),
        });

        const { vtxos = [] } = await indexer.getVtxos({ scripts: [pool.pkScriptHex], spendableOnly: true });
        const coins = vtxos
          .filter(
            (v) =>
              !v.isSpent &&
              !v.isSwept &&
              !v.isUnrolled &&
              !(Array.isArray(v.assets) && v.assets.length > 0) &&
              Number(v.value) > 0,
          )
          .map((v) => ({
            ...v,
            value: Number(v.value),
            tapLeafScript: pool.script.forfeit(),
            tapTree: pool.script.encode(),
          }));
        const fundAmount = Number(ctx.quote.from_amount);
        const selection = selectVirtualCoins(coins, fundAmount);
        const outputs = [{ script: ArkAddress.decode(lockup.address).pkScript, amount: BigInt(fundAmount) }];
        const minChange = BigInt(Math.max(Number(pool.info.dust || 330n), Number(pool.info.vtxoMinAmount || 330n)));
        if (selection.changeAmount >= minChange) {
          outputs.push({ script: pool.pkScript, amount: selection.changeAmount });
        }
        const serverUnrollScript = assertValidServerUnrollScript(
          pool.info.checkpointTapscript,
          pool.arkNet,
          toXOnly(hexToBytes(pool.info.forfeitPubkey), "forfeit key"),
        );

        let arkTxid;
        try {
          arkTxid = await signAndSubmitOffchainTx({
            provider: operator,
            inputs: selection.inputs,
            outputs,
            serverUnrollScript,
            identity: pool.singleKey,
            verifyServerSignatures: { serverPubkey: pool.serverXonly },
            oneShot: false,
          });
        } catch (err) {
          // Pre-submission failure: VHTLC was never funded -> safe to release held L1 outpoints!
          err.safeToReleaseL1 = true;
          throw err;
        }

        const deadline = Date.now() + pollTimeoutMs;
        while (Date.now() <= deadline) {
          const fate = await readLockupFate(indexer, {
            swapPkScript: lockup.swapPkScript,
            paymentHash: facts.paymentHash,
          });
          if (fate.preimage) {
            return {
              status: "done",
              rfqId: ctx.rfqId,
              paymentHash: facts.paymentHash,
              preimageHex: bytesToHex(fate.preimage),
              amountSats: ctx.invoiceAmountSats,
              lnFeeSats: ctx.lnFeeSats,
              serviceFeeSats: ctx.serviceFeeSats,
              arkTxid,
              swapPkScriptHex: lockup.swapPkScriptHex,
            };
          }
          if (fate.fate === "returned" || fate.fate === "exited") {
            const err = new Error(`fronter_arkade_lightning_send_${fate.fate}`);
            err.safeToReleaseL1 = true;
            err.arkTxid = arkTxid;
            err.swapPkScriptHex = lockup.swapPkScriptHex;
            throw err;
          }
          await new Promise((r) => setTimeout(r, pollIntervalMs));
        }

        // CRITICAL: VHTLC is still live on Arkade! NEVER release held L1 outpoints on timeout!
        const timeoutErr = new Error("fronter_arkade_lightning_send_timeout");
        timeoutErr.safeToReleaseL1 = false;
        timeoutErr.arkTxid = arkTxid;
        timeoutErr.swapPkScriptHex = lockup.swapPkScriptHex;
        throw timeoutErr;
      });
    },

    async checkArkadeLockupFate({ swapPkScriptHex, paymentHash }) {
      const fate = await readLockupFate(indexer, {
        swapPkScript: hexToBytes(swapPkScriptHex),
        paymentHash,
      });
      return {
        fate: fate.preimage ? "claimed" : fate.fate || "open",
        preimageHex: fate.preimage ? bytesToHex(fate.preimage) : null,
      };
    },

    async createLightningReceive({ amountSats, rfqId = randomBytes(32).toString("hex") }) {
      const pool = await getPoolArkScript();
      const secrets = deriveLightningReceiveSecrets(cleanArkPriv, rfqId);
      const emulatorPubkey = toXOnly(
        hexToBytes(resolveEmulatorPubkey(pool.arkNet, env.ARKADE_EMULATOR_PUBKEY?.trim() || undefined)),
        "emulator key",
      );
      const claimDelay = unilateralClaimDelay(Number(pool.info.unilateralExitDelay));
      const quote = await withRfq((t) =>
        t.requestQuote(
          lightningReceiveRequest({
            rfqId: secrets.rfqId,
            paymentHash: secrets.paymentHash,
            payoutAddress: pool.address,
            payoutPubkey: secrets.claimXonly,
            amount: Number(amountSats),
            amountSide: "from",
          }),
        ),
      );
      const normalizedQuote = {
        ...quote,
        from_amount: Number(quote.from_amount),
        to_amount: Number(quote.to_amount),
      };
      if (normalizedQuote.from_amount !== Number(amountSats) || !(normalizedQuote.to_amount > 0)) {
        throw new Error("invalid_lightning_receive_quote_amount");
      }
      const derived = deriveLightningReceive({
        quote: normalizedQuote,
        paymentHash: secrets.paymentHash,
        payoutPubkey: secrets.claimXonly,
        payoutAddress: pool.address,
        operatorPubkey: pool.serverXonly,
        emulatorPubkey,
        claimDelay,
        hrp: pool.arkNet.hrp,
      });
      const { payDeadline } = verifyReceiveInvoice({
        invoice: derived.invoice,
        decode: decodeBolt11,
        paymentHash: secrets.paymentHash,
        quote: normalizedQuote,
      });
      if (payDeadline <= Math.floor(Date.now() / 1000)) {
        throw new Error("lightning_receive_invoice_already_expired");
      }
      return {
        rfqId: secrets.rfqId,
        invoice: derived.invoice,
        paymentHash: secrets.paymentHash,
        payAmountSats: normalizedQuote.from_amount,
        expectedAmountSats: normalizedQuote.to_amount,
        feeSats: Math.max(0, normalizedQuote.from_amount - normalizedQuote.to_amount),
        expiresAt: payDeadline,
        lockupAddress: derived.address,
        swapPkScriptHex: bytesToHex(derived.swapPkScript),
        quoteJson: JSON.stringify(normalizedQuote),
      };
    },

    async claimLightningReceive({ receiveRecord }) {
      const pool = await getPoolArkScript();
      const secrets = deriveLightningReceiveSecrets(cleanArkPriv, receiveRecord.rfqId);
      const quote =
        typeof receiveRecord.quoteJson === "string"
          ? JSON.parse(receiveRecord.quoteJson)
          : receiveRecord.quote;
      const emulatorPubkey = toXOnly(
        hexToBytes(resolveEmulatorPubkey(pool.arkNet, env.ARKADE_EMULATOR_PUBKEY?.trim() || undefined)),
        "emulator key",
      );
      const claimDelay = unilateralClaimDelay(Number(pool.info.unilateralExitDelay));
      const derived = deriveLightningReceive({
        quote,
        paymentHash: secrets.paymentHash,
        payoutPubkey: secrets.claimXonly,
        payoutAddress: pool.address,
        operatorPubkey: pool.serverXonly,
        emulatorPubkey,
        claimDelay,
        hrp: pool.arkNet.hrp,
      });

      let totalClaimed = 0;
      let partiallyClaimed = false;
      for (let round = 0; round < 8; round += 1) {
        const { vtxos = [] } = await indexer.getVtxos({
          scripts: [bytesToHex(derived.swapPkScript)],
          spendableOnly: true,
        });
        const live = vtxos
          .filter((v) => !v.isSpent && !v.isUnrolled && Number(v.value) > 0)
          .map((v) => ({ ...v, value: Number(v.value), recoverable: Boolean(v.isSwept) }));
        if (live.length === 0) {
          if (totalClaimed > 0) break;
          const fate = await readLockupFate(indexer, {
            swapPkScript: derived.swapPkScript,
            paymentHash: secrets.paymentHash,
            receiver: true,
          });
          if (fate.fate === "claimed") {
            return {
              status: "claimed",
              alreadyClaimed: true,
              claimedSats: Number(receiveRecord.expectedAmountSats || quote.to_amount || 0),
            };
          }
          if (fate.fate === "returned" || fate.fate === "exited") {
            return { status: "expired" };
          }
          return { status: "pending" };
        }
        const res = await pushClaim(operator, {
          vtxos: live,
          contract: derived.script,
          receiver: secrets.claimSingleKey,
          preimage: secrets.preimage,
          expectedAmount: Number(receiveRecord.expectedAmountSats || quote.to_amount),
          destinationPkScript: pool.pkScript,
          network: pool.arkNet,
          partiallyClaimed,
        });
        totalClaimed += Number(res?.amount ?? live.reduce((s, v) => s + v.value, 0));
        if (!(Number(res?.left || 0) > 0)) break;
        partiallyClaimed = true;
      }
      return {
        status: "claimed",
        claimedSats: totalClaimed,
      };
    },

    /**
     * Serialized server L1 hot-wallet payout to user's `bc1p...`.
     * Charges user a predictable 1-in-2-out fee (never server consolidation overhead)
     * and tracks local spent/change UTXOs to prevent concurrent UTXO collisions.
     */
    async sendL1Payout({ toScriptHex, amountSats }) {
      return withPoolLock("l1_hot_wallet", async () => {
        if (!hasL1Key || !l1P2tr) throw new Error("fronter_l1_hot_wallet_not_configured");
        const utxos = await listPoolL1Utxos();
        const sorted = [...utxos].sort((a, b) => {
          if (Boolean(a.confirmed) !== Boolean(b.confirmed)) return a.confirmed ? -1 : 1;
          return b.value - a.value;
        });
        const feeRate = await esploraClient.estimateFeeRate(3);
        // User pays predictable 1-in-2-out P2TR fee; server absorbs extra consolidation weight if fragmented.
        const userFeeSats = BigInt(estimateP2trVbytes(1, 2) * feeRate);
        const targetNet = BigInt(amountSats) - userFeeSats;
        const destDust = BigInt(dustLimitForScriptHex(toScriptHex));
        if (targetNet < destDust) {
          throw new Error("fronter_l1_payout_below_dust_after_fee");
        }

        const selected = [];
        let totalIn = 0n;
        let actualFeeSats = userFeeSats;
        for (const u of sorted) {
          selected.push(u);
          totalIn += BigInt(u.value);
          actualFeeSats = BigInt(estimateP2trVbytes(selected.length, 2) * feeRate);
          if (totalIn >= targetNet + actualFeeSats) break;
        }
        if (totalIn < targetNet + actualFeeSats) {
          throw new Error("fronter_l1_pool_insufficient_liquidity");
        }

        const tx = new Transaction({ version: 2 });
        for (const u of selected) {
          tx.addInput({
            txid: u.txid,
            index: u.vout,
            sequence: 0xfffffffe,
            witnessUtxo: { script: l1P2tr.script, amount: BigInt(u.value) },
            tapInternalKey: l1P2tr.tapInternalKey,
          });
        }
        tx.addOutput({ script: hexToBytes(toScriptHex), amount: targetNet });
        const change = totalIn - targetNet - actualFeeSats;
        let changeVout = null;
        if (change >= BigInt(P2TR_DUST_SATS)) {
          changeVout = 1;
          tx.addOutput({ script: l1P2tr.script, amount: change });
        } else {
          actualFeeSats = totalIn - targetNet;
        }

        const priv = hexToBytes(cleanL1Priv);
        try {
          tx.sign(priv);
          tx.finalize();
        } finally {
          priv.fill(0);
        }

        const rawHex = bytesToHex(tx.extract());
        const txid = (await esploraClient.broadcastTx(rawHex)) || tx.id.toLowerCase();

        for (const u of selected) {
          poolSpentOutpoints.add(`${u.txid}:${u.vout}`);
          poolLocalChange.delete(`${u.txid}:${u.vout}`);
        }
        if (changeVout !== null) {
          poolLocalChange.set(`${txid}:${changeVout}`, {
            txid,
            vout: changeVout,
            value: Number(change),
            confirmed: false,
          });
        }
        return {
          txid,
          vout: 0,
          payoutSats: Number(targetNet),
          feeSats: Number(userFeeSats),
          actualMinerFeeSats: Number(actualFeeSats),
          rawHex,
        };
      });
    },
  };
}

function selectL1Utxos(utxos, targetSats, feeRateSatVb) {
  const ordered = [...utxos].sort((a, b) => {
    if (Boolean(a.confirmed) !== Boolean(b.confirmed)) return a.confirmed ? -1 : 1;
    return b.value - a.value;
  });
  const selected = [];
  let totalIn = 0n;
  for (const u of ordered) {
    selected.push(u);
    totalIn += BigInt(u.value);
    const fee2 = BigInt(estimateP2trVbytes(selected.length, 2) * feeRateSatVb);
    if (totalIn >= BigInt(targetSats) + fee2) {
      const change = totalIn - BigInt(targetSats) - fee2;
      if (change >= BigInt(P2TR_DUST_SATS)) {
        return { selected, totalIn, feeSats: fee2, changeSats: change };
      }
      const fee1 = BigInt(estimateP2trVbytes(selected.length, 1) * feeRateSatVb);
      if (totalIn >= BigInt(targetSats) + fee1) {
        return { selected, totalIn, feeSats: totalIn - BigInt(targetSats), changeSats: 0n };
      }
    }
    const fee1 = BigInt(estimateP2trVbytes(selected.length, 1) * feeRateSatVb);
    if (totalIn >= BigInt(targetSats) + fee1) {
      return { selected, totalIn, feeSats: totalIn - BigInt(targetSats), changeSats: 0n };
    }
  }
  return null;
}

/**
 * Drop-in replacement for `createAgentArkadeRuntime` implementing Muun-model
 * pure-L1 2-of-2 MuSig2+CSV user wallets backed by a single server Arkade 0-conf fronter.
 */
export function createAgentL1FronterRuntime({
  env = process.env,
  cosignerClient,
  ledgerPath = ":memory:",
  ledger = null,
  esploraClient = null,
  serverPool = null,
  fetchImpl = fetch,
  network = env.FRONTER_BITCOIN_NETWORK || "bitcoin",
  nuriServerCsv = null,
  csvSafetyBlocks = DEFAULT_CSV_SAFETY_BLOCKS,
  csvSafetySeconds = DEFAULT_CSV_SAFETY_SECONDS,
  lendMaxSats = Number(env.FRONTER_LEND_MAX_SATS ?? DEFAULT_LEND_MAX_SATS),
  maxDebtSats = Number(env.FRONTER_MAX_DEBT_SATS ?? DEFAULT_MAX_DEBT_SATS),
  l1SettleFloorSats = Number(env.FRONTER_L1_SETTLE_FLOOR_SATS ?? DEFAULT_L1_SETTLE_FLOOR_SATS),
  sendFeeBps = Number(env.FRONTER_SERVICE_FEE_BPS ?? 25),
  receiveFeeBps = Number(env.FRONTER_RECEIVE_FEE_BPS ?? 0),
} = {}) {
  const defaultNet = normalizeBitcoinNetwork(network);
  const esplora =
    esploraClient ||
    createEsploraL1Client({
      baseUrl: env.FRONTER_ESPLORA_URL || DEFAULT_ESPLORA_URL,
      fetchImpl,
    });
  const pool =
    serverPool ||
    createServerArkadeLiquidityPool({
      env,
      fetchImpl,
      esplora,
      network: defaultNet,
    });
  const store = ledger || openL1FronterLedger(ledgerPath);
  const ownsStore = !ledger;
  const withWalletLock = createKeyedMutex();

  let syncedCosignerParams = null;
  let syncedCosignerAt = 0;

  // Live-sync `nuri_server_csv` and `l1_network` from `nuri-agent-cosigner /healthz`
  // so derived `bc1p...` addresses ALWAYS match live cosigner configuration!
  async function resolveL1Config() {
    if (nuriServerCsv) {
      return { csv: nuriServerCsv, net: defaultNet };
    }
    if (syncedCosignerParams && Date.now() - syncedCosignerAt < COSIGNER_HEALTH_TTL_MS) {
      return syncedCosignerParams;
    }
    if (cosignerClient && typeof cosignerClient.healthz === "function") {
      try {
        const h = await cosignerClient.healthz();
        if (h?.ok && h.nuri_server_csv?.type && h.nuri_server_csv?.value) {
          syncedCosignerParams = {
            csv: { type: String(h.nuri_server_csv.type), value: Number(h.nuri_server_csv.value) },
            net: normalizeBitcoinNetwork(h.l1_network || defaultNet),
          };
          syncedCosignerAt = Date.now();
          return syncedCosignerParams;
        }
      } catch {}
    }
    return { csv: DEFAULT_L1_CSV, net: defaultNet };
  }

  async function deriveWalletScript(walletRecord) {
    const { csv, net } = await resolveL1Config();
    return deriveAgentL1Wallet({
      aggregatedBtcXonlyHex: walletRecord.aggregatedBtcXonlyHex,
      agentBtcPub33Hex: walletRecord.agentBtcPub33Hex,
      nuriServerCsv: csv,
      network: net,
    });
  }

  async function isNearCsvExpiry(u, csv, tipHeight) {
    if (!u.confirmed) return false;
    if (csv.type === "blocks") {
      if (!Number.isSafeInteger(tipHeight) || !Number.isSafeInteger(u.blockHeight)) return false;
      return tipHeight - u.blockHeight + 1 >= csv.value - csvSafetyBlocks;
    }
    if (Number.isFinite(u.blockTime) && u.blockTime > 0) {
      const nowSec = Math.floor(Date.now() / 1000);
      return nowSec - (u.blockTime - 7200) >= csv.value - csvSafetySeconds;
    }
    return false;
  }

  async function listWalletUtxos(walletRecord, { excludeNearCsv = false } = {}) {
    const l1 = await deriveWalletScript(walletRecord);
    const chainUtxos = await esplora.listUtxos(l1.address);
    const trustedLocal = store.listUnspentTrustedUtxos(walletRecord.walletId);
    const spentLocally = store.getSpentOutpointsSet(walletRecord.walletId);
    const reservedLocally = store.getActiveReservedOutpointsSet(walletRecord.walletId);

    const trustedMap = new Map(trustedLocal.map((u) => [u.outpoint, u]));
    const merged = new Map();
    for (const u of chainUtxos) {
      const outpoint = `${u.txid}:${u.vout}`;
      if (spentLocally.has(outpoint) || reservedLocally.has(outpoint)) continue;
      const tMeta = trustedMap.get(outpoint);
      merged.set(outpoint, {
        ...u,
        outpoint,
        trusted: u.confirmed || Boolean(tMeta),
        ancestorDepth: u.confirmed ? 0 : tMeta?.ancestorDepth ?? 1,
      });
    }

    // Merge recent trusted 0-conf UTXOs not yet visible on Esplora; prune stale/externally-spent ghosts!
    const now = Date.now();
    for (const tu of trustedLocal) {
      if (spentLocally.has(tu.outpoint) || reservedLocally.has(tu.outpoint)) continue;
      if (merged.has(tu.outpoint)) continue;
      if (now - tu.createdAtMs > TRUSTED_GRACE_MS && typeof esplora.getOutspend === "function") {
        try {
          const sp = await esplora.getOutspend(tu.txid, tu.vout);
          if (sp?.spent) {
            store.markOutpointsSpentLocally(walletRecord.walletId, [tu.outpoint], sp.txid || "external_spend");
            continue;
          }
          const tx = typeof esplora.getTx === "function" ? await esplora.getTx(tu.txid) : null;
          if (!tx) {
            // Evicted or never hit mempool past grace window: don't resurrect phantom balance.
            continue;
          }
        } catch {}
      }
      merged.set(tu.outpoint, tu);
    }

    let tipHeight = null;
    if (excludeNearCsv && l1.nuriServerCsv.type === "blocks" && typeof esplora.getTipHeight === "function") {
      try {
        tipHeight = await esplora.getTipHeight();
      } catch {}
    }

    const all = [...merged.values()];
    const spendable = [];
    const nearCsv = [];
    const externalUnconfirmed = [];
    for (const u of all) {
      if (!u.confirmed && !u.trusted) {
        externalUnconfirmed.push(u);
        continue;
      }
      if (!u.confirmed && (u.ancestorDepth || 1) >= MAX_TRUSTED_ANCESTOR_DEPTH) {
        // Defer further 0-conf chaining once close to Bitcoin Core's 25-ancestor limit.
        externalUnconfirmed.push(u);
        continue;
      }
      if (excludeNearCsv && (await isNearCsvExpiry(u, l1.nuriServerCsv, tipHeight))) {
        nearCsv.push(u);
        continue;
      }
      spendable.push(u);
    }
    return { l1, spendable, nearCsv, externalUnconfirmed };
  }

  /**
   * Crash-recovery reconciler: completes any swap whose LN preimage was already obtained
   * (`status = 'broadcast_pending'`) so server L1 replenishment is never lost on crash or Esplora 503.
   */
  async function reconcilePendingBroadcasts(walletRecord) {
    const pending = store.listSwapsByStatus(walletRecord.walletId, ["broadcast_pending"]);
    if (pending.length === 0) return;
    const l1 = await deriveWalletScript(walletRecord);
    for (const row of pending) {
      if (!row.l1_raw_hex || !row.l1_txid) continue;
      let finalTxid = row.l1_txid;
      try {
        finalTxid = (await esplora.broadcastTx(row.l1_raw_hex)) || row.l1_txid;
      } catch (err) {
        if (!isAlreadyBroadcastError(err)) continue; // keep broadcast_pending for next retry
      }
      const spentOutpoints = row.spent_outpoints_json ? JSON.parse(row.spent_outpoints_json) : [];
      const changeOutpoints = row.change_outpoints_json ? JSON.parse(row.change_outpoints_json) : [];
      if (cosignerClient && typeof cosignerClient.markL1Broadcast === "function") {
        await cosignerClient
          .markL1Broadcast({
            cred_id_b64u: walletRecord.credIdB64u,
            index: walletRecord.slotIndex,
            op_id: row.op_id,
            spending_txid: row.l1_txid,
            change_outpoints: changeOutpoints,
          })
          .catch(() => {});
      }
      store.runTx(() => {
        store.markOutpointsSpentLocally(walletRecord.walletId, spentOutpoints, finalTxid);
        for (const ch of changeOutpoints) {
          const [cTxid, cVoutStr] = String(ch.outpoint).split(":");
          store.addTrustedUtxo({
            walletId: walletRecord.walletId,
            txid: cTxid,
            vout: Number(cVoutStr),
            amountSats: Number(ch.amount_sats),
            scriptPubKeyHex: l1.scriptPubKeyHex,
            sourceKind: "cosigned_change",
            ancestorDepth: Number(ch.ancestor_depth || 1),
          });
        }
        const cur = store.getLedger(walletRecord.walletId);
        const collected = Math.max(0, -Number(row.debt_delta_sats || 0));
        store.setLedger(walletRecord.walletId, {
          debtSats: Math.max(0, cur.debtSats - collected),
          pendingReceiveSats: Math.max(
            0,
            cur.pendingReceiveSats - Number(row.credit_used_sats || 0) + Number(row.output_padding_sats || 0),
          ),
        });
        store.upsertSwap({
          opId: row.op_id,
          walletId: row.wallet_id,
          direction: row.direction,
          mode: row.mode,
          status: "done",
          paymentHash: row.payment_hash,
          preimageHex: row.preimage_hex,
          bolt11: row.bolt11,
          amountSats: row.amount_sats,
          feeSats: row.fee_sats,
          serviceFeeSats: row.service_fee_sats,
          debtDeltaSats: row.debt_delta_sats,
          l1Txid: finalTxid,
          l1RawHex: row.l1_raw_hex,
          creditUsedSats: row.credit_used_sats,
          outputPaddingSats: row.output_padding_sats,
        });
      });
    }
  }

  async function readBalance(walletRecord) {
    await withWalletLock(walletRecord.walletId, () => reconcilePendingBroadcasts(walletRecord)).catch(() => {});
    const { l1, spendable, externalUnconfirmed } = await listWalletUtxos(walletRecord);
    const ledgerState = store.getLedger(walletRecord.walletId);

    let confirmedSats = 0n;
    let trustedUnconfSats = 0n;
    for (const u of spendable) {
      if (u.confirmed) confirmedSats += BigInt(u.value);
      else trustedUnconfSats += BigInt(u.value);
    }
    const extUnconfSats = externalUnconfirmed.reduce((sum, u) => sum + BigInt(u.value), 0n);
    const rawSpendable =
      confirmedSats + trustedUnconfSats - BigInt(ledgerState.debtSats) + BigInt(ledgerState.pendingReceiveSats);
    const sats = rawSpendable > 0n ? rawSpendable : 0n;

    return {
      address: l1.address,
      btcAddress: l1.address,
      pkScriptHex: l1.scriptPubKeyHex,
      sats,
      onchainConfirmedSats: confirmedSats,
      onchainUnconfirmedTrustedSats: trustedUnconfSats,
      onchainUnconfirmedExternalSats: extUnconfSats,
      debtSats: ledgerState.debtSats,
      pendingReceiveSats: ledgerState.pendingReceiveSats,
      utxoCount: spendable.length,
      custodyMode: "l1_0conf",
      nuriServerCsv: l1.nuriServerCsv,
    };
  }

  async function estimateSendOverheadSats(walletRecord, amountSats) {
    const ledgerState = store.getLedger(walletRecord.walletId);
    const lnPctFee = Math.max(100, Math.ceil(Number(amountSats) * 0.03));
    if (Number(amountSats) + lnPctFee <= lendMaxSats && ledgerState.debtSats + Number(amountSats) + lnPctFee <= maxDebtSats) {
      return lnPctFee;
    }
    let feeRate = 3;
    try {
      feeRate = await esplora.estimateFeeRate(3);
    } catch {}
    return lnPctFee + estimateP2trVbytes(1, 2) * feeRate;
  }

  async function buildAndCoSignL1Tx({
    walletRecord,
    agentBtcPrivHex,
    l1,
    spendableUtxos,
    recipientScriptHex,
    recipientAmountSats,
    opId,
    maxTotalSpendSats = null,
    extraPriorCostSats = 0,
  }) {
    if (!cosignerClient) throw new Error("cosigner_client_required");
    const destDust = dustLimitForScriptHex(recipientScriptHex);
    if (Number(recipientAmountSats) < destDust) {
      throw new Error(`amount_below_dust:${destDust}`);
    }
    const feeRate = await esplora.estimateFeeRate(3);
    const pick = selectL1Utxos(spendableUtxos, recipientAmountSats, feeRate);
    if (!pick) {
      const avail = spendableUtxos.reduce((s, u) => s + BigInt(u.value), 0n);
      throw new Error(`insufficient_l1_balance:need_${recipientAmountSats}_have_${avail.toString()}`);
    }
    // Enforce maxSats INCLUDING L1 miner fee BEFORE cosigning or paying LN!
    if (maxTotalSpendSats !== null && maxTotalSpendSats !== undefined) {
      const totalWithL1Fee = BigInt(extraPriorCostSats) + BigInt(pick.feeSats);
      if (totalWithL1Fee > BigInt(maxTotalSpendSats)) {
        const err = new Error("total_with_l1_fee_exceeds_max_sats");
        err.code = "over_max_amount";
        err.invoiceSats = Number(totalWithL1Fee);
        err.maxSats = Number(maxTotalSpendSats);
        throw err;
      }
    }

    const tx = new Transaction({ version: 2 });
    const prevScripts = [];
    const prevAmounts = [];
    let maxParentDepth = 0;
    for (const u of pick.selected) {
      tx.addInput({
        txid: u.txid,
        index: u.vout,
        sequence: 0xfffffffe,
        witnessUtxo: { script: l1.pkScript, amount: BigInt(u.value) },
        tapInternalKey: l1.aggregatedXonly,
        tapMerkleRoot: l1.tapMerkleRoot,
      });
      prevScripts.push(l1.pkScript);
      prevAmounts.push(BigInt(u.value));
      maxParentDepth = Math.max(maxParentDepth, u.confirmed ? 0 : Number(u.ancestorDepth || 1));
    }
    tx.addOutput({ script: hexToBytes(recipientScriptHex), amount: BigInt(recipientAmountSats) });
    if (pick.changeSats >= BigInt(P2TR_DUST_SATS)) {
      tx.addOutput({ script: l1.pkScript, amount: pick.changeSats });
    }

    const clientPriv = hexToBytes(agentBtcPrivHex);
    const clientPub33 = hexToBytes(walletRecord.agentBtcPub33Hex);
    const clientNonces = [];
    try {
      for (let i = 0; i < tx.inputsLength; i += 1) {
        const msg32 = tx.preimageWitnessV1(i, prevScripts, SigHash.DEFAULT, prevAmounts);
        const nonce = musig2.nonceGen(clientPub33, clientPriv, l1.aggregatedXonly, msg32, randomBytes(32));
        clientNonces.push({ inputIndex: i, msg32, nonce });
      }

      const cosigned = await cosignerClient.signL1Psbt({
        cred_id_b64u: walletRecord.credIdB64u,
        index: walletRecord.slotIndex,
        psbt_b64: Buffer.from(tx.toPSBT()).toString("base64"),
        nonces: clientNonces.map((n) => ({
          input_index: n.inputIndex,
          client_pub_nonce: bytesToHex(n.nonce.public),
        })),
        expected_recipient: {
          script_hex: recipientScriptHex,
          min_amount_sats: Number(recipientAmountSats),
        },
        op_id: opId,
      });

      const sigs = cosigned?.signatures || [];
      if (sigs.length !== clientNonces.length) {
        throw new Error(`l1_cosigner_sig_count_mismatch:${sigs.length}:${clientNonces.length}`);
      }

      for (let i = 0; i < clientNonces.length; i += 1) {
        const item = clientNonces[i];
        const srv = sigs[i];
        const serverPub = hexToBytes(srv.server_pubkey);
        const serverNonce = hexToBytes(srv.server_pub_nonce66);
        const serverPartial = hexToBytes(srv.server_partial32);
        const tweak32 = hexToBytes(srv.tweak32);

        const sortedKeys = musig2.sortKeys([serverPub, clientPub33]);
        const orderedNonces = sortedKeys.map((pk) =>
          Buffer.compare(Buffer.from(pk), Buffer.from(serverPub)) === 0 ? serverNonce : item.nonce.public,
        );
        const aggNonce = musig2.nonceAggregate(orderedNonces);
        const session = new musig2.Session(aggNonce, sortedKeys, item.msg32, [tweak32], [true]);
        const serverIdx = sortedKeys.findIndex(
          (pk) => Buffer.compare(Buffer.from(pk), Buffer.from(serverPub)) === 0,
        );
        if (!session.partialSigVerify(serverPartial, orderedNonces, serverIdx)) {
          throw new Error(`l1_cosigner_partial_invalid:${i}`);
        }
        const clientPartial = session.sign(item.nonce.secret, clientPriv);
        const orderedPartials = sortedKeys.map((pk) =>
          Buffer.compare(Buffer.from(pk), Buffer.from(serverPub)) === 0 ? serverPartial : clientPartial,
        );
        const sig64 = session.partialSigAgg(orderedPartials);
        if (!schnorr.verify(sig64, item.msg32, l1.tweakedXonly)) {
          throw new Error(`l1_musig2_sig_invalid:${i}`);
        }
        tx.updateInput(item.inputIndex, { tapKeySig: sig64 });
      }
      tx.finalize();

      const changeOutpoints = (cosigned.change_outpoints || []).map((c) => ({
        ...c,
        ancestor_depth: maxParentDepth + 1,
      }));
      return {
        txid: tx.id.toLowerCase(),
        rawHex: bytesToHex(tx.extract()),
        feeSats: Number(pick.feeSats),
        changeSats: Number(pick.changeSats),
        spentOutpoints: pick.selected.map((u) => u.outpoint),
        changeOutpoints,
        lockAttestation: cosigned.lock_attestation || null,
      };
    } finally {
      clientPriv.fill(0);
      for (const item of clientNonces) {
        if (item.nonce?.secret instanceof Uint8Array) item.nonce.secret.fill(0);
      }
    }
  }

  /**
   * Instant 0-conf L1 -> Lightning via server-side Arkade pool.
   * Serialized per wallet; Muun `LEND` (policy-authorized) for tiny sends;
   * cosigner-locked hold-broadcast (+ `COLLECT`) + crash-safe reconciler for larger sends.
   */
  async function payBolt11Invoice({
    walletRecord,
    agentBtcPrivHex,
    bolt11,
    maxSats,
    opId = `l1-ln-${randomBytes(8).toString("hex")}`,
  }) {
    return withWalletLock(walletRecord.walletId, async () => {
      await reconcilePendingBroadcasts(walletRecord).catch(() => {});

      const cleanInvoice = String(bolt11 || "").trim().replace(/^lightning:/i, "");
      const facts = decodeBolt11(cleanInvoice);
      if (!facts.amountSats || facts.amountSats <= 0) {
        throw new Error("amountless_bolt11_not_supported");
      }
      const nowSec = Math.floor(Date.now() / 1000);
      if (facts.expiresAt && nowSec >= facts.expiresAt) {
        throw new Error("bolt11_invoice_expired");
      }
      if (maxSats !== undefined && maxSats !== null && BigInt(facts.amountSats) > BigInt(maxSats)) {
        const err = new Error("invoice_exceeds_max_sats");
        err.code = "over_max_amount";
        err.invoiceSats = facts.amountSats;
        err.maxSats = Number(maxSats);
        throw err;
      }

      const existing = store.getSwap(opId);
      if (existing?.status === "done") {
        return {
          status: "done",
          replay: true,
          paymentHash: existing.payment_hash,
          preimageHex: existing.preimage_hex,
          amountSats: Number(existing.amount_sats),
          feeSats: Number(existing.fee_sats),
          totalSats: Number(existing.amount_sats) + Number(existing.fee_sats),
          arkTxid: existing.l1_txid || `${existing.mode}:${existing.op_id}`,
          l1Txid: existing.l1_txid,
          settlementMode: existing.mode,
        };
      }
      if (existing?.status === "broadcast_pending") {
        // Preimage is already verified; broadcast will retry on next reconcile.
        return {
          status: "done",
          replay: true,
          paymentHash: existing.payment_hash,
          preimageHex: existing.preimage_hex,
          amountSats: Number(existing.amount_sats),
          feeSats: Number(existing.fee_sats),
          totalSats: Number(existing.amount_sats) + Number(existing.fee_sats),
          arkTxid: existing.l1_txid,
          l1Txid: existing.l1_txid,
          settlementMode: existing.mode,
        };
      }
      if (existing?.status === "paying_ln") {
        throw new Error(`l1_swap_in_flight:${opId}`);
      }

      const quoteCtx = await pool.quoteLightningSend({ bolt11: cleanInvoice });
      if (maxSats !== undefined && maxSats !== null && BigInt(quoteCtx.totalCostSats) > BigInt(maxSats)) {
        const err = new Error("total_with_fee_exceeds_max_sats");
        err.code = "over_max_amount";
        err.invoiceSats = quoteCtx.totalCostSats;
        err.maxSats = Number(maxSats);
        throw err;
      }

      const { l1, spendable } = await listWalletUtxos(walletRecord, { excludeNearCsv: true });
      const ledgerState = store.getLedger(walletRecord.walletId);
      const onchainSpendableSats = spendable.reduce((sum, u) => sum + u.value, 0);

      const creditUsed = Math.min(ledgerState.pendingReceiveSats, quoteCtx.totalCostSats);
      const neededAfterCredit = quoteCtx.totalCostSats - creditUsed;

      // Path 1: Fully covered by pending micro-receive credit (0 L1 tx, cosigner policy-checked!)
      if (neededAfterCredit === 0) {
        if (cosignerClient && typeof cosignerClient.authorizeL1Spend === "function") {
          await cosignerClient.authorizeL1Spend({
            cred_id_b64u: walletRecord.credIdB64u,
            index: walletRecord.slotIndex,
            op_id: opId,
            amount_sats: quoteCtx.totalCostSats,
            kind: "l1_fronter_micro_credit",
          });
        }
        // Reserve debit atomically BEFORE paying LN!
        store.runTx(() => {
          const cur = store.getLedger(walletRecord.walletId);
          store.setLedger(walletRecord.walletId, {
            debtSats: cur.debtSats,
            pendingReceiveSats: cur.pendingReceiveSats - creditUsed,
          });
          store.upsertSwap({
            opId,
            walletId: walletRecord.walletId,
            direction: "out",
            mode: "micro_credit",
            status: "paying_ln",
            paymentHash: facts.paymentHash,
            bolt11: cleanInvoice,
            amountSats: facts.amountSats,
            feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats,
            serviceFeeSats: Number(quoteCtx.serviceFeeSats || 0),
            creditUsedSats: creditUsed,
          });
        });
        try {
          const paid = await pool.payLightningInvoice({ bolt11: cleanInvoice, quoteContext: quoteCtx });
          if (!paid?.preimageHex || bytesToHex(sha256(hexToBytes(paid.preimageHex))) !== facts.paymentHash) {
            throw new Error("invalid_lightning_preimage");
          }
          store.upsertSwap({
            opId,
            walletId: walletRecord.walletId,
            direction: "out",
            mode: "micro_credit",
            status: "done",
            paymentHash: facts.paymentHash,
            preimageHex: paid.preimageHex,
            bolt11: cleanInvoice,
            amountSats: facts.amountSats,
            feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats,
            serviceFeeSats: Number(quoteCtx.serviceFeeSats || 0),
            creditUsedSats: creditUsed,
          });
          return {
            status: "done",
            paymentHash: facts.paymentHash,
            preimageHex: paid.preimageHex,
            amountSats: facts.amountSats,
            feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats,
            totalSats: quoteCtx.totalCostSats,
            arkTxid: `credit:${opId}`,
            l1Txid: null,
            settlementMode: "micro_credit",
          };
        } catch (err) {
          // Only refund credit & release spend cap if VHTLC was NOT left live!
          if (err?.safeToReleaseL1 !== false) {
            store.runTx(() => {
              const cur = store.getLedger(walletRecord.walletId);
              store.setLedger(walletRecord.walletId, {
                debtSats: cur.debtSats,
                pendingReceiveSats: cur.pendingReceiveSats + creditUsed,
              });
              store.upsertSwap({
                opId,
                walletId: walletRecord.walletId,
                direction: "out",
                mode: "micro_credit",
                status: "failed",
                paymentHash: facts.paymentHash,
                bolt11: cleanInvoice,
                amountSats: facts.amountSats,
                feeSats: 0,
                error: err?.message || String(err),
              });
            });
            if (cosignerClient && typeof cosignerClient.releaseL1Spend === "function") {
              await cosignerClient
                .releaseL1Spend({ cred_id_b64u: walletRecord.credIdB64u, index: walletRecord.slotIndex, op_id: opId })
                .catch(() => {});
            }
          }
          throw err;
        }
      }

      // Path 2: Muun `LEND` — tiny outgoing LN backed by CSV-safe L1 UTXOs (ZERO L1 tx, cosigner policy-checked!)
      const projectedDebt = ledgerState.debtSats + neededAfterCredit;
      const minL1CoverBuffer = 500;
      const canLend =
        neededAfterCredit <= lendMaxSats &&
        projectedDebt <= maxDebtSats &&
        onchainSpendableSats >= projectedDebt + minL1CoverBuffer;

      if (canLend) {
        let policyOk = true;
        if (cosignerClient && typeof cosignerClient.authorizeL1Spend === "function") {
          const auth = await cosignerClient.authorizeL1Spend({
            cred_id_b64u: walletRecord.credIdB64u,
            index: walletRecord.slotIndex,
            op_id: opId,
            amount_sats: quoteCtx.totalCostSats,
            kind: "l1_fronter_lend",
          });
          // Ensure future COLLECT will fit within grant's max_per_tx_sats
          const grantMaxPerTx = Number(auth?.policy?.max_per_tx_sats ?? maxDebtSats);
          if (projectedDebt > grantMaxPerTx) {
            policyOk = false;
            await cosignerClient
              .releaseL1Spend({ cred_id_b64u: walletRecord.credIdB64u, index: walletRecord.slotIndex, op_id: opId })
              .catch(() => {});
          }
        }
        if (policyOk) {
          // Reserve debt & credit atomically BEFORE paying LN!
          store.runTx(() => {
            const cur = store.getLedger(walletRecord.walletId);
            store.setLedger(walletRecord.walletId, {
              debtSats: cur.debtSats + neededAfterCredit,
              pendingReceiveSats: cur.pendingReceiveSats - creditUsed,
            });
            store.upsertSwap({
              opId,
              walletId: walletRecord.walletId,
              direction: "out",
              mode: "lend",
              status: "paying_ln",
              paymentHash: facts.paymentHash,
              bolt11: cleanInvoice,
              amountSats: facts.amountSats,
              feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats,
              serviceFeeSats: Number(quoteCtx.serviceFeeSats || 0),
              debtDeltaSats: neededAfterCredit,
              creditUsedSats: creditUsed,
            });
          });
          try {
            const paid = await pool.payLightningInvoice({ bolt11: cleanInvoice, quoteContext: quoteCtx });
            if (!paid?.preimageHex || bytesToHex(sha256(hexToBytes(paid.preimageHex))) !== facts.paymentHash) {
              throw new Error("invalid_lightning_preimage");
            }
            store.upsertSwap({
              opId,
              walletId: walletRecord.walletId,
              direction: "out",
              mode: "lend",
              status: "done",
              paymentHash: facts.paymentHash,
              preimageHex: paid.preimageHex,
              bolt11: cleanInvoice,
              amountSats: facts.amountSats,
              feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats,
              serviceFeeSats: Number(quoteCtx.serviceFeeSats || 0),
              debtDeltaSats: neededAfterCredit,
              creditUsedSats: creditUsed,
              arkTxid: paid.arkTxid || null,
              swapPkScriptHex: paid.swapPkScriptHex || null,
            });
            return {
              status: "done",
              paymentHash: facts.paymentHash,
              preimageHex: paid.preimageHex,
              amountSats: facts.amountSats,
              feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats,
              totalSats: quoteCtx.totalCostSats,
              arkTxid: `lend:${opId}`,
              l1Txid: null,
              settlementMode: "lend",
              debtSatsAfter: projectedDebt,
            };
          } catch (err) {
            if (err?.safeToReleaseL1 !== false) {
              store.runTx(() => {
                const cur = store.getLedger(walletRecord.walletId);
                store.setLedger(walletRecord.walletId, {
                  debtSats: Math.max(0, cur.debtSats - neededAfterCredit),
                  pendingReceiveSats: cur.pendingReceiveSats + creditUsed,
                });
                store.upsertSwap({
                  opId,
                  walletId: walletRecord.walletId,
                  direction: "out",
                  mode: "lend",
                  status: "failed",
                  paymentHash: facts.paymentHash,
                  bolt11: cleanInvoice,
                  amountSats: facts.amountSats,
                  feeSats: 0,
                  error: err?.message || String(err),
                });
              });
              if (cosignerClient && typeof cosignerClient.releaseL1Spend === "function") {
                await cosignerClient
                  .releaseL1Spend({ cred_id_b64u: walletRecord.credIdB64u, index: walletRecord.slotIndex, op_id: opId })
                  .catch(() => {});
              }
            }
            throw err;
          }
        }
      }

      // Path 3: Cosigner-locked 0-conf L1 fronting (+ Muun `COLLECT`) with hold-broadcast + crash reconciler!
      if (!pool.l1DepositScriptHex) {
        throw new Error("fronter_l1_deposit_address_not_configured");
      }
      const rawL1Target = neededAfterCredit + ledgerState.debtSats;
      const outputPadding = rawL1Target < P2TR_DUST_SATS ? P2TR_DUST_SATS - rawL1Target : 0;
      const l1TargetSats = rawL1Target + outputPadding;
      const mode = ledgerState.debtSats > 0 ? "l1_0conf_collect" : "l1_0conf";

      const signedL1 = await buildAndCoSignL1Tx({
        walletRecord,
        agentBtcPrivHex,
        l1,
        spendableUtxos: spendable,
        recipientScriptHex: pool.l1DepositScriptHex,
        recipientAmountSats: l1TargetSats,
        opId,
        maxTotalSpendSats: maxSats,
        extraPriorCostSats: quoteCtx.totalCostSats,
      });

      const totalFeeSats = quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats + signedL1.feeSats;
      store.upsertSwap({
        opId,
        walletId: walletRecord.walletId,
        direction: "out",
        mode,
        status: "paying_ln",
        paymentHash: facts.paymentHash,
        bolt11: cleanInvoice,
        amountSats: facts.amountSats,
        feeSats: totalFeeSats,
        serviceFeeSats: Number(quoteCtx.serviceFeeSats || 0),
        debtDeltaSats: -ledgerState.debtSats,
        l1Txid: signedL1.txid,
        l1RawHex: signedL1.rawHex,
        spentOutpoints: signedL1.spentOutpoints,
        changeOutpoints: signedL1.changeOutpoints,
        creditUsedSats: creditUsed,
        outputPaddingSats: outputPadding,
      });

      let paid;
      try {
        paid = await pool.payLightningInvoice({ bolt11: cleanInvoice, quoteContext: quoteCtx });
        if (!paid?.preimageHex || bytesToHex(sha256(hexToBytes(paid.preimageHex))) !== facts.paymentHash) {
          throw new Error("invalid_lightning_preimage");
        }
      } catch (err) {
        // CRITICAL: NEVER release cosigner outpoints on timeout/unknown error while Arkade VHTLC is live!
        // ONLY release when LN failed BEFORE VHTLC funding OR VHTLC was confirmed returned/refunded!
        if (err?.safeToReleaseL1 !== false) {
          await cosignerClient
            .releaseL1Outpoints({
              cred_id_b64u: walletRecord.credIdB64u,
              index: walletRecord.slotIndex,
              op_id: opId,
              spending_txid: signedL1.txid,
            })
            .catch(() => {});
          store.upsertSwap({
            opId,
            walletId: walletRecord.walletId,
            direction: "out",
            mode,
            status: "failed",
            paymentHash: facts.paymentHash,
            bolt11: cleanInvoice,
            amountSats: facts.amountSats,
            feeSats: 0,
            l1Txid: signedL1.txid,
            error: err?.message || String(err),
          });
        } else {
          store.upsertSwap({
            opId,
            walletId: walletRecord.walletId,
            direction: "out",
            mode,
            status: "paying_ln",
            paymentHash: facts.paymentHash,
            bolt11: cleanInvoice,
            amountSats: facts.amountSats,
            feeSats: totalFeeSats,
            debtDeltaSats: -ledgerState.debtSats,
            l1Txid: signedL1.txid,
            l1RawHex: signedL1.rawHex,
            arkTxid: err?.arkTxid || null,
            swapPkScriptHex: err?.swapPkScriptHex || null,
            spentOutpoints: signedL1.spentOutpoints,
            changeOutpoints: signedL1.changeOutpoints,
            creditUsedSats: creditUsed,
            outputPaddingSats: outputPadding,
            error: err?.message || String(err),
          });
        }
        throw err;
      }

      // Persist `broadcast_pending` + verified preimage IMMEDIATELY before Esplora broadcast!
      // If broadcast fails transiently or process crashes, reconcilePendingBroadcasts finishes it!
      store.upsertSwap({
        opId,
        walletId: walletRecord.walletId,
        direction: "out",
        mode,
        status: "broadcast_pending",
        paymentHash: facts.paymentHash,
        preimageHex: paid.preimageHex,
        bolt11: cleanInvoice,
        amountSats: facts.amountSats,
        feeSats: totalFeeSats,
        serviceFeeSats: Number(quoteCtx.serviceFeeSats || 0),
        debtDeltaSats: -ledgerState.debtSats,
        l1Txid: signedL1.txid,
        l1RawHex: signedL1.rawHex,
        arkTxid: paid.arkTxid || null,
        swapPkScriptHex: paid.swapPkScriptHex || null,
        spentOutpoints: signedL1.spentOutpoints,
        changeOutpoints: signedL1.changeOutpoints,
        creditUsedSats: creditUsed,
        outputPaddingSats: outputPadding,
      });

      await reconcilePendingBroadcasts(walletRecord);
      const finalRow = store.getSwap(opId);

      return {
        status: "done",
        paymentHash: facts.paymentHash,
        preimageHex: paid.preimageHex,
        amountSats: facts.amountSats,
        feeSats: totalFeeSats,
        l1FeeSats: signedL1.feeSats,
        totalSats: facts.amountSats + totalFeeSats,
        arkTxid: finalRow?.l1_txid || signedL1.txid,
        l1Txid: finalRow?.l1_txid || signedL1.txid,
        l1BroadcastPending: finalRow?.status !== "done",
        settlementMode: mode,
        debtCollectedSats: ledgerState.debtSats,
      };
    });
  }

  /**
   * Incoming Lightning invoice backed by the single server Arkade pool.
   */
  async function createLightningReceive({ walletRecord, amountSats, rfqId = randomBytes(32).toString("hex") }) {
    const sats = Number(amountSats);
    if (!Number.isSafeInteger(sats) || sats <= 0) {
      throw new Error("lightning_receive_requires_positive_amount_sats");
    }
    const l1 = await deriveWalletScript(walletRecord);
    const created = await pool.createLightningReceive({ amountSats: sats, rfqId });
    return {
      ...created,
      payoutAddress: l1.address,
      payoutPkScriptHex: l1.scriptPubKeyHex,
    };
  }

  /**
   * Claim incoming Lightning receive into server Arkade pool, then settle to user's
   * pure-L1 wallet using Muun `FulfillFullDebt` + instant 0-conf L1 payout (or micro-credit).
   * Serialized + atomic SQLite reservation guarantees ZERO double payouts or infinite loops!
   */
  async function claimLightningReceive({ walletRecord, receiveRecord }) {
    return withWalletLock(walletRecord.walletId, async () => {
      const opId = `l1-in-${receiveRecord.rfqId}`;
      const existing = store.getSwap(opId);
      if (existing?.status === "done") {
        return {
          status: "claimed",
          alreadyClaimed: true,
          claimTxid: existing.l1_txid,
          claimedSats: Number(existing.amount_sats),
          settlementMode: existing.mode,
        };
      }
      if (existing?.status === "claiming") {
        return { status: "pending" };
      }

      const claimed = await pool.claimLightningReceive({ receiveRecord });
      if (claimed.status !== "claimed") {
        return { status: claimed.status || "pending" };
      }
      const netReceivedSats = Number(claimed.claimedSats || receiveRecord.expectedAmountSats || 0);
      if (netReceivedSats <= 0) {
        return { status: "pending" };
      }

      // Atomically reserve this inbound swap op_id BEFORE broadcasting any L1 payout!
      const reservation = store.reserveSwap({
        opId,
        walletId: walletRecord.walletId,
        direction: "in",
        mode: "claiming",
        status: "claiming",
        paymentHash: receiveRecord.paymentHash || null,
        amountSats: netReceivedSats,
      });
      if (!reservation.reserved) {
        const cur = reservation.swap;
        if (cur?.status === "done") {
          return {
            status: "claimed",
            alreadyClaimed: true,
            claimTxid: cur.l1_txid,
            claimedSats: Number(cur.amount_sats),
            settlementMode: cur.mode,
          };
        }
        return { status: "pending" };
      }

      const l1 = await deriveWalletScript(walletRecord);
      const ledgerState = store.getLedger(walletRecord.walletId);
      const receiveServiceFeeSats =
        receiveFeeBps > 0
          ? Math.min(Math.max(0, netReceivedSats - 1), Math.ceil((netReceivedSats * receiveFeeBps) / 10_000))
          : 0;
      const creditedSats = netReceivedSats - receiveServiceFeeSats;

      // Step 1: Muun `FulfillFullDebt` — cancel user's LEND debt first with ZERO L1 tx!
      const debtCanceled = Math.min(ledgerState.debtSats, creditedSats);
      const remainingAfterDebt = creditedSats - debtCanceled;
      const newDebt = ledgerState.debtSats - debtCanceled;
      const poolForL1 = ledgerState.pendingReceiveSats + remainingAfterDebt;

      // Step 2: Settle immediately as a 0-conf L1 P2TR tx to user's `bc1p...` if >= settle floor!
      if (poolForL1 >= l1SettleFloorSats) {
        let payout;
        try {
          payout = await pool.sendL1Payout({
            toScriptHex: l1.scriptPubKeyHex,
            amountSats: poolForL1,
          });
        } catch (err) {
          // L1 payout never broadcast -> delete claiming reservation so next tick can retry safely.
          store.db.prepare("DELETE FROM nuri_l1_fronter_swaps WHERE op_id = ? AND status = 'claiming'").run(opId);
          throw err;
        }

        const mode = debtCanceled > 0 ? "partial_debt_l1_settle" : "l1_0conf_settle";
        // Persist `done` + `l1_txid` + ledger + local UTXO ATOMICALLY BEFORE calling cosigner!
        // Guarantees zero infinite re-payout loops even if cosigner is transiently unreachable.
        store.runTx(() => {
          store.addTrustedUtxo({
            walletId: walletRecord.walletId,
            txid: payout.txid,
            vout: payout.vout,
            amountSats: payout.payoutSats,
            scriptPubKeyHex: l1.scriptPubKeyHex,
            sourceKind: "fronter_payout",
            ancestorDepth: 1,
          });
          store.setLedger(walletRecord.walletId, { debtSats: newDebt, pendingReceiveSats: 0 });
          store.upsertSwap({
            opId,
            walletId: walletRecord.walletId,
            direction: "in",
            mode,
            status: "done",
            paymentHash: receiveRecord.paymentHash || null,
            amountSats: creditedSats,
            feeSats: payout.feeSats + receiveServiceFeeSats,
            serviceFeeSats: receiveServiceFeeSats,
            debtDeltaSats: -debtCanceled,
            l1Txid: payout.txid,
          });
        });

        // Non-fatal cosigner trusted-outpoint registration (output still becomes spendable at 1-conf if this fails).
        let trustedRegistered = false;
        if (cosignerClient && typeof cosignerClient.registerTrustedL1Outpoint === "function") {
          try {
            await cosignerClient.registerTrustedL1Outpoint({
              cred_id_b64u: walletRecord.credIdB64u,
              index: walletRecord.slotIndex,
              outpoint: `${payout.txid}:${payout.vout}`,
              source_kind: "fronter_payout",
              amount_sats: payout.payoutSats,
            });
            trustedRegistered = true;
          } catch {}
        }

        return {
          status: "claimed",
          claimTxid: payout.txid,
          grossClaimedSats: netReceivedSats,
          claimedSats: creditedSats,
          serviceFeeSats: receiveServiceFeeSats,
          l1PayoutSats: payout.payoutSats,
          l1FeeSats: payout.feeSats,
          debtCanceledSats: debtCanceled,
          trustedRegistered,
          settlementMode: mode,
        };
      }

      // Step 3: Full debt cancellation (`full_debt`) or micro-receive credit (`micro_credit`)
      const mode =
        remainingAfterDebt === 0
          ? "full_debt"
          : debtCanceled > 0
            ? "full_debt_plus_micro"
            : "micro_credit";
      store.runTx(() => {
        store.setLedger(walletRecord.walletId, {
          debtSats: newDebt,
          pendingReceiveSats: poolForL1,
        });
        store.upsertSwap({
          opId,
          walletId: walletRecord.walletId,
          direction: "in",
          mode,
          status: "done",
          paymentHash: receiveRecord.paymentHash || null,
          amountSats: creditedSats,
          feeSats: receiveServiceFeeSats,
          serviceFeeSats: receiveServiceFeeSats,
          debtDeltaSats: -debtCanceled,
          l1Txid: null,
        });
      });
      return {
        status: "claimed",
        claimTxid: null,
        grossClaimedSats: netReceivedSats,
        claimedSats: creditedSats,
        serviceFeeSats: receiveServiceFeeSats,
        debtCanceledSats: debtCanceled,
        pendingReceiveSats: poolForL1,
        settlementMode: mode,
      };
    });
  }

  /**
   * Direct native on-chain Bitcoin send from user's L1 2-of-2 MuSig2+CSV wallet (no SwapKit!).
   * Protects any outstanding LEND debt collateral and enforces script-type dust + maxSats with fee.
   */
  async function sendOnchainBtc({
    walletRecord,
    agentBtcPrivHex,
    toBtcAddress,
    amountSats,
    maxSats = null,
    opId = `l1-send-${randomBytes(8).toString("hex")}`,
  }) {
    return withWalletLock(walletRecord.walletId, async () => {
      await reconcilePendingBroadcasts(walletRecord).catch(() => {});
      const amount = Number(amountSats);
      const l1 = await deriveWalletScript(walletRecord);
      const netParams = bitcoinNetworkParams(l1.network);
      const destScript = OutScript.encode(Address(netParams).decode(String(toBtcAddress).trim()));
      const destScriptHex = bytesToHex(destScript);
      const destDust = dustLimitForScriptHex(destScriptHex);
      if (!Number.isSafeInteger(amount) || amount < destDust) {
        throw new Error(`amount_below_dust:${destDust}`);
      }

      const isSelfRefresh = destScriptHex === l1.scriptPubKeyHex;
      const { spendable } = await listWalletUtxos(walletRecord, { excludeNearCsv: !isSelfRefresh });
      const ledgerState = store.getLedger(walletRecord.walletId);
      const availSats = spendable.reduce((s, u) => s + u.value, 0);

      // Prevent under-collateralizing outstanding Muun LEND debt on external L1 sends!
      if (!isSelfRefresh && ledgerState.debtSats > 0) {
        const feeRate = await esplora.estimateFeeRate(3);
        const estFee = estimateP2trVbytes(1, 2) * feeRate;
        if (availSats - amount - estFee < ledgerState.debtSats + 500) {
          throw new Error(`l1_send_would_undercollateralize_debt:${ledgerState.debtSats}`);
        }
      }

      const signed = await buildAndCoSignL1Tx({
        walletRecord,
        agentBtcPrivHex,
        l1,
        spendableUtxos: spendable,
        recipientScriptHex: destScriptHex,
        recipientAmountSats: amount,
        opId,
        maxTotalSpendSats: maxSats,
        extraPriorCostSats: amount,
      });

      let txid;
      try {
        txid = (await esplora.broadcastTx(signed.rawHex)) || signed.txid;
      } catch (err) {
        if (isAlreadyBroadcastError(err)) {
          txid = signed.txid;
        } else {
          if (isDefinitePreMempoolReject(err)) {
            await cosignerClient
              .releaseL1Outpoints({
                cred_id_b64u: walletRecord.credIdB64u,
                index: walletRecord.slotIndex,
                op_id: opId,
                spending_txid: signed.txid,
              })
              .catch(() => {});
          }
          throw err;
        }
      }

      const mb = await cosignerClient
        .markL1Broadcast({
          cred_id_b64u: walletRecord.credIdB64u,
          index: walletRecord.slotIndex,
          op_id: opId,
          spending_txid: signed.txid,
          change_outpoints: signed.changeOutpoints,
        })
        .catch(() => null);

      store.markOutpointsSpentLocally(walletRecord.walletId, signed.spentOutpoints, txid);
      const trustedChange = Array.isArray(mb?.trusted_change_outpoints)
        ? mb.trusted_change_outpoints
        : signed.changeOutpoints;
      for (const ch of trustedChange) {
        const [cTxid, cVoutStr] = String(ch.outpoint).split(":");
        store.addTrustedUtxo({
          walletId: walletRecord.walletId,
          txid: cTxid,
          vout: Number(cVoutStr),
          amountSats: Number(ch.amount_sats),
          scriptPubKeyHex: l1.scriptPubKeyHex,
          sourceKind: "cosigned_change",
          ancestorDepth: Number(ch.ancestor_depth || 1),
        });
      }
      return {
        txid,
        amountSats: amount,
        feeSats: signed.feeSats,
        from: l1.address,
        to: toBtcAddress,
      };
    });
  }

  async function checkLightningSendFate({ paymentHash }) {
    if (!paymentHash) return { fate: "pending", preimageHex: null };
    const row = store.db
      .prepare(
        "SELECT * FROM nuri_l1_fronter_swaps WHERE payment_hash = ? ORDER BY updated_at_ms DESC LIMIT 1",
      )
      .get(String(paymentHash).toLowerCase());
    if (!row) return { fate: "pending", preimageHex: null };
    if (row.status === "done" || row.status === "broadcast_pending") {
      return { fate: "claimed", preimageHex: row.preimage_hex || null };
    }
    if (row.status === "failed") return { fate: "refunded", preimageHex: null };
    if (row.status === "paying_ln" && row.swap_pk_script_hex && typeof pool.checkArkadeLockupFate === "function") {
      try {
        const liveFate = await pool.checkArkadeLockupFate({
          swapPkScriptHex: row.swap_pk_script_hex,
          paymentHash: row.payment_hash,
        });
        if (liveFate.preimageHex) {
          store.upsertSwap({
            opId: row.op_id,
            walletId: row.wallet_id,
            direction: row.direction,
            mode: row.mode,
            status: row.l1_raw_hex ? "broadcast_pending" : "done",
            paymentHash: row.payment_hash,
            preimageHex: liveFate.preimageHex,
            bolt11: row.bolt11,
            amountSats: row.amount_sats,
            feeSats: row.fee_sats,
            serviceFeeSats: row.service_fee_sats,
            debtDeltaSats: row.debt_delta_sats,
            l1Txid: row.l1_txid,
            l1RawHex: row.l1_raw_hex,
          });
          return { fate: "claimed", preimageHex: liveFate.preimageHex };
        }
        if (liveFate.fate === "returned" || liveFate.fate === "exited") {
          return { fate: "refunded", preimageHex: null };
        }
      } catch {}
    }
    return { fate: "pending", preimageHex: null };
  }

  async function sendArkade() {
    throw new Error("direct_arkade_send_disabled_in_l1_0conf_mode");
  }

  async function getPoolStatus() {
    const poolInfo = typeof pool.getPoolStatus === "function" ? await pool.getPoolStatus() : { configured: Boolean(pool.configured) };
    const { csv, net } = await resolveL1Config();
    const ledgerTotals = store.aggregateTotals();
    const arkBal = poolInfo.arkadeBalanceSats !== undefined && poolInfo.arkadeBalanceSats !== null ? Number(poolInfo.arkadeBalanceSats) : null;
    const l1Bal = poolInfo.l1HotBalanceSats !== undefined && poolInfo.l1HotBalanceSats !== null ? Number(poolInfo.l1HotBalanceSats) : null;
    const totalFloatSats = arkBal !== null && l1Bal !== null ? arkBal + l1Bal : null;
    const netFloatEquitySats =
      totalFloatSats !== null
        ? totalFloatSats + ledgerTotals.totalDebtSats - ledgerTotals.totalPendingReceiveSats
        : null;
    return {
      ...poolInfo,
      network: net,
      nuriServerCsv: csv,
      totalFloatSats,
      netFloatEquitySats,
      feesConfig: {
        sendFeeBps,
        receiveFeeBps,
        lendMaxSats,
        l1SettleFloorSats,
        maxDebtSats,
      },
      ledgerTotals,
    };
  }

  return {
    custodyMode: "l1_0conf",
    network: defaultNet,
    deriveWalletScript,
    readBalance,
    estimateSendOverheadSats,
    payBolt11Invoice,
    createLightningReceive,
    claimLightningReceive,
    sendOnchainBtc,
    sendArkade,
    checkLightningSendFate,
    reconcilePendingBroadcasts,
    getPoolStatus,
    getLedgerState: (walletId) => store.getLedger(walletId),
    decodeBolt11,
    resolveLightningAddressInvoice: (opts) => resolveLightningAddressInvoice({ fetchImpl, ...opts }),
    close() {
      if (ownsStore) store.close();
    },
  };
}
