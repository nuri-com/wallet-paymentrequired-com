// Pure-L1 2-of-2 MuSig2+CSV Agent Wallet + Server-Only Arkade 0-Conf Lightning Fronter.
//
// Architecture (Muun model on Nuri's existing Taproot + Arkade stack):
//   - User/Agent wallets hold ONLY plain L1 Bitcoin UTXOs in:
//       tr(MuSig2(agent, cosigner), and_v(v:pk(agent), older(nuriServerCsv)))
//     No per-wallet Arkade SDK, no client VTXOs, no VTXO renewal, no exit chains.
//   - Outgoing (L1 -> Lightning):
//       1) Tiny sends (<= lendMaxSats, total debt <= maxDebtSats, backed by confirmed L1 UTXOs):
//          Muun `LEND` — server's single Arkade pool pays LN immediately with ZERO L1 tx
//          (zero user custody risk; server lends micro-sats, repaid on next L1 tx via `COLLECT`).
//       2) Normal sends (or when collecting prior debt):
//          Build L1 key-path P2TR PSBT paying server L1 replenish address (+ debt `COLLECT`),
//          co-sign via `nuri-agent-cosigner` `/v1/l1/sign-psbt` (atomically locks spent outpoints
//          in SQLite so RBF is cryptographically impossible), HOLD broadcast until server Arkade
//          pool obtains LN preimage, then broadcast L1 tx & mark-broadcast (0 L1 fee if LN fails!).
//   - Incoming (Lightning -> User L1 `bc1p...`):
//       Server's single Arkade pool issues & claims the BOLT11 invoice.
//       1) First cancels any `debt_sats` (Muun `FulfillFullDebt` — ZERO L1 tx).
//       2) If remaining + `pending_receive_sats` >= `l1SettleFloorSats`, server L1 hot wallet
//          immediately broadcasts a 0-conf L1 P2TR payout to user's `bc1p...` and registers the
//          outpoint as trusted 0-conf (immediately spendable!).
//       3) Otherwise credits `pending_receive_sats` (auto-swept to L1 once >= floor or applied
//          as instant credit on the very next outgoing LN payment).
//   - Direct on-chain BTC sends (`bc1...` / BIP21): native 1-tx L1 MuSig2 spend (zero SwapKit hop).
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
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

const BIP68_LOCKTIME_GRANULARITY = 9;
const BIP68_LOCKTIME_MASK = 0x0000ffff;
const BIP68_LOCKTIME_TYPE_FLAG = 1 << 22;
const BIP68_SECONDS_MOD = 1 << BIP68_LOCKTIME_GRANULARITY;
const BIP68_SECONDS_MAX = BIP68_LOCKTIME_MASK << BIP68_LOCKTIME_GRANULARITY;
const REGTEST_NETWORK = { bech32: "bcrt", pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef };

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
 * Byte-identical to `nuri-agent-cosigner` (`deriveAgentL1Taproot`) and consumer Nuri.
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
    address: out.address,
    pkScript: out.script,
    scriptPubKeyHex: bytesToHex(out.script),
    tapMerkleRoot: out.tapMerkleRoot,
    tapMerkleRootHex: bytesToHex(out.tapMerkleRoot),
    tweakedXonly: out.tweakedPubkey,
    tweakedXonlyHex: bytesToHex(out.tweakedPubkey),
    aggregatedXonly: aggXonly,
    csvSequence,
    csvLeafScriptHex: bytesToHex(csvLeafScript),
    csvControlBlockHex: controlBlock ? bytesToHex(controlBlock) : null,
  };
}

export function estimateP2trVbytes(inputCount, outputCount) {
  return Math.ceil(10.5 + inputCount * 57.5 + outputCount * 43);
}

export function createEsploraL1Client({
  baseUrl = DEFAULT_ESPLORA_URL,
  fetchImpl = fetch,
  timeoutMs = 12_000,
} = {}) {
  const origin = String(baseUrl || DEFAULT_ESPLORA_URL).trim().replace(/\/+$/, "");

  async function req(path, opts = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(`${origin}${path}`, { ...opts, signal: controller.signal });
      if (res.status === 404) return { ok: false, status: 404, res };
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`esplora_http_${res.status}:${text.slice(0, 160)}`);
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
        if (!ok) return 2;
        const map = await res.json();
        const rate = Number(map?.[String(targetBlocks)] ?? map?.["6"] ?? map?.["1"] ?? 2);
        return Number.isFinite(rate) && rate >= 1 ? Math.ceil(rate) : 2;
      } catch {
        return 2;
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

/**
 * SQLite ledger for Muun-style LEND/COLLECT/FulfillFullDebt, micro-receive accumulator,
 * trusted server-originated 0-conf UTXOs, and exactly-once swap journal.
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
      debt_delta_sats INTEGER NOT NULL DEFAULT 0,
      l1_txid TEXT,
      l1_raw_hex TEXT,
      error TEXT,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_l1_fronter_swaps_wallet
      ON nuri_l1_fronter_swaps (wallet_id, created_at_ms DESC);

    CREATE TABLE IF NOT EXISTS nuri_l1_trusted_utxos (
      outpoint TEXT PRIMARY KEY,
      wallet_id TEXT NOT NULL,
      txid TEXT NOT NULL,
      vout INTEGER NOT NULL,
      amount_sats INTEGER NOT NULL,
      script_pubkey_hex TEXT NOT NULL,
      source_kind TEXT NOT NULL,
      spent_by_txid TEXT,
      created_at_ms INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_l1_trusted_utxos_wallet
      ON nuri_l1_trusted_utxos (wallet_id, spent_by_txid);
  `);

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
    const debt = Math.max(0, Math.trunc(Number(debtSats || 0)));
    const pending = Math.max(0, Math.trunc(Number(pendingReceiveSats || 0)));
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

  function upsertSwap(row) {
    const now = row.updatedAtMs ?? Date.now();
    db.prepare(`
      INSERT INTO nuri_l1_fronter_swaps (
        op_id, wallet_id, direction, mode, status, payment_hash, preimage_hex, bolt11,
        amount_sats, fee_sats, debt_delta_sats, l1_txid, l1_raw_hex, error, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(op_id) DO UPDATE SET
        mode = excluded.mode,
        status = excluded.status,
        preimage_hex = COALESCE(excluded.preimage_hex, nuri_l1_fronter_swaps.preimage_hex),
        fee_sats = excluded.fee_sats,
        debt_delta_sats = excluded.debt_delta_sats,
        l1_txid = COALESCE(excluded.l1_txid, nuri_l1_fronter_swaps.l1_txid),
        l1_raw_hex = COALESCE(excluded.l1_raw_hex, nuri_l1_fronter_swaps.l1_raw_hex),
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
      Math.trunc(Number(row.debtDeltaSats || 0)),
      row.l1Txid ?? null,
      row.l1RawHex ?? null,
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
    nowMs = Date.now(),
  }) {
    const normTxid = String(txid).toLowerCase();
    const outpoint = `${normTxid}:${Number(vout)}`;
    db.prepare(`
      INSERT INTO nuri_l1_trusted_utxos (
        outpoint, wallet_id, txid, vout, amount_sats, script_pubkey_hex, source_kind, spent_by_txid, created_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
      ON CONFLICT(outpoint) DO NOTHING
    `).run(
      outpoint,
      String(walletId),
      normTxid,
      Number(vout),
      Math.trunc(Number(amountSats)),
      String(scriptPubKeyHex).toLowerCase(),
      String(sourceKind),
      nowMs,
    );
    return outpoint;
  }

  function listUnspentTrustedUtxos(walletId) {
    return db
      .prepare(
        "SELECT outpoint, txid, vout, amount_sats, script_pubkey_hex, source_kind, created_at_ms FROM nuri_l1_trusted_utxos WHERE wallet_id = ? AND spent_by_txid IS NULL",
      )
      .all(String(walletId))
      .map((r) => ({
        outpoint: r.outpoint,
        txid: r.txid,
        vout: Number(r.vout),
        value: Number(r.amount_sats),
        scriptPubKeyHex: r.script_pubkey_hex,
        sourceKind: r.source_kind,
        confirmed: false,
        trusted: true,
      }));
  }

  function markOutpointsSpentLocally(walletId, outpoints, spentByTxid) {
    const stmt = db.prepare(`
      INSERT INTO nuri_l1_trusted_utxos (
        outpoint, wallet_id, txid, vout, amount_sats, script_pubkey_hex, source_kind, spent_by_txid, created_at_ms
      ) VALUES (?, ?, ?, ?, 0, '', 'spent_marker', ?, ?)
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

  let closed = false;
  return {
    db,
    getLedger,
    setLedger,
    getSwap,
    upsertSwap,
    addTrustedUtxo,
    listUnspentTrustedUtxos,
    markOutpointsSpentLocally,
    getSpentOutpointsSet,
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
  const esploraClient = esplora || createEsploraL1Client({ baseUrl: env.FRONTER_ESPLORA_URL || DEFAULT_ESPLORA_URL, fetchImpl });

  const cleanArkPriv = String(poolArkadePrivKeyHex || "").trim().toLowerCase().replace(/^0x/, "");
  const cleanL1Priv = String(poolL1PrivKeyHex || "").trim().toLowerCase().replace(/^0x/, "");
  const hasArkKey = /^[0-9a-f]{64}$/.test(cleanArkPriv);
  const hasL1Key = /^[0-9a-f]{64}$/.test(cleanL1Priv);

  let l1P2tr = null;
  if (hasL1Key) {
    const pubXonly = schnorr.getPublicKey(hexToBytes(cleanL1Priv));
    l1P2tr = p2tr(pubXonly, undefined, netParams);
  }
  const depositAddress = String(poolL1DepositAddress || "").trim() || l1P2tr?.address || null;
  let depositScriptHex = l1P2tr ? bytesToHex(l1P2tr.script) : null;
  if (!depositScriptHex && depositAddress) {
    depositScriptHex = bytesToHex(OutScript.encode(Address(netParams).decode(depositAddress)));
  }

  const serverUrl = String(arkadeServerUrl || DEFAULT_ARKADE_SERVER_URL).replace(/\/+$/, "");
  const relays = String(env.ARKADE_NOSTR_RELAYS || DEFAULT_ARKADE_NOSTR_RELAYS.join(","))
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const solverPubkey = String(env.ARKADE_SOLVER_PUBKEY || DEFAULT_ARKADE_SOLVER_PUBKEY).trim();
  const operator = new RestOperatorProvider(serverUrl);
  const indexer = new RestIndexerProvider(serverUrl);
  let cachedInfo = null;
  let cachedInfoAt = 0;

  async function getInfo() {
    if (cachedInfo && Date.now() - cachedInfoAt < 60_000) return cachedInfo;
    cachedInfo = await operator.getInfo();
    cachedInfoAt = Date.now();
    return cachedInfo;
  }

  async function withRfq(info, fn) {
    const transport = nostrRfqTransport({
      relays,
      solverPubkey,
      signerKey: randomBytes(32),
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

  return {
    configured: Boolean(hasArkKey && depositAddress),
    l1DepositAddress: depositAddress,
    l1DepositScriptHex: depositScriptHex,

    async quoteLightningSend({ bolt11 }) {
      const facts = decodeBolt11(bolt11);
      if (!facts.amountSats || facts.amountSats <= 0) {
        throw new Error("amountless_bolt11_not_supported");
      }
      const pool = await getPoolArkScript();
      const rfqId = randomBytes(32).toString("hex");
      const quote = await withRfq(pool.info, (t) =>
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
      const lnFeeSats = Math.max(0, fundAmountSats - invoiceAmountSats);
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
      const facts = decodeBolt11(bolt11);
      const pool = await getPoolArkScript();
      const ctx = quoteContext || (await this.quoteLightningSend({ bolt11 }));
      const emulatorPubkey = toXOnly(
        hexToBytes(resolveEmulatorPubkey(pool.arkNet, env.ARKADE_EMULATOR_PUBKEY)),
        "emulator key",
      );
      const claimDelay = unilateralClaimDelay(Number(pool.info.unilateralExitDelay));
      const now = Math.floor(Date.now() / 1000);
      const receiverPkScript = hexToBytes(ctx.quote.profile.receiver_pk_script);
      const contract = lightningSendContract({
        senderPubkey: pool.xonly,
        receiverPubkey: receiverPkScript.subarray(2),
        paymentHash: hexToBytes(facts.paymentHash),
        refundLocktime: ctx.quote.refund_locktime,
        unilateralClaimDelay: claimDelay,
        unilateralRefundDelay: Number(ctx.quote.profile.refund_without_receiver_delay),
        unilateralRefundWithoutReceiverDelay: Number(ctx.quote.profile.refund_without_receiver_delay),
        serverPubkey: pool.serverXonly,
        emulatorPubkey,
      });
      const lockupAddress = new ArkAddress(pool.serverXonly, contract.tweakedPublicKey, pool.arkNet.hrp).encode();
      verifyLockupAddress(lockupAddress, ctx.quote);

      const { vtxos = [] } = await indexer.getVtxos({ scripts: [pool.pkScriptHex], spendableOnly: true });
      const coins = vtxos
        .filter((v) => !v.isSpent && Number(v.value) > 0)
        .map((v) => ({ ...v, value: Number(v.value), tapLeafScript: pool.script.forfeit(), tapTree: pool.script.encode() }));
      const fundAmount = Number(ctx.quote.from_amount);
      const selection = selectVirtualCoins(coins, fundAmount);
      const outputs = [{ script: ArkAddress.decode(lockupAddress).pkScript, amount: BigInt(fundAmount) }];
      const dust = Number(pool.info.dust || 330n);
      if (selection.changeAmount >= BigInt(dust)) {
        outputs.push({ script: pool.pkScript, amount: selection.changeAmount });
      }
      const serverUnrollScript = assertValidServerUnrollScript(
        pool.info.checkpointTapscript,
        pool.arkNet,
        toXOnly(hexToBytes(pool.info.forfeitPubkey), "forfeit key"),
      );
      const arkTxid = await signAndSubmitOffchainTx({
        provider: operator,
        inputs: selection.inputs,
        outputs,
        serverUnrollScript,
        identity: pool.singleKey,
        oneShot: false,
      });

      const deadline = Date.now() + pollTimeoutMs;
      while (Date.now() <= deadline) {
        const fate = await readLockupFate(indexer, {
          swapPkScript: contract.pkScript,
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
          };
        }
        if (fate.fate === "refunded") throw new Error("fronter_arkade_lightning_send_refunded");
        await new Promise((r) => setTimeout(r, pollIntervalMs));
      }
      throw new Error("fronter_arkade_lightning_send_timeout");
    },

    async createLightningReceive({ amountSats, rfqId = randomBytes(32).toString("hex") }) {
      const pool = await getPoolArkScript();
      const secrets = deriveLightningReceiveSecrets(cleanArkPriv, rfqId);
      const emulatorPubkey = toXOnly(
        hexToBytes(resolveEmulatorPubkey(pool.arkNet, env.ARKADE_EMULATOR_PUBKEY)),
        "emulator key",
      );
      const claimDelay = unilateralClaimDelay(Number(pool.info.unilateralExitDelay));
      const quote = await withRfq(pool.info, (t) =>
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
      const { payDeadline } = verifyReceiveInvoice({
        invoice: derived.invoice,
        decode: decodeBolt11,
        paymentHash: secrets.paymentHash,
        quote,
      });
      const expectedAmountSats = Number(quote.to_amount);
      const payAmountSats = Number(quote.from_amount);
      return {
        rfqId: secrets.rfqId,
        invoice: derived.invoice,
        paymentHash: secrets.paymentHash,
        payAmountSats,
        expectedAmountSats,
        feeSats: Math.max(0, payAmountSats - expectedAmountSats),
        expiresAt: payDeadline,
        lockupAddress: derived.address,
        swapPkScriptHex: bytesToHex(derived.swapPkScript),
        quoteJson: JSON.stringify(quote),
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
        hexToBytes(resolveEmulatorPubkey(pool.arkNet, env.ARKADE_EMULATOR_PUBKEY)),
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
      const { vtxos = [] } = await indexer.getVtxos({
        scripts: [bytesToHex(derived.swapPkScript)],
        spendableOnly: true,
      });
      const live = vtxos
        .filter((v) => !v.isSpent && Number(v.value) > 0)
        .map((v) => ({ ...v, value: Number(v.value), recoverable: Boolean(v.isRecoverable) }));
      if (live.length === 0) {
        const fate = await readLockupFate(indexer, {
          swapPkScript: derived.swapPkScript,
          paymentHash: secrets.paymentHash,
        });
        if (fate.fate === "claimed") {
          return { status: "claimed", alreadyClaimed: true, claimedSats: Number(receiveRecord.expectedAmountSats || 0) };
        }
        return { status: "pending" };
      }
      await pushClaim(operator, {
        vtxos: live,
        contract: derived.script,
        receiver: secrets.claimSingleKey,
        preimage: secrets.preimage,
        expectedAmount: Number(receiveRecord.expectedAmountSats || quote.to_amount),
        destinationPkScript: pool.pkScript,
        network: pool.arkNet,
      });
      return {
        status: "claimed",
        claimedSats: live.reduce((sum, v) => sum + v.value, 0),
      };
    },

    /**
     * Broadcast an instant 0-conf L1 P2TR payout from the server L1 hot wallet
     * to a user's L1 `bc1p...` address (used to settle incoming Lightning receives).
     */
    async sendL1Payout({ toScriptHex, amountSats }) {
      if (!hasL1Key || !l1P2tr) throw new Error("fronter_l1_hot_wallet_not_configured");
      const utxos = await esploraClient.listUtxos(l1P2tr.address);
      const sorted = [...utxos].sort((a, b) => b.value - a.value);
      const feeRate = await esploraClient.estimateFeeRate(3);
      const priv = hexToBytes(cleanL1Priv);

      const selected = [];
      let totalIn = 0n;
      let feeSats = 0n;
      for (const u of sorted) {
        selected.push(u);
        totalIn += BigInt(u.value);
        feeSats = BigInt(estimateP2trVbytes(selected.length, 2) * feeRate);
        if (totalIn >= BigInt(amountSats) + feeSats) break;
      }
      const targetNet = BigInt(amountSats) - feeSats;
      if (targetNet < BigInt(P2TR_DUST_SATS)) {
        throw new Error("fronter_l1_payout_below_dust_after_fee");
      }
      if (totalIn < BigInt(amountSats)) {
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
      const change = totalIn - targetNet - feeSats;
      if (change >= BigInt(P2TR_DUST_SATS)) {
        tx.addOutput({ script: l1P2tr.script, amount: change });
      }
      tx.sign(priv);
      tx.finalize();
      const rawHex = bytesToHex(tx.extract());
      const txid = await esploraClient.broadcastTx(rawHex);
      return {
        txid: txid || tx.id.toLowerCase(),
        vout: 0,
        payoutSats: Number(targetNet),
        feeSats: Number(feeSats),
        rawHex,
      };
    },
  };
}

function selectL1Utxos(utxos, targetSats, feeRateSatVb) {
  // Prefer confirmed UTXOs first, then trusted 0-conf UTXOs, largest first.
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
      // Change is below dust: absorb into fee (1 output only).
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
  nuriServerCsv = DEFAULT_L1_CSV,
  lendMaxSats = Number(env.FRONTER_LEND_MAX_SATS ?? DEFAULT_LEND_MAX_SATS),
  maxDebtSats = Number(env.FRONTER_MAX_DEBT_SATS ?? DEFAULT_MAX_DEBT_SATS),
  l1SettleFloorSats = Number(env.FRONTER_L1_SETTLE_FLOOR_SATS ?? DEFAULT_L1_SETTLE_FLOOR_SATS),
} = {}) {
  const normNet = normalizeBitcoinNetwork(network);
  const netParams = bitcoinNetworkParams(normNet);
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
      network: normNet,
    });
  const store = ledger || openL1FronterLedger(ledgerPath);
  const ownsStore = !ledger;

  async function deriveWalletScript(walletRecord) {
    return deriveAgentL1Wallet({
      aggregatedBtcXonlyHex: walletRecord.aggregatedBtcXonlyHex,
      agentBtcPub33Hex: walletRecord.agentBtcPub33Hex,
      nuriServerCsv,
      network: normNet,
    });
  }

  async function listWalletUtxos(walletRecord) {
    const l1 = await deriveWalletScript(walletRecord);
    const chainUtxos = await esplora.listUtxos(l1.address);
    const trustedLocal = store.listUnspentTrustedUtxos(walletRecord.walletId);
    const spentLocally = store.getSpentOutpointsSet(walletRecord.walletId);

    const trustedSet = new Set(trustedLocal.map((u) => u.outpoint));
    const merged = new Map();
    for (const u of chainUtxos) {
      const outpoint = `${u.txid}:${u.vout}`;
      if (spentLocally.has(outpoint)) continue;
      merged.set(outpoint, {
        ...u,
        outpoint,
        trusted: u.confirmed || trustedSet.has(outpoint),
      });
    }
    for (const tu of trustedLocal) {
      if (spentLocally.has(tu.outpoint)) continue;
      if (!merged.has(tu.outpoint)) {
        merged.set(tu.outpoint, tu);
      }
    }

    const all = [...merged.values()];
    const spendable = all.filter((u) => u.confirmed || u.trusted);
    const externalUnconfirmed = all.filter((u) => !u.confirmed && !u.trusted);
    return { l1, spendable, externalUnconfirmed };
  }

  async function readBalance(walletRecord) {
    const { l1, spendable, externalUnconfirmed } = await listWalletUtxos(walletRecord);
    const ledgerState = store.getLedger(walletRecord.walletId);

    let confirmedSats = 0n;
    let trustedUnconfSats = 0n;
    for (const u of spendable) {
      if (u.confirmed) confirmedSats += BigInt(u.value);
      else trustedUnconfSats += BigInt(u.value);
    }
    const extUnconfSats = externalUnconfirmed.reduce((sum, u) => sum + BigInt(u.value), 0n);
    const rawSpendable = confirmedSats + trustedUnconfSats - BigInt(ledgerState.debtSats) + BigInt(ledgerState.pendingReceiveSats);
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
    };
  }

  async function buildAndCoSignL1Tx({
    walletRecord,
    agentBtcPrivHex,
    l1,
    spendableUtxos,
    recipientScriptHex,
    recipientAmountSats,
    opId,
  }) {
    if (!cosignerClient) throw new Error("cosigner_client_required");
    const feeRate = await esplora.estimateFeeRate(3);
    const pick = selectL1Utxos(spendableUtxos, recipientAmountSats, feeRate);
    if (!pick) {
      const avail = spendableUtxos.reduce((s, u) => s + BigInt(u.value), 0n);
      throw new Error(`insufficient_l1_balance:need_${recipientAmountSats}_have_${avail.toString()}`);
    }

    const tx = new Transaction({ version: 2 });
    const prevScripts = [];
    const prevAmounts = [];
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

      return {
        txid: tx.id.toLowerCase(),
        rawHex: bytesToHex(tx.extract()),
        feeSats: Number(pick.feeSats),
        changeSats: Number(pick.changeSats),
        spentOutpoints: pick.selected.map((u) => u.outpoint),
        changeOutpoints: cosigned.change_outpoints || [],
        lockAttestation: cosigned.lock_attestation || null,
      };
    } finally {
      clientPriv.fill(0);
    }
  }

  /**
   * Instant 0-conf L1 -> Lightning via server-side Arkade pool.
   * Uses Muun `LEND` for tiny sends, and cosigner-locked hold-broadcast (+ `COLLECT`)
   * for larger sends so RBF is impossible and failed LN pays 0 L1 miner fee!
   */
  async function payBolt11Invoice({
    walletRecord,
    agentBtcPrivHex,
    bolt11,
    maxSats,
    opId = `l1-ln-${randomBytes(8).toString("hex")}`,
  }) {
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

    // Durable idempotency replay check
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
        arkTxid: existing.l1_txid || `lend:${existing.op_id}`,
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

    const { l1, spendable } = await listWalletUtxos(walletRecord);
    const ledgerState = store.getLedger(walletRecord.walletId);
    const onchainSpendableSats = spendable.reduce((sum, u) => sum + u.value, 0);

    const creditUsed = Math.min(ledgerState.pendingReceiveSats, quoteCtx.totalCostSats);
    const neededAfterCredit = quoteCtx.totalCostSats - creditUsed;

    // Path 1: Fully covered by pending micro-receive credit (0 L1 tx)
    if (neededAfterCredit === 0) {
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
      });
      try {
        const paid = await pool.payLightningInvoice({ bolt11: cleanInvoice, quoteContext: quoteCtx });
        if (!paid?.preimageHex || bytesToHex(sha256(hexToBytes(paid.preimageHex))) !== facts.paymentHash) {
          throw new Error("invalid_lightning_preimage");
        }
        store.setLedger(walletRecord.walletId, {
          debtSats: ledgerState.debtSats,
          pendingReceiveSats: ledgerState.pendingReceiveSats - creditUsed,
        });
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
        store.upsertSwap({
          opId,
          walletId: walletRecord.walletId,
          direction: "out",
          mode: "micro_credit",
          status: "failed",
          paymentHash: facts.paymentHash,
          bolt11: cleanInvoice,
          amountSats: facts.amountSats,
          feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats,
          error: err?.message || String(err),
        });
        throw err;
      }
    }

    // Path 2: Muun `LEND` — tiny outgoing LN backed by user's confirmed/trusted L1 UTXOs (ZERO L1 tx!)
    const projectedDebt = ledgerState.debtSats + neededAfterCredit;
    const minL1CoverBuffer = 500;
    const canLend =
      neededAfterCredit <= lendMaxSats &&
      projectedDebt <= maxDebtSats &&
      onchainSpendableSats >= projectedDebt + minL1CoverBuffer;

    if (canLend) {
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
        debtDeltaSats: neededAfterCredit,
      });
      try {
        const paid = await pool.payLightningInvoice({ bolt11: cleanInvoice, quoteContext: quoteCtx });
        if (!paid?.preimageHex || bytesToHex(sha256(hexToBytes(paid.preimageHex))) !== facts.paymentHash) {
          throw new Error("invalid_lightning_preimage");
        }
        store.setLedger(walletRecord.walletId, {
          debtSats: projectedDebt,
          pendingReceiveSats: ledgerState.pendingReceiveSats - creditUsed,
        });
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
          debtDeltaSats: neededAfterCredit,
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
        store.upsertSwap({
          opId,
          walletId: walletRecord.walletId,
          direction: "out",
          mode: "lend",
          status: "failed",
          paymentHash: facts.paymentHash,
          bolt11: cleanInvoice,
          amountSats: facts.amountSats,
          feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats,
          error: err?.message || String(err),
        });
        throw err;
      }
    }

    // Path 3: Cosigner-locked 0-conf L1 fronting (+ Muun `COLLECT` of prior debt) with hold-broadcast!
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
    });

    // Durable journal BEFORE paying LN; L1 tx broadcast is HELD until LN settles!
    store.upsertSwap({
      opId,
      walletId: walletRecord.walletId,
      direction: "out",
      mode,
      status: "paying_ln",
      paymentHash: facts.paymentHash,
      bolt11: cleanInvoice,
      amountSats: facts.amountSats,
      feeSats: quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats + signedL1.feeSats,
      debtDeltaSats: -ledgerState.debtSats,
      l1Txid: signedL1.txid,
      l1RawHex: signedL1.rawHex,
    });

    let paid;
    try {
      paid = await pool.payLightningInvoice({ bolt11: cleanInvoice, quoteContext: quoteCtx });
      if (!paid?.preimageHex || bytesToHex(sha256(hexToBytes(paid.preimageHex))) !== facts.paymentHash) {
        throw new Error("invalid_lightning_preimage");
      }
    } catch (err) {
      // LN failed BEFORE broadcasting L1 -> discard L1 tx and unlock outpoints (0 L1 fee lost!).
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
      throw err;
    }

    // LN succeeded with verified preimage -> broadcast the already-signed L1 replenishment tx!
    const broadcastTxid = await esplora.broadcastTx(signedL1.rawHex);
    const finalTxid = broadcastTxid || signedL1.txid;

    await cosignerClient.markL1Broadcast({
      cred_id_b64u: walletRecord.credIdB64u,
      index: walletRecord.slotIndex,
      op_id: opId,
      spending_txid: signedL1.txid,
      change_outpoints: signedL1.changeOutpoints,
    });

    store.markOutpointsSpentLocally(walletRecord.walletId, signedL1.spentOutpoints, finalTxid);
    for (const ch of signedL1.changeOutpoints) {
      const [cTxid, cVoutStr] = String(ch.outpoint).split(":");
      store.addTrustedUtxo({
        walletId: walletRecord.walletId,
        txid: cTxid,
        vout: Number(cVoutStr),
        amountSats: Number(ch.amount_sats),
        scriptPubKeyHex: l1.scriptPubKeyHex,
        sourceKind: "cosigned_change",
      });
    }

    // Clear collected debt; any dust OutputPadding surplus is credited back to pendingReceiveSats.
    store.setLedger(walletRecord.walletId, {
      debtSats: 0,
      pendingReceiveSats: ledgerState.pendingReceiveSats - creditUsed + outputPadding,
    });

    const totalFeeSats = quoteCtx.lnFeeSats + quoteCtx.serviceFeeSats + signedL1.feeSats;
    store.upsertSwap({
      opId,
      walletId: walletRecord.walletId,
      direction: "out",
      mode,
      status: "done",
      paymentHash: facts.paymentHash,
      preimageHex: paid.preimageHex,
      bolt11: cleanInvoice,
      amountSats: facts.amountSats,
      feeSats: totalFeeSats,
      debtDeltaSats: -ledgerState.debtSats,
      l1Txid: finalTxid,
      l1RawHex: signedL1.rawHex,
    });

    return {
      status: "done",
      paymentHash: facts.paymentHash,
      preimageHex: paid.preimageHex,
      amountSats: facts.amountSats,
      feeSats: totalFeeSats,
      l1FeeSats: signedL1.feeSats,
      totalSats: facts.amountSats + totalFeeSats,
      arkTxid: finalTxid,
      l1Txid: finalTxid,
      settlementMode: mode,
      debtCollectedSats: ledgerState.debtSats,
    };
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
   * pure-L1 wallet using Muun `FulfillFullDebt` + instant 0-conf L1 payout (or micro-credit sweep).
   */
  async function claimLightningReceive({ walletRecord, receiveRecord }) {
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

    const claimed = await pool.claimLightningReceive({ receiveRecord });
    if (claimed.status !== "claimed") {
      return { status: "pending" };
    }
    const netReceivedSats = Number(claimed.claimedSats || receiveRecord.expectedAmountSats || 0);
    if (netReceivedSats <= 0) {
      return { status: "pending" };
    }

    const l1 = await deriveWalletScript(walletRecord);
    const ledgerState = store.getLedger(walletRecord.walletId);

    // Step 1: Muun `FulfillFullDebt` — cancel user's LEND debt first with ZERO L1 tx!
    const debtCanceled = Math.min(ledgerState.debtSats, netReceivedSats);
    const remainingAfterDebt = netReceivedSats - debtCanceled;
    const newDebt = ledgerState.debtSats - debtCanceled;
    const poolForL1 = ledgerState.pendingReceiveSats + remainingAfterDebt;

    // Step 2: Settle immediately as a 0-conf L1 P2TR tx to user's `bc1p...` if >= settle floor!
    if (poolForL1 >= l1SettleFloorSats) {
      const payout = await pool.sendL1Payout({
        toScriptHex: l1.scriptPubKeyHex,
        amountSats: poolForL1,
      });
      const outpoint = `${payout.txid}:${payout.vout}`;
      if (cosignerClient) {
        await cosignerClient.registerTrustedL1Outpoint({
          cred_id_b64u: walletRecord.credIdB64u,
          index: walletRecord.slotIndex,
          outpoint,
          source_kind: "fronter_payout",
          amount_sats: payout.payoutSats,
        });
      }
      store.addTrustedUtxo({
        walletId: walletRecord.walletId,
        txid: payout.txid,
        vout: payout.vout,
        amountSats: payout.payoutSats,
        scriptPubKeyHex: l1.scriptPubKeyHex,
        sourceKind: "fronter_payout",
      });
      store.setLedger(walletRecord.walletId, { debtSats: newDebt, pendingReceiveSats: 0 });
      const mode = debtCanceled > 0 ? "partial_debt_l1_settle" : "l1_0conf_settle";
      store.upsertSwap({
        opId,
        walletId: walletRecord.walletId,
        direction: "in",
        mode,
        status: "done",
        paymentHash: receiveRecord.paymentHash || null,
        amountSats: netReceivedSats,
        feeSats: payout.feeSats,
        debtDeltaSats: -debtCanceled,
        l1Txid: payout.txid,
      });
      return {
        status: "claimed",
        claimTxid: payout.txid,
        claimedSats: netReceivedSats,
        l1PayoutSats: payout.payoutSats,
        l1FeeSats: payout.feeSats,
        debtCanceledSats: debtCanceled,
        settlementMode: mode,
      };
    }

    // Step 3: Either 100% canceled debt (`full_debt`) or tiny receive below L1 dust/fee floor (`micro_credit`)
    store.setLedger(walletRecord.walletId, {
      debtSats: newDebt,
      pendingReceiveSats: poolForL1,
    });
    const mode =
      remainingAfterDebt === 0
        ? "full_debt"
        : debtCanceled > 0
          ? "full_debt_plus_micro"
          : "micro_credit";
    store.upsertSwap({
      opId,
      walletId: walletRecord.walletId,
      direction: "in",
      mode,
      status: "done",
      paymentHash: receiveRecord.paymentHash || null,
      amountSats: netReceivedSats,
      feeSats: 0,
      debtDeltaSats: -debtCanceled,
      l1Txid: null,
    });
    return {
      status: "claimed",
      claimTxid: null,
      claimedSats: netReceivedSats,
      debtCanceledSats: debtCanceled,
      pendingReceiveSats: poolForL1,
      settlementMode: mode,
    };
  }

  /**
   * Direct native on-chain Bitcoin send from user's L1 2-of-2 MuSig2+CSV wallet (no SwapKit!).
   */
  async function sendOnchainBtc({
    walletRecord,
    agentBtcPrivHex,
    toBtcAddress,
    amountSats,
    opId = `l1-send-${randomBytes(8).toString("hex")}`,
  }) {
    const amount = Number(amountSats);
    if (!Number.isSafeInteger(amount) || amount < P2TR_DUST_SATS) {
      throw new Error(`amount_below_dust:${P2TR_DUST_SATS}`);
    }
    const destScript = OutScript.encode(Address(netParams).decode(String(toBtcAddress).trim()));
    const destScriptHex = bytesToHex(destScript);
    const { l1, spendable } = await listWalletUtxos(walletRecord);

    const signed = await buildAndCoSignL1Tx({
      walletRecord,
      agentBtcPrivHex,
      l1,
      spendableUtxos: spendable,
      recipientScriptHex: destScriptHex,
      recipientAmountSats: amount,
      opId,
    });
    const txid = (await esplora.broadcastTx(signed.rawHex)) || signed.txid;
    await cosignerClient.markL1Broadcast({
      cred_id_b64u: walletRecord.credIdB64u,
      index: walletRecord.slotIndex,
      op_id: opId,
      spending_txid: signed.txid,
      change_outpoints: signed.changeOutpoints,
    });
    store.markOutpointsSpentLocally(walletRecord.walletId, signed.spentOutpoints, txid);
    for (const ch of signed.changeOutpoints) {
      const [cTxid, cVoutStr] = String(ch.outpoint).split(":");
      store.addTrustedUtxo({
        walletId: walletRecord.walletId,
        txid: cTxid,
        vout: Number(cVoutStr),
        amountSats: Number(ch.amount_sats),
        scriptPubKeyHex: l1.scriptPubKeyHex,
        sourceKind: "cosigned_change",
      });
    }
    return {
      txid,
      amountSats: amount,
      feeSats: signed.feeSats,
      from: l1.address,
      to: toBtcAddress,
    };
  }

  async function checkLightningSendFate({ paymentHash }) {
    if (!paymentHash) return { fate: "pending", preimageHex: null };
    const row = store.db
      .prepare("SELECT status, preimage_hex FROM nuri_l1_fronter_swaps WHERE payment_hash = ? ORDER BY updated_at_ms DESC LIMIT 1")
      .get(String(paymentHash).toLowerCase());
    if (!row) return { fate: "pending", preimageHex: null };
    return {
      fate: row.status === "done" ? "claimed" : row.status === "failed" ? "refunded" : "pending",
      preimageHex: row.preimage_hex || null,
    };
  }

  async function sendArkade() {
    throw new Error("direct_arkade_send_disabled_in_l1_0conf_mode");
  }

  return {
    custodyMode: "l1_0conf",
    network: normNet,
    deriveWalletScript,
    readBalance,
    payBolt11Invoice,
    createLightningReceive,
    claimLightningReceive,
    sendOnchainBtc,
    sendArkade,
    checkLightningSendFate,
    getLedgerState: (walletId) => store.getLedger(walletId),
    decodeBolt11,
    resolveLightningAddressInvoice: (opts) => resolveLightningAddressInvoice({ fetchImpl, ...opts }),
    close() {
      if (ownsStore) store.close();
    },
  };
}
