// Durable SQLite store for v2 Nuri Passkey PRF Agent Wallets (`nuri-agent-wallet-v1`).
//
// Security properties:
// - Stores only SHA-256(`wallet_key`) in SQLite (`wallet_key` = `npw1_<43-char-base64url>`).
// - Agent EVM + BTC child private keys are encrypted at rest with AES-256-GCM under
//   HKDF-SHA256(AGENT_KERNEL_ENCRYPTION_KEY, wallet_key, info="nuri-prf-agent-store-v1:<wallet_id>")
//   so neither the SQLite file alone nor a leaked `wallet_key` alone reveals the keys.
// - Grant session reply ephemeral secret keys are encrypted under `AGENT_KERNEL_ENCRYPTION_KEY`
//   and wiped from SQLite immediately once the `agent_grant` ceremony is finalized.
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { getAddress } from "viem";

export const PRF_WALLET_KEY_PREFIX = "npw1_";
export const PRF_WALLET_KEY_RE = /^npw1_[A-Za-z0-9_-]{43}$/;

const STORE_AAD_PREFIX = "nuri-prf-agent-store-v1";
const SESSION_AAD_PREFIX = "nuri-prf-grant-session-v1";

export function isPrfWalletKey(value) {
  return typeof value === "string" && PRF_WALLET_KEY_RE.test(value.trim());
}

export function generatePrfWalletKey() {
  return `${PRF_WALLET_KEY_PREFIX}${randomBytes(32).toString("base64url")}`;
}

export function hashWalletKey(walletKey) {
  return createHash("sha256").update(String(walletKey || "").trim(), "utf8").digest("hex");
}

function parseMasterEncryptionKey(raw) {
  const clean = String(raw || "").trim();
  if (!clean) throw new Error("agent_kernel_encryption_key_required");
  const buf = /^[0-9a-f]{64}$/i.test(clean)
    ? Buffer.from(clean, "hex")
    : Buffer.from(clean, "base64url");
  if (buf.length !== 32) {
    throw new Error("agent_kernel_encryption_key_must_be_32_bytes");
  }
  return new Uint8Array(buf);
}

function deriveWalletSealKey(masterKeyBytes, walletKey, walletId) {
  return Buffer.from(
    hkdf(
      sha256,
      masterKeyBytes,
      new TextEncoder().encode(String(walletKey).trim()),
      new TextEncoder().encode(`${STORE_AAD_PREFIX}:${walletId}`),
      32,
    ),
  );
}

function deriveSessionSealKey(masterKeyBytes, requestId) {
  return Buffer.from(
    hkdf(
      sha256,
      masterKeyBytes,
      new TextEncoder().encode(SESSION_AAD_PREFIX),
      new TextEncoder().encode(`${SESSION_AAD_PREFIX}:${requestId}`),
      32,
    ),
  );
}

function sealJson(payloadObj, keyBuf, aadText) {
  const iv = randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(payloadObj), "utf8");
  try {
    const cipher = createCipheriv("aes-256-gcm", keyBuf, iv);
    cipher.setAAD(Buffer.from(aadText, "utf8"));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1.${iv.toString("base64url")}.${tag.toString("base64url")}.${ct.toString("base64url")}`;
  } finally {
    plaintext.fill(0);
  }
}

function openJson(blob, keyBuf, aadText) {
  const parts = String(blob || "").split(".");
  if (parts.length !== 4 || parts[0] !== "v1") {
    throw new Error("invalid_sealed_blob");
  }
  const [, ivB64, tagB64, ctB64] = parts;
  const decipher = createDecipheriv("aes-256-gcm", keyBuf, Buffer.from(ivB64, "base64url"));
  decipher.setAAD(Buffer.from(aadText, "utf8"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  const pt = Buffer.concat([
    decipher.update(Buffer.from(ctB64, "base64url")),
    decipher.final(),
  ]);
  try {
    return JSON.parse(pt.toString("utf8"));
  } finally {
    pt.fill(0);
  }
}

export function openPrfAgentWalletStore({
  path = ":memory:",
  encryptionKey = process.env.AGENT_KERNEL_ENCRYPTION_KEY,
} = {}) {
  const masterKey = parseMasterEncryptionKey(encryptionKey);
  if (path !== ":memory:") {
    mkdirSync(dirname(path), { recursive: true });
  }
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS nuri_prf_grant_sessions (
      request_id TEXT PRIMARY KEY,
      connect_session_id TEXT NOT NULL UNIQUE,
      slot_index INTEGER NOT NULL,
      reply_pubkey TEXT NOT NULL,
      sealed_reply_sk TEXT,
      policy_json TEXT NOT NULL,
      approval_url TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      status TEXT NOT NULL,
      wallet_id TEXT,
      issued_wallet_key_sealed TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS nuri_prf_agent_wallets (
      wallet_id TEXT PRIMARY KEY,
      wallet_key_hash TEXT NOT NULL UNIQUE,
      cred_id_b64u TEXT NOT NULL,
      slot_index INTEGER NOT NULL,
      main_eoa TEXT NOT NULL,
      passkey_signer_address TEXT NOT NULL,
      agent_eth_eoa TEXT NOT NULL,
      cosigner_eoa TEXT NOT NULL,
      safe_address TEXT NOT NULL,
      agent_btc_pub33_hex TEXT NOT NULL,
      cosigner_btc_pub33_hex TEXT NOT NULL,
      aggregated_btc_xonly_hex TEXT NOT NULL,
      arkade_address TEXT,
      policy_json TEXT NOT NULL,
      sealed_secrets TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_nuri_prf_wallets_cred_slot
      ON nuri_prf_agent_wallets(cred_id_b64u, slot_index);
    CREATE INDEX IF NOT EXISTS idx_nuri_prf_wallets_main_eoa
      ON nuri_prf_agent_wallets(LOWER(main_eoa));

    CREATE TABLE IF NOT EXISTS nuri_prf_lightning_receives (
      rfq_id TEXT PRIMARY KEY,
      wallet_id TEXT NOT NULL,
      request_id TEXT,
      payment_hash TEXT NOT NULL,
      invoice TEXT NOT NULL,
      pay_amount_sats INTEGER NOT NULL,
      expected_amount_sats INTEGER NOT NULL,
      fee_sats INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      lockup_address TEXT NOT NULL,
      swap_pk_script_hex TEXT NOT NULL,
      payout_address TEXT NOT NULL,
      quote_json TEXT NOT NULL,
      status TEXT NOT NULL,
      claim_txid TEXT,
      claimed_sats INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_nuri_prf_ln_receives_wallet_status
      ON nuri_prf_lightning_receives(wallet_id, status);

    CREATE TABLE IF NOT EXISTS nuri_prf_agent_ops (
      wallet_id TEXT NOT NULL,
      request_id TEXT NOT NULL,
      action TEXT NOT NULL,
      rail TEXT NOT NULL,
      status TEXT NOT NULL,
      amount_display TEXT,
      summary_json TEXT NOT NULL,
      result_json TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (wallet_id, request_id)
    );
    CREATE INDEX IF NOT EXISTS idx_nuri_prf_ops_wallet_created
      ON nuri_prf_agent_ops(wallet_id, created_at DESC);
  `);

  function mapWalletRow(row) {
    if (!row) return null;
    return {
      walletId: row.wallet_id,
      walletKeyHash: row.wallet_key_hash,
      credIdB64u: row.cred_id_b64u,
      slotIndex: Number(row.slot_index),
      mainEoa: getAddress(row.main_eoa),
      passkeySignerAddress: getAddress(row.passkey_signer_address),
      agentEthEoa: getAddress(row.agent_eth_eoa),
      cosignerEoa: getAddress(row.cosigner_eoa),
      safeAddress: getAddress(row.safe_address),
      agentBtcPub33Hex: row.agent_btc_pub33_hex,
      cosignerBtcPub33Hex: row.cosigner_btc_pub33_hex,
      aggregatedBtcXonlyHex: row.aggregated_btc_xonly_hex,
      arkadeAddress: row.arkade_address || null,
      policy: JSON.parse(row.policy_json || "{}"),
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    };
  }

  function createGrantSession({
    requestId = randomUUID(),
    connectSessionId,
    slotIndex = 0,
    replyPubkey,
    replySkHex,
    policy = {},
    approvalUrl,
    expiresAt,
    nowMs = Date.now(),
  }) {
    const sessKey = deriveSessionSealKey(masterKey, requestId);
    let sealedSk;
    try {
      sealedSk = sealJson(
        { replySkHex },
        sessKey,
        `${SESSION_AAD_PREFIX}:${requestId}:${connectSessionId}`,
      );
    } finally {
      sessKey.fill(0);
    }
    db.prepare(
      `INSERT INTO nuri_prf_grant_sessions (
        request_id, connect_session_id, slot_index, reply_pubkey, sealed_reply_sk,
        policy_json, approval_url, expires_at, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
    ).run(
      requestId,
      connectSessionId,
      Number(slotIndex),
      replyPubkey,
      sealedSk,
      JSON.stringify(policy || {}),
      approvalUrl,
      String(expiresAt),
      nowMs,
      nowMs,
    );
    return getGrantSession(requestId);
  }

  function getGrantSession(requestId) {
    const row = db
      .prepare("SELECT * FROM nuri_prf_grant_sessions WHERE request_id = ?")
      .get(String(requestId || ""));
    if (!row) return null;
    return {
      requestId: row.request_id,
      connectSessionId: row.connect_session_id,
      slotIndex: Number(row.slot_index),
      replyPubkey: row.reply_pubkey,
      hasSealedReplySk: Boolean(row.sealed_reply_sk),
      policy: JSON.parse(row.policy_json || "{}"),
      approvalUrl: row.approval_url,
      expiresAt: row.expires_at,
      status: row.status,
      walletId: row.wallet_id || null,
      hasIssuedWalletKey: Boolean(row.issued_wallet_key_sealed),
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    };
  }

  function readGrantSessionReplySk(requestId) {
    const row = db
      .prepare("SELECT request_id, connect_session_id, sealed_reply_sk FROM nuri_prf_grant_sessions WHERE request_id = ?")
      .get(String(requestId || ""));
    if (!row || !row.sealed_reply_sk) return null;
    const sessKey = deriveSessionSealKey(masterKey, row.request_id);
    try {
      const opened = openJson(
        row.sealed_reply_sk,
        sessKey,
        `${SESSION_AAD_PREFIX}:${row.request_id}:${row.connect_session_id}`,
      );
      return opened.replySkHex;
    } finally {
      sessKey.fill(0);
    }
  }

  function popIssuedGrantWalletKey(requestId) {
    const row = db
      .prepare(
        "SELECT request_id, connect_session_id, wallet_id, issued_wallet_key_sealed FROM nuri_prf_grant_sessions WHERE request_id = ?",
      )
      .get(String(requestId || ""));
    if (!row || !row.issued_wallet_key_sealed) return null;
    const sessKey = deriveSessionSealKey(masterKey, row.request_id);
    try {
      const opened = openJson(
        row.issued_wallet_key_sealed,
        sessKey,
        `${SESSION_AAD_PREFIX}:key:${row.request_id}:${row.connect_session_id}`,
      );
      db.prepare(
        "UPDATE nuri_prf_grant_sessions SET issued_wallet_key_sealed = NULL, updated_at = ? WHERE request_id = ?",
      ).run(Date.now(), row.request_id);
      return opened.walletKey;
    } finally {
      sessKey.fill(0);
    }
  }

  function markGrantSessionExpired(requestId, nowMs = Date.now()) {
    db.prepare(
      "UPDATE nuri_prf_grant_sessions SET status = 'expired', sealed_reply_sk = NULL, updated_at = ? WHERE request_id = ?",
    ).run(nowMs, String(requestId || ""));
  }

  function finalizeGrantWallet({
    requestId,
    walletId = randomUUID(),
    walletKey = generatePrfWalletKey(),
    credIdB64u,
    slotIndex = 0,
    mainEoa,
    passkeySignerAddress,
    agentEthEoa,
    cosignerEoa,
    safeAddress,
    agentBtcPub33Hex,
    cosignerBtcPub33Hex,
    aggregatedBtcXonlyHex,
    arkadeAddress = null,
    policy = {},
    agentEthPrivHex,
    agentBtcPrivHex,
    nowMs = Date.now(),
  }) {
    if (!isPrfWalletKey(walletKey)) throw new Error("invalid_prf_wallet_key");
    const keyHash = hashWalletKey(walletKey);
    const sealKey = deriveWalletSealKey(masterKey, walletKey, walletId);
    let sealedSecrets;
    try {
      sealedSecrets = sealJson(
        {
          agentEthPrivHex: String(agentEthPrivHex).replace(/^0x/, "").toLowerCase(),
          agentBtcPrivHex: String(agentBtcPrivHex).replace(/^0x/, "").toLowerCase(),
        },
        sealKey,
        `${STORE_AAD_PREFIX}:${walletId}:${credIdB64u}:${slotIndex}:${getAddress(safeAddress)}`,
      );
    } finally {
      sealKey.fill(0);
    }

    db.exec("BEGIN IMMEDIATE");
    try {
      db.prepare(
        `INSERT INTO nuri_prf_agent_wallets (
          wallet_id, wallet_key_hash, cred_id_b64u, slot_index,
          main_eoa, passkey_signer_address, agent_eth_eoa, cosigner_eoa, safe_address,
          agent_btc_pub33_hex, cosigner_btc_pub33_hex, aggregated_btc_xonly_hex, arkade_address,
          policy_json, sealed_secrets, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        walletId,
        keyHash,
        credIdB64u,
        Number(slotIndex),
        getAddress(mainEoa),
        getAddress(passkeySignerAddress),
        getAddress(agentEthEoa),
        getAddress(cosignerEoa),
        getAddress(safeAddress),
        String(agentBtcPub33Hex).toLowerCase(),
        String(cosignerBtcPub33Hex).toLowerCase(),
        String(aggregatedBtcXonlyHex).toLowerCase(),
        arkadeAddress,
        JSON.stringify(policy || {}),
        sealedSecrets,
        nowMs,
        nowMs,
      );

      if (requestId) {
        const sessRow = db
          .prepare("SELECT connect_session_id FROM nuri_prf_grant_sessions WHERE request_id = ?")
          .get(requestId);
        if (sessRow) {
          const sessKey = deriveSessionSealKey(masterKey, requestId);
          let sealedIssuedKey;
          try {
            sealedIssuedKey = sealJson(
              { walletKey },
              sessKey,
              `${SESSION_AAD_PREFIX}:key:${requestId}:${sessRow.connect_session_id}`,
            );
          } finally {
            sessKey.fill(0);
          }
          db.prepare(
            `UPDATE nuri_prf_grant_sessions
                SET status = 'approved',
                    sealed_reply_sk = NULL,
                    wallet_id = ?,
                    issued_wallet_key_sealed = ?,
                    updated_at = ?
              WHERE request_id = ?`,
          ).run(walletId, sealedIssuedKey, nowMs, requestId);
        }
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }

    return {
      walletKey,
      wallet: getWalletById(walletId),
    };
  }

  function getWalletById(walletId) {
    const row = db
      .prepare("SELECT * FROM nuri_prf_agent_wallets WHERE wallet_id = ?")
      .get(String(walletId || ""));
    return mapWalletRow(row);
  }

  function getWalletByKey(walletKey) {
    if (!isPrfWalletKey(walletKey)) return null;
    const row = db
      .prepare("SELECT * FROM nuri_prf_agent_wallets WHERE wallet_key_hash = ?")
      .get(hashWalletKey(walletKey));
    return mapWalletRow(row);
  }

  function findLatestWalletByMainEoa(mainEoa) {
    if (!mainEoa) return null;
    const row = db
      .prepare(
        "SELECT * FROM nuri_prf_agent_wallets WHERE LOWER(main_eoa) = LOWER(?) ORDER BY created_at DESC LIMIT 1",
      )
      .get(String(mainEoa));
    return mapWalletRow(row);
  }

  function unlockWalletSecrets(walletKey) {
    if (!isPrfWalletKey(walletKey)) throw new Error("invalid_prf_wallet_key");
    const row = db
      .prepare("SELECT * FROM nuri_prf_agent_wallets WHERE wallet_key_hash = ?")
      .get(hashWalletKey(walletKey));
    if (!row) throw new Error("wallet_not_found");
    const wallet = mapWalletRow(row);
    const sealKey = deriveWalletSealKey(masterKey, walletKey, wallet.walletId);
    try {
      const secrets = openJson(
        row.sealed_secrets,
        sealKey,
        `${STORE_AAD_PREFIX}:${wallet.walletId}:${wallet.credIdB64u}:${wallet.slotIndex}:${wallet.safeAddress}`,
      );
      return { wallet, secrets };
    } finally {
      sealKey.fill(0);
    }
  }

  function updateWalletArkadeAddress(walletId, arkadeAddress, nowMs = Date.now()) {
    if (!arkadeAddress) return;
    db.prepare(
      "UPDATE nuri_prf_agent_wallets SET arkade_address = ?, updated_at = ? WHERE wallet_id = ?",
    ).run(String(arkadeAddress), nowMs, String(walletId));
  }

  function saveLightningReceive({
    rfqId,
    walletId,
    requestId = null,
    paymentHash,
    invoice,
    payAmountSats,
    expectedAmountSats,
    feeSats = 0,
    expiresAt,
    lockupAddress,
    swapPkScriptHex,
    payoutAddress,
    quoteJson,
    nowMs = Date.now(),
  }) {
    db.prepare(
      `INSERT INTO nuri_prf_lightning_receives (
        rfq_id, wallet_id, request_id, payment_hash, invoice,
        pay_amount_sats, expected_amount_sats, fee_sats, expires_at,
        lockup_address, swap_pk_script_hex, payout_address, quote_json,
        status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
    ).run(
      rfqId,
      walletId,
      requestId,
      paymentHash,
      invoice,
      Number(payAmountSats),
      Number(expectedAmountSats),
      Number(feeSats),
      Number(expiresAt),
      lockupAddress,
      swapPkScriptHex,
      payoutAddress,
      typeof quoteJson === "string" ? quoteJson : JSON.stringify(quoteJson),
      nowMs,
      nowMs,
    );
    return getLightningReceive(rfqId);
  }

  function mapReceiveRow(row) {
    if (!row) return null;
    return {
      rfqId: row.rfq_id,
      walletId: row.wallet_id,
      requestId: row.request_id || null,
      paymentHash: row.payment_hash,
      invoice: row.invoice,
      payAmountSats: Number(row.pay_amount_sats),
      expectedAmountSats: Number(row.expected_amount_sats),
      feeSats: Number(row.fee_sats),
      expiresAt: Number(row.expires_at),
      lockupAddress: row.lockup_address,
      swapPkScriptHex: row.swap_pk_script_hex,
      payoutAddress: row.payout_address,
      quoteJson: row.quote_json,
      status: row.status,
      claimTxid: row.claim_txid || null,
      claimedSats: row.claimed_sats !== null ? Number(row.claimed_sats) : null,
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    };
  }

  function getLightningReceive(rfqId) {
    const row = db
      .prepare("SELECT * FROM nuri_prf_lightning_receives WHERE rfq_id = ?")
      .get(String(rfqId || ""));
    return mapReceiveRow(row);
  }

  function getLightningReceiveByRequest(walletId, requestId) {
    if (!requestId) return null;
    const row = db
      .prepare(
        "SELECT * FROM nuri_prf_lightning_receives WHERE wallet_id = ? AND request_id = ? ORDER BY created_at DESC LIMIT 1",
      )
      .get(String(walletId), String(requestId));
    return mapReceiveRow(row);
  }

  function listPendingLightningReceives(walletId) {
    return db
      .prepare(
        "SELECT * FROM nuri_prf_lightning_receives WHERE wallet_id = ? AND status = 'pending' ORDER BY created_at ASC",
      )
      .all(String(walletId))
      .map(mapReceiveRow);
  }

  function markLightningReceiveClaimed(rfqId, { claimTxid = null, claimedSats = null } = {}, nowMs = Date.now()) {
    db.prepare(
      `UPDATE nuri_prf_lightning_receives
          SET status = 'claimed', claim_txid = ?, claimed_sats = ?, updated_at = ?
        WHERE rfq_id = ?`,
    ).run(claimTxid, claimedSats, nowMs, String(rfqId));
  }

  function getOperation(walletId, requestId) {
    if (!walletId || !requestId) return null;
    const row = db
      .prepare("SELECT * FROM nuri_prf_agent_ops WHERE wallet_id = ? AND request_id = ?")
      .get(String(walletId), String(requestId));
    if (!row) return null;
    return {
      walletId: row.wallet_id,
      requestId: row.request_id,
      action: row.action,
      rail: row.rail,
      status: row.status,
      amountDisplay: row.amount_display || null,
      summary: JSON.parse(row.summary_json || "{}"),
      result: JSON.parse(row.result_json || "{}"),
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    };
  }

  function recordOperation({
    walletId,
    requestId,
    action,
    rail,
    status,
    amountDisplay = null,
    summary = {},
    result = {},
    nowMs = Date.now(),
  }) {
    const reqId = String(requestId || randomUUID());
    db.prepare(
      `INSERT INTO nuri_prf_agent_ops (
        wallet_id, request_id, action, rail, status, amount_display,
        summary_json, result_json, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(wallet_id, request_id) DO UPDATE SET
        status = excluded.status,
        amount_display = COALESCE(excluded.amount_display, nuri_prf_agent_ops.amount_display),
        summary_json = excluded.summary_json,
        result_json = excluded.result_json,
        updated_at = excluded.updated_at`,
    ).run(
      String(walletId),
      reqId,
      String(action),
      String(rail),
      String(status),
      amountDisplay,
      JSON.stringify(summary || {}),
      JSON.stringify(result || {}),
      nowMs,
      nowMs,
    );
    return getOperation(walletId, reqId);
  }

  function listOperations(walletId, { limit = 50 } = {}) {
    return db
      .prepare(
        "SELECT * FROM nuri_prf_agent_ops WHERE wallet_id = ? ORDER BY created_at DESC LIMIT ?",
      )
      .all(String(walletId), Math.max(1, Math.min(200, Number(limit) || 50)))
      .map((row) => ({
        request_id: row.request_id,
        action: row.action,
        rail: row.rail,
        status: row.status,
        ...(row.amount_display ? { amount: row.amount_display } : {}),
        ...JSON.parse(row.summary_json || "{}"),
        created_at: new Date(Number(row.created_at)).toISOString(),
      }));
  }

  function close() {
    masterKey.fill(0);
    db.close();
  }

  return {
    db,
    createGrantSession,
    getGrantSession,
    readGrantSessionReplySk,
    popIssuedGrantWalletKey,
    markGrantSessionExpired,
    finalizeGrantWallet,
    getWalletById,
    getWalletByKey,
    findLatestWalletByMainEoa,
    unlockWalletSecrets,
    updateWalletArkadeAddress,
    saveLightningReceive,
    getLightningReceive,
    getLightningReceiveByRequest,
    listPendingLightningReceives,
    markLightningReceiveClaimed,
    getOperation,
    recordOperation,
    listOperations,
    close,
  };
}
