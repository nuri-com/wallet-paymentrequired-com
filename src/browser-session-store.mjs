import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";













export function createBrowserSessionStore({ path } = {}) {
  if (!path) return null;
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  if (path !== ":memory:") chmodSync(path, 0o600);
  db.exec(`
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS connection_sessions (
      session_id   TEXT PRIMARY KEY,
      token_sha256 TEXT,
      account      TEXT,
      signer_kind  TEXT,
      connected_at INTEGER,
      expires_at   INTEGER NOT NULL,
      data         TEXT NOT NULL
    ) STRICT;
  `);
  
  
  
  
  const upsert = db.prepare(`
    INSERT INTO connection_sessions (session_id, token_sha256, account, signer_kind, connected_at, expires_at, data)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      token_sha256 = COALESCE(excluded.token_sha256, connection_sessions.token_sha256),
      account      = COALESCE(excluded.account, connection_sessions.account),
      signer_kind  = excluded.signer_kind,
      connected_at = COALESCE(connection_sessions.connected_at, excluded.connected_at),
      expires_at   = excluded.expires_at,
      data         = excluded.data
  `);
  const byId = db.prepare("SELECT * FROM connection_sessions WHERE session_id = ?");
  const drop = db.prepare("DELETE FROM connection_sessions WHERE session_id = ?");
  const dropExpired = db.prepare("DELETE FROM connection_sessions WHERE expires_at <= ?");

  return {
    save({ sessionId, tokenSha256 = null, account = null, signerKind = null, connectedAt = null, expiresAt, data }) {
      upsert.run(sessionId, tokenSha256, account, signerKind, connectedAt, expiresAt, data);
    },
    load(sessionId) {
      return byId.get(sessionId) ?? null;
    },
    remove(sessionId) {
      return drop.run(sessionId).changes > 0;
    },
    purgeExpired(now = Date.now()) {
      return dropExpired.run(now).changes;
    },
    close() {
      db.close();
    },
  };
}














export function createRemoteSignerSessionStore({ path } = {}) {
  if (!path) return null;
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  if (path !== ":memory:") chmodSync(path, 0o600);
  db.exec(`
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS remote_signer_sessions (
      session_id        TEXT PRIMARY KEY,
      signer_session_id TEXT NOT NULL,
      expires_at        INTEGER NOT NULL,
      data              TEXT NOT NULL
    ) STRICT;
  `);
  const upsert = db.prepare(`
    INSERT INTO remote_signer_sessions (session_id, signer_session_id, expires_at, data)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      signer_session_id = excluded.signer_session_id,
      expires_at        = excluded.expires_at,
      data              = excluded.data
  `);
  const byId = db.prepare("SELECT * FROM remote_signer_sessions WHERE session_id = ?");
  const drop = db.prepare("DELETE FROM remote_signer_sessions WHERE session_id = ?");
  const dropExpired = db.prepare("DELETE FROM remote_signer_sessions WHERE expires_at <= ?");

  return {
    save({ sessionId, signerSessionId, expiresAt, data }) {
      upsert.run(sessionId, signerSessionId, expiresAt, data);
    },
    load(sessionId) {
      return byId.get(sessionId) ?? null;
    },
    remove(sessionId) {
      return drop.run(sessionId).changes > 0;
    },
    purgeExpired(now = Date.now()) {
      return dropExpired.run(now).changes;
    },
    close() {
      db.close();
    },
  };
}
