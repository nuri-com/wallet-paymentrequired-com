















import { DatabaseSync } from "node:sqlite";
import { mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";

export const SPEND_POLICY_DEFAULTS = { per_payment: "50", per_day: "200" }; // kept for mcp-bank.mjs description text
export const SPEND_POLICY_WINDOW_MS = 24 * 60 * 60 * 1000;


const CURRENCY_SCALE = { EUR: 2, USD: 2, GBP: 2, BRL: 2, MXN: 2, INR: 2, CNY: 2, HKD: 2, IDR: 0, NGN: 2, AED: 2, COP: 2, PHP: 2, USDC: 6, EURC: 6 };


const SCALE = 6n, UNIT = 10n ** SCALE;
const DECIMAL = /^(0|[1-9]\d*)(\.\d+)?$/;

function toFace(amount, label) {
  if (typeof amount !== "string" || !DECIMAL.test(amount)) throw new Error(`spend_limit_amount_invalid: ${label}`);
  const [whole, fraction = ""] = amount.split(".");
  if (fraction.length > Number(SCALE)) throw new Error(`spend_limit_amount_precision: ${label}`);
  return BigInt(whole) * UNIT + BigInt(fraction.padEnd(Number(SCALE), "0"));
}


function faceOf(amount, currency) {
  const fraction = String(amount).split(".")[1] ?? "";
  if (fraction.length > (CURRENCY_SCALE[currency] ?? 2)) throw new Error(`spend_limit_amount_precision: payment`);
  return toFace(amount, "payment");
}
function fromFace(scaled, currency) {
  const scale = CURRENCY_SCALE[currency] ?? 2;
  const padded = scaled.toString().padStart(Number(SCALE) + 1, "0");
  const whole = padded.slice(0, -Number(SCALE)) || "0";
  let fraction = padded.slice(-Number(SCALE)).slice(0, scale).replace(/0+$/, "");
  if (scale >= 2) fraction = fraction.padEnd(2, "0"); 
  return `${whole}${fraction ? `.${fraction}` : ""} ${currency}`;
}
const exceeded = message => {
  const error = new Error(`spend_limit_exceeded: ${message}`);
  return error;
};

export function createSpendPolicy({ path } = {}) {
  if (typeof path !== "string" || !path) throw new Error("spend_policy_db_path_required");
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  if (path !== ":memory:") chmodSync(path, 0o600);
  db.exec(`PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS agent_spend_events (
      ref TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      currency TEXT NOT NULL,
      amount_minor INTEGER NOT NULL,
      spent_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS agent_spend_owner_currency ON agent_spend_events(owner, currency, spent_at);
    CREATE INDEX IF NOT EXISTS agent_spend_owner_time ON agent_spend_events(owner, spent_at);
    CREATE TABLE IF NOT EXISTS spend_policy (
      owner TEXT PRIMARY KEY,
      per_payment TEXT NOT NULL,
      per_day TEXT NOT NULL,
      updated_at INTEGER NOT NULL,
      approval_ref TEXT
    );
    CREATE TABLE IF NOT EXISTS spend_policy_requests (
      id TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      per_payment TEXT NOT NULL,
      per_day TEXT NOT NULL,
      nonce TEXT NOT NULL,
      sign_text TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      approval_id TEXT,
      approval_url TEXT,
      state TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );`);
  // Limits are owner-set only (D-LIMITS-ONE-PLACE): no env ceiling, and a field
  // may be NULL ("no limit on that one"). Old tables stored both NOT NULL —
  // rebuild them once when the column still forbids it, and add the pending
  // request's per-scope payload.
  if (db.prepare("PRAGMA table_info(spend_policy)").all().some(c => c.name === "per_payment" && c.notnull)) {
    db.exec(`BEGIN IMMEDIATE;
      CREATE TABLE spend_policy_new(owner TEXT PRIMARY KEY, per_payment TEXT, per_day TEXT, updated_at INTEGER NOT NULL, approval_ref TEXT);
      INSERT INTO spend_policy_new SELECT owner, per_payment, per_day, updated_at, approval_ref FROM spend_policy;
      DROP TABLE spend_policy; ALTER TABLE spend_policy_new RENAME TO spend_policy; COMMIT;`);
  }
  if (!db.prepare("PRAGMA table_info(spend_policy_requests)").all().some(c => c.name === "payload"))
    db.exec("ALTER TABLE spend_policy_requests ADD COLUMN payload TEXT");
  const insertEvent = db.prepare("INSERT OR IGNORE INTO agent_spend_events (ref, owner, currency, amount_minor, spent_at) VALUES (?, ?, ?, ?, ?)");
  const spentStmt = db.prepare("SELECT COALESCE(SUM(amount_minor), 0) AS total FROM agent_spend_events WHERE owner=? AND spent_at > ?");
  
  
  const spentExcludingStmt = db.prepare("SELECT COALESCE(SUM(amount_minor), 0) AS total FROM agent_spend_events WHERE owner=? AND spent_at > ? AND ref != ?");
  const getPolicy = db.prepare("SELECT per_payment, per_day FROM spend_policy WHERE owner=?");
  const putPolicy = db.prepare("INSERT INTO spend_policy (owner, per_payment, per_day, updated_at, approval_ref) VALUES (?,?,?,?,?) ON CONFLICT(owner) DO UPDATE SET per_payment=excluded.per_payment, per_day=excluded.per_day, updated_at=excluded.updated_at, approval_ref=excluded.approval_ref");
  const insRequest = db.prepare("INSERT INTO spend_policy_requests (id, owner, per_payment, per_day, nonce, sign_text, expires_at, approval_id, approval_url, state, created_at, payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
  const getRequest = db.prepare("SELECT * FROM spend_policy_requests WHERE id=?");
  const updRequest = db.prepare("UPDATE spend_policy_requests SET state=?, approval_id=?, approval_url=? WHERE id=?");

  
  
  function policy(owner) {
    const key = String(owner ?? "").toLowerCase();
    const row = key ? getPolicy.get(key) : null;
    const spentScaled = BigInt(spentStmt.get(key, Date.now() - SPEND_POLICY_WINDOW_MS)?.total ?? 0);
    const perDay = row?.per_day ?? null;
    const remaining = perDay === null ? null
      : (() => { const r = toFace(perDay, "per_day") - spentScaled; return fromFace(r > 0n ? r : 0n, "USD").replace(/ USD$/, ""); })();
    return { per_payment: row?.per_payment ?? null, per_day: perDay,
      spent_24h: fromFace(spentScaled, "USD").replace(/ USD$/, ""), remaining_24h: remaining };
  }

  function guard({ owner, amount, currency, ref }) {
    const key = String(owner ?? "").toLowerCase();
    if (!key) throw new Error("spend_limit_owner_required");
    if (!(currency in CURRENCY_SCALE)) throw new Error(`spend_limit_currency_unsupported: ${currency}`);
    const row = getPolicy.get(key);
    if (!row) return; // no owner-set limits (D-LIMITS-ONE-PLACE): nothing to check
    const face = faceOf(amount, currency);
    if (row.per_payment !== null && face > toFace(row.per_payment, "per_payment"))
      throw exceeded(`This payment cannot be sent. ${fromFace(face, currency)} is above your ${fromFace(toFace(row.per_payment, "per_payment"), currency)} limit for one payment. Try a smaller amount or wait until older payments are more than 24 hours old.`);
    const spent = BigInt((ref ? spentExcludingStmt : spentStmt).get(...(ref ? [key, Date.now() - SPEND_POLICY_WINDOW_MS, ref] : [key, Date.now() - SPEND_POLICY_WINDOW_MS]))?.total ?? 0);
    if (row.per_day !== null && spent + face > toFace(row.per_day, "per_day"))
      throw exceeded(`This payment cannot be sent. ${fromFace(face, currency)} would pass your ${fromFace(toFace(row.per_day, "per_day"), currency)} total for 24 hours. Try a smaller amount or wait until older payments are more than 24 hours old.`);
  }

  function record({ owner, amount, currency, ref, spentAt = Date.now() }) {
    if (typeof ref !== "string" || !ref) throw new Error("spend_limit_record_ref_required");
    if (!(currency in CURRENCY_SCALE)) throw new Error(`spend_limit_currency_unsupported: ${currency}`);
    if (!getPolicy.get(String(owner).toLowerCase())) return; // nothing limits this owner — skip the event row
    insertEvent.run(ref, String(owner).toLowerCase(), currency, Number(faceOf(amount, currency)), spentAt);
  }

  
  
  const release = ref => db.prepare("DELETE FROM agent_spend_events WHERE ref=?").run(ref).changes;

  function hasPolicy(owner) {
    const key = String(owner ?? "").toLowerCase();
    return Boolean(key && getPolicy.get(key));
  }

  function clearPolicy(owner) {
    const key = String(owner ?? "").toLowerCase();
    db.prepare("DELETE FROM spend_policy WHERE owner=?").run(key);
    return policy(key);
  }

  function setPolicy(owner, { per_payment, per_day }, { approval_ref = null } = {}) {
    const key = String(owner ?? "").toLowerCase();
    if (!key) throw new Error("spend_limit_owner_required");
    const current = getPolicy.get(key) ?? {};
    const merged = { per_payment, per_day };
    for (const name of ["per_payment", "per_day"]) {
      if (merged[name] === undefined) merged[name] = current[name] ?? null; // missing keeps the current value
      if (merged[name] !== null && (typeof merged[name] !== "string" || !DECIMAL.test(merged[name]) || !/[1-9]/.test(merged[name])))
        throw new Error(`limit_invalid: ${name} must be a positive amount, for example 25.00.`);
    }
    putPolicy.run(key, merged.per_payment, merged.per_day, Date.now(), approval_ref);
    return policy(key);
  }

  function createRequest({ id, owner, per_payment, per_day, nonce, signText, expiresAt, payload }) {
    insRequest.run(id, String(owner).toLowerCase(), per_payment ?? "", per_day ?? "", nonce, signText, expiresAt, null, null, "awaiting_approval", Date.now(), payload ?? null);
    return getRequest.get(id);
  }
  const request = id => getRequest.get(id);
  const pendingRequests = owner => db.prepare(
    "SELECT id, state, created_at FROM spend_policy_requests WHERE owner=? AND state='awaiting_approval' ORDER BY created_at DESC LIMIT 10")
    .all(String(owner ?? "").toLowerCase()).map(row => ({ kind: "limits", id: row.id, status: row.state, since: row.created_at ? new Date(row.created_at).toISOString() : null }));
  function updateRequest(id, { state, approvalId, approvalUrl }) {
    updRequest.run(state, approvalId ?? null, approvalUrl ?? null, id);
    return getRequest.get(id);
  }

  return { policy, guard, record, release, setPolicy, hasPolicy, clearPolicy, createRequest, request, pendingRequests, updateRequest,
    windowMs: SPEND_POLICY_WINDOW_MS, close: () => db.close() };
}
