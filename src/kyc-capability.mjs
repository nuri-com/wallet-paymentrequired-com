import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";

const VERSION = "v1";
const KEY_CONTEXT = Buffer.from("nuri-kyc-capability-key-v1");
const AAD_CONTEXT = "nuri-kyc-capability-v1";
const IV_BYTES = 12;
const TAG_BYTES = 16;
const ADDRESS_BYTES = 20;
const BODY_BYTES = IV_BYTES + TAG_BYTES + ADDRESS_BYTES;
const SECRET_BYTES = 32;
const SECRET_TEXT_CHARS = 43;
const USERNAME_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?$/;


export function normalizeKycUsername(value) {
  const username = String(value || "").trim().toLowerCase();
  return USERNAME_PATTERN.test(username) ? username : null;
}

export function kycCapabilityConfigured(secret) {
  const bytes = decodeSecret(secret);
  if (!bytes) return false;
  bytes.fill(0);
  return true;
}

export function createKycCapabilityLimiter({
  windowMs = 5 * 60_000,
  maxHits = 10,
  maxEntries = 10_000,
  clock = Date.now,
} = {}) {
  if (![windowMs, maxHits, maxEntries].every((value) => Number.isSafeInteger(value) && value > 0)) {
    throw new Error("kyc_limiter_config_invalid");
  }
  const rows = new Map();
  return {
    isLimited(fingerprint) {
      const key = String(fingerprint || "");
      const now = clock();
      let row = rows.get(key);
      if (row && now - row.startedAt >= windowMs) {
        rows.delete(key);
        row = null;
      } else if (row) {
        rows.delete(key); 
      }
      if (!row) {
        if (rows.size >= maxEntries) rows.delete(rows.keys().next().value);
        row = { startedAt: now, count: 0 };
      }
      row.count += 1;
      rows.set(key, row);
      return row.count > maxHits;
    },
    get size() { return rows.size; },
  };
}



export function sealKycCapability(secret, address, audience, username) {
  const normalized = String(address || "").trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) throw new Error("address_required");
  const source = decodeSecret(secret);
  if (!source) throw new Error("kyc_capability_unconfigured");
  let key;
  let plaintext;
  try {
    const aad = capabilityAad(audience, username);
    key = deriveKey(source, aad);
    const iv = randomBytes(IV_BYTES);
    plaintext = Buffer.from(normalized.slice(2), "hex");
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${VERSION}.${Buffer.concat([iv, tag, ciphertext]).toString("base64url")}`;
  } finally {
    key?.fill(0);
    plaintext?.fill(0);
    source.fill(0);
  }
}


export function openKycCapability(secret, token, audience, username) {
  const source = decodeSecret(secret);
  if (!source) return null;
  let key;
  let plaintext;
  try {
    const aad = capabilityAad(audience, username);
    const match = /^v1\.([A-Za-z0-9_-]{64})$/.exec(String(token || ""));
    if (!match) return null;
    const body = Buffer.from(match[1], "base64url");
    if (body.length !== BODY_BYTES) return null;

    key = deriveKey(source, aad);
    const iv = body.subarray(0, IV_BYTES);
    const tag = body.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
    const ciphertext = body.subarray(IV_BYTES + TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length !== ADDRESS_BYTES) return null;
    return `0x${plaintext.toString("hex")}`;
  } catch {
    return null;
  } finally {
    key?.fill(0);
    plaintext?.fill(0);
    source.fill(0);
  }
}

export function kycCapabilityFingerprint(token) {
  return createHash("sha256").update(String(token || "")).digest("hex").slice(0, 16);
}

function deriveKey(secret, aad) {
  return Buffer.from(hkdfSync("sha256", secret, KEY_CONTEXT, aad, 32));
}

function capabilityAad(audience, username) {
  const origin = new URL(String(audience || "")).origin;
  if (!origin || origin === "null") throw new Error("kyc_capability_audience_required");
  const base = `${AAD_CONTEXT}\0${origin}`;
  if (username === undefined || username === null || username === "") return Buffer.from(base);
  const normalizedUsername = normalizeKycUsername(username);
  if (!normalizedUsername) throw new Error("kyc_capability_username_invalid");
  return Buffer.from(`${base}\0${normalizedUsername}`);
}

function decodeSecret(secret) {
  const text = Buffer.isBuffer(secret) ? secret.toString("utf8") : String(secret || "");
  if (text.length !== SECRET_TEXT_CHARS || !/^[A-Za-z0-9_-]{43}$/.test(text)) return null;
  const bytes = Buffer.from(text, "base64url");
  if (bytes.length !== SECRET_BYTES || bytes.toString("base64url") !== text) return null;
  if (new Set(bytes).size < 16) {
    bytes.fill(0);
    return null;
  }
  return bytes;
}
