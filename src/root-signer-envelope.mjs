// Root signer codec: the SAME envelope convention as the local bridge
// (src/browser-bridge.mjs:24-26, decryptEnvelope :721-748; browser side
// encryptForServer in src/privy-bridge-client.mjs:331). The browser encrypts
// to the REGISTERED consumer P-256 key; the broker never holds that key and
// never decrypts. Consumers decrypt here and verify the bindings before any
// durable effect or ACK.
import crypto from "node:crypto";

export const ROOT_SIGNER_VERSION = "nuri-wirex-bridge-v1";
export const ROOT_SIGNER_ENVELOPE_ALG = "P-256-ECDH+A256GCM";
export const ROOT_SIGNER_RESPONSE_INFO = "nuri-wirex-bridge-response";
export const ROOT_SIGNER_PAYLOAD_KIND = "root-signer-result-v1";
export const ROOT_PRIVY_APP_ID = "cmt30ut1500080cjodoqk7xao";
export const ROOT_SIGNER_CONSUMERS = ["wallet", "banking"];
export const ROOT_SIGNER_INTENTS = ["register", "auth"];
export const ROOT_SIGNER_STATUSES = ["pending", "submitted", "consumed", "expired", "cancelled"];
export const RESULT_RETENTION_MS = 300_000;
export const MAX_ENVELOPE_BYTES = 65_536;
export const MAX_REQUEST_MS = 24 * 60 * 60_000;
export const ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^0x[0-9a-fA-F]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const EXTRA_ID = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const MAX_EXTRAS = 8;
const MAX_EXTRA_MESSAGE = 16_384;
// Extra requests are typed DATA executed by the root UI's fixed switch; never code or URLs.
// Reserved ids (C0 §2): agentSignerSignature = wallet derivation message (wallet only);
// privyAccessToken = Privy access token (banking only). Other sign_message ids are caller-owned consent.
const EXTRA_TYPES = { wallet: ["sign_message"], banking: ["sign_message", "privy_access_token"] };
const RESERVED_EXTRA_IDS = { agentSignerSignature: "wallet", privyAccessToken: "banking" };
const SIWE_KEYS = ["domain", "uri", "statement", "chainId", "nonce", "issuedAt", "expirationTime"];

export function newRootSignerId() {
  return crypto.randomBytes(32).toString("base64url");
}

export function readRootSignerId(value, name) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw codeError("invalid_request", `${name}_invalid`);
  return value;
}

// Sanitized immutable approval descriptor: exactly one of signText/signHash/signTypedData/siwe,
// optional consent, optional typed extras. Mirrors the one-request rule of mergeApprovalPayload
// (src/privy-bridge-client.mjs:136-146); siwe = same declarative params as assertSiwe
// (src/browser-bridge.mjs:772-777), rendered by the UI with messageForAddress.
export function readApprovalDescriptor(value, consumerId) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw codeError("invalid_request", "approval_invalid");
  const signText = optionalText(value.signText, "signText", 4096);
  const signHash = value.signHash === undefined || value.signHash === null ? null : value.signHash;
  if (signHash !== null && (typeof signHash !== "string" || !HASH.test(signHash))) throw codeError("invalid_request", "signHash_invalid");
  const signTypedData = value.signTypedData === undefined || value.signTypedData === null ? null : value.signTypedData;
  if (signTypedData !== null && !isTypedData(signTypedData)) throw codeError("invalid_request", "signTypedData_invalid");
  const siwe = value.siwe === undefined || value.siwe === null ? null : readSiwe(value.siwe);
  const consentText = optionalText(value.consentText, "consentText", 4096);
  if ([signText, signHash, signTypedData, siwe].filter((item) => item !== null).length !== 1) throw codeError("invalid_request", "approval_needs_exactly_one_request");
  const extraRequests = [];
  if (value.extraRequests !== undefined) {
    if (!Array.isArray(value.extraRequests) || value.extraRequests.length > MAX_EXTRAS) throw codeError("invalid_request", "extraRequests_invalid");
    const allowed = EXTRA_TYPES[consumerId] || [];
    const ids = new Set();
    for (const extra of value.extraRequests) {
      if (!extra || typeof extra !== "object" || Array.isArray(extra)) throw codeError("invalid_request", "extraRequest_invalid");
      if (typeof extra.id !== "string" || !EXTRA_ID.test(extra.id) || ids.has(extra.id)) throw codeError("invalid_request", "extraRequest_id_invalid");
      if (RESERVED_EXTRA_IDS[extra.id] && RESERVED_EXTRA_IDS[extra.id] !== consumerId) throw codeError("invalid_request", `extraRequest_${extra.id}_not_allowed_for_${consumerId}`);
      if (!allowed.includes(extra.type)) throw codeError("invalid_request", `extraRequest_type_not_allowed_for_${consumerId}`);
      if (extra.id === "privyAccessToken" && extra.type !== "privy_access_token") throw codeError("invalid_request", "extraRequest_privyAccessToken_type");
      if (extra.id === "agentSignerSignature" && extra.type !== "sign_message") throw codeError("invalid_request", "extraRequest_agentSignerSignature_type");
      ids.add(extra.id);
      if (extra.type === "sign_message") {
        if (typeof extra.message !== "string" || extra.message.length < 1 || extra.message.length > MAX_EXTRA_MESSAGE) throw codeError("invalid_request", "extraRequest_message_invalid");
        extraRequests.push({ id: extra.id, type: "sign_message", message: extra.message });
      } else extraRequests.push({ id: extra.id, type: extra.type });
    }
  }
  return { signText, signHash, signTypedData, siwe, consentText, extraRequests };
}

function readSiwe(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw codeError("invalid_request", "siwe_invalid");
  const siwe = {};
  for (const key of SIWE_KEYS) {
    const item = value[key];
    const ok = typeof item === "number" ? Number.isSafeInteger(item) && item > 0 && key === "chainId"
      : typeof item === "string" && item.length > 0 && item.length <= 4096 && (key === "statement" || !/[\r\n]/.test(item));
    if (!ok) throw codeError("invalid_request", `siwe_${key}_invalid`);
    siwe[key] = item;
  }
  if (value.version !== undefined) {
    if (value.version !== 1 && value.version !== "1") throw codeError("invalid_request", "siwe_version_invalid");
    siwe.version = value.version;
  }
  return siwe;
}

export function readRootSignerEnvelope(value, state) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw codeError("envelope_invalid", "envelope_not_object");
  if (value.version !== ROOT_SIGNER_VERSION) throw codeError("envelope_invalid", "envelope_version");
  if (value.alg !== ROOT_SIGNER_ENVELOPE_ALG) throw codeError("envelope_invalid", "envelope_alg");
  if (typeof value.state !== "string" || value.state !== state) throw codeError("envelope_invalid", "envelope_state_mismatch");
  for (const field of ["epk", "iv", "ciphertext"]) {
    if (typeof value[field] !== "string" || !value[field] || !B64URL.test(value[field])) throw codeError("envelope_invalid", `envelope_${field}`);
  }
  if (Buffer.from(value.epk, "base64url").length !== 65 || Buffer.from(value.iv, "base64url").length !== 12) throw codeError("envelope_invalid", "envelope_key_or_iv_length");
  const envelope = { version: value.version, state: value.state, alg: value.alg, epk: value.epk, iv: value.iv, ciphertext: value.ciphertext };
  if (Buffer.byteLength(JSON.stringify(envelope)) > MAX_ENVELOPE_BYTES) throw codeError("envelope_too_large", "envelope_too_large");
  return envelope;
}

// Digest over the frozen ciphertext bytes (fixed field order); the ACK binds to it.
export function envelopeDigest(envelope) {
  const fixed = readRootSignerEnvelope(envelope, envelope?.state);
  return crypto.createHash("sha256").update(JSON.stringify(fixed)).digest("hex");
}

// Consumer side. privateKey: 32-byte P-256 scalar as base64url (never leaves the consumer).
export function decryptRootSignerEnvelope(envelope, { privateKey, state }) {
  const fixed = readRootSignerEnvelope(envelope, state);
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(privateKey, "base64url"));
  const sharedSecret = ecdh.computeSecret(Buffer.from(fixed.epk, "base64url"));
  const salt = crypto.createHash("sha256").update(`${ROOT_SIGNER_VERSION}:${state}`).digest();
  const key = Buffer.from(crypto.hkdfSync("sha256", sharedSecret, salt, Buffer.from(ROOT_SIGNER_RESPONSE_INFO), 32));
  const encrypted = Buffer.from(fixed.ciphertext, "base64url");
  if (encrypted.length < 17) throw codeError("envelope_invalid", "ciphertext_too_short");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(fixed.iv, "base64url"));
  decipher.setAuthTag(encrypted.subarray(encrypted.length - 16));
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(encrypted.subarray(0, encrypted.length - 16)), decipher.final()]);
    return JSON.parse(plaintext.toString("utf8"));
  } finally {
    for (const buffer of [sharedSecret, salt, key, plaintext]) if (buffer) { crypto.randomFillSync(buffer); buffer.fill(0); }
  }
}

// Bindings the consumer MUST check before any effect (same pins as the local bridge:
// version/state/intent, plus request/consumer/app/expiry). Signatures and the address
// are verified by the consumer with its own existing verification code.
export function assertRootSignerPayload(payload, expected) {
  if (!payload || typeof payload !== "object") throw codeError("payload_invalid", "payload_not_object");
  if (payload.version !== ROOT_SIGNER_VERSION) throw codeError("payload_invalid", "payload_version_mismatch");
  if (payload.kind !== ROOT_SIGNER_PAYLOAD_KIND) throw codeError("payload_invalid", "payload_kind_mismatch");
  for (const field of ["requestId", "consumerId", "state", "intent", "privyAppId"]) {
    if (payload[field] !== expected[field]) throw codeError("payload_invalid", `payload_${field}_mismatch`);
  }
  if (payload.expiresAt !== expected.expiresAt) throw codeError("payload_invalid", "payload_expiresAt_mismatch");
  if (expected.expectedAddress && String(payload.address).toLowerCase() !== expected.expectedAddress.toLowerCase()) throw codeError("payload_invalid", "payload_address_mismatch");
  if (typeof payload.address !== "string" || !ADDRESS.test(payload.address)) throw codeError("payload_invalid", "payload_address_invalid");
  if (typeof payload.signature !== "string" || !payload.signature || payload.signature.length > 4096) throw codeError("payload_invalid", "payload_signature_invalid");
  if (typeof payload.message !== "string") throw codeError("payload_invalid", "payload_message_invalid");
  assertNoSecretFieldNames(payload);
  return payload;
}

// Narrow helper for the deploy writer / consumer key generation (same ECDH usage as
// src/browser-bridge.mjs:243). Returns base64url raw public key (65 bytes) and private scalar.
export function createConsumerResultKeyPair() {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  return { publicKey: ecdh.getPublicKey().toString("base64url"), privateKey: ecdh.getPrivateKey().toString("base64url") };
}

export function isP256PublicKey(value) {
  if (typeof value !== "string" || !B64URL.test(value)) return false;
  const bytes = Buffer.from(value, "base64url");
  return bytes.length === 65 && bytes[0] === 0x04;
}

export function codeError(code, detail = code, status = 400) {
  return Object.assign(new Error(detail), { code, status });
}

function optionalText(value, name, max) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !value.trim() || value.length > max) throw codeError("invalid_request", `${name}_invalid`);
  return value;
}

function isTypedData(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!value.domain || !value.types || typeof value.primaryType !== "string" || !value.primaryType || !value.message) return false;
  return JSON.stringify(value).length <= 32_768;
}

function assertNoSecretFieldNames(value, path = "$") {
  if (Array.isArray(value)) { value.forEach((item, index) => assertNoSecretFieldNames(item, `${path}[${index}]`)); return; }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (/(^|[_-])(private|secret|seed|mnemonic|xprv)([_-]|$)|privatekey/i.test(key)) throw codeError("payload_invalid", `payload_contains_secret_field:${path}.${key}`);
    assertNoSecretFieldNames(child, `${path}.${key}`);
  }
}
