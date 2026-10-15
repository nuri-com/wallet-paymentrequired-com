










import { createCipheriv, createDecipheriv, createECDH, createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import { verifyMessage } from "ethers";




export const AGENT_SIGNER_MESSAGE = "Nuri agent signer v1";

const DOMAIN = Buffer.from("nuri/agent-signer/v1\0", "utf8");


const P256_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

export const AGENT_SIGNER_MIN_SECRET_BYTES = 16;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}



export function scalarFromSeed(seed) {
  let s = BigInt(`0x${Buffer.from(seed).toString("hex")}`);
  let material = Buffer.from(seed);
  
  while (s === 0n || s >= P256_N) {
    material = sha256(material);
    s = BigInt(`0x${material.toString("hex")}`);
  }
  return material.subarray(0, 32);
}

export function keypairFromScalar(scalar32) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(scalar32));
  const uncompressed = ecdh.getPublicKey(null, "uncompressed");
  const privateKey = createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: uncompressed.subarray(1, 33).toString("base64url"),
      y: uncompressed.subarray(33, 65).toString("base64url"),
      d: Buffer.from(scalar32).toString("base64url"),
    },
    format: "jwk",
  })
    .export({ type: "pkcs8", format: "der" })
    .toString("base64");
  
  const publicKey = createPublicKey({ key: Buffer.from(privateKey, "base64"), format: "der", type: "pkcs8" })
    .export({ type: "spki", format: "der" })
    .toString("base64");
  return { publicKey, privateKey };
}









export function deriveAgentSignerKeypair(secretBytes) {
  if (typeof secretBytes === "string") throw new Error("agent_signer_secret_invalid");
  if (!Buffer.isBuffer(secretBytes) && !(secretBytes instanceof Uint8Array)) {
    throw new Error("agent_signer_secret_invalid");
  }
  const secret = Buffer.from(secretBytes);
  if (secret.length === 0) throw new Error("agent_signer_secret_required");
  if (secret.length < AGENT_SIGNER_MIN_SECRET_BYTES) throw new Error("agent_signer_secret_too_short");
  const seed = sha256(Buffer.concat([DOMAIN, secret]));
  
  
  
  const scalar = scalarFromSeed(seed);
  const out = keypairFromScalar(scalar);
  scalar.fill(0);
  seed.fill(0);
  secret.fill(0);
  return out;
}















const HEX_SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}$/;






export function signatureSourceToBytes(value) {
  if (typeof value === "string") {
    
    
    if (value.length !== 132 || !HEX_SIGNATURE_PATTERN.test(value)) throw new Error("agent_signer_secret_invalid");
    const bytes = Buffer.from(value.slice(2), "hex");
    if (bytes.length !== 65) throw new Error("agent_signer_secret_invalid");
    return bytes;
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  throw new Error("agent_signer_secret_invalid");
}









export async function assertDeterministicSigner(signMessage, expectedPublicKey = null) {
  if (typeof signMessage !== "function") throw new Error("agent_signer_source_invalid");
  if (expectedPublicKey !== null && typeof expectedPublicKey !== "string") {
    throw new Error("agent_signer_source_invalid");
  }
  const first = deriveAgentSignerKeypair(signatureSourceToBytes(await signMessage(AGENT_SIGNER_MESSAGE)));
  const second = deriveAgentSignerKeypair(signatureSourceToBytes(await signMessage(AGENT_SIGNER_MESSAGE)));
  const match =
    first.publicKey === second.publicKey && first.privateKey === second.privateKey;
  if (!match) throw new Error("wallet_not_deterministic");
  if (expectedPublicKey !== null && first.publicKey !== expectedPublicKey) {
    throw new Error("agent_signer_key_mismatch");
  }
  return first;
}

// Custody v2, LLM key after connect (owner 2026-09-25): the EOA-derived key is NOT kept by the
// server. The tap derives it, seals it to a P-256 public key only the LLM can open (the guest
// wallet_key's model key, or the connect session's pass), and the LLM gets it back once as its
// new wallet_key. Between the tap and that call only the sealed box exists (ECIES: ephemeral
// P-256 ECDH -> HKDF-SHA256 -> AES-256-GCM); the server cannot open it.

// Verifies the tap's signature over AGENT_SIGNER_MESSAGE and returns the 32-byte scalar + keys.
// The caller zeroes `scalar` once it has sealed it.
export function deriveAgentSignerFromSignature(owner, signature) {
  const expected = String(owner || "").toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(expected)) throw new Error("agent_signer_owner_invalid");
  if (verifyMessage(AGENT_SIGNER_MESSAGE, signature).toLowerCase() !== expected) throw new Error("agent_signer_signature_mismatch");
  const secret = signatureSourceToBytes(signature);
  const seed = sha256(Buffer.concat([DOMAIN, secret]));
  const scalar = Buffer.from(scalarFromSeed(seed));
  seed.fill(0); secret.fill(0);
  return { scalar, ...keypairFromScalar(scalar) };
}

const BOX_INFO = Buffer.from("nuri/agent-key-box/v1", "utf8");
const spki = (b64) => createPublicKey({ key: Buffer.from(String(b64).replace(/\s/g, ""), "base64"), format: "der", type: "spki" });
const pkcs8 = (b64) => createPrivateKey({ key: Buffer.from(String(b64), "base64"), format: "der", type: "pkcs8" });
function boxKey(shared, ephemeralPublic) {
  return Buffer.from(hkdfSync("sha256", shared, ephemeralPublic, BOX_INFO, 32));
}

// Seal bytes to a P-256 SPKI public key (base64). Output: "eph.iv.body" base64url.
export function sealToPublicKey(recipientPublicKey, plaintext) {
  const eph = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const ephDer = eph.publicKey.export({ type: "spki", format: "der" });
  const key = boxKey(diffieHellman({ privateKey: eph.privateKey, publicKey: spki(recipientPublicKey) }), ephDer);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()]);
  key.fill(0);
  return [ephDer, iv, body].map((b) => b.toString("base64url")).join(".");
}

// Opens a box with the recipient's PKCS8 private key (base64). null when it does not open.
export function openWithPrivateKey(recipientPrivateKey, sealed) {
  try {
    const [ephDer, iv, body] = String(sealed).split(".").map((p) => Buffer.from(p, "base64url"));
    const key = boxKey(diffieHellman({ privateKey: pkcs8(recipientPrivateKey), publicKey: createPublicKey({ key: ephDer, format: "der", type: "spki" }) }), ephDer);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(body.subarray(body.length - 16));
    const out = Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()]);
    key.fill(0);
    return out;
  } catch { return null; }
}

// The connected wallet_key: version 0x03 ++ the EOA-derived scalar ++ the wallet's UUID bytes
// (66 chars base64url). The UUID keeps each wallet's access hash unique, because one EOA derives
// the same scalar for every wallet it owns.
export function connectedWalletKey(scalar, walletId) {
  const id = Buffer.from(String(walletId).replace(/-/g, ""), "hex");
  if (Buffer.from(scalar).length !== 32 || id.length !== 16) throw new Error("connected_wallet_key_invalid");
  return Buffer.concat([Buffer.from([3]), Buffer.from(scalar), id]).toString("base64url");
}
