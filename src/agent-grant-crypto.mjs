// Frozen deterministic Agent child-key derivation (`nuri-agent-wallet-v1`),
// ECDH + HKDF-SHA256 + XChaCha20-Poly1305 reply decryption (`nuri-agent-grant-reply-v1`),
// and connect.nuri.com MCP client for `wallet_sign_start` / `wallet_sign_result`
// (`operation: "agent_grant"`).
import { createHash, randomBytes } from "node:crypto";
import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { bech32m } from "@scure/base";
import { HDKey } from "@scure/bip32";
import { getAddress, verifyMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";

export const AGENT_DERIVATION_VERSION = "nuri-agent-wallet-v1";
export const AGENT_GRANT_REPLY_FORMAT = "nuri-agent-grant-reply-v1";
export const AGENT_WALLET_SALT_DOMAIN = "app:nuri.com|agent-wallet|v1";
export const AGENT_REPLY_SALT_DOMAIN = "nuri-agent-grant-reply-v1";
export const AGENT_BIP86_PATH = "m/86'/0'/0'/0/0";
export const AGENT_ETH_PATH = "m/44'/60'/0'/0/0";
export const MAX_AGENT_INDEX = 1_000_000;
export const DEFAULT_CONNECT_URL = "https://connect.nuri.com";

const AGENT_WALLET_SALT = sha256(new TextEncoder().encode(AGENT_WALLET_SALT_DOMAIN));
const AGENT_REPLY_SALT = new TextEncoder().encode(AGENT_REPLY_SALT_DOMAIN);

function utf8(value) {
  return new TextEncoder().encode(value);
}

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

export function zeroizeBytes(buf) {
  if (!buf) return;
  buf.fill(0);
}

export function assertValidAgentIndex(index = 0) {
  const num = Number(index);
  if (!Number.isSafeInteger(num) || num < 0 || num > MAX_AGENT_INDEX) {
    throw new Error("agent_index_invalid");
  }
  return num;
}

export function agentEthereumInfoString(index) {
  return `app:nuri.com|agent-wallet|v1|chain=ethereum|fmt=secp256k1|index=${assertValidAgentIndex(index)}`;
}

export function agentBitcoinInfoString(index) {
  return `app:nuri.com|agent-wallet|v1|chain=bitcoin|fmt=taproot|index=${assertValidAgentIndex(index)}`;
}

function taprootSingleSigAddress(compressedPubkey33) {
  const internal = compressedPubkey33.slice(1);
  const tag = sha256(utf8("TapTweak"));
  const tweak = sha256(new Uint8Array([...tag, ...tag, ...internal]));
  const tweakScalar = BigInt(`0x${bytesToHex(tweak)}`) % secp256k1.CURVE.n;
  const point = secp256k1.ProjectivePoint.fromHex(compressedPubkey33).add(
    secp256k1.ProjectivePoint.BASE.multiply(tweakScalar),
  );
  const tweakedXOnly = point.toRawBytes(true).slice(1);
  return bech32m.encode("bc", [1, ...bech32m.toWords(tweakedXOnly)]);
}

export function deriveAgentWallet(prf, index = 0) {
  if (!(prf instanceof Uint8Array) || prf.byteLength < 32) {
    throw new Error("agent_prf_invalid");
  }
  const idx = assertValidAgentIndex(index);
  const ethEntropy = hkdf(sha256, prf, AGENT_WALLET_SALT, utf8(agentEthereumInfoString(idx)), 32);
  const btcEntropy = hkdf(sha256, prf, AGENT_WALLET_SALT, utf8(agentBitcoinInfoString(idx)), 32);
  const ethRoot = HDKey.fromMasterSeed(ethEntropy);
  const btcRoot = HDKey.fromMasterSeed(btcEntropy);
  const ethChild = ethRoot.derive(AGENT_ETH_PATH);
  const btcChild = btcRoot.derive(AGENT_BIP86_PATH);
  try {
    if (!ethChild.privateKey || !ethChild.publicKey || !btcChild.privateKey || !btcChild.publicKey) {
      throw new Error("agent_wallet_derivation_failed");
    }
    const agentEthPrivateKey = new Uint8Array(ethChild.privateKey);
    const agentBtcPrivateKey = new Uint8Array(btcChild.privateKey);
    const ethHex = `0x${bytesToHex(agentEthPrivateKey)}`;
    const ethEoa = getAddress(privateKeyToAccount(ethHex).address);
    const btcPub33 = new Uint8Array(btcChild.publicKey);
    const ethPub33 = new Uint8Array(ethChild.publicKey);
    const btcXOnly = schnorr.getPublicKey(agentBtcPrivateKey);
    return {
      public: {
        derivation_version: AGENT_DERIVATION_VERSION,
        index: idx,
        agent_eth_eoa: ethEoa,
        agent_eth_public_key_33_hex: bytesToHex(ethPub33),
        agent_btc_public_key_33_hex: bytesToHex(btcPub33),
        agent_btc_xonly_pubkey_hex: bytesToHex(btcXOnly),
        agent_btc_taproot_address: taprootSingleSigAddress(btcPub33),
      },
      secrets: {
        agent_eth_private_key: agentEthPrivateKey,
        agent_btc_private_key: agentBtcPrivateKey,
      },
    };
  } finally {
    zeroizeBytes(ethEntropy);
    zeroizeBytes(btcEntropy);
    ethRoot.wipePrivateData();
    btcRoot.wipePrivateData();
    ethChild.wipePrivateData();
    btcChild.wipePrivateData();
  }
}

export function generateGrantReplyKeypair() {
  const sk = secp256k1.utils.randomPrivateKey();
  const replyPubkey = bytesToHex(schnorr.getPublicKey(sk));
  return { replySkHex: bytesToHex(sk), replyPubkey };
}

function grantReplyKey(skBytes, peerXOnlyHex, sessionId) {
  const shared = secp256k1.getSharedSecret(skBytes, `02${String(peerXOnlyHex).toLowerCase()}`, true);
  const x = shared.slice(1);
  try {
    return hkdf(sha256, x, AGENT_REPLY_SALT, utf8(String(sessionId)), 32);
  } finally {
    zeroizeBytes(x);
    zeroizeBytes(shared);
  }
}

function grantAad(sessionId, agentPublic, policy) {
  return utf8(JSON.stringify({
    format: AGENT_GRANT_REPLY_FORMAT,
    session_id: String(sessionId),
    index: agentPublic.index,
    agent_eth_eoa: getAddress(agentPublic.agent_eth_eoa),
    agent_btc_public_key_33_hex: String(agentPublic.agent_btc_public_key_33_hex).toLowerCase(),
    policy: policy || {},
  }));
}

export function agentGrantProofMessage({ sessionId, replyPubkey, reply }) {
  const cipherDigest = createHash("sha256").update(String(reply.ciphertext_b64u || ""), "utf8").digest("hex");
  return [
    "Nuri agent wallet grant v1",
    `Session: ${sessionId}`,
    `Index: ${reply.agent_public.index}`,
    `Agent EVM EOA: ${getAddress(reply.agent_public.agent_eth_eoa)}`,
    `Agent BTC Pubkey: ${String(reply.agent_public.agent_btc_public_key_33_hex).toLowerCase()}`,
    `Reply Pubkey: ${String(replyPubkey).toLowerCase()}`,
    `Ephemeral Pubkey: ${String(reply.ephemeral_pubkey).toLowerCase()}`,
    `Policy: ${JSON.stringify(reply.policy || {})}`,
    `Ciphertext SHA-256: ${cipherDigest}`,
  ].join("\n");
}

export function decryptAgentGrantReply({ replySkHex, sessionId, reply }) {
  const skBytes = hexToBytes(replySkHex);
  const key = grantReplyKey(skBytes, reply.ephemeral_pubkey, sessionId);
  try {
    const aad = grantAad(sessionId, reply.agent_public, reply.policy);
    const nonce = new Uint8Array(Buffer.from(String(reply.nonce_b64u), "base64url"));
    const ciphertext = new Uint8Array(Buffer.from(String(reply.ciphertext_b64u), "base64url"));
    let plaintext;
    try {
      plaintext = xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
    } catch {
      throw new Error("agent_grant_reply_invalid");
    }
    const parsed = JSON.parse(new TextDecoder().decode(plaintext));
    zeroizeBytes(plaintext);
    if (
      parsed.format !== AGENT_GRANT_REPLY_FORMAT ||
      parsed.derivation_version !== AGENT_DERIVATION_VERSION ||
      Number(parsed.index) !== Number(reply.agent_public.index)
    ) {
      throw new Error("agent_grant_bundle_mismatch");
    }
    const ethAcc = privateKeyToAccount(`0x${String(parsed.agent_eth_private_key_hex).toLowerCase()}`);
    if (getAddress(ethAcc.address) !== getAddress(reply.agent_public.agent_eth_eoa)) {
      throw new Error("agent_grant_eth_key_mismatch");
    }
    const btcSk = hexToBytes(parsed.agent_btc_private_key_hex);
    const btcPub33 = bytesToHex(secp256k1.getPublicKey(btcSk, true));
    zeroizeBytes(btcSk);
    if (btcPub33 !== String(reply.agent_public.agent_btc_public_key_33_hex).toLowerCase()) {
      throw new Error("agent_grant_btc_key_mismatch");
    }
    return parsed;
  } finally {
    zeroizeBytes(skBytes);
    zeroizeBytes(key);
  }
}

export async function verifyAgentGrantProof({ mainEoa, sessionId, replyPubkey, grantResult }) {
  const message = agentGrantProofMessage({ sessionId, replyPubkey, reply: grantResult });
  const ok = await verifyMessage({
    address: getAddress(mainEoa),
    message,
    signature: grantResult.signature,
  }).catch(() => false);
  if (!ok) throw new Error("agent_grant_signature_invalid");
  return true;
}

export function createConnectGrantClient({
  baseUrl = process.env.CONNECT_NURI_URL || DEFAULT_CONNECT_URL,
  fetchImpl = fetch,
} = {}) {
  const origin = String(baseUrl || DEFAULT_CONNECT_URL).replace(/\/$/, "");

  async function callMcpTool(name, args, { signal } = {}) {
    const res = await fetchImpl(`${origin}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: randomBytes(6).toString("hex"),
        method: "tools/call",
        params: { name, arguments: args },
      }),
      signal,
    });
    const body = await res.json().catch(() => null);
    if (!res.ok || !body || body.error) {
      throw new Error(body?.error?.message || `connect_mcp_http_${res.status}`);
    }
    const toolRes = body.result || {};
    if (toolRes.structuredContent && typeof toolRes.structuredContent === "object") {
      if (toolRes.isError) throw new Error(toolRes.structuredContent.error || "connect_mcp_tool_error");
      return toolRes.structuredContent;
    }
    const text = toolRes.content?.find?.((c) => c?.type === "text")?.text;
    const parsed = text ? JSON.parse(text) : {};
    if (toolRes.isError || parsed?.error) throw new Error(parsed?.error || "connect_mcp_tool_error");
    return parsed;
  }

  return {
    origin,
    async startAgentGrant({ replyPubkey, index = 0, policy = {}, credIdB64u, expectedEoa, timeoutMs, signal }) {
      return await callMcpTool("wallet_sign_start", {
        operation: "agent_grant",
        payload: { reply_pubkey: replyPubkey, index, policy },
        ...(credIdB64u ? { cred_id_b64u: credIdB64u } : {}),
        ...(expectedEoa ? { expected_eoa: expectedEoa } : {}),
        ...(timeoutMs !== undefined ? { timeout_ms: timeoutMs } : {}),
      }, { signal });
    },
    async readAgentGrantResult({ sessionId, signal }) {
      return await callMcpTool("wallet_sign_result", { session_id: sessionId }, { signal });
    },
  };
}
