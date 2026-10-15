import { generateKeyPairSync, createPublicKey, sign as signAuthorization } from "node:crypto";

import { formatRequestForAuthorizationSignature } from "@privy-io/node";

















export const AGENT_QUORUM_THRESHOLD = 2;
export const QUORUM_ID_PATTERN = /^[a-z0-9]{20,64}$/;

function required(value, name) {
  const text = String(value || "").trim();
  if (!text) throw new Error(`${name}_required`);
  return text;
}




export function generateAuthorizationKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    privateKeyEncoding: { type: "pkcs8", format: "der" },
    publicKeyEncoding: { type: "spki", format: "der" },
  });
  return { publicKey: publicKey.toString("base64"), privateKey: privateKey.toString("base64") };
}

export function publicKeyOfAuthorizationPrivateKey(authorizationPrivateKey) {
  const material = Buffer.from(String(authorizationPrivateKey || "").replace(/^(wallet-auth:|wallet-api:)/, ""), "base64");
  try {
    const key = createPublicKey({ key: material, format: "der", type: "pkcs8" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new Error("not-p256");
    }
    return key.export({ type: "spki", format: "der" }).toString("base64");
  } finally {
    material.fill(0);
  }
}

export function assertAuthorizationPublicKey(publicKey) {
  const text = required(publicKey, "agent_quorum_public_key").replace(/\s/g, "");
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(text, "base64"), format: "der", type: "spki" });
  } catch {
    throw new Error("agent_quorum_public_key_invalid");
  }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("agent_quorum_public_key_invalid");
  }
  return text;
}

export function assertQuorumId(quorumId) {
  const id = required(quorumId, "agent_quorum_id");
  if (!QUORUM_ID_PATTERN.test(id)) throw new Error("agent_quorum_id_invalid");
  return id;
}









export function quorumAuthorizationInput({ appId, method, url, body, requestExpiry }) {
  const id = required(appId, "privy_agent_app_id");
  const verb = required(method, "agent_quorum_method");
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(verb)) throw new Error("agent_quorum_method_invalid");
  const target = required(url, "agent_quorum_url");
  if (!target.startsWith("https://api.privy.io/v1/")) throw new Error("agent_quorum_url_invalid");
  if (body === undefined || (typeof body === "object" && body !== null && Object.keys(body).length === 0)) {
    throw new Error("agent_quorum_body_required");
  }
  const expiry = Number(requestExpiry);
  if (!Number.isSafeInteger(expiry) || expiry <= Date.now() || expiry > Date.now() + 300_000) {
    throw new Error("agent_quorum_expiry_invalid");
  }
  const headers = { "privy-app-id": id, "privy-request-expiry": String(expiry) };
  return { version: 1, method: verb, url: target, body, headers };
}

export function authorizationPayloadBytes(input) {
  return formatRequestForAuthorizationSignature(structuredClone(input));
}




export function signQuorumAuthorization(input, authorizationPrivateKey) {
  let payload;
  try {
    payload = authorizationPayloadBytes(input);
  } catch (error) {
    throw new Error(`agent_quorum_payload_invalid:${String(error?.message || error).slice(0, 80)}`, { cause: error });
  }
  const material = Buffer.from(String(authorizationPrivateKey || "").replace(/^(wallet-auth:|wallet-api:)/, ""), "base64");
  try {
    const key = createPublicKey({ key: material, format: "der", type: "pkcs8" });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new Error("agent_quorum_signer_key_invalid");
    }
    return signAuthorization("sha256", payload, { key: material, format: "der", type: "pkcs8" }).toString("base64");
  } catch (error) {
    if (typeof error?.message === "string" && (error.message === "agent_quorum_signer_key_invalid" || error.message.startsWith("agent_quorum_payload_invalid:"))) throw error;
    throw new Error(`agent_quorum_signer_key_invalid:${String(error?.message || error).slice(0, 80)}`, { cause: error });
  } finally {
    material.fill(0);
  }
}

export function joinAuthorizationSignatures(signatures) {
  if (!Array.isArray(signatures) || signatures.length !== AGENT_QUORUM_THRESHOLD) {
    throw new Error("agent_quorum_two_signatures_required");
  }
  for (const signature of signatures) {
    if (typeof signature !== "string" || !signature || signature.length > 512) throw new Error("agent_quorum_signature_invalid");
  }
  return signatures.join(",");
}




export function assertAgentQuorum({ quorum, serverPublicKey, runtimePublicKey }) {
  const server = assertAuthorizationPublicKey(serverPublicKey).replace(/\s/g, "");
  const runtime = assertAuthorizationPublicKey(runtimePublicKey).replace(/\s/g, "");
  if (server === runtime) throw new Error("agent_quorum_keys_must_differ");
  if (!quorum || typeof quorum.id !== "string" || !quorum.id) throw new Error("agent_quorum_not_found");
  if (quorum.authorization_threshold !== AGENT_QUORUM_THRESHOLD) throw new Error("agent_quorum_threshold_invalid");
  const keys = Array.isArray(quorum.authorization_keys) ? quorum.authorization_keys.map((key) => String(key?.public_key || "").replace(/\s/g, "")).sort() : [];
  if (keys.length !== 2 || keys[0] !== [server, runtime].sort()[0] || keys[1] !== [server, runtime].sort()[1]) {
    throw new Error("agent_quorum_key_mismatch");
  }
  if (Array.isArray(quorum.user_ids) && quorum.user_ids.length > 0) throw new Error("agent_quorum_user_members_forbidden");
  if (Array.isArray(quorum.key_quorum_ids) && quorum.key_quorum_ids.length > 0) throw new Error("agent_quorum_nested_members_forbidden");
  return quorum.id;
}
