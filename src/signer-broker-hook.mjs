// ROOT SIGNER HOOK (C0 §1 amendment, §2 consumer side; R2 D1-D3)
//
// The product side of the broker: a pending bridge session is REGISTERED with the broker
// (async, at the MCP boundary, after the sync createSession already persisted the row), and
// its retained result is HYDRATED back into the same session through the bridge's own
// acceptBrokerResult (same verify/persist pipeline as a legacy tap). The broker never sees the
// session pass, the per-session key or any product secret; the consumer's static P-256 scalar
// lives only in a mounted file (ROOT_SIGNER_RESULT_KEY_FILE).
//
// Client = B1's src/root-signer-client.mjs (createRootSignerClient). It is imported lazily by
// specifier so a deployment without the broker (ROOT_SIGNER_URL unset) is exactly the old code
// path and never loads it; a deployment WITH the broker fails loudly at boot if the module is
// missing (no stand-in client here).

import { readFileSync } from "node:fs";
import { AGENT_SIGNER_MESSAGE } from "./agent-signer-derivation.mjs";
import { wirexLoginRequest } from "./privy-bridge-client.mjs";
import { logEvent } from "./log.mjs";

export const ROOT_PRIVY_APP_ID = "cmt30ut1500080cjodoqk7xao"; // C0 §2: fixed root app identity

export function readRootSignerConfig(env = process.env, { consumerId } = {}) {
  const baseUrl = String(env.ROOT_SIGNER_URL || "").trim();
  if (!baseUrl) return null;
  if (consumerId !== "wallet" && consumerId !== "banking") throw new Error("root_signer_consumer_required");
  const credential = String(env.ROOT_SIGNER_CREDENTIAL || "").trim();
  const keyFile = String(env.ROOT_SIGNER_RESULT_KEY_FILE || "").trim();
  if (!credential) throw new Error("ROOT_SIGNER_CREDENTIAL_required");
  if (!keyFile) throw new Error("ROOT_SIGNER_RESULT_KEY_FILE_required");
  const privateKeyB64 = readFileSync(keyFile, "utf8").trim();
  if (Buffer.from(privateKeyB64, "base64url").length !== 32) throw new Error("root_signer_result_key_invalid");
  return Object.freeze({ baseUrl, consumerId, credential, privateKeyB64, returnOrigin: env.PUBLIC_ORIGIN || null });
}

export async function createRootSignerHook({ bridge, config, wirexLogin = null, clientModule = "./root-signer-client.mjs" } = {}) {
  if (!config) return null;
  if (!bridge || typeof bridge.acceptBrokerResult !== "function") throw new Error("root_signer_bridge_required");
  const { createRootSignerClient, decryptRootSignerEnvelope, assertRootSignerPayload } = await import(clientModule);
  const client = createRootSignerClient({ baseUrl: config.baseUrl, consumerId: config.consumerId, credential: config.credential });
  const consumerId = config.consumerId;

  // Registers one pending session with the broker. Called ONCE per session at the async MCP
  // boundary; the row already exists (sync createSession) so a crash here loses nothing.
  // Extras (C0 §2): wallet asks for the agent derivation signature only; banking asks for the
  // Privy access token and, when the root is pinned (expectedAddress), the pre-rendered Wirex
  // login message whose nonce is stored on the session (R2 D2).
  async function register(sessionId) {
    const session = bridge.requireSession(sessionId);
    if (session.status !== "pending") throw new Error("session_already_used");
    if (session.brokerRequestId) return { requestId: session.brokerRequestId, approvalUrl: session.approvalUrl, status: "pending" };
    // R2 D3: prepared reads (card details / PIN / read session) render their challenge BEFORE the
    // broker request exists, through the bridge's own prepareApproval (same as a legacy page load).
    if (session.prepareSigning && typeof session.signText !== "string") bridge.prepareApproval(sessionId, session.state);
    const extraRequests = [];
    if (consumerId === "wallet" && session.context?.kind === "mcp_connection") extraRequests.push({ id: "agentSignerSignature", type: "sign_message", message: AGENT_SIGNER_MESSAGE });
    if (consumerId === "banking") {
      extraRequests.push({ id: "privyAccessToken", type: "privy_access_token" });
      if (session.expectedAddress && wirexLogin?.company_id) {
        const login = wirexLoginRequest({ companyId: wirexLogin.company_id, chainId: wirexLogin.chain_id }, session.expectedAddress);
        session.context.wirexLoginNonce = login.nonce;
        extraRequests.push({ id: "wirexLoginSignature", type: "sign_message", message: login.message });
      }
    }
    const approval = {
      ...(session.signText !== undefined ? { signText: session.signText } : {}),
      ...(session.signHash !== undefined ? { signHash: session.signHash } : {}),
      ...(session.signTypedData !== undefined ? { signTypedData: session.signTypedData } : {}),
      ...(session.siwe !== undefined ? { siwe: session.siwe } : {}),
      ...(session.consentText !== undefined ? { consentText: session.consentText } : {}),
      ...(extraRequests.length ? { extraRequests } : {}),
    };
    const expiresAt = Math.min(session.approvalExpiresAt ?? session.expiresAt, session.signingExpiresAt ?? Infinity);
    const created = await client.createRequest({
      requestId: sessionId, state: session.state, expiresAt, intent: session.intent, privyAppId: ROOT_PRIVY_APP_ID,
      ...(session.expectedAddress ? { expectedAddress: session.expectedAddress } : {}),
      approval, ...(config.returnOrigin ? { returnOrigin: config.returnOrigin } : {}),
    });
    bridge.bindBrokerRequest(sessionId, { requestId: created.requestId, extras: extraRequests.map((e) => e.id), approvalUrl: created.approvalUrl, expiresAt });
    logEvent("info", "root_signer_registered", { consumer: consumerId, status: created.status });
    return created;
  }

  // Reads the broker status; when a result is retained, adopts it through the bridge and ACKs
  // only after the bridge persisted the approved row (C0 §2 retention/ACK rule). Same-digest
  // replay after a restart re-adopts without re-executing any effect that already landed
  // (bridge answers replay:true) and repeats the identical ACK.
  async function hydrate(sessionId) {
    const session = bridge.requireSession(sessionId);
    if (!session.brokerRequestId) return null;
    if (session.status === "approved" && session.brokerDigest) {
      await client.acknowledge(session.brokerRequestId, { digest: session.brokerDigest, accepted: true }).catch(() => null);
      return { status: "consumed" };
    }
    const status = await client.readStatus(session.brokerRequestId);
    if (status.status !== "submitted") return status;
    const result = await client.readResult(session.brokerRequestId);
    // Open with B1's own codec (src/root-signer-envelope.mjs decryptRootSignerEnvelope) and check the
    // broker bindings with B1's assertRootSignerPayload; the bridge then re-verifies the signature
    // and persists exactly as it does for a local tap.
    const open = (envelope, state) => assertRootSignerPayload(decryptRootSignerEnvelope(envelope, { privateKey: config.privateKeyB64, state }),
      { requestId: session.brokerRequestId, consumerId, state: session.state, intent: session.intent, privyAppId: ROOT_PRIVY_APP_ID, expiresAt: session.brokerExpiresAt,
        ...(session.expectedAddress ? { expectedAddress: session.expectedAddress } : {}) });
    const adopted = await bridge.acceptBrokerResult(sessionId, { envelope: result.envelope, digest: result.digest, approvedAt: result.approvedAt }, { open, consumerId });
    await client.acknowledge(session.brokerRequestId, { digest: result.digest, accepted: true });
    logEvent("info", "root_signer_adopted", { consumer: consumerId, replay: adopted.replay === true });
    return { status: "consumed" };
  }

  return { consumerId, register, hydrate, client };
}
