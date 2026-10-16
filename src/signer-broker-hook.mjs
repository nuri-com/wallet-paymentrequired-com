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
  async function register(sessionId, options = {}) {
    checkBudget(options);
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
    }, options);
    bridge.bindBrokerRequest(sessionId, { requestId: created.requestId, extras: extraRequests.map((e) => e.id), approvalUrl: created.approvalUrl, expiresAt });
    logEvent("info", "root_signer_registered", { consumer: consumerId, status: created.status });
    return created;
  }

  // Reads the broker status; when a result is retained, adopts it through the bridge and ACKs
  // only after the bridge persisted the approved row (C0 §2 retention/ACK rule). Same-digest
  // replay after a restart re-adopts without re-executing any effect that already landed
  // (bridge answers replay:true) and repeats the identical ACK.
  function budget({ signal, deadline = Date.now() + 3_000 } = {}) {
    return { signal, deadline: Math.min(deadline, Date.now() + 25_000) };
  }
  function checkBudget({ signal, deadline = Infinity }) {
    signal?.throwIfAborted();
    if (Date.now() >= deadline) throw new Error("broker_deadline");
  }
  async function hydrate(sessionId, options = {}) {
    options = budget(options);
    const session = bridge.requireSession(sessionId);
    if (!session.brokerRequestId) return null;
    // Even approved rows must recover their local owner/box before any ACK.
    if (consumerId === "wallet" && session.context?.kind === "mcp_connection" && session.context.walletId && !session.context.grantFor)
      return hydrateClaims(session.context.walletId, options);
    checkBudget(options);
    if (session.status === "approved" && session.brokerDigest) {
      await client.acknowledge(session.brokerRequestId, { digest: session.brokerDigest, accepted: true }, options).catch(() => null);
      return { status: "consumed" };
    }
    const status = await client.readStatus(session.brokerRequestId, options);
    if (status.status !== "submitted") return status;
    const result = await client.readResult(session.brokerRequestId, options);
    return adopt(sessionId, session, result, options);
  }

  async function adopt(sessionId, session, result, options) {
    // Open with B1's own codec (src/root-signer-envelope.mjs decryptRootSignerEnvelope) and check the
    // broker bindings with B1's assertRootSignerPayload; the bridge then re-verifies the signature
    // and persists exactly as it does for a local tap.
    const open = (envelope, state) => assertRootSignerPayload(decryptRootSignerEnvelope(envelope, { privateKey: config.privateKeyB64, state }),
      { requestId: session.brokerRequestId, consumerId, state: session.state, intent: session.intent, privyAppId: ROOT_PRIVY_APP_ID, expiresAt: session.brokerExpiresAt,
        ...(session.expectedAddress ? { expectedAddress: session.expectedAddress } : {}) });
    checkBudget(options);
    const adopted = await bridge.acceptBrokerResult(sessionId, { envelope: result.envelope, digest: result.digest, approvedAt: result.approvedAt, submitOrder: result.submitOrder }, { open, consumerId, ...options });
    checkBudget(options);
    await client.acknowledge(session.brokerRequestId, { digest: result.digest, accepted: true }, options);
    logEvent("info", "root_signer_adopted", { consumer: consumerId, replay: adopted.replay === true });
    return { status: "consumed" };
  }

  // No adoption or ACK until every candidate was read. A missing/unreadable submitted
  // result may precede the apparent winner: fail closed, never skip it. Broker submitOrder
  // is persisted atomically with ciphertext, independent of wall-clock ties/regressions.
  // Historical results without that order remain unresolved; approvedAt is only for expiry.
  function hydrateClaims(walletId, options = {}) {
    // Independent budgets: a cancelled caller never borrows or leaves an unbounded scan.
    return readClaims(walletId, budget(options));
  }

  async function readClaims(walletId, options) {
    try {
      let first = null, tied = false;
      const delivered = new Set(), candidates = new Set();
      // A link read as pending before we discover a delivered candidate can submit
      // BEFORE that candidate. Re-snapshot and re-read unresolved links after a
      // candidate is known; new links minted during the first pass are included too.
      for (let pass = 0; pass < 2; pass++) {
        checkBudget(options);
        for (const id of bridge.sessionStore?.brokerClaims?.(walletId) ?? []) candidates.add(id);
        for (const id of candidates) {
          checkBudget(options);
          if (delivered.has(id)) continue; // submitted ciphertext/timestamp are immutable
          const session = bridge.requireSession(id);
          let result;
          if (session.status === "approved" && session.brokerApplied === true) {
            // ACK may have cleared ciphertext; the durable winner still participates in election.
            result = { digest: session.brokerDigest, submitOrder: session.brokerSubmitOrder };
            if (!/^[0-9a-f]{64}$/.test(result.digest ?? "")) throw new Error("broker_claim_result_mismatch");
          } else {
            const status = await client.readStatus(session.brokerRequestId, options);
            if (status.requestId !== session.brokerRequestId) throw new Error("broker_claim_request_mismatch");
            if (session.status !== "approved" && ["pending", "expired", "cancelled"].includes(status.status)) continue;
            if (status.status !== "submitted") throw new Error("broker_claim_status_unresolved");
            result = await client.readResult(session.brokerRequestId, options);
            if (result.requestId !== session.brokerRequestId || result.digest !== status.resultDigest || result.submitOrder !== status.submitOrder)
              throw new Error("broker_claim_result_mismatch");
            if (!Number.isSafeInteger(result.approvedAt) || result.approvedAt < 0)
              throw new Error("broker_approved_at_invalid");
            if (session.status === "approved" && session.brokerDigest !== result.digest) throw new Error("broker_claim_result_mismatch");
          }
          if (!Number.isSafeInteger(result.submitOrder) || result.submitOrder < 1)
            throw new Error("broker_claim_order_unknown");
          delivered.add(id);
          if (!first || result.submitOrder < first.result.submitOrder) {
            first = { id, session, result };
            tied = false;
          } else if (result.submitOrder === first.result.submitOrder) tied = true;
        }
        checkBudget(options);
        if (!first) return null;
      }
      if (tied) throw new Error("broker_claim_order_ambiguous");
      // The existing bridge still owns ALL digest, decryption, binding, signature,
      // expiry and replay checks; no fallback to a later result if these reject.
      checkBudget(options);
      return first ? await adopt(first.id, first.session, first.result, options) : null;
    } catch (error) {
      logEvent("warn", "root_signer_hydrate_failed", { error: String(error?.message || error).slice(0, 80) });
      return { status: "pending" };
    }
  }

  return { consumerId, register, hydrate, hydrateClaims, client };
}
