// Consumer-side HTTP client for the root signer broker (C0/contracts.md §2).
// Every method is async; errors carry {code, status}. No product logic here.
import { ID_PATTERN, ROOT_PRIVY_APP_ID, ROOT_SIGNER_CONSUMERS, codeError } from "./root-signer-envelope.mjs";

export { decryptRootSignerEnvelope, assertRootSignerPayload, envelopeDigest, newRootSignerId, createConsumerResultKeyPair } from "./root-signer-envelope.mjs";

export function createRootSignerClient({ baseUrl, consumerId, credential, fetchImpl = globalThis.fetch } = {}) {
  if (typeof baseUrl !== "string" || !/^https?:\/\//.test(baseUrl)) throw codeError("client_config", "baseUrl_invalid", 500);
  if (!ROOT_SIGNER_CONSUMERS.includes(consumerId)) throw codeError("client_config", "consumerId_invalid", 500);
  if (typeof credential !== "string" || credential.length < 16) throw codeError("client_config", "credential_invalid", 500);
  if (typeof fetchImpl !== "function") throw codeError("client_config", "fetchImpl_invalid", 500);
  const root = baseUrl.replace(/\/+$/, "");

  async function call(method, path, body) {
    let response;
    try {
      response = await fetchImpl(`${root}${path}`, {
        method, cache: "no-store",
        headers: { authorization: `Bearer ${credential}`, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch (error) {
      throw codeError("broker_unreachable", error?.message || "broker_unreachable", 503);
    }
    let json = null;
    try { json = await response.json(); } catch { json = null; }
    if (!response.ok) throw codeError(json?.error || `http_${response.status}`, json?.detail || json?.error || `http_${response.status}`, response.status);
    if (!json || typeof json !== "object") throw codeError("broker_bad_response", "broker_bad_response", 502);
    return json;
  }

  return {
    consumerId,
    // input: {requestId?, state?, expiresAt, expectedAddress?, privyAppId, intent, approval, returnOrigin?}
    async createRequest(input) {
      if (!input || typeof input !== "object") throw codeError("invalid_request", "input_invalid");
      if (input.privyAppId !== ROOT_PRIVY_APP_ID) throw codeError("invalid_request", "privyAppId_not_root");
      const { requestId, approvalUrl, status, expiresAt } = await call("POST", "/v1/requests", { ...input, consumerId });
      return { requestId, approvalUrl, status, expiresAt };
    },
    async readStatus(requestId) {
      const { requestId: id, status, expiresAt, resultDigest } = await call("GET", `/v1/requests/${encodeURIComponent(readId(requestId))}`);
      return { requestId: id, status, expiresAt, ...(resultDigest ? { resultDigest } : {}) };
    },
    async readResult(requestId) {
      const { requestId: id, consumerId: owner, envelope, digest, approvedAt, retainUntil } = await call("GET", `/v1/requests/${encodeURIComponent(readId(requestId))}/result`);
      if (owner !== consumerId) throw codeError("wrong_consumer", "result_consumer_mismatch", 403);
      return { requestId: id, consumerId: owner, envelope, digest, approvedAt, retainUntil };
    },
    async acknowledge(requestId, { digest, accepted } = {}) {
      if (accepted !== true || typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) throw codeError("invalid_request", "ack_invalid");
      const { status } = await call("POST", `/v1/requests/${encodeURIComponent(readId(requestId))}/ack`, { digest, accepted: true });
      return { status };
    },
    async cancel(requestId) {
      const { status } = await call("POST", `/v1/requests/${encodeURIComponent(readId(requestId))}/cancel`, {});
      return { status };
    },
  };
}

function readId(value) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw codeError("invalid_request", "requestId_invalid");
  return value;
}
