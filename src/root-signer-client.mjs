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

  // One deadline covers headers AND body. A failed call opens a shared short circuit,
  // including registration after hydration, so an outage is not retried for every link.
  let retryAt = 0;
  async function call(method, path, body, { signal, deadline = Infinity } = {}) {
    signal?.throwIfAborted();
    if (Date.now() >= deadline) throw codeError("broker_deadline", "broker_deadline", 503);
    if (Date.now() < retryAt) throw codeError("broker_backoff", "broker_retry_later", 503);
    const controller = new AbortController();
    let timer, onAbort;
    const timeout = new Promise((_, reject) => {
      onAbort = () => { controller.abort(); reject(signal.reason ?? codeError("broker_cancelled", "broker_cancelled", 503)); };
      signal?.addEventListener("abort", onAbort, { once: true });
      timer = setTimeout(() => {
        controller.abort();
        reject(codeError("broker_unreachable", "broker_timeout", 503));
      }, Math.min(3_000, Math.max(0, deadline - Date.now())));
    });
    try {
      return await Promise.race([timeout, (async () => {
        let response;
        try {
          response = await fetchImpl(`${root}${path}`, {
            method, cache: "no-store", signal: controller.signal,
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
      })()]);
    } catch (error) {
      if (!signal?.aborted && Date.now() < deadline) retryAt = Date.now() + 5_000;
      throw error;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }

  return {
    consumerId,
    // input: {requestId?, state?, expiresAt, expectedAddress?, privyAppId, intent, approval, returnOrigin?}
    async createRequest(input, options) {
      if (!input || typeof input !== "object") throw codeError("invalid_request", "input_invalid");
      if (input.privyAppId !== ROOT_PRIVY_APP_ID) throw codeError("invalid_request", "privyAppId_not_root");
      const { requestId, approvalUrl, status, expiresAt } = await call("POST", "/v1/requests", { ...input, consumerId }, options);
      return { requestId, approvalUrl, status, expiresAt };
    },
    async readStatus(requestId, options) {
      const { requestId: id, status, expiresAt, resultDigest, submitOrder } = await call("GET", `/v1/requests/${encodeURIComponent(readId(requestId))}`, undefined, options);
      return { requestId: id, status, expiresAt, ...(resultDigest ? { resultDigest, submitOrder } : {}) };
    },
    async readResult(requestId, options) {
      const { requestId: id, consumerId: owner, envelope, digest, approvedAt, retainUntil, submitOrder } = await call("GET", `/v1/requests/${encodeURIComponent(readId(requestId))}/result`, undefined, options);
      if (owner !== consumerId) throw codeError("wrong_consumer", "result_consumer_mismatch", 403);
      return { requestId: id, consumerId: owner, envelope, digest, approvedAt, retainUntil, submitOrder };
    },
    async acknowledge(requestId, { digest, accepted } = {}, options) {
      if (accepted !== true || typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) throw codeError("invalid_request", "ack_invalid");
      const { status } = await call("POST", `/v1/requests/${encodeURIComponent(readId(requestId))}/ack`, { digest, accepted: true }, options);
      return { status };
    },
    async cancel(requestId, options) {
      const { status } = await call("POST", `/v1/requests/${encodeURIComponent(readId(requestId))}/cancel`, {}, options);
      return { status };
    },
  };
}

function readId(value) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw codeError("invalid_request", "requestId_invalid");
  return value;
}
