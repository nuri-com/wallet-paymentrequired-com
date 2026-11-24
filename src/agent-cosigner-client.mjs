// Loopback HTTP client for `nuri-agent-cosigner` (`http://127.0.0.1:8794`).
// Authenticates every call with `Authorization: Bearer $AGENT_COSIGNER_RPC_SECRET`.

export class AgentCosignerRpcError extends Error {
  constructor(message, { status = 500, code = "cosigner_rpc_failed" } = {}) {
    super(message);
    this.name = "AgentCosignerRpcError";
    this.status = status;
    this.code = code;
  }
}

function serializeBigInts(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(serializeBigInts);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, serializeBigInts(v)]));
  }
  return value;
}

export function createAgentCosignerClient({
  baseUrl = process.env.AGENT_COSIGNER_URL || "",
  secret = process.env.AGENT_COSIGNER_RPC_SECRET || "",
  fetchImpl = fetch,
} = {}) {
  const origin = String(baseUrl || "").trim().replace(/\/$/, "");
  const token = String(secret || "").trim();
  const configured = Boolean(origin && token);

  async function post(path, body, { signal } = {}) {
    if (!configured) {
      throw new AgentCosignerRpcError("nuri-agent-cosigner is not configured", {
        status: 503,
        code: "cosigner_not_configured",
      });
    }
    let res;
    try {
      res = await fetchImpl(`${origin}${path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(serializeBigInts(body || {})),
        signal,
      });
    } catch (err) {
      throw new AgentCosignerRpcError(err?.message || "cosigner unreachable", {
        status: 503,
        code: "cosigner_unreachable",
      });
    }
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.ok === false) {
      throw new AgentCosignerRpcError(
        data?.error || `cosigner HTTP ${res.status}`,
        { status: res.status, code: data?.code || "cosigner_refused" },
      );
    }
    return data;
  }

  return {
    configured,
    origin,
    async healthz({ signal } = {}) {
      if (!origin) return { ok: false };
      const res = await fetchImpl(`${origin}/healthz`, { signal });
      return await res.json();
    },
    publicKeys: (body, opts) => post("/v1/agent/public-keys", body, opts),
    registerGrant: (body, opts) => post("/v1/agent/grants/register", body, opts),
    grantStatus: (body, opts) => post("/v1/agent/grants/status", body, opts),
    revokeGrant: (body, opts) => post("/v1/agent/grants/revoke", body, opts),
    signSafeTx: (body, opts) => post("/v1/evm/sign-safe-tx", body, opts),
    signTypedData: (body, opts) => post("/v1/evm/sign-typed-data", body, opts),
    signArkadePsbt: (body, opts) => post("/v1/arkade/sign-psbt", body, opts),
    initArkadeTreeSession: (body, opts) => post("/v1/arkade/tree/session", body, opts),
    arkadeTreeNonce: (body, opts) => post("/v1/arkade/tree/nonce", body, opts),
    arkadeTreeSign: (body, opts) => post("/v1/arkade/tree/sign", body, opts),
    signL1Psbt: (body, opts) => post("/v1/l1/sign-psbt", body, opts),
    markL1Broadcast: (body, opts) => post("/v1/l1/outpoints/mark-broadcast", body, opts),
    releaseL1Outpoints: (body, opts) => post("/v1/l1/outpoints/release", body, opts),
    l1OutpointsStatus: (body, opts) => post("/v1/l1/outpoints/status", body, opts),
    registerTrustedL1Outpoint: (body, opts) => post("/v1/l1/outpoints/register-trusted", body, opts),
  };
}
