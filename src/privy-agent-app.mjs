const PRIVY_API = "https://api.privy.io/v1";

function required(value, name) {
  const text = String(value || "").trim();
  if (!text) throw new Error(`${name}_required`);
  return text;
}

function errorOf(status, body, fallback) {
  const code = typeof body?.code === "string" ? body.code : "";
  if (status === 401 || status === 403) throw new Error("privy_agent_app_unauthorized");
  if (status === 404) throw new Error("privy_agent_wallet_not_found");
  if (status === 429) throw new Error("privy_agent_provider_rate_limited");
  if (code === "missing_or_invalid_privy_app_id") throw new Error("privy_agent_app_id_invalid");
  throw new Error(`${fallback}:${status}`);
}

















export function createNuriPrivyAppClient({ appId, appSecret, fetchImpl = fetch } = {}) {
  const id = required(appId, "privy_agent_app_id");
  const secret = required(appSecret, "privy_agent_app_secret");
  const authorization = `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

  async function call(path, body, { signatures, requestExpiry } = {}, method = "POST") {
    let response;
    try {
      response = await fetchImpl(`${PRIVY_API}${path}`, {
        method,
        headers: {
          authorization,
          "privy-app-id": id,
          "content-type": "application/json",
          ...(signatures ? { "privy-authorization-signature": signatures } : {}),
          ...(requestExpiry !== undefined ? { "privy-request-expiry": String(requestExpiry) } : {}),
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60_000),
      });
    } catch (error) {
      throw new Error(`privy_agent_provider_unavailable:${String(error?.name || error?.message || error).slice(0, 80)}`);
    }
    let parsed = null;
    try { parsed = await response.json(); } catch { parsed = null; }
    if (!response.ok) errorOf(response.status, parsed, "privy_agent_provider_error");
    return parsed;
  }

  async function get(path) {
    let response;
    try {
      response = await fetchImpl(`${PRIVY_API}${path}`, {
        method: "GET",
        headers: { authorization, "privy-app-id": id },
        signal: AbortSignal.timeout(60_000),
      });
    } catch {
      throw new Error("privy_agent_provider_unavailable");
    }
    let parsed = null;
    try { parsed = await response.json(); } catch { parsed = null; }
    if (!response.ok) errorOf(response.status, parsed, "privy_agent_provider_error");
    return parsed;
  }

  return {
    appId: id,
    
    
    
    
    
    async createQuorum({ display_name, authorization_threshold, public_keys }) {
      return call("/key_quorums", { display_name, authorization_threshold, public_keys });
    },
    async getQuorum(quorumId) {
      return get(`/key_quorums/${required(quorumId, "agent_quorum_id")}`);
    },
    // Custody v2 connect: swap the guest's model key for the EOA-derived key. The quorum owns the
    // wallet, so the PATCH carries the current members' signatures (server + old model key).
    async updateQuorum(quorumId, body, quorum) {
      return call(`/key_quorums/${required(quorumId, "agent_quorum_id")}`, body, quorum, "PATCH");
    },
    
    
    
    
    
    
    
    
    
    
    
    
    
    async createWallet({ ownerQuorumId } = {}) {
      if (typeof ownerQuorumId !== "string" || !ownerQuorumId) throw new Error("agent_quorum_id_required");
      const created = await call("/wallets", { chain_type: "ethereum", owner_id: ownerQuorumId });
      const walletId = created?.id;
      const address = created?.address;
      if (typeof walletId !== "string" || !walletId || !/^0x[0-9a-fA-F]{40}$/.test(String(address || ""))) {
        throw new Error("privy_agent_wallet_create_failed");
      }
      return { walletId, address };
    },

    async getWallet(walletId) {
      const wallet = await get(`/wallets/${required(walletId, "privy_wallet_id")}`);
      if (typeof wallet?.id !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(String(wallet?.address || ""))) {
        throw new Error("privy_agent_wallet_not_found");
      }
      return { walletId: wallet.id, address: wallet.address, ownerId: wallet.owner_id ?? null };
    },

    
    
    
    
    
    
    
    async signHash(walletId, hash, quorum) {
      if (!/^0x[0-9a-f]{64}$/i.test(String(hash || ""))) throw new Error("privy_agent_hash_invalid");
      const signed = await call(`/wallets/${required(walletId, "privy_wallet_id")}/rpc`, {
        method: "secp256k1_sign",
        params: { hash },
      }, quorum);
      const signature = signed?.data?.signature || signed?.signature;
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
        throw new Error("privy_agent_signature_invalid");
      }
      return signature;
    },

    async signTypedData(walletId, typedData, quorum) {
      const { domain, message, types, primaryType, primary_type } = typedData || {};
      if (!domain || !message || !types || !(primaryType || primary_type)) throw new Error("privy_agent_typed_data_invalid");
      
      
      
      const normalized = JSON.parse(JSON.stringify({ domain, message, primary_type: primaryType || primary_type, types },
        (_key, value) => typeof value === "bigint" ? value.toString() : value));
      const signed = await call(`/wallets/${required(walletId, "privy_wallet_id")}/rpc`, {
        method: "eth_signTypedData_v4",
        params: { typed_data: normalized },
      }, quorum);
      const signature = signed?.data?.signature || signed?.signature;
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
        throw new Error("privy_agent_signature_invalid");
      }
      return signature;
    },
  };
}

export function assertNuriPrivyAppEnv(env = process.env) {
  return {
    appId: required(env.PRIVY_AGENT_APP_ID, "privy_agent_app_id"),
    appSecret: required(env.PRIVY_AGENT_APP_SECRET, "privy_agent_app_secret"),
  };
}
