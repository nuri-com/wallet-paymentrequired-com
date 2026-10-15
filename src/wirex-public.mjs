// Public Wirex constants and error type the shared modules need, copied VERBATIM from the
// monolith (source c16ab56): src/wirex-baas.mjs lines 14-16, 18, 23-25, 27-49, 391-397 and
// src/wirex-api.mjs line 29. This file holds no client, no token source and no credential:
// WirexBaasClient / WirexApiClient live only in the banking repository. The wallet service refuses
// WIREX_TOKEN_URL / WIREX_COMPANY_ID / WIREX_CLIENT_ID / WIREX_CLIENT_SECRET at boot
// (src/service-mode.mjs:24-28), so readBaasConfig() yields companyId "" here and the approval page
// offers no Wirex login (src/browser-bridge.mjs:149-150).

const DEFAULT_API = "https://api-baas.wirexapp.tech";
const DEFAULT_PCI = "https://wx-acquiring-card-manager-uat.wirexapp.com";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const WIREX_LOGIN_NONCE_WINDOW_S = 300;

export function wirexLoginMessage({ owner, companyId, chainId, nonce }) {
  return `I, owner of account ${owner} confirm that I request access token for company ${companyId} on chain ${chainId} at ${nonce}`;
}

export function readBaasConfig(env = process.env) {
  const tokenUrl = String(env.WIREX_TOKEN_URL || "").trim().replace(/\/+$/, "");
  if (env.WIREX_TOKEN_URL && !/^https?:\/\/\S+$/.test(tokenUrl)) {
    
    throw new Error(`wirex_token_url_invalid: WIREX_TOKEN_URL must be an http(s) URL pointing at the partner-token service, got: ${env.WIREX_TOKEN_URL}`);
  }
  // LOGIN V2 (wallet-signature, #150) — SANDBOX ONLY FOR NOW. Production (Base mainnet 8453) always
  // uses login v1: partner token via WIREX_TOKEN_URL -> /user/authorize. v2 comes later, once
  // company_id, token lifetime and owner_address are settled for mainnet (issue #150 open).
  const chainId = Number(env.WIREX_CHAIN_ID || 84532);
  const companyId = chainId === 8453 ? "" : String(env.WIREX_COMPANY_ID || "").trim();
  if (companyId && !UUID_PATTERN.test(companyId)) {
    throw new Error("wirex_company_id_invalid: WIREX_COMPANY_ID must be the UUID Wirex assigned to this company (it is public, not a secret)");
  }
  return {
    apiUrl: String(env.WIREX_API_BASE_URL || DEFAULT_API).replace(/\/+$/, ""),
    pciUrl: String(env.WIREX_PCI_BASE_URL || DEFAULT_PCI).replace(/\/+$/, ""),
    tokenUrl,
    companyId,
    chainId,
    timeoutMs: Number(env.WIREX_TIMEOUT_MS || 30_000),
  };
}

export class WirexBaasError extends Error {
  constructor(what, status, body) {
    super(`wirex_baas_${String(what).replace(/\W+/g, "_")}_${status}`);
    this.status = status;
    this.body = body;
  }
}

export const V1_APP_HOSTS = Object.freeze(["wirex.nuri.com", ["banking", "nuri.com"].join(".")]);
