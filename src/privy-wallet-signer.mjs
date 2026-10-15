import { PrivyClient, formatRequestForAuthorizationSignature } from "@privy-io/node";
import { createHash, createPublicKey, randomBytes, generateKeyPairSync, sign as signAuthorization } from "node:crypto";
import { createViemAccount } from "@privy-io/node/viem";
import { getAddress } from "viem";
import { verifyMessage } from "ethers";
import { logEvent } from "./log.mjs";
import { readPrivyApp } from "./privy-apps.mjs";

const PRIVY_ERROR_CODES = new Set([
  "invalid_data", "policy_violation", "insufficient_funds", "transaction_broadcast_failure",
  "missing_or_empty_authorization_header", "zero_correct_authorization_signatures",
  "insufficient_correct_authorization_signatures", "incorrect_quantity_of_authorization_signatures",
  "request_expired", "no_valid_user_session_keys", "user_session_keys_expired",
]);

export async function fetchPrivyCardRequest(input, init, fetchImpl = fetch) {
  const response = await fetchImpl(input, init);
  const path = new URL(input instanceof Request ? input.url : input).pathname;
  const stage = path === "/v1/wallets/authenticate" ? "authenticate"
    : /^\/v1\/wallets\/[^/]+\/rpc$/.test(path) ? "wallet_rpc" : null;
  if (!response.ok && stage) {
    let code = "unknown";
    try {
      const body = await response.clone().json();
      if (PRIVY_ERROR_CODES.has(body?.code)) code = body.code;
    } catch {  }
    logEvent("warn", "privy_card_request_failed", { stage, status: response.status, code });
  }
  return response;
}

const PRIVY_API = "https://api.privy.io";





export function createPrivyProxyFetch({ proxyUrl, proxyToken }, fetchImpl = fetch) {
  const base = required(proxyUrl, "privy_proxy_url").replace(/\/+$/, "");
  const bearer = `Bearer ${required(proxyToken, "privy_proxy_token")}`;
  return (input, init = {}) => {
    const url = input instanceof Request ? input.url : String(input);
    if (!url.startsWith(`${PRIVY_API}/`)) return fetchImpl(input, init);
    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    for (const [name, value] of new Headers(init.headers || {})) headers.set(name, value);
    headers.set("authorization", bearer);
    return fetchImpl(base + url.slice(PRIVY_API.length), { ...init, headers });
  };
}

function required(value, name) {
  const text = String(value || "").trim();
  if (!text) throw new Error(`${name}_required`);
  return text;
}


export async function assertPrivyAgentSigner({ appId, appSecret, authorizationPrivateKey, signerId, client }) {
  const id = required(signerId, 'privy_signer_id');
  const fingerprint = createHash('sha256').update(id).digest('hex').slice(0, 12);
  const failure = code => Object.assign(new Error(`${code}:stage=signer_preflight:signer=${fingerprint}`), { code, stage: 'signer_preflight', signerFingerprint: fingerprint });
  const material = Buffer.from(String(authorizationPrivateKey || '').replace(/^(wallet-auth:|wallet-api:)/, ''), 'base64');
  let publicKey;
  try {
    const key = createPublicKey({ key: material, format: 'der', type: 'pkcs8' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw failure('privy_agent_authorization_key_invalid');
    publicKey = key.export({ type: 'spki', format: 'der' }).toString('base64');
  } catch { throw failure('privy_agent_authorization_key_invalid'); }
  finally { material.fill(0); }
  const sdk = client || new PrivyClient({ appId: required(appId, 'privy_app_id'), appSecret: required(appSecret, 'privy_app_secret'), maxRetries: 0 });
  let quorum;
  try { quorum = await sdk.keyQuorums().get(id); }
  catch (error) { throw failure(error?.status === 404 ? 'privy_agent_signer_not_found' : 'privy_agent_signer_unavailable'); }
  if (!quorum || quorum.id !== id) throw failure('privy_agent_signer_mismatch');
  if (quorum.authorization_threshold !== 1) throw failure('privy_agent_signer_threshold_invalid');
  if (!Array.isArray(quorum.authorization_keys) || !quorum.authorization_keys.some(key => typeof key?.public_key === 'string' && key.public_key.replace(/\s/g, '') === publicKey)) throw failure('privy_agent_signer_key_mismatch');
  return { signerFingerprint: fingerprint };
}

export function selectPrivyAgentWallet({ wallets, rootAddress, signerId, walletIndex = 0 }) {
  const root = getAddress(rootAddress);
  const signer = required(signerId, "privy_signer_id");
  
  if (!Number.isInteger(walletIndex) || walletIndex < 0 || walletIndex > 2) throw new Error("privy_agent_wallet_index_invalid");
  const matches = wallets
    .filter((wallet) => !wallet.archived_at
      && wallet.chain_type === "ethereum"
      && getAddress(wallet.address) !== root
      && wallet.additional_signers?.some((entry) => entry.signer_id === signer))
    .sort((left, right) => left.created_at - right.created_at || String(left.id).localeCompare(String(right.id)));
  return matches[walletIndex] || null;
}

export async function discoverPrivyAgentWallet({ appId, appSecret, rootAddress, signerId, walletIndex = 0 }) {
  const client = new PrivyClient({
    appId: required(appId, "privy_app_id"),
    appSecret: required(appSecret, "privy_app_secret"),
  });
  const user = await client.users().getByWalletAddress({ address: getAddress(rootAddress) });
  const wallets = [];
  for await (const wallet of client.wallets().list({ user_id: user.id, chain_type: "ethereum" })) wallets.push(wallet);
  const wallet = selectPrivyAgentWallet({ wallets, rootAddress, signerId, walletIndex });
  return wallet ? { userId: user.id, walletId: wallet.id, address: getAddress(wallet.address) } : null;
}

export function assertPrivyAgentWalletBinding({ discovered, providerUserId, providerWalletId, address }) {
  if (!discovered
    || discovered.userId !== providerUserId
    || discovered.walletId !== providerWalletId
    || getAddress(discovered.address) !== getAddress(address)) {
    throw new Error("privy_agent_callback_not_bound_to_expected_wallet");
  }
  return discovered;
}

export function createPrivyUserWalletAccount({ appId, appSecret, authorizationPrivateKey, walletId, address }) {
  const client = new PrivyClient({
    appId: required(appId, "privy_app_id"),
    appSecret: required(appSecret, "privy_app_secret"),
  });
  return createViemAccount(client, {
    walletId: required(walletId, "privy_wallet_id"),
    address: getAddress(address),
    authorizationContext: {
      authorization_private_keys: [required(authorizationPrivateKey, "privy_authorization_private_key")],
    },
  });
}

const TYPED_CODE = /^[a-z][a-z0-9_]*$/;
const CARD_MESSAGE_PREFIX = "By signing this I confirm that I am executing action GetCardDetails at ";
const GRANT_REQUEST_MS = 60_000;

function authorization(key, validate = () => {}) {
  return { sign_fns: [async payload => {
    validate();
    return signAuthorization("sha256", payload, { key, format: "der", type: "pkcs8" }).toString("base64");
  }] };
}

function walletSnapshot(wallet) {
  return JSON.stringify({ owner: wallet.owner_id, signers: (wallet.additional_signers || []).map(entry => ({
    signer_id: entry.signer_id, override_policy_ids: entry.override_policy_ids || [],
  })).sort((a, b) => a.signer_id.localeCompare(b.signer_id)) });
}



export function createPrivyConnectionSigner({ env = process.env, client } = {}) {
  const grants = new WeakMap(), locks = new Map();
  
  
  const app = (partner) => readPrivyApp(env, partner ?? "nuri");
  
  
  
  
  
  const sdks = new Map();
  const sdk = (partner = "nuri") => {
    if (client) return client;
    if (!sdks.has(partner)) {
      const { appId, appSecret, proxyUrl, proxyToken } = app(partner);
      const transport = proxyUrl ? createPrivyProxyFetch({ proxyUrl, proxyToken }) : fetch;
      sdks.set(partner, new PrivyClient({ appId: required(appId, "privy_app_id"),
        appSecret: proxyUrl ? "" : required(appSecret, "privy_app_secret"),
        fetch: (input, init) => fetchPrivyCardRequest(input, init, transport), maxRetries: 0, timeout: 30_000 }));
    }
    return sdks.get(partner);
  };
  const check = (session, grant) => {
    if (session?.status !== "approved" || session.signerAdapter !== "privy" || session.context?.kind !== "mcp_connection"
      || !session.result?.signer || !Number.isSafeInteger(session.expiresAt) || Date.now() >= session.expiresAt
      || grant?.closed || (grant && Date.now() >= grant.expiresAt)) throw new Error("connection_unavailable");
    
    
    
    
    if (session.privyAppId && session.privyAppId !== app(session.partner).appId) throw new Error("privy_app_changed");
  };
  
  
  
  function reasonOf(error) {
    const message = typeof error?.message === "string" ? error.message : "";
    if (TYPED_CODE.test(message)) return message;
    const code = error?.error?.code ?? error?.body?.code;
    if (typeof code === "string" && TYPED_CODE.test(code)) return `privy_${code}`;
    if (Number.isInteger(error?.status)) return `privy_http_${error.status}`;
    const name = error?.constructor?.name;
    return typeof name === "string" && name && name !== "Error" ? name : "unknown_error";
  }
  async function safe(stage, operation) {
    try { return await operation(); }
    catch (error) {
      const reason = reasonOf(error);
      const status = Number.isInteger(error?.status) && error.status >= 100 && error.status <= 599 ? error.status : undefined;
      logEvent("warn", "privy_card_grant_failed", { stage, status: status ?? 0, reason });
      throw Object.assign(new Error(`card_signing_failed: ${reason}`), { cardStage: stage, status, reason });
    }
  }
  function release(grant) {
    if (locks.get(grant.wallet?.id) === grant) locks.delete(grant.wallet.id);
  }
  function dispose(grant) {
    grant.closed = true;
    clearTimeout(grant.timer);
    if (!grant.inFlight && !grant.submitted) release(grant);
    const material = grant.key?.privateKey;
    grant.key = null;
    
    
    if (material && grant.quorum && !grant.attached && !grant.submitted) {
      void sdk(grant?.partner ?? 'nuri').keyQuorums().delete(grant.quorum.id, { authorization_context: authorization(material) })
        .catch(() => logEvent("warn", "privy_card_cleanup_failed", { stage: "delete_unattached_quorum" }))
        .finally(() => material.fill(0));
    } else material?.fill(0);
  }
  function matches(wallet, grant) {
    return wallet.id === grant.wallet.id && !wallet.archived_at && wallet.owner_id === grant.wallet.owner_id
      && getAddress(wallet.address) === grant.wallet.address
      && wallet.additional_signers?.some(entry => entry.signer_id === grant.quorum.id
        && entry.override_policy_ids?.length === 1 && entry.override_policy_ids[0] === grant.policy.id);
  }
  function response(grant) {
    return { status: "authorization_required", request_id: grant.request.id,
      payload_base64: grant.request.payload, expires_at: grant.request.expiresAt };
  }
  async function reconcileExpiredLock(walletId) {
    const previous = locks.get(walletId);
    if (!previous || previous.inFlight || !previous.request || Date.now() < previous.request.expiresAt) return;
    previous.reconciling ??= (async () => {
      if (previous.submitted) {
        const wallet = await sdk(previous.partner ?? 'nuri').wallets().get(walletId);
        previous.attached = matches(wallet, previous);
        previous.ready = previous.attached && !previous.closed;
      }
      previous.request = null;
      previous.submitted = false;
      release(previous);
    })().finally(() => { previous.reconciling = null; });
    await previous.reconciling;
  }
  async function prepareOnce(session, grant) {
    check(session, grant);
    if (grant.ready) return { status: "ready" };
    if (!grant.wallet) {
      const accessToken = session.context.privy?.accessToken;
      if (typeof accessToken !== "string" || !accessToken) throw new Error("reconnect_required");
      let claims;
      try { claims = await sdk(grant?.partner ?? 'nuri').utils().auth().verifyAccessToken(accessToken); }
      catch (error) { throw new Error(Number.isInteger(error?.status) ? "access_token_jwks_unavailable" : "access_token_invalid"); }
      const wallets = [];
      for await (const wallet of sdk(grant?.partner ?? 'nuri').wallets().list({ user_id: claims.user_id, chain_type: "ethereum" })) {
        if (!wallet.archived_at && getAddress(wallet.address) === getAddress(session.result.signer)) wallets.push(wallet);
      }
      check(session, grant);
      if (wallets.length !== 1 || !wallets[0].owner_id) throw new Error("signing_wallet_unavailable");
      grant.wallet = { id: wallets[0].id, address: getAddress(wallets[0].address), owner_id: wallets[0].owner_id };
      delete session.context.privy.accessToken;
    }
    await reconcileExpiredLock(grant.wallet.id);
    check(session, grant);
    if (grant.ready) return { status: "ready" };
    const active = locks.get(grant.wallet.id);
    if (active && active !== grant) return { status: "processing" };
    if (grant.inFlight || grant.submitted) return { status: "processing" };
    locks.set(grant.wallet.id, grant);
    if (grant.request && Date.now() < grant.request.expiresAt) return response(grant);
    try {
      if (!grant.quorum) {
        grant.key = generateKeyPairSync("ec", { namedCurve: "prime256v1",
          privateKeyEncoding: { type: "pkcs8", format: "der" }, publicKeyEncoding: { type: "spki", format: "der" } });
        grant.key.publicKey = grant.key.publicKey.toString("base64");
        check(session, grant);
        grant.quorum = await sdk(grant?.partner ?? 'nuri').keyQuorums().create({ display_name: "Nuri card session",
          authorization_threshold: 1, public_keys: [grant.key.publicKey] });
        check(session, grant);
        if (grant.quorum.authorization_threshold !== 1 || grant.quorum.authorization_keys?.length !== 1
          || grant.quorum.authorization_keys[0].public_key.replace(/\s/g, "") !== grant.key.publicKey
          || grant.quorum.user_ids?.length || grant.quorum.key_quorum_ids?.length) throw new Error("quorum_not_verified");
        const conditions = [
          { field_source: "message", field: "content", operator: "starts_with", value: CARD_MESSAGE_PREFIX },
          { field_source: "message", field: "byte_length", operator: "eq", value: "81" },
          { field_source: "system", field: "current_unix_timestamp", operator: "lt", value: String(Math.floor(grant.expiresAt / 1000)) },
        ];
        grant.policy = await sdk(grant?.partner ?? 'nuri').policies().create({ version: "1.0", name: "Nuri card session", chain_type: "ethereum",
          owner_id: grant.wallet.owner_id, rules: [{ name: "Reveal card during this session", method: "personal_sign", action: "ALLOW", conditions }] });
        check(session, grant);
        const rule = grant.policy.rules?.[0];
        if (grant.policy.owner_id !== grant.wallet.owner_id || grant.policy.rules?.length !== 1 || rule?.method !== "personal_sign"
          || rule.action !== "ALLOW" || rule.conditions?.length !== conditions.length
          || conditions.some(expected => !rule.conditions.some(actual => Object.keys(expected).every(key => actual[key] === expected[key])))) throw new Error("policy_not_verified");
      }
      const wallet = await sdk(grant?.partner ?? 'nuri').wallets().get(grant.wallet.id);
      check(session, grant);
      if (wallet.owner_id !== grant.wallet.owner_id || getAddress(wallet.address) !== grant.wallet.address || wallet.archived_at) throw new Error("wallet_owner_changed");
      const body = { additional_signers: [...(wallet.additional_signers || []), { signer_id: grant.quorum.id, override_policy_ids: [grant.policy.id] }] };
      const expiresAt = Math.min(Date.now() + GRANT_REQUEST_MS, grant.expiresAt);
      const input = { version: 1, method: "PATCH", url: `${PRIVY_API}/v1/wallets/${grant.wallet.id}`,
        headers: { "privy-app-id": required(app(grant?.partner ?? session?.partner ?? 'nuri').appId, "privy_app_id"), "privy-request-expiry": String(expiresAt) }, body };
      grant.request = { id: randomBytes(24).toString("base64url"), body, expiresAt, snapshot: walletSnapshot(wallet),
        payload: Buffer.from(formatRequestForAuthorizationSignature(input)).toString("base64") };
      return response(grant);
    } catch (error) {
      dispose(grant);
      throw error;
    }
  }
  async function prepare(session) {
    return safe("authorize_card_signature", async () => {
      check(session);
      let grant = grants.get(session);
      
      
      
      
      if (grant?.closed) throw new Error("reconnect_required");
      if (!grant && !session.context.privy) {
        if (session.context.signingReady) throw new Error("reconnect_required");
        return null;
      }
      if (!grant) {
        grant = { expiresAt: session.expiresAt, ready: false, closed: false, partner: session.partner ?? "nuri" };
        grants.set(session, grant);
        grant.timer = setTimeout(() => dispose(grant), Math.min(2_147_483_647, Math.max(0, grant.expiresAt - Date.now()))); // setTimeout max 24.8 d; above it Node fires after 1 ms and the grant died at once
        grant.timer.unref();
      }
      grant.preparing ??= prepareOnce(session, grant).finally(() => { grant.preparing = null; });
      return grant.preparing;
    });
  }
  async function complete(session, { requestId, signature } = {}) {
    return safe("authorize_card_signature", async () => {
      const grant = grants.get(session);
      if (!grant || grant.closed) { check(session); throw new Error("reconnect_required"); }
      check(session, grant);
      if (!grant || typeof requestId !== "string" || typeof signature !== "string" || signature.length > 256
        || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature)) throw new Error("invalid_authorization");
      if (grant.ready && grant.completedRequest === requestId) return { status: "ready" };
      if (!grant.request || grant.request.id !== requestId || locks.get(grant.wallet.id) !== grant) throw new Error("authorization_expired");
      if (grant.inFlight) return grant.inFlight;
      if (grant.submitted) return { status: "processing" };
      if (Date.now() >= grant.request.expiresAt) {
        grant.request = null;
        release(grant);
        return { status: "processing" };
      }
      grant.inFlight = (async () => {
        const wallet = await sdk(grant?.partner ?? 'nuri').wallets().get(grant.wallet.id);
        check(session, grant);
        if (locks.get(grant.wallet.id) !== grant) throw new Error("authorization_expired");
        if (Date.now() >= grant.request.expiresAt || walletSnapshot(wallet) !== grant.request.snapshot) {
          grant.request = null;
          release(grant);
          return { status: "processing" };
        }
        grant.submitted = true;
        await sdk(grant?.partner ?? 'nuri').wallets().update(grant.wallet.id, { ...grant.request.body, request_expiry: grant.request.expiresAt,
          authorization_context: { signatures: [signature] } });
        const updated = await sdk(grant?.partner ?? 'nuri').wallets().get(grant.wallet.id);
        check(session, grant);
        if (!matches(updated, grant) || walletSnapshot(updated) !== walletSnapshot({ ...updated, additional_signers: grant.request.body.additional_signers })) throw new Error("grant_not_verified");
        grant.attached = true;
        grant.ready = true;
        grant.completedRequest = requestId;
        release(grant);
        return { status: "ready" };
      })().finally(() => { grant.inFlight = null; });
      return grant.inFlight;
    });
  }
  async function sign(session, message) {
    return safe("authorize_card_signature", async () => {
      const grant = grants.get(session);
      if (!grant || grant.closed) { check(session); throw new Error("reconnect_required"); }
      check(session, grant);
      const nonce = typeof message === "string" && message.startsWith(CARD_MESSAGE_PREFIX) ? message.slice(CARD_MESSAGE_PREFIX.length) : "";
      const now = Date.now(), nonceMs = Number(nonce) * 1000;
      if (!grant?.ready || !grant.key || !/^\d{10}$/.test(nonce) || nonceMs > now || now >= nonceMs + 300_000) throw new Error("card_signing_unavailable");
      const { signature } = await sdk(grant?.partner ?? 'nuri').wallets().ethereum().signMessage(grant.wallet.id, {
        message, authorization_context: authorization(grant.key.privateKey, () => check(session, grant)),
      });
      check(session, grant);
      if (getAddress(verifyMessage(message, signature)) !== grant.wallet.address) throw new Error("card_signature_mismatch");
      if (Date.now() >= nonceMs + 300_000) throw new Error("card_signing_unavailable");
      return signature;
    });
  }
  return { prepare, complete, sign };
}

export function privyAgentAssignments(ids) {
  if (!Array.isArray(ids) || ![1, 3].includes(ids.length) || ids.some(id => typeof id !== 'string' || !id.trim())) throw new Error('one_or_three_quorums_required');
  const assigned = ids.length === 1 ? [ids[0], ids[0], ids[0]] : ids;
  return assigned.map((signerId, index) => ({ signerId, label: `agent-${index + 1}`, walletIndex: assigned.slice(0, index).filter(id => id === signerId).length }));
}
