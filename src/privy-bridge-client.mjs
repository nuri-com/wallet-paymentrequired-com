import { resolveShortLink } from "../public/short-link.mjs";

export const BRIDGE_VERSION = "nuri-wirex-bridge-v1";
export const RESPONSE_INFO = "nuri-wirex-bridge-response";
export const MAX_LINK_MS = 24 * 60 * 60 * 1000;

export function readBridgeParams(urlValue, now = Date.now()) {
  const url = new URL(urlValue);
  const query = url.searchParams;
  const sessionId = (query.get("session_id") || "").trim();
  const state = (query.get("state") || "").trim();
  const intent = (query.get("intent") || "").trim();
  const callback = (query.get("callback") || "").trim();
  const clientPublicKey = (query.get("client_pubkey") || "").trim();
  const expires = Number(query.get("expires") || "0");
  const basePath = url.pathname.replace(/\/bridge\/privy\/?$/, "");

  if (
    !/^[A-Za-z0-9_-]{16,128}$/.test(sessionId) ||
    !/^[A-Za-z0-9_-]{32,128}$/.test(state) ||
    !["register", "auth"].includes(intent) ||
    !isAllowedCallbackUrl(callback, basePath, url.origin) ||
    !isP256PublicKey(clientPublicKey) ||
    !Number.isFinite(expires) || expires <= now || expires - now > MAX_LINK_MS
  ) return null;

  return { origin: url.origin, basePath, sessionId, state, intent, callback, clientPublicKey, expires };
}

export async function loadBridgeParams(urlValue, fetchImpl = globalThis.fetch, now = Date.now()) {
  if (/\/s$/.test(new URL(urlValue).pathname)) urlValue = await resolveShortLink(urlValue, fetchImpl, new URL(urlValue).origin);
  const link = readBridgeParams(urlValue, now);
  if (!link) return null;
  return readApproval(link, fetchImpl);
}


export async function refreshBridgeParams(params, fetchImpl = globalThis.fetch) {
  const fresh = await readApproval(params, fetchImpl);
  
  
  const comparable = ["card_details", "card_pin", "read_session"].includes(params.approvalType)
    ? { ...fresh, signText: params.signText } : fresh;
  if (bridgeSelectionBinding(params, 'refresh') !== bridgeSelectionBinding(comparable, 'refresh')
    || (params.connectionAddress && params.connectionAddress.toLowerCase() !== fresh.connectionAddress.toLowerCase())) {
    throw Object.assign(new Error('This approval request changed.'), { terminal: true });
  }
  return fresh;
}

async function readApproval(link, fetchImpl) {
  const approvalUrl = `${link.origin}${link.basePath}/api/browser-sessions/${encodeURIComponent(link.sessionId)}/approval?state=${encodeURIComponent(link.state)}`;
  const response = await fetchImpl(approvalUrl, {
    credentials: "same-origin",
    cache: "no-store",
    headers: { accept: "application/json" },
  });
  if (!response.ok) throw await approvalResponseError(response);
  return mergeApprovalPayload(link, await response.json());
}

export async function prepareBridgeSigning(params, fetchImpl = globalThis.fetch) {
  if (!["card_details", "card_pin", "read_session"].includes(params.approvalType)) return params;
  const response = await fetchImpl(`${params.origin}${params.basePath}/api/browser-sessions/${encodeURIComponent(params.sessionId)}/approval`, {
    method: "POST", credentials: "same-origin", cache: "no-store",
    headers: { "content-type": "application/json" }, body: JSON.stringify({ state: params.state }),
  });
  if (!response.ok) throw await approvalResponseError(response);
  const prepared = mergeApprovalPayload(params, await response.json());
  if (prepared.approvalType !== params.approvalType || prepared.expectedAddress !== params.expectedAddress) throw new Error("This link isn't valid. Ask your assistant for a new one.");
  return prepared;
}


export async function completeWalletConnection(params, address, signAndSubmit, {
  fetchImpl = globalThis.fetch.bind(globalThis), sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), authorize,
} = {}) {
  const signed = new Set();
  let authorization;
  const endpoint = `${params.origin}${params.basePath}/api/browser-sessions/${params.sessionId}/connection`;
  while (Date.now() < params.expires) {
    const response = await fetchImpl(endpoint, {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ state: params.state, ...(authorization ? { authorization } : {}) }),
    });
    if (!response.ok) throw new Error(`Account connection failed: HTTP ${response.status}`);
    authorization = undefined;
    const result = await response.json();
    if (result.status === "connected") return result;
    if (result.status === "authorization_required") {
      if (typeof authorize !== "function" || typeof result.request_id !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(result.request_id)
        || typeof result.payload_base64 !== "string" || result.payload_base64.length > 65536 || !/^[A-Za-z0-9+/]+={0,2}$/.test(result.payload_base64)
        || !Number.isSafeInteger(result.expires_at) || result.expires_at <= Date.now() || result.expires_at > params.expires) throw new Error("That request isn't valid. Go back to chat and start again.");
      if (signed.has(result.request_id)) throw new Error("That didn't work. Go back to chat and start again.");
      signed.add(result.request_id);
      const { signature } = await authorize(Uint8Array.from(atob(result.payload_base64), c => c.charCodeAt(0)));
      if (typeof signature !== "string" || !signature || signature.length > 4096) throw new Error("That didn't work. Go back to chat and start again.");
      if (Date.now() >= result.expires_at) continue;
      authorization = { requestId: result.request_id, signature };
      continue;
    }
    let request;
    if (result.status === "ownership_required") request = params;
    else if (result.status === "signature_required") {
      let url = new URL(result.approval_url);
      if (url.origin === params.origin && url.pathname === `${params.basePath}/s`) url = new URL(await resolveShortLink(url.href, fetchImpl, params.origin));
      if (url.origin !== params.origin || url.pathname !== `${params.basePath}/bridge/privy`) throw new Error("This link isn't valid. Go back to chat and start again.");
      request = await loadBridgeParams(url.href, fetchImpl);
      if (!request?.signHash || request.signTypedData || request.consentText || request.walletConnection
        || request.expectedAddress.toLowerCase() !== address.toLowerCase()) throw new Error("This request isn't for your wallet. Go back to chat and start again.");
    } else if (result.status !== "processing") throw new Error("That didn't work. Go back to chat and start again.");
    if (request) {
      if (signed.has(request.sessionId)) throw new Error("That didn't work. Go back to chat and start again.");
      signed.add(request.sessionId);
      await signAndSubmit(request);
    } else await sleep(1000);
  }
  throw new Error("This link has expired. Ask your assistant for a new one.");
}

export function mergeApprovalPayload(link, payload) {
  const clientPublicKey = payload?.client_public_key === undefined ? link.clientPublicKey : payload.client_public_key;
  const approvalStatus = payload?.approval_status === undefined ? "pending" : payload.approval_status;
  const approvalType = payload?.approval_type ?? null;
  const walletConnection = payload?.wallet_connection === true;
  const connectionAddress = payload?.connection_address || "";
  const siwe = payload?.siwe || null;
  const signText = typeof payload?.sign_text === "string" ? payload.sign_text : null;
  const signHash = /^0x[0-9a-fA-F]{64}$/.test(payload?.sign_hash || "") ? payload.sign_hash : null;
  const signTypedData = payload?.sign_typed_data || null;
  const consentText = typeof payload?.consent_text === "string" ? payload.consent_text : null;
  const expectedAddress = typeof payload?.expected_address === "string" ? payload.expected_address.trim() : "";
  const privyAgentSignerId = typeof payload?.privy_agent_signer_id === "string" ? payload.privy_agent_signer_id.trim() : "";
  const privyRootAddress = typeof payload?.privy_root_address === "string" ? payload.privy_root_address.trim() : "";
  const wirexLogin = readWirexLogin(payload?.wirex_login);
  const requestCount = [signHash, signText, isValidSiwe(siwe) ? siwe : null, isValidTypedData(signTypedData) ? signTypedData : null]
    .filter(Boolean).length;

  if (
    payload?.signer_adapter !== "privy" ||
    typeof clientPublicKey !== "string" || !isP256PublicKey(clientPublicKey) ||
    !["pending", "approved"].includes(approvalStatus) ||
    ![null, "card_details", "card_pin", "read_session", "payment_agent_setup"].includes(approvalType) ||
    (["card_details", "card_pin", "read_session"].includes(approvalType) && (walletConnection || !signText || signHash || signTypedData || (consentText && approvalType !== "card_details") || siwe)) ||
    (approvalType === 'payment_agent_setup' && (walletConnection || !isValidTypedData(signTypedData) || !consentText || !expectedAddress || signText || signHash || siwe || privyAgentSignerId || privyRootAddress)) ||
    requestCount !== 1 ||
    (connectionAddress && (!walletConnection || !/^0x[0-9a-fA-F]{40}$/.test(connectionAddress))) ||
    (walletConnection && (link.intent !== "auth" || !signText || siwe || signHash || signTypedData || consentText || privyAgentSignerId || privyRootAddress)) ||
    (signText && signText.length > 4096) ||
    (consentText && (!consentText.trim() || consentText.length > 4096)) ||
    (expectedAddress && !/^0x[0-9a-fA-F]{40}$/.test(expectedAddress)) ||
    (Boolean(privyAgentSignerId) !== Boolean(privyRootAddress)) ||
    (privyAgentSignerId && !/^[A-Za-z0-9:._-]{3,256}$/.test(privyAgentSignerId)) ||
    (privyRootAddress && !/^0x[0-9a-fA-F]{40}$/.test(privyRootAddress)) ||
    wirexLogin === false ||
    (wirexLogin && !walletConnection)
  ) throw Object.assign(new Error("This approval link isn't valid."), { terminal: true });

  return { ...link, clientPublicKey, approvalStatus, approvalType, walletConnection, connectionAddress, siwe, signText, signHash, signTypedData, consentText, expectedAddress, privyAgentSignerId, privyRootAddress, wirexLogin, rootApproval: payload.root_approval || null };
}

// Public values for the Wirex wallet-signature login (#150): null when the deployment does not
// offer it, false when present but malformed (the link is then refused).
function readWirexLogin(value) {
  if (value === undefined || value === null) return null;
  if (!value || typeof value !== "object") return false;
  const companyId = typeof value.company_id === "string" ? value.company_id.trim() : "";
  const chainId = Number(value.chain_id);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(companyId) || !Number.isSafeInteger(chainId) || chainId <= 0) return false;
  return { companyId, chainId };
}

// The exact text Wirex verifies; mirrors wirexLoginMessage in src/wirex-baas.mjs (the browser
// bundle must not import that server module). Built at tap time: the nonce is unix seconds now.
export function wirexLoginRequest(wirexLogin, owner, nonce = Math.floor(Date.now() / 1000)) {
  return { nonce, message: `I, owner of account ${owner} confirm that I request access token for company ${wirexLogin.companyId} on chain ${wirexLogin.chainId} at ${nonce}` };
}

async function approvalResponseError(response) {
  let code;
  try { code = (await response.json())?.error; } catch {  }
  
  const terminal = [401, 403, 404, 410].includes(response.status)
    || ["session_not_found", "session_expired", "approval_state_mismatch", "approval_session_unavailable",
      "session_id_is_required", "session_id_invalid"].includes(code);
  return Object.assign(new Error(terminal
    ? (code === "session_expired" || response.status === 410 ? "This approval has expired." : "This approval is unavailable.")
    : "Couldn't load this approval. Try again."), { terminal, status: response.status, code });
}


export function connectionAttempt(params, action, address = "", storage, binding) {
  if (!params) return null;
  try {
    storage ||= window.sessionStorage;
    const key = `wallet-connection:${params.sessionId}:${params.state}`;
    const saved = JSON.parse(storage.getItem(key) || "null");
    let attempt = saved?.expires === params.expires && params.expires > Date.now() ? saved : null;
    
    
    if (attempt?.binding) {
      try {
        const parts = JSON.parse(attempt.binding);
        if (Array.isArray(parts) && parts.length === 2 && parts[0] && typeof parts[0] === 'object'
          && !Array.isArray(parts[0]) && typeof parts[1] === 'string') {
          attempt.binding = bridgeSelectionBinding(parts[0], parts[1]) || attempt.binding;
        }
      } catch {  }
    }
    if (action === "clear") { storage.removeItem(key); return null; }
    if (action === "start" || action === "retry") attempt ||= {
      expires: params.expires, address: "", recovered: false, retryOnly: action === "retry",
    };
    if (!attempt) return null;
    if (action === "recover" || action === "retry") {
      if (attempt.recovered) return null;
      attempt.recovered = true;
    }
    if (action === "start") attempt.retryOnly = false;
    if (address && attempt.address && address.toLowerCase() !== attempt.address.toLowerCase()) return null;
    if (binding && attempt.binding && binding !== attempt.binding) return null;
    if (address) attempt.address = address;
    if (binding) attempt.binding = binding;
    if (action !== "read") {
      const text = JSON.stringify(attempt);
      storage.setItem(key, text);
      if (storage.getItem(key) !== text) return null;
    }
    return attempt;
  } catch { return null; } 
}

export function messageForAddress(params, address) {
  if (params.signTypedData) return JSON.stringify(params.signTypedData);
  if (params.signHash) return params.signHash;
  if (params.signText) return params.signText;
  return formatSiwe(params.siwe, address);
}

export function personalSignInput(params, message) {
  return params.signHash || personalSignTextInput(message);
}

export function personalSignTextInput(message) {
  return bytesToHex(new TextEncoder().encode(message));
}





export function selectBridgeWallet(embeddedWallets, requiredAddress) {
  if (requiredAddress) {
    return embeddedWallets.find(
      ({ address }) => address.toLowerCase() === requiredAddress.toLowerCase(),
    );
  }
  const importedWallets = embeddedWallets.filter((wallet) => wallet.imported === true);
  if (importedWallets.length === 1) return importedWallets[0];
  if (importedWallets.length > 1) return undefined;
  const primaryWallets = embeddedWallets.filter(
    ({ walletIndex, imported }) => walletIndex === 0 && imported === false,
  );
  return primaryWallets.length === 1 ? primaryWallets[0] : undefined;
}



export function resolveBridgeWallet(wallets, linkedAccounts, requiredAddresses = []) {
  const addressKey = value => typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value) ? value.toLowerCase() : null;
  const supported = value => ['privy', 'privy-v2'].includes(value?.walletClientType);
  const pins = requiredAddresses.filter(Boolean).map(addressKey);
  const connected = (Array.isArray(wallets) ? wallets : []).filter(wallet => supported(wallet)
    && (!wallet.chainType || wallet.chainType === 'ethereum'));
  const linked = (Array.isArray(linkedAccounts) ? linkedAccounts : []).filter(account => account?.type === 'wallet'
    && account.chainType === 'ethereum' && supported(account));
  const diagnostics = { connected: connected.length, linked: linked.length, pinned: pins.length > 0,
    linkedMetadataPresent: Array.isArray(linkedAccounts) };
  const result = (reason, wallet, choices = []) => ({ reason, wallet, choices, diagnostics });
  if (pins.some(pin => !pin) || new Set(pins).size > 1) return result('pin_conflict');
  if (!Array.isArray(linkedAccounts)) return result('metadata_missing');
  const addresses = new Set([...connected, ...linked].map(wallet => addressKey(wallet.address)));
  if (addresses.has(null)) return result('metadata_conflict');
  const candidates = [];
  for (const address of addresses) {
    const sdk = connected.filter(wallet => addressKey(wallet.address) === address);
    const accounts = linked.filter(wallet => addressKey(wallet.address) === address);
    if (sdk.length > 1 || accounts.length > 1) return result('metadata_conflict');
    const records = [...sdk, ...accounts];
    const metadata = {};
    for (const field of ['imported', 'walletIndex']) {
      const values = records.map(record => record[field]).filter(value => value !== undefined);
      if (new Set(values).size > 1) return result('metadata_conflict');
      metadata[field] = values[0];
    }
    if ((metadata.imported !== undefined && typeof metadata.imported !== 'boolean')
      || (metadata.walletIndex !== undefined && metadata.walletIndex !== null
        && (!Number.isSafeInteger(metadata.walletIndex) || metadata.walletIndex < 0))) return result('metadata_conflict');
    candidates.push({ address, wallet: sdk[0], linked: accounts.length === 1, ...metadata });
  }
  if (pins.length) {
    const match = candidates.find(candidate => candidate.address === pins[0]);
    if (!match?.wallet) return result('pin_missing');
    if (!match.linked) return result('metadata_missing');
    return result('selected', match.wallet);
  }
  if (!candidates.length) return result('recovery');
  
  
  if (candidates.some(candidate => !candidate.linked)) return result('metadata_missing');
  const choices = candidates.every(candidate => candidate.wallet) ? candidates.map(candidate => candidate.wallet) : [];
  if (candidates.some(candidate => typeof candidate.imported !== 'boolean')) return result('metadata_missing', undefined, choices);
  const imported = candidates.filter(candidate => candidate.imported === true);
  if (!imported.length && candidates.some(candidate => !Number.isSafeInteger(candidate.walletIndex))) return result('metadata_missing', undefined, choices);
  const eligible = imported.length ? imported : candidates.filter(candidate => candidate.walletIndex === 0);
  if (eligible.length === 1) return eligible[0].wallet
    ? result('selected', eligible[0].wallet) : result('not_connected');
  if (candidates.some(candidate => !candidate.wallet)) return result('not_connected');
  return result('ambiguous', undefined, (eligible.length ? eligible : candidates).map(candidate => candidate.wallet));
}



export function bridgeSelectionBinding(params, userId) {
  if (!params || typeof userId !== 'string' || !userId) return null;
  
  const { resumeAddress, connectionAddress, clientPublicKey, approvalStatus, ...request } = params;
  return JSON.stringify([request, userId]);
}

export async function encryptForServer(payload, serverPublicKeyB64u, state, webCrypto = globalThis.crypto) {
  const serverPublicKeyBytes = base64urlToBytes(serverPublicKeyB64u);
  const serverPublicKey = await webCrypto.subtle.importKey(
    "raw", toArrayBuffer(serverPublicKeyBytes), { name: "ECDH", namedCurve: "P-256" }, false, [],
  );
  zeroize(serverPublicKeyBytes, webCrypto);
  const ephemeral = await webCrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const sharedSecret = await webCrypto.subtle.deriveBits({ name: "ECDH", public: serverPublicKey }, ephemeral.privateKey, 256);
  const salt = new Uint8Array(await webCrypto.subtle.digest("SHA-256", toArrayBuffer(new TextEncoder().encode(`${BRIDGE_VERSION}:${state}`))));
  const hkdfKey = await webCrypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  const aesKey = await webCrypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: toArrayBuffer(salt), info: toArrayBuffer(new TextEncoder().encode(RESPONSE_INFO)) },
    hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  const iv = webCrypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  let ciphertext;
  try {
    ciphertext = await webCrypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, aesKey, toArrayBuffer(plaintext));
  } finally {
    zeroize(new Uint8Array(sharedSecret), webCrypto);
    zeroize(salt, webCrypto);
    zeroize(plaintext, webCrypto);
  }
  return {
    version: BRIDGE_VERSION,
    state,
    alg: "P-256-ECDH+A256GCM",
    epk: bytesToBase64url(new Uint8Array(await webCrypto.subtle.exportKey("raw", ephemeral.publicKey))),
    iv: bytesToBase64url(iv),
    ciphertext: bytesToBase64url(new Uint8Array(ciphertext)),
  };
}

export function formatSiwe(s, address) {
  return `${s.domain} wants you to sign in with your Ethereum account:\n${address}\n\n${s.statement}\n\nURI: ${s.uri}\nVersion: ${s.version || 1}\nChain ID: ${s.chainId}\nNonce: ${s.nonce}\nIssued At: ${s.issuedAt}\nExpiration Time: ${s.expirationTime}`;
}

function isValidSiwe(siwe) {
  if (!siwe || typeof siwe !== "object") return false;
  return ["domain", "uri", "statement", "chainId", "nonce", "issuedAt", "expirationTime"]
    .every((key) => siwe[key] !== undefined && siwe[key] !== null && siwe[key] !== "");
}

function isValidTypedData(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!value.domain || !value.types || typeof value.primaryType !== "string" || !value.primaryType || !value.message) return false;
  return JSON.stringify(value).length <= 32_768;
}

function isAllowedCallbackUrl(value, basePath, ownOrigin = "") {
  try {
    const url = new URL(value);
    const local = (url.protocol === "http:" || url.protocol === "https:") && isLocalHost(url.hostname);
    const nuri = url.protocol === "https:" && isNuriHost(url.hostname);
    
    
    
    const own = url.origin === ownOrigin;
    const escaped = basePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const path = new RegExp(`^${escaped}/api/browser-sessions/[A-Za-z0-9_-]{16,128}/callback$`);
    return (local || nuri || own) && path.test(url.pathname) && !url.search && !url.hash && !url.username && !url.password;
  } catch {
    return false;
  }
}

function isP256PublicKey(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    const bytes = base64urlToBytes(value);
    const ok = bytes.length === 65 && bytes[0] === 0x04;
    bytes.fill(0);
    return ok;
  } catch {
    return false;
  }
}

function isNuriHost(hostname) {
  const host = hostname.toLowerCase();
  return host === "nuri.com" || host.endsWith(".nuri.com");
}
function isLocalHost(hostname) {
  return ["localhost", "127.0.0.1", "::1", "[::1]"].includes(hostname);
}
function bytesToHex(bytes) {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
function bytesToBase64url(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function base64urlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function toArrayBuffer(bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
function zeroize(bytes, webCrypto) {
  if (!bytes?.byteLength) return;
  webCrypto.getRandomValues(bytes);
  bytes.fill(0);
}
