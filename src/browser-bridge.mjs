import crypto from "node:crypto";
import { formatUserOperationRequest } from "viem/account-abstraction";
import { readFile } from "node:fs/promises";
import { parseCorsExtraOrigins } from "./env.mjs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { computeAddress, verifyMessage, verifyTypedData, getBytes } from "ethers";

import { formatSiwe } from "./siwe.mjs";
import { readPrivyApp } from "./privy-apps.mjs";
import { readBaasConfig } from "./wirex-public.mjs";






const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT_DIR = join(__dirname, "..");
const PRIVY_BRIDGE_HTML_PATH = join(ROOT_DIR, "public", "privy-bridge.html");
const PRIVY_BRIDGE_JS_PATH = join(ROOT_DIR, "public", "privy-bridge.js");

const VERSION = "nuri-wirex-bridge-v1";
const ENVELOPE_ALG = "P-256-ECDH+A256GCM";
const RESPONSE_INFO = "nuri-wirex-bridge-response";
const INTENTS = ["register", "auth"];




export const MAX_TIMEOUT_MS = 24 * 60 * 60_000;





// Wirex connection lifetime from the tap: 1 h default (D-QUORUM TTL B). The Safe's user half has no TTL: the LLM holds it (D-CUSTODY-V2).
export function connectionTtlMs(env = process.env) {
  const value = Number(env?.CONNECTION_TTL_MS);
  return Number.isSafeInteger(value) && value > 0 ? value : 60 * 60_000;
}
const DEFAULT_TIMEOUT_MS = MAX_TIMEOUT_MS;
const MIN_TIMEOUT_MS = 30_000;
const MAX_ACTIVE_SESSIONS = 1000;





const LINEAGE_PATTERN = /^[A-Za-z0-9:._-]{3,256}$/;














const DEFAULT_BRIDGE_ALLOWED_HOSTS = ".nuri.com";






// One signer only: the Privy login (the owner's EOA signature). The field stays
// in the payloads because stored session rows and the approval page read it.
const SIGNER_ADAPTER = "privy";
const HOST_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;




export function parseHostAllowlist(raw, setting) {
  const entries = [];
  for (const token of String(raw ?? "").split(/[\s,]+/).filter(Boolean)) {
    const entry = token.toLowerCase();
    if (/[*?/@:\\]/.test(entry) || entry.includes("://")) {
      throw new Error(`The ${setting} setting must list plain hostnames, so "${token}" was refused: wildcards and patterns are never allowed here. Replace it with the exact host, or ".example.com" to allow that domain and its subdomains.`);
    }
    const suffix = entry.startsWith(".");
    const host = suffix ? entry.slice(1) : entry;
    const labels = host.split(".");
    if (!host || host.length > 253 || labels.some((label) => !HOST_LABEL.test(label))) {
      throw new Error(`The ${setting} setting lists "${token}", which is not a hostname. Use an exact host like "app.example.com", or ".example.com" to allow that domain and its subdomains.`);
    }
    if (suffix && labels.length < 2) {
      throw new Error(`The ${setting} setting lists "${token}", which would allow every subdomain of a top-level domain. Use a real domain, like ".example.com".`);
    }
    entries.push({ host, suffix });
  }
  if (!entries.length) {
    throw new Error(`The ${setting} setting is empty. List at least one exact host, or ".example.com" to allow that domain and its subdomains.`);
  }
  return entries;
}

export function hostMatchesAllowlist(hostname, entries) {
  const host = String(hostname || "").toLowerCase();
  return entries.some((entry) => (entry.suffix ? host === entry.host || host.endsWith(`.${entry.host}`) : host === entry.host));
}













export function publicUnsignedOperation(operation) {
  if (!operation) return null;
  const fields = ["sender", "nonce", "factory", "factoryData", "callData", "callGasLimit", "verificationGasLimit", "preVerificationGas", "maxFeePerGas", "maxPriorityFeePerGas", "paymaster", "paymasterVerificationGasLimit", "paymasterPostOpGasLimit", "paymasterData"];
  return formatUserOperationRequest(Object.fromEntries(fields.filter(key => operation[key] !== undefined).map(key => [key, operation[key]])));
}

export function createBrowserBridge({ publicOrigin, env = process.env, sessionStore = null, effects = null } = {}) {
  return new BrowserBridge({ publicOrigin, env, sessionStore, effects });
}

class BrowserBridge {
  constructor({ publicOrigin, env, sessionStore = null, effects = null }) {
    this.env = env;
    // D-SIGNER-SEAM-1A: product side effects of an approved connect tap (src/mcp-connection-effects.mjs).
    this.effects = effects;
    this.publicOrigin = normalizeOrigin(publicOrigin || env.PUBLIC_ORIGIN || "http://localhost:8795");
    
    
    
    this.basePath = normalizeBasePath(env.BASE_PATH || "");
    this.publicBase = this.publicOrigin + this.basePath;
    
    
    
    this.bridgeAllowedHosts = parseHostAllowlist(String(env.BRIDGE_ALLOWED_HOSTS ?? "").trim() || DEFAULT_BRIDGE_ALLOWED_HOSTS, "BRIDGE_ALLOWED_HOSTS");
    // Wallet-signature Wirex login (#150): both values are public; the page signs the login
    // message with them at tap time, the same tap that proves wallet ownership.
    const baas = readBaasConfig(env);
    this.wirexLogin = baas.companyId ? Object.freeze({ company_id: baas.companyId, chain_id: baas.chainId }) : null;
    this.sessions = new Map();
    
    
    
    this.sessionStore = sessionStore;
  }

  async privyBridgeHtml(partner = "nuri") {
    const template = await readFile(PRIVY_BRIDGE_HTML_PATH, "utf8");
    
    
    
    
    const privyApp = readPrivyApp(this.env, partner);
    const config = JSON.stringify({
      appId: privyApp.appId,
      clientId: privyApp.clientId,
      embedOrigins: [...parseCorsExtraOrigins(this.env.CORS_EXTRA_ORIGINS)],
    }).replace(/</g, "\\u003c");
    return template.replace("__PRIVY_CONFIG__", config);
  }
  privyBridgeJs() {
    return readFile(PRIVY_BRIDGE_JS_PATH);
  }

  
  
  
  createSession({ intent, siwe, signText, signHash, signTypedData, consentText, rootApproval, prepareSigning, expectedAddress, context = {}, bridgeOptions, timeoutMs, bridgeUrl, partner, privyAgentSignerId, privyRootAddress, lineage } = {}) {
    this.purgeExpiredSessions();
    if (this.sessions.size >= MAX_ACTIVE_SESSIONS) throw new Error("too_many_active_sessions");
    if (!INTENTS.includes(intent)) throw new Error(`intent_must_be_one_of:${INTENTS.join(",")}`);
    if (prepareSigning !== undefined && (typeof prepareSigning !== "function" || signText !== undefined || signHash !== undefined || signTypedData !== undefined || siwe !== undefined)) throw new Error("invalid_signing_preparation");
    const prepared = prepareSigning ? validatePreparedSigning(prepareSigning()) : null;
    if (prepared) signText = prepared.signText;
    const requestCount = [siwe, signText, signHash, signTypedData].filter((value) => value !== undefined).length;
    if (requestCount !== 1) throw new Error("exactly_one_sign_request_required");
    if (signHash !== undefined) {
      if (typeof signHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(signHash)) throw new Error("sign_hash_must_be_0x_32_bytes");
    } else if (signText !== undefined) {
      if (typeof signText !== "string" || !signText.trim()) throw new Error("sign_text_invalid");
      if (signText.length > 4096) throw new Error("sign_text_too_long");
    } else if (signTypedData !== undefined) {
      assertTypedData(signTypedData);
    } else {
      assertSiwe(siwe);
    }
    if (consentText !== undefined) {
      // This guard used to read
      //   `if (!signHash && !signTypedData && adapter !== 'privy')`
      // i.e. a plain signText + consentText pair was only allowed for privy.
      // Privy is now the only signer, so the condition can never be true and
      // the guard is gone rather than left as a branch that cannot fire.
      // The owner-EOA approvals (bank send, account limits, wallet limit lift)
      // are exactly that shape and depend on this.
      if (typeof consentText !== "string" || !consentText.trim()) throw new Error("consent_text_invalid");
      if (consentText.length > 4096) throw new Error("consent_text_too_long");
    }

    const options = this.readBridgeOptions(bridgeOptions);
    
    
    
    
    
    
    const sessionPartner = partner === undefined || partner === null ? "nuri" : partner;
    if (sessionPartner !== "nuri" && sessionPartner !== "wirex") throw new Error("partner_invalid");
    const privyApp = readPrivyApp(this.env, sessionPartner);
    if (!privyApp.connectable) {
      if (sessionPartner === "wirex") {
        const missing = new Error("wirex_signer_not_configured: The Wirex sign-in is not set up on this server yet. Call account {action: \"status\"}: its answer holds the Nuri link; show it unchanged.");
        // connect_wallet is not a catalog tool; the connect link comes from account status (D-C).
        missing.next_action = { type: "call", tool: "account",
          args: { action: "status" }, only_if: "the person is a Nuri user" };
        throw missing;
      }
      throw new Error("privy_not_configured");
    }
    const expectedSignerAddress = expectedAddress ? requiredAddress(expectedAddress, "expected_address") : "";
    const agentSignerId = privyAgentSignerId ? requiredIdentifier(privyAgentSignerId, "privy_agent_signer_id") : "";
    const agentRootAddress = privyRootAddress ? requiredAddress(privyRootAddress, "privy_root_address") : "";
    if (Boolean(agentSignerId) !== Boolean(agentRootAddress)) throw new Error("privy_agent_signer_and_root_address_required_together");

    const timeout = readTimeoutMs(timeoutMs);
    const sessionId = base64url(crypto.randomBytes(32));
    const state = base64url(crypto.randomBytes(32));
    const expiresAt = Date.now() + timeout;
    
    
    
    const requestLineage = readLineage(lineage) || sessionId;
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();
    const callback = `${this.publicBase}/api/browser-sessions/${sessionId}/callback`;
    const approvalUrl = this.buildApprovalUrl({
      bridgeUrl: bridgeUrl || `${this.publicBase}${sessionPartner === "wirex" ? "/bridge/privy/wirex" : "/bridge/privy"}`,
      sessionId,
      state,
      intent,
      callback,
      clientPublicKey: base64url(ecdh.getPublicKey()),
      expiresAt,
      options,
      lineage: requestLineage,
    });

    this.sessions.set(sessionId, {
      intent,
      signerAdapter: SIGNER_ADAPTER,
      state,
      siwe,
      signText: signText || null,
      prepareSigning: prepareSigning || null,
      signingExpiresAt: prepared?.expiresAt || null,
      signHash: signHash || null,
      signTypedData: signTypedData || null,
      rootApproval: rootApproval || null,
      consentText: consentText || null,
      expectedAddress: expectedSignerAddress,
      privyAgentSignerId: agentSignerId,
      privyRootAddress: agentRootAddress,
      context,
      extra: null,
      expiresAt,
      approvalExpiresAt: expiresAt,
      
      
      lineage: requestLineage,
      approvalUrl,
      createdAt: Date.now(),
      privateKey: ecdh.getPrivateKey(),
      status: "pending",
      result: null,
    });
    
    
    
    
    if (privyApp) Object.defineProperty(this.sessions.get(sessionId), "privyAppId", { value: privyApp.appId });
    Object.defineProperty(this.sessions.get(sessionId), "partner", { value: sessionPartner });
    
    
    this.persistSession(sessionId);

    setTimeout(() => {
      const session = this.sessions.get(sessionId);
      if (session?.status === "pending" && Date.now() > session.expiresAt) {
        zeroize(session.privateKey);
        this.sessions.delete(sessionId);
      }
    }, timeout + 60_000).unref();

    return {
      ok: true,
      session_id: sessionId,
      status: "pending",
      intent,
      signer_adapter: SIGNER_ADAPTER,
      approval_url: approvalUrl,
      result_url: `${this.publicBase}/api/browser-sessions/${sessionId}`,
      expires_at: new Date(expiresAt).toISOString(),
      security_boundary: "privy_wallet_signs_browser_side",
    };
  }

  readStatus(sessionId) {
    const session = this.requireSession(sessionId);
    if (Date.now() > session.expiresAt && session.status === "pending") {
      zeroize(session.privateKey);
      this.sessions.delete(sessionId);
      return { ok: false, status: "expired", error: "session_expired" };
    }
    if (session.status !== "approved") {
      return { ok: true, status: "pending", session_id: sessionId, intent: session.intent, expires_at: new Date(session.expiresAt).toISOString() };
    }
    return { ok: true, status: "approved", session_id: sessionId, intent: session.intent, result: publicResult(session.result), expires_at: new Date(session.expiresAt).toISOString() };
  }

  readApprovalPayload(sessionId, state) {
    const session = this.requireSession(sessionId);
    if (state !== session.state) throw new Error("approval_state_mismatch");
    const walletConnection = session.context?.kind === "mcp_connection" && session.intent === "auth";
    
    if (Date.now() >= (session.approvalExpiresAt ?? session.expiresAt)) throw new Error("session_expired");
    if (!["pending", "approved"].includes(session.status)) throw new Error("approval_session_unavailable");
    let clientPublicKey;
    if (session.status === "pending") {
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.setPrivateKey(session.privateKey);
      clientPublicKey = base64url(ecdh.getPublicKey());
    }
    return {
      ok: true,
      approval_status: session.status,
      ...(clientPublicKey ? { client_public_key: clientPublicKey } : {}),
      signer_adapter: session.signerAdapter,
      wallet_connection: walletConnection,
      connection_address: walletConnection && session.status === "approved" ? session.result.address : null,
      siwe: session.siwe || null,
      sign_text: session.signText,
      sign_hash: session.signHash,
      sign_typed_data: session.signTypedData,
      
      root_approval: session.context.kind === "mcp_deployment" ? {
        purpose: "connect_register", owner: session.expectedAddress,
        chain_id: Number(this.env.AA_CHAIN_ID || this.env.WIREX_CHAIN_ID || 84532),
        user_op_hash: session.signHash,
        prepared_user_operation: publicUnsignedOperation(session.context.userOp),
      } : session.rootApproval,
      consent_text: session.consentText,
      expected_address: session.expectedAddress || null,
      privy_agent_signer_id: session.privyAgentSignerId || null,
      privy_root_address: session.privyRootAddress || null,
      ...(walletConnection && this.wirexLogin ? { wirex_login: this.wirexLogin } : {}),
      approval_type: session.prepareSigning && ["card_details", "card_pin", "read_session"].includes(session.context.kind) ? session.context.kind
        : session.context.kind === 'payment_agent_setup' && session.signTypedData && session.consentText && session.expectedAddress && !session.privyAgentSignerId ? 'payment_agent_setup' : null,
    };
  }

  
  
  
  
  
  
  
  newestPendingApproval(lineage) {
    const id = String(lineage ?? "").trim();
    if (!LINEAGE_PATTERN.test(id)) return { ok: true, approval_url: null };
    let newest = null;
    for (const session of this.sessions.values()) {
      
      if (session.lineage !== id || session.status !== "pending") continue;
      if (Date.now() > session.expiresAt) continue;
      
      
      if (!newest || session.createdAt >= newest.createdAt) newest = session;
    }
    return newest
      ? { ok: true, approval_url: newest.approvalUrl, expires_at: new Date(newest.expiresAt).toISOString() }
      : { ok: true, approval_url: null };
  }

  
  
  prepareApproval(sessionId, state) {
    this.readApprovalPayload(sessionId, state);
    const session = this.requireSession(sessionId);
    if (session.status !== "pending") throw new Error("session_already_used");
    if (session.prepareSigning) {
      const prepared = validatePreparedSigning(session.prepareSigning());
      session.signText = prepared.signText;
      session.signingExpiresAt = prepared.expiresAt;
    }
    return this.readApprovalPayload(sessionId, state);
  }

  
  approved(sessionId) {
    const session = this.requireSession(sessionId);
    if (session.status !== "approved") return null;
    return { result: session.result, context: session.context };
  }
  getExtra(sessionId) {
    return this.requireSession(sessionId).extra;
  }
  setExtra(sessionId, extra) {
    this.requireSession(sessionId).extra = extra;
  }

  
  
  cacheAuth(sessionId, { jwt, address }, ttlMs) {
    const session = this.requireSession(sessionId);
    session.extra = { kind: "auth", jwt, address };
    session.expiresAt = Date.now() + ttlMs;
  }

  
  getAuth(sessionId) {
    const session = this.requireSession(sessionId);
    if (Date.now() > session.expiresAt) {
      zeroize(session.privateKey);
      this.sessions.delete(sessionId);
      throw new Error("auth_session_expired");
    }
    if (session.extra?.kind !== "auth" || !session.extra.jwt) throw new Error("not_an_authorized_session");
    return { jwt: session.extra.jwt, address: session.extra.address };
  }

  async acceptCallback(sessionId, envelope) {
    const session = this.requireSession(sessionId);
    if (session.status !== "pending") throw new Error("session_already_used");
    if (Date.now() >= (session.approvalExpiresAt ?? session.expiresAt)) {
      zeroize(session.privateKey);
      this.sessions.delete(sessionId);
      throw new Error("session_expired");
    }
    if (session.signingExpiresAt !== null && Date.now() >= session.signingExpiresAt) throw new Error("signing_challenge_expired");
    const payload = decryptEnvelope(envelope, session);
    assertBridgePayload(payload, session);
    const result = buildApprovedResult(payload, session);
    const hook = { sessionId, session, payload, result, wirexLogin: this.wirexLogin };
    // Runs BEFORE the persist below so what it captures survives a restart.
    this.effects?.prePersist?.(hook);
    // TTL B: a wallet connection lives CONNECTION_TTL_MS from the tap, not the 24 h approval window.
    if (session.context.kind === "mcp_connection") { session.context.connectedAt = Date.now(); session.expiresAt = session.context.connectedAt + connectionTtlMs(); }
    
    
    this.persistSession(sessionId, { ...session, privyAppId: session.privyAppId,
      partner: session.partner, status: "approved", result });
    
    
    
    
    this.effects?.postPersist?.(hook);
    zeroize(session.privateKey);
    session.privateKey = null;
    session.status = "approved";
    session.result = result;
    this.effects?.detached?.(hook);
    return { ok: true };
  }

  // Broker adoption (C0 §1 amendment, R2 D1): the root signer broker returns an envelope sealed
  // to this consumer's STATIC key, never to the per-session key. Everything after decryption is
  // the exact legacy sequence: assertBridgePayload -> buildApprovedResult -> prePersist ->
  // persistSession -> postPersist -> zeroize -> detached. Expiry is judged by the broker's
  // approvedAt (timely submission), not by the time this process reads the result; a stored
  // session is never deleted while a retained broker result may still be read back.
  // Idempotent: status approved + same brokerDigest answers ok again so the ACK can be repeated
  // after a restart; a different digest for an adopted session is rejected.
  async acceptBrokerResult(sessionId, { envelope, digest, approvedAt } = {}, { open, consumerId } = {}) {
    const session = this.requireSession(sessionId);
    const digestValue = requiredString(digest, "digest");
    if (session.status === "approved") {
      if (session.brokerDigest && session.brokerDigest === digestValue) return { ok: true, replay: true };
      throw new Error("session_already_used");
    }
    if (session.status !== "pending") throw new Error("session_already_used");
    if (!session.brokerRequestId) throw new Error("session_not_broker_bound");
    const submittedAt = Number(approvedAt);
    if (!Number.isSafeInteger(submittedAt)) throw new Error("broker_approved_at_invalid");
    if (submittedAt >= (session.approvalExpiresAt ?? session.expiresAt)) throw new Error("session_expired");
    if (session.signingExpiresAt !== null && submittedAt >= session.signingExpiresAt) throw new Error("signing_challenge_expired");
    if (typeof open !== "function") throw new Error("consumer_result_opener_required");
    if (envelopeDigest(envelope) !== digestValue) throw new Error("broker_digest_mismatch");
    const inner = open(envelope, session.state); // B1 codec + binding checks (src/signer-broker-hook.mjs)
    if (!inner || typeof inner !== "object") throw new Error("invalid_bridge_payload");
    if (inner.requestId !== session.brokerRequestId) throw new Error("broker_request_mismatch");
    if (consumerId && inner.consumerId !== consumerId) throw new Error("broker_consumer_mismatch");
    if (inner.state !== session.state) throw new Error("payload_state_mismatch");
    if (session.privyAppId && inner.privyAppId && inner.privyAppId !== session.privyAppId) throw new Error("privy_app_mismatch");
    // Only the extras this session asked for become bridge payload fields (C0 §2: no unsolicited extras).
    const { extras, kind, requestId, consumerId: _c, privyAppId: _a, expiresAt: _e, ...bridgeFields } = inner;
    const payload = { ...bridgeFields };
    for (const id of session.brokerExtras ?? []) {
      const extra = extras?.[id];
      if (!extra || typeof extra !== "object") continue;
      if (extra.type === "sign_message" && typeof extra.signature === "string") payload[id] = extra.signature;
      else if (extra.type === "privy_access_token" && typeof extra.token === "string") payload[id] = extra.token;
    }
    // R2 D2: the Wirex login nonce was chosen product-side at registration; rebuild it here.
    if (payload.wirexLoginSignature !== undefined && Number.isSafeInteger(session.context?.wirexLoginNonce)) payload.wirexLoginNonce = session.context.wirexLoginNonce;
    assertBridgePayload(payload, session);
    const result = buildApprovedResult(payload, session);
    const hook = { sessionId, session, payload, result, wirexLogin: this.wirexLogin };
    this.effects?.prePersist?.(hook);
    if (session.context.kind === "mcp_connection") { session.context.connectedAt = Date.now(); session.expiresAt = session.context.connectedAt + connectionTtlMs(); }
    session.brokerDigest = digestValue;
    this.persistSession(sessionId, { ...session, privyAppId: session.privyAppId,
      partner: session.partner, status: "approved", result });
    this.effects?.postPersist?.(hook);
    zeroize(session.privateKey);
    session.privateKey = null;
    session.status = "approved";
    session.result = result;
    this.effects?.detached?.(hook);
    return { ok: true, replay: false };
  }

  // Binds a pending session to its broker request (C0 §1 amendment): stored in the same row so
  // a restart re-reads the same encrypted result and dedupes by digest.
  bindBrokerRequest(sessionId, { requestId, extras = [], approvalUrl, expiresAt } = {}) {
    const session = this.requireSession(sessionId);
    if (session.status !== "pending") throw new Error("session_already_used");
    session.brokerRequestId = requiredString(requestId, "broker_request_id");
    session.brokerExtras = extras.filter((id) => typeof id === "string");
    if (Number.isSafeInteger(expiresAt)) session.brokerExpiresAt = expiresAt;
    if (typeof approvalUrl === "string" && approvalUrl) { session.approvalUrl = approvalUrl; if (session.context?.approvalUrl) session.context.approvalUrl = approvalUrl; }
    this.persistSession(sessionId);
    return session;
  }

  buildApprovalUrl({ bridgeUrl, sessionId, state, intent, callback, clientPublicKey, expiresAt, options, lineage }) {
    const url = new URL(bridgeUrl);
    assertApprovalPageHost(url, this.bridgeAllowedHosts);
    url.searchParams.set("session_id", sessionId);
    url.searchParams.set("state", state);
    url.searchParams.set("intent", intent);
    url.searchParams.set("callback", callback);
    url.searchParams.set("client_pubkey", clientPublicKey);
    url.searchParams.set("expires", String(expiresAt));
    
    
    url.searchParams.set("lineage", lineage);
    if (options.userName) url.searchParams.set("user_name", options.userName);
    if (options.autoStart) url.searchParams.set("auto_start", "1");
    return url.toString();
  }

  readBridgeOptions(input = {}) {
    const userName = String(input.userName || "").trim().slice(0, 128);
    const autoStart = input.autoStart === true;
    return { userName, autoStart };
  }

  requireSession(sessionId) {
    const id = requiredString(sessionId, "session_id");
    let session = this.sessions.get(id);
    if (!session && this.sessionStore) {
      session = this.reloadSession(id);
      if (session) this.sessions.set(id, session);
    }
    if (!session) throw new Error("session_not_found");
    return session;
  }

  
  
  
  
  // Identity handoff (src/identity-handoff.mjs): the recipient's own approved row for a pass the
  // owner service authorized. Same id, root result, consent text, app and partner pins; the hash
  // is computed here from the pass the caller holds; no token, seal or key box exists on it.
  importQualifiedSession(sessionId, record) {
    const id = requiredString(sessionId, "session_id");
    if (this.sessions.has(id) || this.sessionStore?.load?.(id)) throw new Error("session_exists");
    const context = { ...record.context, kind: "mcp_connection", signer: "privy", secretSha256: record.secretSha256, qualifiedFrom: record.qualifiedFrom };
    if (record.approval_url) context.approvalUrl = record.approval_url;
    const session = { intent: "auth", signerAdapter: SIGNER_ADAPTER, state: crypto.randomBytes(16).toString("base64url"),
      siwe: null, signText: record.sign_text, prepareSigning: null, signingExpiresAt: null, signHash: null, signTypedData: null,
      rootApproval: null, consentText: null, expectedAddress: record.result.address, privyAgentSignerId: null, privyRootAddress: null,
      context, extra: null, expiresAt: record.expires_at, approvalExpiresAt: record.expires_at, lineage: record.lineage ?? null,
      approvalUrl: record.approval_url ?? null, createdAt: Date.now(), privateKey: null, status: "approved", result: { ...record.result } };
    Object.defineProperty(session, "partner", { value: record.partner === "wirex" ? "wirex" : "nuri" });
    if (record.privy_app_id) Object.defineProperty(session, "privyAppId", { value: record.privy_app_id });
    // Durable before the caller is answered: a restart reloads the same pinned row.
    this.persistSession(id, session);
    this.sessions.set(id, session);
    return session;
  }

  extendSessionExpiry(sessionId, expiresAt) {
    const session = this.sessions.get(sessionId);
    if (!session || !Number.isSafeInteger(expiresAt) || expiresAt <= session.expiresAt) return;
    session.expiresAt = expiresAt;
    this.persistSession(sessionId);
  }

  
  persistSession(sessionId, session = this.sessions.get(sessionId)) {
    if (!this.sessionStore || !isRecoverableSession(session)) return;
    const context = durableContext(session.context);
    this.sessionStore.save({
      sessionId,
      tokenSha256: session.context.secretSha256 || (session.context.secret ? sha256Hex(session.context.secret) : null),
      account: session.result?.signer || null,
      signerKind: session.context.signer || null,
      connectedAt: session.status === "approved" ? Date.now() : null,
      expiresAt: session.expiresAt,
      data: JSON.stringify({
        intent: session.intent, signerAdapter: session.signerAdapter, state: session.state,
        siwe: session.siwe, signText: session.signText, signingExpiresAt: session.signingExpiresAt,
        signHash: session.signHash, signTypedData: session.signTypedData, rootApproval: session.rootApproval,
        consentText: session.consentText, expectedAddress: session.expectedAddress,
        privyAgentSignerId: session.privyAgentSignerId,
        privyRootAddress: session.privyRootAddress, context,
        
        
        
        privyAppId: session.privyAppId ?? null,
        partner: session.partner ?? "nuri",
        recoveryVersion: 1, lineage: session.lineage, approvalUrl: session.approvalUrl,
        createdAt: session.createdAt, approvalExpiresAt: session.approvalExpiresAt ?? session.expiresAt,
        expiresAt: session.expiresAt, status: session.status, result: session.result,
        // Broker binding (C0 §1 amendment): same row, so a restart re-reads the same result.
        ...(session.brokerRequestId ? { brokerRequestId: session.brokerRequestId, brokerExpiresAt: session.brokerExpiresAt ?? null, brokerExtras: session.brokerExtras ?? [] } : {}),
        ...(session.brokerDigest ? { brokerDigest: session.brokerDigest } : {}),
      }),
    });
  }

  
  reloadSession(sessionId) {
    const row = this.sessionStore?.load(sessionId);
    if (!row) return null;
    let data;
    try {
      data = JSON.parse(row.data);
    } catch {
      this.sessionStore.remove(sessionId);
      return null;
    }
    if (!data || !isRecoverableSession(data)) return null;
    const context = durableContext(data.context);
    if (row.token_sha256) context.secretSha256 = row.token_sha256;
    if (!["pending", "approved"].includes(data.status)) return null;
    if (data.status === "approved" && !data.result?.address) return null;
    let privateKey = null;
    if (data.status === "pending") {
      if (data.recoveryVersion !== 1 || !validRecoveryLink(data, sessionId, row.expires_at)) return null;
      if (Date.now() >= row.expires_at) throw new Error("session_expired");
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.generateKeys();
      privateKey = ecdh.getPrivateKey();
    }
    
    
    
    const { privyAppId, partner: partner_ = "nuri", ...rest } = data;
    const reloaded = { ...rest, expiresAt: row.expires_at, context, privateKey, prepareSigning: null, extra: null };
    Object.defineProperty(reloaded, "partner", { value: partner_ });
    
    
    
    
    if (privyAppId) Object.defineProperty(reloaded, "privyAppId", { value: privyAppId });
    return reloaded;
  }

  purgeExpiredSessions() {
    const now = Date.now();
    for (const [sessionId, session] of this.sessions) {
      if (now <= session.expiresAt) continue;
      zeroize(session.privateKey);
      this.sessions.delete(sessionId);
    }
    this.sessionStore?.purgeExpired(now);
  }
}



function isRecoverableSession(session) {
  if (!session || session.prepareSigning || session.intent !== "auth"
    || session.signerAdapter !== SIGNER_ADAPTER) return false;
  if (session.context?.kind === "mcp_connection") return typeof session.signText === "string"
    && !!session.signText.trim() && !session.siwe && !session.signHash && !session.signTypedData;
  if (session.context?.kind !== "mcp_wallet_pay" || typeof session.context.paymentId !== "string"
    || !session.context.paymentId || session.siwe || session.signText || session.signHash) return false;
  const data = session.signTypedData;
  const fields = [["from", "address"], ["to", "address"], ["value", "uint256"],
    ["validAfter", "uint256"], ["validBefore", "uint256"], ["nonce", "bytes32"]];
  return data?.primaryType === "TransferWithAuthorization"
    && data.domain && data.message
    && JSON.stringify(data.types?.TransferWithAuthorization) === JSON.stringify(fields.map(([name, type]) => ({ name, type })))
    && Object.keys(data.types).every(key => ["TransferWithAuthorization", "EIP712Domain"].includes(key))
    && /^0x[0-9a-fA-F]{40}$/.test(session.expectedAddress || "")
    && typeof data.message.from === "string"
    && data.message.from.toLowerCase() === session.expectedAddress.toLowerCase();
}

function durableContext(context) {
  const fields = context.kind === "mcp_wallet_pay" ? ["kind", "paymentId"]
    : ["kind", "signer", "partner", "secretSha256", "approvalUrl", "connectedAt", "buyPaymentId", "signingReady", "createInput", "walletId", "wirexLoginNonce", "qualifiedFrom", "grantRequest", "grantFor"];
  const safe = Object.fromEntries(fields.filter(key => ["string", "number", "boolean"].includes(typeof context[key]))
    .map(key => [key, context[key]]));
  
  if (context.kind === "mcp_connection") {
    for (const [key, names] of [["accountReady", ["account_exists", "smart_account_address", "deployment_tx_hash"]],
      ["deployment", ["session_id", "approval_url", "expires_at", "status"]]]) {
      if (context[key]) safe[key] = Object.fromEntries(names.filter(name => context[key][name] === null
        || ["string", "number", "boolean"].includes(typeof context[key][name])).map(name => [name, context[key][name]]));
    }
    // Wirex wallet-signature login (#150): the verified tap signature until the MCP has traded
    // it (single use, 5-minute window), then the user token it bought. The token is a bearer
    // secret, so only its seal under the person's pass is written (src/mcp-session.mjs
    // sealWithPass); the clear token stays in RAM. A restart re-seeds the client cache from the
    // seal on the next authorized call (src/mcp-account.mjs authorized) instead of a new tap.
    if (typeof context.wirexLogin?.signature === "string" && Number.isSafeInteger(context.wirexLogin.nonce)) {
      safe.wirexLogin = { signature: context.wirexLogin.signature, nonce: context.wirexLogin.nonce };
    }
    if (typeof context.wirexSealed?.box === "string" && Number.isFinite(context.wirexSealed.expiresAt)) {
      safe.wirexSealed = { box: context.wirexSealed.box, expiresAt: context.wirexSealed.expiresAt };
    }
    // The re-derived LLM key, sealed under the pass (only the caller's pass opens it); dropped once handed out.
    if (typeof context.agentKeyBox === "string") safe.agentKeyBox = context.agentKeyBox;
  }
  return safe;
}



function validRecoveryLink(data, sessionId, expiresAt) {
  try {
    const url = new URL(data.approvalUrl);
    const base = /^[A-Za-z0-9_-]{43}$/.test(data.state) && LINEAGE_PATTERN.test(data.lineage)
      && Number.isSafeInteger(data.createdAt) && Number.isSafeInteger(expiresAt)
      && data.approvalExpiresAt === expiresAt && data.expiresAt === expiresAt
      && url.searchParams.get("state") === data.state;
    // Broker-bound link (C0 §2 route /bridge/privy?request_id&state): the request id is the pin.
    if (data.brokerRequestId) return base && url.searchParams.get("request_id") === data.brokerRequestId;
    return base
      && url.searchParams.get("session_id") === sessionId
      && url.searchParams.get("intent") === data.intent && url.searchParams.get("lineage") === data.lineage
      && Number(url.searchParams.get("expires")) === expiresAt;
  } catch { return false; }
}

function buildApprovedResult(payload, session) {
  const address = requiredAddress(payload.address, "address");
  const message = requiredString(payload.message, "message");
  const signature = requiredString(payload.signature, "signature");
  const recovered = session.signTypedData
    ? verifyTypedData(session.signTypedData.domain, withoutDomainType(session.signTypedData.types), session.signTypedData.message, signature)
    : session.signHash ? verifyMessage(getBytes(message), signature) : verifyMessage(message, signature);
  const publicKey = optionalPublicKey(payload.publicKey || payload.public_key);
  const bitcoinPublicKey = optionalCompressedPublicKey(payload.bitcoinPublicKey || payload.bitcoin_public_key);
  if (recovered.toLowerCase() !== address.toLowerCase()) throw new Error("signature_does_not_match_address");
  if (publicKey && computeAddress(publicKey).toLowerCase() !== address.toLowerCase()) throw new Error("public_key_does_not_match_address");
  if (session.expectedAddress && address.toLowerCase() !== session.expectedAddress.toLowerCase()) throw new Error("signature_address_does_not_match_expected_address");

  const expected = session.signTypedData ? JSON.stringify(session.signTypedData)
    : session.signHash ? session.signHash : session.signText ? session.signText : formatSiwe({ ...session.siwe, address });
  if (message !== expected) throw new Error("signed_message_mismatch");

  let consentSignature = null;
  if (session.consentText) {
    const consentMessage = requiredString(payload.consentMessage, "consent_message");
    consentSignature = requiredString(payload.consentSignature, "consent_signature");
    if (consentMessage !== session.consentText) throw new Error("consent_message_mismatch");
    const consentSigner = verifyMessage(consentMessage, consentSignature);
    if (consentSigner.toLowerCase() !== address.toLowerCase()) throw new Error("consent_signature_does_not_match_address");
  }

  let privyAgent = {};
  if (session.privyAgentSignerId) {
    const providerWalletId = requiredIdentifier(payload.providerWalletId, "provider_wallet_id");
    const providerUserId = requiredIdentifier(payload.providerUserId, "provider_user_id");
    const rootAddress = requiredAddress(payload.rootAddress, "root_address");
    if (rootAddress.toLowerCase() !== session.privyRootAddress.toLowerCase()) throw new Error("privy_root_address_mismatch");
    if (address.toLowerCase() === rootAddress.toLowerCase()) throw new Error("privy_agent_must_be_additional_wallet");
    privyAgent = {
      provider_wallet_id: providerWalletId,
      provider_user_id: providerUserId,
      root_address: rootAddress,
    };
  }

  return {
    signer_adapter: session.signerAdapter,
    address,
    message,
    signature,
    signer: recovered,
    public_key: publicKey || null,
    bitcoin_public_key: bitcoinPublicKey || null,
    signature_matches_address: true,
    consent_message: session.consentText || null,
    consent_signature: consentSignature,
    consent_signature_matches_address: session.consentText ? true : null,
    ...privyAgent,
    private_key: "browser_only_never_sent_to_mcp",
  };
}

function decryptEnvelope(envelope, session) {
  if (!session.privateKey) throw new Error("session_private_key_destroyed");
  return decryptEnvelopeWith(envelope, session.privateKey, session.state);
}

// One codec (C0 §2): the per-session ephemeral key (legacy links) and the static consumer
// key (broker results, acceptBrokerResult) open the same nuri-wirex-bridge-v1 envelope.
// envelopeDigest equals the broker's digest (B1/interface.json codec.digest: sha256 hex over
// the fixed-order envelope fields) so the ACK binds to exactly the adopted bytes.
export function envelopeDigest(envelope) {
  if (!envelope || typeof envelope !== "object") throw new Error("invalid_bridge_envelope");
  const fixed = { version: envelope.version, state: envelope.state, alg: envelope.alg, epk: envelope.epk, iv: envelope.iv, ciphertext: envelope.ciphertext };
  for (const [name, value] of Object.entries(fixed)) if (typeof value !== "string" || !value) throw new Error(`envelope_${name}_required`);
  return crypto.createHash("sha256").update(JSON.stringify(fixed)).digest("hex");
}
export function decryptEnvelopeWith(envelope, privateKey, state) {
  if (!envelope || envelope.version !== VERSION) throw new Error("invalid_bridge_envelope");
  if (envelope.state !== state) throw new Error("envelope_state_mismatch");
  if (envelope.alg !== ENVELOPE_ALG) throw new Error("unsupported_bridge_envelope_algorithm");
  if (!privateKey) throw new Error("envelope_private_key_required");

  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(privateKey);
  const sharedSecret = ecdh.computeSecret(base64urlToBuffer(requiredString(envelope.epk, "epk")));
  const salt = crypto.createHash("sha256").update(`${VERSION}:${state}`).digest();
  const key = Buffer.from(crypto.hkdfSync("sha256", sharedSecret, salt, Buffer.from(RESPONSE_INFO), 32));
  const iv = base64urlToBuffer(requiredString(envelope.iv, "iv"));
  const encrypted = base64urlToBuffer(requiredString(envelope.ciphertext, "ciphertext"));
  if (encrypted.length < 17) throw new Error("ciphertext_too_short");
  const ciphertext = encrypted.subarray(0, encrypted.length - 16);
  const tag = encrypted.subarray(encrypted.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  try {
    return JSON.parse(plaintext.toString("utf8"));
  } finally {
    zeroize(sharedSecret);
    zeroize(salt);
    zeroize(key);
    zeroize(plaintext);
  }
}

function assertBridgePayload(payload, session) {
  if (!payload || typeof payload !== "object") throw new Error("invalid_bridge_payload");
  if (payload.version !== VERSION) throw new Error("payload_version_mismatch");
  if (payload.state !== session.state) throw new Error("payload_state_mismatch");
  if (payload.intent !== session.intent) throw new Error("payload_intent_mismatch");
  assertNoSecretFieldNames(payload);
}

function assertNoSecretFieldNames(value, path = "$") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoSecretFieldNames(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (/(^|[_-])(private|secret|seed|mnemonic|xprv)([_-]|$)|privatekey/i.test(key)) {
      throw new Error(`bridge_payload_contains_secret_field:${path}.${key}`);
    }
    assertNoSecretFieldNames(child, `${path}.${key}`);
  }
}

function assertSiwe(siwe) {
  if (!siwe || typeof siwe !== "object") throw new Error("siwe_params_required");
  for (const key of ["domain", "uri", "statement", "chainId", "nonce", "issuedAt", "expirationTime"]) {
    if (siwe[key] === undefined || siwe[key] === null || siwe[key] === "") throw new Error(`siwe_${key}_required`);
  }
}

function assertTypedData(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("typed_data_invalid");
  if (!value.domain || !value.types || !value.message) throw new Error("typed_data_fields_required");
  if (typeof value.primaryType !== "string" || !value.primaryType) throw new Error("typed_data_primaryType_required");
  if (JSON.stringify(value).length > 32_768) throw new Error("typed_data_too_large");
}

function withoutDomainType(types) {
  const { EIP712Domain: _ignored, ...rest } = types;
  return rest;
}

function publicResult(result) {
  if (!result || typeof result !== "object") return result;
  return { ...result, private_key: "browser_only_never_sent_to_mcp" };
}




function assertApprovalPageHost(url, allowedHosts) {
  const host = url.hostname.toLowerCase();
  if (isLocalDevHost(host)) return;
  if (url.protocol !== "https:") {
    throw new Error(`The approval page "${url.origin}${url.pathname}" is not https, so no approval link was created: approvals only travel over https. Give the tool an https approval URL (or a localhost development URL).`);
  }
  if (hostMatchesAllowlist(host, allowedHosts)) return;
  throw new Error(`"${host}" is not an approval page for this deployment, so the approval link was refused. If that page is really yours, add "${host}" (or ".your-domain.com" to allow a domain and its subdomains) to the BRIDGE_ALLOWED_HOSTS deployment setting.`);
}


function isLocalDevHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}
function normalizeOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" && !isLocalDevHost(url.hostname)) {
    throw new Error("PUBLIC_ORIGIN must be https except for localhost development");
  }
  return url.origin;
}
function normalizeBasePath(value) {
  let path = String(value || "").trim();
  if (!path || path === "/") return "";
  if (!path.startsWith("/")) path = `/${path}`;
  return path.replace(/\/+$/, "");
}
function optionalPublicKey(value) {
  if (!value) return "";
  const publicKey = String(value).trim();
  if (!/^0x04[0-9a-fA-F]{128}$/.test(publicKey) && !/^0x0[23][0-9a-fA-F]{64}$/.test(publicKey)) {
    throw new Error("public_key_must_be_compressed_or_uncompressed_evm_public_key");
  }
  return publicKey;
}
function optionalCompressedPublicKey(value) {
  if (!value) return "";
  const publicKey = String(value).trim().toLowerCase().replace(/^0x/, "");
  if (!/^0[23][0-9a-f]{64}$/.test(publicKey)) throw new Error("bitcoin_public_key_must_be_compressed_secp256k1");
  return publicKey;
}


function requiredAddress(value, name) {
  const address = requiredString(value, name);
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`${name}_must_be_evm_address`);
  return address;
}
function requiredString(value, name) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name}_is_required`);
  return value.trim();
}
function requiredIdentifier(value, name) {
  const text = requiredString(value, name);
  if (!/^[A-Za-z0-9:._-]{3,256}$/.test(text)) throw new Error(`${name}_invalid`);
  return text;
}
function validatePreparedSigning(value) {
  if (!value || typeof value.signText !== "string" || !value.signText.trim() || value.signText.length > 4096
    || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) throw new Error("invalid_signing_preparation");
  return value;
}



function readLineage(value) {
  if (value === undefined || value === null || value === "") return null;
  const text = String(value).trim();
  if (!LINEAGE_PATTERN.test(text)) throw new Error("lineage_invalid");
  return text;
}

function readTimeoutMs(value) {
  const timeoutMs = value == null ? DEFAULT_TIMEOUT_MS : Number(value);
  if (!Number.isFinite(timeoutMs) || timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) throw new Error("timeout_ms_out_of_range");
  return timeoutMs;
}
function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function base64urlToBuffer(value) {
  return Buffer.from(value, "base64url");
}
function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}
function zeroize(value) {
  if (!value || typeof value.fill !== "function") return;
  crypto.randomFillSync(value);
  value.fill(0);
}
