import { prepareRegistration, readAccountRegistration, readRegistrationReceipt, submitRegistration } from "./aa-register.mjs";
import { ISO_COUNTRY_CODES, isWirexUserNotFound } from "./kyc-provision.mjs";
import { WirexBaasError } from "./wirex-public.mjs";
import { authorizeSession, SESSION_PATTERN, sealWithPass, openWithPass } from "./mcp-session.mjs";
import { NEXT_ACTION_SCHEMA, CONNECT_REQUIRED_PROPERTIES } from "./mcp-tool-results.mjs";




const COUNTRY_ALIASES = new Map(Object.entries({
  "uk": "GB", "united kingdom": "GB", "great britain": "GB", "britain": "GB", "england": "GB",
  "scotland": "GB", "wales": "GB", "northern ireland": "GB", "usa": "US", "u s a": "US",
  "america": "US", "united states of america": "US", "uae": "AE", "united arab emirates": "AE",
  "emirates": "AE", "holland": "NL", "the netherlands": "NL", "south korea": "KR", "korea": "KR",
  "north korea": "KP", "russia": "RU", "czech republic": "CZ", "ivory coast": "CI",
  "cape verde": "CV", "east timor": "TL", "burma": "MM", "swaziland": "SZ", "turkey": "TR",
  "macedonia": "MK", "vatican": "VA", "hong kong": "HK", "taiwan": "TW", "vietnam": "VN",
  "bolivia": "BO", "venezuela": "VE", "tanzania": "TZ", "moldova": "MD", "iran": "IR",
  "syria": "SY", "laos": "LA", "brunei": "BN", "curacao": "CW", "cote d ivoire": "CI",
}));
const COUNTRY_LEAD_INS = ["i currently live in", "i am currently living in", "my country is", "the country is",
  "i am a citizen of", "i am living in", "i currently live", "i live in", "i am from", "i m from", "im from",
  "living in", "residing in", "citizen of", "based in", "i live", "i stay in", "i am in", "i m in", "im in",
  "i am", "my country", "country", "from", "in"];


function foldCountryText(value) {
  return String(value ?? "").normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().replace(/[^a-z]+/g, " ").trim().replace(/^(?:the|a) /, "");
}

let countryNameTable = null;
function countryNames() {
  if (countryNameTable) return countryNameTable;
  countryNameTable = new Map(COUNTRY_ALIASES);
  for (const locale of ["en", "de"]) {
    let display;
    try { display = new Intl.DisplayNames([locale], { type: "region" }); } catch { continue; }
    for (const code of ISO_COUNTRY_CODES) {
      const name = foldCountryText(display.of(code));
      if (name && name !== foldCountryText(code) && !countryNameTable.has(name)) countryNameTable.set(name, code);
    }
  }
  return countryNameTable;
}




export function countryCodeFromAnswer(answer) {
  const text = String(answer ?? "").trim();
  if (!text) return "";
  const letters = text.toUpperCase();
  if (ISO_COUNTRY_CODES.has(letters)) return letters;
  let folded = foldCountryText(text);
  const table = countryNames();
  for (let round = 0; round < 4 && folded; round++) {
    if (table.has(folded)) return table.get(folded);
    const lead = COUNTRY_LEAD_INS.find((phrase) => folded === phrase || folded.startsWith(`${phrase} `));
    if (!lead) break;
    folded = folded.slice(lead.length).trim();
  }
  return "";
}



function providerFailure(scope, response, next) {
  const error = new WirexBaasError(scope, response.status, response.payload);
  error.message = `${error.message}: ${next}`;
  return error;
}







export const CONNECTED_WALLET_WORDS = "The wallet you connected with. It proves it is you and it signs for you. Your bank money and your card live in the wallet that belongs to your account.";
export const ACCOUNT_WALLET_WORDS = "Your account's own wallet. Your money and your card are kept here, and every transfer, withdrawal and card payment comes out of it.";

export const OTHER_WALLET_WORDS = "One of your other wallet addresses. Your money and your card are not kept here; your account's own wallet is.";
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;


export function withAddressLabels(result, words) {
  if (!result || typeof result !== "object" || Array.isArray(result)) return result;
  const labels = Object.fromEntries(Object.entries(words).filter(([field]) => EVM_ADDRESS.test(result[field] ?? "")));
  return Object.keys(labels).length ? { ...result, address_labels: { ...(result.address_labels ?? {}), ...labels } } : result;
}

export const CREATE_ACCOUNT_TOOL = {
  name: "create_account",
  title: "Create account",
  description: "Create the account behind a card, an IBAN, payouts or reading what the provider holds, once the wallet connection reports connected. This only opens the identity check; it does not make a card — for a card, finish this, then call provision_virtual_card_and_bank_account. Ask for the person's email and the country they live in; never guess either. An identity-check link is shown unchanged and checked by you later; a rejection means the person contacts support.",
  inputSchema: { type: "object", additionalProperties: false, required: ["session", "email", "country"], properties: {
    session: { type: "string", pattern: SESSION_PATTERN, description: "Never show this to the person and never ask them for it; it comes only from the account tool's answer (account status)." },
    email: { type: "string", format: "email", maxLength: 254, description: "The email address the person wants on the account. Ask for it in ordinary words, send exactly what they give, and never guess or invent one." },
    country: { type: "string", maxLength: 64, description: "The country the person lives in, in their own words. Ask which country they live in and send exactly what they said; never guess or show a format." },
  } },
  outputSchema: { type: "object", additionalProperties: false, required: ["ok"], properties: {
    error: { type: "string", description: "Plain words saying what went wrong and the one next thing to do, when ok is false." },
    ok: { type: "boolean" }, status: { type: "string", enum: ["created", "already_exists", "connect_required"], description: "created means the account is now on record. already_exists means it was already there and nothing was created a second time. connect_required means no wallet is connected and the result carries the sign-in link." },
    smart_account_address: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$", description: "Your account's own wallet address: your money and your card are kept here. It is not the wallet the person connected with, which only proves who they are. Keep it for later steps; show it only when the person asks for it." },
    address_labels: { type: "object", additionalProperties: { type: "string" }, description: "Plain words for every wallet address this answer shows, given under the same field name. Read them rather than guessing which wallet an address belongs to." },
    kyc: { type: "string", enum: ["not_started", "in_review", "verified", "rejected", "unknown"], description: "Where the identity check stands, in plain words: not_started means the check still has to be done, in_review means it is being looked at, verified means it passed, rejected means it did not." },
    kyc_provider_status: { type: "string", description: "The identity-check state in the provider's own words." },
    kyc_status: { type: "string", description: "Old name for kyc_provider_status, kept for one release." },
    message: { type: "string", description: "One plain sentence saying where the identity check stands and the next thing to do." },
    kyc_url: { type: "string", format: "uri", description: "A link where the person confirms who they are. Show it unchanged when it comes back." },
    next_action: NEXT_ACTION_SCHEMA,
    allowed_merchants: { type: "array" },
    ...CONNECT_REQUIRED_PROPERTIES,
  }, oneOf: [
    { properties: { ok: { type: "boolean", enum: [true] }, status: { type: "string", enum: ["connect_required"] } }, required: ["status", "message", "request_id", "approval_url", "next_action"] },
    { properties: { ok: { type: "boolean", enum: [true] } }, required: ["status", "smart_account_address", "address_labels", "kyc", "kyc_provider_status", "message"] },
    { properties: { ok: { type: "boolean", enum: [false] } }, required: ["error"] },
  ] },
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
};






const ACCOUNT_PAY_ANNOUNCEMENT = "Bank pay, bank withdraw and deposits work on the connection alone.";
const ACCOUNT_NO_PAY_ANNOUNCEMENT = "Bank withdraw and deposits work on the connection alone.";
export function createAccountTool(payEnabled) {
  if (payEnabled) return CREATE_ACCOUNT_TOOL;
  if (!CREATE_ACCOUNT_TOOL.description.includes(ACCOUNT_PAY_ANNOUNCEMENT)) {
    throw new Error("account_pay_announcement_moved: the sentence that names which steps work on the connection alone has moved, so nothing was published. Update the announcement this step strips out.");
  }
  const description = CREATE_ACCOUNT_TOOL.description.replace(ACCOUNT_PAY_ANNOUNCEMENT, ACCOUNT_NO_PAY_ANNOUNCEMENT);
  if (/\bpay\b/i.test(description)) {
    throw new Error("account_pay_announcement_survived: the direct payment wording survived the strip, so nothing was published. It would have advertised a step this deployment cannot take.");
  }
  return { ...CREATE_ACCOUNT_TOOL, description };
}

export async function lookupAccount(wirexBaas, address) {
  if (!wirexBaas?.configured()) throw new Error("wirex_baas_not_configured: the account service is not switched on here, so nothing can be created. Tell the person this is not available in this setup, and do not retry.");
  try {
    const response = await wirexBaas.getUser(address);
    if (!response.ok) throw providerFailure("account_lookup", response, "the account service did not answer properly. Nothing changed; try the same step again in a moment.");
    const user = response.payload?.data ?? response.payload;
    if (user?.error || user?.error_reason || typeof user?.user_id !== "string" || !user.user_id.trim()) throw new Error("wirex_account_lookup_invalid: the account service answered with something unreadable, so the account state is unknown. Nothing changed; try the same call again in a moment.");
    return user;
  } catch (error) {
    if (error instanceof WirexBaasError && error.message === "wirex_baas_user_auth_400" && isWirexUserNotFound(error)) return null;
    throw error;
  }
}


export function sddVerificationStatus(user) {
  const verification = user?.verification;
  const statuses = ["None", "Pending", "Applied", "InReview", "Approved", "Rejected", "Cancelled", "Canceled"];
  const levels = verification?.levels === undefined ? [] : verification.levels;
  if (!statuses.includes(verification?.status) || !Array.isArray(levels)
    || levels.some(level => !level || typeof level.type !== "string" || !level.type || !statuses.includes(level.status))
    || levels.filter(level => level.type === "SDD").length > 1) throw new Error("wirex_verification_invalid: the identity check state came back unreadable, so it is unknown whether the check passed. Do not tell the person they are verified; try again.");
  return levels.find(level => level.type === "SDD")?.status || (verification.status === "Approved" ? "None" : verification.status);
}





export function canonicalKyc(providerStatus) {
  switch (providerStatus) {
    case "Approved": return "verified";
    case "Pending": case "InReview": return "in_review";
    case "Rejected": return "rejected";
    case "Applied": case "None": case "Cancelled": case "Canceled": return "not_started";
    default: return "unknown";
  }
}

export function kycMessage(canonical) {
  switch (canonical) {
    case "not_started": return "Verify your identity to activate your card and bank account.";
    case "in_review": return "Your identity verification is still being reviewed.";
    case "verified": return "Your account is verified.";
    case "rejected": return "Your identity verification was not approved. Contact support.";
    default: return "Your identity verification state is unknown. Ask again in a moment.";
  }
}


export function createMcpAccount({ bridge, wirexBaas, aaConfig, stateStore, registration = {}, connectionSigner, onboardingFollowup }) {
  const lookup = registration.lookup || ((address) => readAccountRegistration(address, aaConfig));
  const prepare = registration.prepare || ((address) => prepareRegistration(address, aaConfig));
  const submit = registration.submit || ((input) => submitRegistration(input, aaConfig));
  const reconcile = registration.reconcile || ((hash) => readRegistrationReceipt(hash, aaConfig));
  const active = new Map();

  function connection(id) {
    if (typeof id !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(id)) throw new Error("connection_required: no wallet connection was given, or it is not one this service handed out. Start one new wallet connection and use the private pass it returns.");
    const session = bridge.requireSession(id);
    
    
    
    
    if (session.context.kind !== "mcp_connection" || session.signerAdapter !== "privy") throw new Error("connection_type_mismatch: this private pass belongs to a different kind of connection. Start one new wallet connection and use the pass from that one.");
    if (Date.now() >= session.expiresAt) throw new Error("connection_expired: the wallet connection has timed out. Start one new wallet connection, then repeat this call.");
    if (session.status !== "approved" || !session.result?.signer) throw new Error("connection_not_approved: the wallet is not connected yet. Show the approval link and check it again; do not create anything until it reports connected.");
    return session;
  }

  async function exclusive(address, operation) {
    if (active.has(address)) throw new Error("account_operation_in_progress: the same step is already running for this wallet. Wait a moment and check again instead of starting a second one.");
    const promise = Promise.resolve().then(operation);
    active.set(address, promise);
    try { return await promise; } finally { active.delete(address); }
  }

  
  
  
  
  
  
  
  async function advance(id) {
    const session = connection(id);
    const context = session.context;
    let cardGrant = null;
    if (connectionSigner && context.privy && !context.signingReady && !context.signingSkipped) {
      // Asking for the grant can fail too (live: card_signing_failed: connection_unavailable) — connect without it.
      const authorization = await connectionSigner.prepare(session).catch(error => {
        if (!/^card_signing_failed/.test(String(error?.message))) throw error;
        context.signingSkipped = true;
        return null;
      });
      connection(id);
      if (authorization?.status === "ready") context.signingReady = true;
      else if (authorization) cardGrant = authorization;
    }
    
    
    
    
    const wallet = await advanceWallet(id, session);
    return cardGrant ?? wallet;
  }

  async function advanceWallet(id, session) {
    const context = session.context;
    if (context.accountReady) {
      const user = await lookupAccount(wirexBaas, session.result.signer);
      connection(id);
      context.accountReady.account_exists = Boolean(user);
      
      
      bridge.persistSession?.(id);
      return { status: "connected", ...context.accountReady };
    }
    if (context.accountError) {
      const error = context.accountError;
      delete context.accountError;
      throw error;
    }
    if (context.accountPending) return { status: "processing" };
    if (context.deployment) {
      const deployment = bridge.requireSession(context.deployment.session_id);
      if (Date.now() >= deployment.expiresAt) throw new Error("deployment_expired: the wallet setup link timed out before it was approved. Start one new wallet connection and repeat the step.");
      if (deployment.status !== "approved") return { status: "signature_required", approval_url: context.deployment.approval_url };
    }
    
    context.accountPending = exclusive(session.result.signer.toLowerCase(), async () => {
      await advanceOnce(id, session);
    }).catch((error) => { context.accountError = error; }).finally(() => { delete context.accountPending; });
    return { status: "processing" };
  }

  async function advanceOnce(id, session) {
    const address = session.result.signer;
    const context = session.context;
    const user = await lookupAccount(wirexBaas, address);
    connection(id);
    const lifecycle = await stateStore.get(address);
    if (lifecycle) {
      if (lifecycle.status === "confirmed" && lifecycle.tx_hash) return ready(lifecycle.kernel_address, lifecycle.tx_hash);
      const receipt = await reconcile(lifecycle.user_op_hash);
      if (receipt.status === "pending") return;
      if (receipt.status === "failed") {
        await stateStore.remove(address);
        delete context.deployment;
        throw new Error("account_deployment_failed: the wallet setup failed and left nothing behind. Start one new wallet connection and repeat it.");
      }
      if (receipt.status !== "succeeded" || !receipt.tx_hash) throw new Error("account_deployment_unconfirmed: the wallet setup result could not be confirmed, so its real state is unknown. Check the connection again before telling the person anything.");
      await stateStore.put({ ...lifecycle, status: "confirmed", tx_hash: receipt.tx_hash });
      return ready(lifecycle.kernel_address, receipt.tx_hash);
    }
    if (context.deployment) {
      const approved = await bridge.approved(context.deployment.session_id);
      if (!approved || approved.result.signer.toLowerCase() !== address.toLowerCase()) throw new Error("deployment_signer_mismatch: the approval was signed by a different wallet than the one being set up. Refuse it and start one new wallet connection.");
      connection(id);
      const { kernelAddress, userOpHash, userOp } = approved.context;
      await stateStore.put({ eoa: address, kernel_address: kernelAddress, user_op_hash: userOpHash, status: "submitting", tx_hash: null });
      
      const result = await submit({ eoaAddress: address, userOp, signature: approved.result.signature });
      if (result.user_op_hash?.toLowerCase() !== userOpHash.toLowerCase() || result.success !== true || !result.tx_hash) throw new Error("account_deployment_unconfirmed: the wallet setup result could not be confirmed, so its real state is unknown. Check the connection again before telling the person anything.");
      await stateStore.put({ eoa: address, kernel_address: kernelAddress, user_op_hash: userOpHash, status: "confirmed", tx_hash: result.tx_hash });
      return ready(kernelAddress, result.tx_hash);
    }
    const registered = await lookup(address);
    if (registered.registered === true) return ready(registered.kernelAddress, null);
    if (registered.registered !== false) throw new Error("account_registration_invalid: the wallet setup data could not be read properly. Do not report success; start one new wallet connection.");
    const prepared = await prepare(address);
    connection(id);
    if (!/^0x[0-9a-fA-F]{40}$/.test(prepared?.kernelAddress || "") || !/^0x[0-9a-fA-F]{64}$/.test(prepared?.userOpHash || "") || !prepared.userOp) throw new Error("account_deployment_prepare_invalid: the wallet setup could not be prepared, so nothing was sent. Check the same wallet connection again.");
    
    
    
    
    context.deployment = await bridge.createSession({
      intent: "auth", adapter: session.signerAdapter, partner: session.context?.partner, expectedAddress: address, signHash: prepared.userOpHash,
      context: { kind: "mcp_deployment", connectionId: id, ...prepared },
      timeoutMs: Math.min(24 * 60 * 60_000, session.expiresAt - Date.now()), // bridge MAX_TIMEOUT_MS (24 h); connections can live longer
    });

    function ready(kernel, txHash) {
      connection(id);
      if (!/^0x[0-9a-fA-F]{40}$/.test(kernel || "")) throw new Error("account_registration_invalid: the wallet setup data could not be read properly. Do not report success; start one new wallet connection.");
      context.accountReady = { account_exists: Boolean(user), smart_account_address: kernel, deployment_tx_hash: txHash };
      
      bridge.persistSession?.(id);
    }
  }

  async function create(args) {
    if (!args || typeof args !== "object" || Array.isArray(args) || Object.keys(args).some((key) => !["session", "email", "country"].includes(key))) throw new Error("create_account_arguments_invalid: this call carried something the account step does not accept. Send only the private pass, the person's email address and the country they live in, and nothing else.");
    const session = authorized(args.session);
    if (!session.context.accountReady) throw new Error("account_connection_incomplete: the wallet is not connected yet. Finish the wallet connection, then create the account.");
    const email = typeof args.email === "string" ? args.email.trim() : "";
    const country = countryCodeFromAnswer(args.country);
    if (email.length > 254 || !/^[^\s@;=]+@[^\s@;=]+\.[^\s@;=]+$/.test(email)) throw new Error("email_invalid: that is not an email address. Ask the person for their email address and send it exactly as they give it.");
    if (!country) throw new Error("country_invalid: the country in this call could not be matched to any country. Ask the person which country they live in and send the country name they say, exactly as they say it.");
    const input = JSON.stringify({ email, country });
    if (session.context.createInput && session.context.createInput !== input) throw new Error("account_creation_details_changed: the email address or the country differs from the first attempt. Repeat with the details already used, or ask the person which one is right, and never send two different versions.");
    session.context.createInput = input;
    const address = session.result.signer;
    return exclusive(address.toLowerCase(), async () => {
      let user = await lookupAccount(wirexBaas, address);
      const existed = Boolean(user);
      if (!user) {
        authorized(args.session);
        let response, unreadable;
        try {
          response = await wirexBaas.createUser(address, { email, country });
        } catch (error) {
          
          
          if (!(error instanceof WirexBaasError) || !error.message.startsWith("wirex_baas_provider_body_unreadable")) throw error;
          unreadable = error;
        }
        
        user = await lookupAccount(wirexBaas, address);
        if (!user) {
          if (unreadable) throw unreadable;
          throw providerFailure("create_user", response, "the account service refused to open the account, so nothing was created. Try the same details once more, then tell the person it did not go through.");
        }
      }
      authorized(args.session);
      const verificationResponse = await wirexBaas.getUserV2(address);
      if (!verificationResponse.ok) throw providerFailure("account_verification", verificationResponse, "the identity check state could not be read, so it is unknown. Say nothing about the check; try the same call again.");
      authorized(args.session);
      const verification = sddVerificationStatus(verificationResponse.payload?.data ?? verificationResponse.payload);
      const kyc = canonicalKyc(verification);
      const result = withAddressLabels({ ok: true, status: existed ? "already_exists" : "created", smart_account_address: session.context.accountReady.smart_account_address,
        kyc, kyc_provider_status: verification, kyc_status: verification, message: `${existed ? "Your account was already on record." : "Account created."} ${kycMessage(kyc)}` },
        { smart_account_address: ACCOUNT_WALLET_WORDS });
      if (kyc === "not_started") {
        result.kyc_url = await createKycUrl(wirexBaas, address);
        session.context.kycUrl = result.kyc_url;
      }
      void onboardingFollowup?.capture({ email, username: session.context.accountReady.smart_account_address }).catch((error) => {
        console.error("[wirex-onboarding-followup] capture failed", {
          code: error instanceof Error ? error.message : "unknown",
        });
      });
      authorized(args.session);
      session.context.accountReady.account_exists = true;
      return result;
    });
  }

  async function completeAuthorization(id, input) {
    const session = connection(id);
    if (!connectionSigner || !session.context.privy) throw new Error("signing_authorization_unavailable: this connection did not ask for a signing grant, so there is nothing to confirm here. Continue with the account step.");
    // A failed card-signing grant must not block the connection (live 2026-09-27: card_signing_failed:
    // reconnect_required → the whole connect answered 500). Connect without it; card details ask again later.
    const result = await connectionSigner.complete(session, input).catch(error => {
      if (!/^card_signing_failed/.test(String(error?.message))) throw error;
      session.context.signingSkipped = true;
      return { status: "skipped" };
    });
    connection(id);
    session.context.signingReady = result?.status === "ready";
    return result;
  }
  
  
  
  
  
  
  
  
  
  
  // After a restart the Wirex client cache is empty while the session row is not
  // (src/browser-bridge.mjs reloadSession). The first authorized call re-seeds it from
  // the sealed token with the pass the caller just proved, so a deploy needs no new tap.
  // A clear token still only in RAM (minted before the pass was known) is sealed and persisted here.
  function reseedWirexToken(credential, session) {
    const owner = session.result?.signer;
    if (!wirexBaas?.setUserToken || !owner) return;
    const id = credential.split(".")[0];
    const pass = credential.split(".")[1];
    const context = session.context;
    if (context.wirex?.token && !context.wirexSealed) {
      context.wirexSealed = { box: sealWithPass(id, pass, context.wirex.token), expiresAt: context.wirex.expiresAt };
      bridge.persistSession?.(id);
    }
    if (wirexBaas.hasUserToken(owner)) return;
    const token = context.wirex?.token || (context.wirexSealed && openWithPass(id, pass, context.wirexSealed.box));
    const expiresAt = context.wirex?.expiresAt ?? context.wirexSealed?.expiresAt;
    if (token && Number.isFinite(expiresAt) && expiresAt > Date.now()) wirexBaas.setUserToken(owner, token, expiresAt);
  }

  function authorized(credential, { signingGrant = true } = {}) {
    const session = authorizeSession(connection, credential);
    reseedWirexToken(credential, session);
    if (signingGrant && session.context.privy && !session.context.signingReady && !session.context.signingSkipped) throw new Error("signing_authorization_incomplete: the person has not approved the signing grant yet. Finish that approval on the wallet connection first, then create the account.");
    return session;
  }
  return { advance, create, connection, authorized, completeAuthorization };
}

export async function createKycUrl(wirexBaas, address) {
  const response = await wirexBaas.createKycLink(address);
  if (!response.ok) throw providerFailure("kyc_link", response, "the account service did not return a usable link for the identity check. Do not give the person any link; try the same call again.");
  const url = new URL(response.payload?.redirect_uri);
  if (url.origin !== "https://in.sumsub.com" || url.username || url.password || !url.pathname.startsWith("/websdk/p/")) throw new Error("kyc_link_invalid: the identity check link came back from somewhere unexpected, so it was refused. Do not give the person any link; try the account step again.");
  return url.href;
}
