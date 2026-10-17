import { randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { withAddressLabels, ACCOUNT_WALLET_WORDS, CONNECTED_WALLET_WORDS } from "./mcp-account.mjs";
import { walletReceiveInfo } from "./wallet-units.mjs";
import { sessionCredential, connectFirstError, connectRequiredSignal, sealWithPass } from "./mcp-session.mjs";
import { isWirexUserNotFound } from "./kyc-provision.mjs";
import { MAX_TIMEOUT_MS, connectionTtlMs } from "./signer-client.mjs";
import { openLinkThen, pollFor, humanUntil } from "./mcp-tool-results.mjs";
import { logEvent, fingerprint } from "./log.mjs";

// D-GRAMMAR: every public answer carries ok plus exactly one of five statuses,
// and none of the inner explanatory fields. This is the one edge that enforces
// the vocabulary on whatever a tool returns.
const PUBLIC_STATUSES = new Set(["done", "pending", "approval_required", "connect_required", "failed"]);
const PUBLIC_DROP = new Set(["coverage", "hint", "expires_human", "result_url", "security_boundary", "signer_adapter", "intent",
  "filter", "types", "page_limit_reached", "total_count", "has_more", "pagination", "page_size", "count", "stage",
  "predicate", "applied_filters", "unsupported_filters", "next_action"]);
export function publicAnswer(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return data;
  const out = {};
  for (const [key, value] of Object.entries(data))
    if (!PUBLIC_DROP.has(key) && !key.endsWith("_notice")) out[key] = value;
  if (out.status !== undefined && !PUBLIC_STATUSES.has(out.status))
    logEvent("warn", "public_status_unmapped", { status: String(out.status) });
  if (!PUBLIC_STATUSES.has(out.status)) out.status = out.ok === false ? "failed" : "done";
  if (typeof out.ok !== "boolean") out.ok = out.status !== "failed";
  return out;
}

// The call a poll or an open-link hint should make once the connection lands.
// The continuation at `call` above keeps request_id (it doubles as the tool's
// idempotency label) and re-runs this tool with the resolved session, so the
// args must be a call that tool really takes:
// wallet's schema requires `action` (src/mcp-wallet-tool.mjs:57), so a bare
// { request_id } was refused. balance is wallet's free read; every other tool
// keeps the caller's action (and manage op) — account limits stays limits — or its first read when none came. Never
// more: the other fields may hold a card number, and the sentence asks for them.
const CONTINUE_ACTION = { wallet: "balance" }, FIRST_ACTION = { account: "status", bank: "card" };
function continueCall(name, id, original = {}) {
  const tool = name === "connect_wallet" ? "wallet" : name;
  const keep = (key) => (!CONTINUE_ACTION[tool] && typeof original?.[key] === "string" ? { [key]: original[key] } : {});
  const action = CONTINUE_ACTION[tool] ?? keep("action").action ?? FIRST_ACTION[tool]; return { tool, args: { request_id: id, ...(action ? { action } : {}), ...keep("op") } };
}

// The one sentence a model with no session must read: what happened, the one
// link to show, and the ONE call that follows the tap — named for the tool it
// was already calling, so nothing has to be guessed or invented (D-NEXT-SENTENCE).
export function connectRequiredMessage(name, original = {}) {
  const { tool, args } = continueCall(name, "", original), more = !CONTINUE_ACTION[tool] && Object.keys(original ?? {}).some((key) => !["action", "op", "request_id", "session"].includes(key));
  const call = [tool, args.action, args.op].filter(Boolean).join(" ");
  return `Not connected. Show this link; after the tap call ${call} again with the same request_id${more ? " and the same fields" : ""}.`;
}

// connect_wallet mints the answer, so its structured hints name wallet.balance —
// the continuation for a caller that asked for nothing else. When the connect
// link was raised by another tool, re-point every hint at THAT tool, so the
// sentence, next_action and poll all name one and the same call.
function connectRequired(name, data, original) {
  // Live 2026-10-17 (DeepSeek v4.1): a repeat with the same request_id got the first-link sentence
  // again, so the model re-sent the link and blamed the person. Say which of three states it is.
  const again = typeof original?.request_id === "string" && original.request_id === data?.request_id;
  const message = !again ? connectRequiredMessage(name, original)
    : data?.status === "processing" ? "Logged in. One more tap: show this NEW link; then the same call again."
      : "Not tapped yet. Same link as before; when the person says done, the same call again. If they did tap and it still says this, start over: account status with no request_id.";
  const out = { ...data, status: "connect_required", message };
  const id = typeof out.request_id === "string" ? out.request_id : "";
  const { tool, args } = continueCall(name, id, original);
  if (out.next_action?.type === "open_link" && out.next_action.then) {
    out.next_action = { ...out.next_action, then: { ...out.next_action.then, tool, args } };
  }
  if (out.poll) out.poll = { ...out.poll, tool, args };
  return out;
}




// The catalog is the product surface: wallet, account, bank (D-C, issue #166;
// D-CORE-THREE).
// Connecting a wallet is NOT a tool: any of them that needs a session and
// gets none throws an error with `.connect_required = true`, and this layer
// answers with the connect link instead. After the person approves, the model
// calls the same tool again with the `session` value from the connect result,
// or with only the `request_id` — both resolve to the approved session here.

export const CONNECTION_CONSENT = "Connect this chat to your wallet. It can see your money and manage your cards, and it always asks you before money moves.";

// The one place a connect approval is minted. connect_wallet uses it, and so
// does wallet.balance when it has to offer an unclaimed wallet's backup link
// (D-NEXT-SENTENCE) — one link, one shape, one code path.
export async function mintConnectApproval(bridge, { partner = "nuri", walletId } = {}) {
  const timeoutMs = MAX_TIMEOUT_MS;
  // D-QUORUM A: a link minted for a guest Safe carries its id; the tap on it is the claim.
  const context = { kind: "mcp_connection", signer: "privy", partner, ...(typeof walletId === "string" && walletId ? { walletId } : {}) };
  const signText = [
    CONNECTION_CONSENT,
    `Origin: ${bridge.publicOrigin}`,
    `Nonce: ${randomBytes(32).toString("base64url")}`,
    `Expires: ${new Date(Date.now() + timeoutMs).toISOString()}`,
  ].join("\n");
  const approval = await bridge.createSession({ intent: "auth", timeoutMs, signText, context, partner });
  const id = approval.session_id;
  context.approvalUrl = approval.approval_url;
  const session = sessionCredential(id, bridge.requireSession(id));
  bridge.persistSession?.(id);
  return { request_id: id, approval_url: approval.approval_url, session };
}

// The shape of a connect reference (the session id minted for an approval).
// It is deliberately distinct from a caller-chosen idempotency request_id.
const CONNECT_REF = /^[A-Za-z0-9_-]{43}$/;
// Tools that do nothing without a live session (their gate is "connect").
const SESSION_TOOLS = new Set(["bank"]);
// Error codes that mean "this session cannot be used, a new tap is needed".
const SESSION_DEAD = /^(connection_(expired|not_approved|type_mismatch)|reconnect_required)\b/;

export function createMcpConnection({ bridge, accountFlow, wallet, account, bank, chainId, wirexBaas, charges, broker = null, connectAdvance = true, identity = null } = {}) {
  // Wirex wallet-signature login (#150). The tap that connected the wallet also signed the
  // Wirex login message; the bridge verified it and left { signature, nonce } in
  // context.wirexLogin. This process (the one with Wirex access) trades it for a user token
  // once, keeps the token on the session (persisted, like the pass hash; never in tool
  // results or logs) and seeds the client cache, so every card/bank call for this owner
  // runs on the user's own token instead of the partner route.
  // Wirex accepts the signature for 5 minutes after the nonce and only once. connect_wallet
  // reads the session at most 250 ms after the tap, so this normally lands at once; if this
  // process is down at that moment the login is simply lost: the partner route (when
  // configured) or a reconnect_required answer applies, and nothing else changes.
  async function wirexUserLogin(id, session) {
    if (!wirexBaas?.config?.companyId) return;
    const owner = session.result.signer;
    const context = session.context;
    const held = context.wirex;
    if (held?.token && Number.isFinite(held.expiresAt) && held.expiresAt > Date.now() + 60_000) {
      if (!wirexBaas.hasUserToken(owner)) wirexBaas.setUserToken(owner, held.token, held.expiresAt);
      delete context.wirexLogin;
      return;
    }
    const login = context.wirexLogin;
    if (!login?.signature || !Number.isSafeInteger(login.nonce)) return;
    delete context.wirexLogin;
    try {
      const { token, expiresAt } = await wirexBaas.loginWithSignature({ owner, signature: login.signature, nonce: login.nonce });
      context.wirex = { token, expiresAt };
      // Survives a restart only as a seal under the pass (in RAM right after the mint).
      if (context.secret) context.wirexSealed = { box: sealWithPass(id, context.secret, token), expiresAt };
      logEvent("info", "wirex_user_login", { status: 200, expires_at: new Date(expiresAt).toISOString() });
    } catch (error) {
      logEvent("warn", "wirex_user_login_failed", { status: error?.status ?? 0, error: String(error?.body?.error || error?.body?.error_reason || error?.message || error) });
    }
    bridge.persistSession?.(id);
  }

  // Lazy bank grant (C0 §3): a handed-off row (src/identity-handoff.mjs) carries identity only. Before a
  // banking tool runs on it, the same root grants Wirex rights once: a child broker request pinned to the
  // row's verified root and partner (expectedAddress, so the broker asks privy_access_token +
  // wirexLoginSignature, src/signer-broker-hook.mjs:56-61). The child is never a pass (no secret) and is
  // tracked as context.grantRequest; the original id, pass hash and result stay as they are.
  // null = nothing to do (rights cached, not a handed-off row, not the banking owner).
  async function bankGrant(credential, { signal } = {}) {
    const pin = identity?.pinOf?.(credential);
    if (!pin || !connectAdvance || !broker || !wirexBaas?.config?.companyId) return null;
    const session = accountFlow.authorized(credential, { signingGrant: false }); // pass proof, reseeds a sealed token
    const id = credential.split(".")[0], owner = session.result.signer;
    if (wirexBaas.hasUserToken(owner)) return null;
    let child = null;
    try { child = session.context.grantRequest ? bridge.requireSession(session.context.grantRequest) : null; } catch { child = null; }
    if (child?.status === "pending" && Date.now() < child.expiresAt) await broker.hydrate(session.context.grantRequest).catch(() => null);
    signal?.throwIfAborted();
    if (child?.status === "approved") {
      if (child.context.grantFor !== id || String(child.result?.signer).toLowerCase() !== owner.toLowerCase()) throw connectRequiredSignal();
      if (child.context.wirexLogin) session.context.wirexLogin = child.context.wirexLogin;
      delete session.context.grantRequest;
      await wirexUserLogin(id, session);
      accountFlow.authorized(credential, { signingGrant: false }); // seals the new token under the pass, persists
      if (wirexBaas.hasUserToken(owner)) return null;
      child = null; // the signature bought no token: one new grant
    }
    if (!child || child.status !== "pending" || Date.now() >= child.expiresAt) {
      const signText = [CONNECTION_CONSENT, `Origin: ${bridge.publicOrigin}`, `Nonce: ${randomBytes(32).toString("base64url")}`,
        `Expires: ${new Date(Date.now() + MAX_TIMEOUT_MS).toISOString()}`].join("\n");
      const context = { kind: "mcp_connection", signer: "privy", partner: pin.partner, grantFor: id };
      const created = await bridge.createSession({ intent: "auth", timeoutMs: MAX_TIMEOUT_MS, signText, expectedAddress: pin.expectedAddress, context, partner: pin.partner });
      context.approvalUrl = created.approval_url;
      bridge.persistSession?.(created.session_id);
      await broker.register(created.session_id);
      session.context.grantRequest = created.session_id;
      bridge.persistSession?.(id);
      child = bridge.requireSession(created.session_id);
    }
    const url = child.approvalUrl ?? child.context.approvalUrl;
    return { ok: true, status: "connect_required", message: "Open the link and approve once so your bank account works here.", approval_url: url,
      next_action: openLinkThen(url, { tool: "bank", args: { action: "card", session: credential }, until: "the approval is done" }) };
  }

  let waitingChecks = 0;

  const catalog = [wallet, account, bank].filter(Boolean);
  const byName = new Map(catalog.map((entry) => [entry.tool.name, entry]));
  // D-TOOLS-PAID: each description names its price, generated from the one price table (src/tool-prices.mjs).
  const allTools = catalog.map((entry) => charges?.describe ? charges.describe(entry.tool) : entry.tool);

  // D-NO-GATE: tools() is the whole product surface, always — what docs, llms.txt
  // and tools/list all show; every tool checks its own session/KYC/owner needs.
  const tools = () => allTools;

  async function call(name, args = {}, opts = {}) { const started = Date.now(); let out; try { return (out = await callTool(name, args, opts)); } finally { const a = out?.structuredContent; logEvent("info", "tool_result", { tool: name, action: typeof args?.action === "string" ? args.action : null, status: a?.status ?? null, error: typeof a?.error === "string" ? a.error.slice(0, 80).replace(/[0-9A-Za-z]{12,}/g, "…") : null, ms: Date.now() - started, sfp: fingerprint(String(args?.session ?? "").split(".")[0]) || null, kfp: fingerprint(args?.wallet_key) || null }); } } async function callTool(name, args = {}, opts = {}) { logEvent("info", "tool_call", { tool: name, action: typeof args?.action === "string" ? args.action : null, fields: Object.keys(args ?? {}).filter(k => k !== "action").sort() }); // names only, never values
    try {
      opts = { ...opts, deadline: opts.deadline ?? Date.now() + 25_000 };
      // request_id-only continuation: the model approved nothing yet but hands
      // back the reference from the connect result. Resolve it to a session
      // and run the action — the reference stays in the args as the tool's
      // idempotency label. While the connection is still pending, answer
      // with the same link again.
      //
      // Only a *connect reference* may be consumed here. request_id is also the
      // caller-chosen idempotency label for wallet.pay/send/stop/withdraw and
      // bank.send/push, so anything that is not shaped like a connect reference
      // (43 chars base64url, the id minted at line 165) must fall through to the
      // tool untouched — otherwise a plain idempotency label is mistaken for a
      // damaged connection and the caller gets connection_required instead of
      // the connect link.
      if (!args?.session && typeof args?.request_id === "string" && CONNECT_REF.test(args.request_id)) {
        const check = await callInner("connect_wallet", { request_id: args.request_id }, opts);
        const data = check.structuredContent;
        // "processing" = approved, the account advance is still running (connectAdvance, :377). It
        // needs no tap: the tool's own readiness wait (banking server accountReadyFor) finishes it.
        if ((data?.status === "connected" || data?.status === "processing") && data.session) {
          // Keep the reference in the args — it doubles as the tool's
          // idempotency label (bank send rejected a stripped call with
          // "request_id was not sent").
          args = { ...args, session: data.session };
        } else {
          const out = publicAnswer(connectRequired(name, data, args));
          return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out, isError: false };
        }
      }
      return await callInner(name, args, opts);
    }
    catch (error) {
      // Every tool answers an expired or dead session the same way: the connect
      // link (live 2026-09-26: account answered reconnect_required naming the
      // internal connect_wallet while bank gave the link). Tools that ran into it
      // deep inside (session expiry, a lost Wirex user token) throw the plain code.
      if (error?.connect_required || SESSION_DEAD.test(String(error?.message))) {
        if (!bridge || !accountFlow) error = connectFirstError();
        else try {
          // Resume the pending connection the session belongs to when there is
          // one (this waits quietly for the approval); otherwise start a fresh
          // connection. Either way the model gets one link to show.
          const hinted = typeof args?.session === "string" && /^[A-Za-z0-9_-]{43}\./.test(args.session)
            ? args.session.split(".")[0] : undefined;
          let pending;
          try { pending = await callInner("connect_wallet", hinted ? { request_id: hinted } : {}, opts); }
          catch (hintError) { if (!hinted) throw hintError; pending = await callInner("connect_wallet", {}, opts); } // no second identical mint
          let landed = pending?.structuredContent;
          // The hint adopted a delivered broker result just now (hydrate, :339). "processing" is approved too
          // (account advance running); after a restart the pass secret is not in RAM, so the answer carries no
          // session (src/mcp-session.mjs:45) and the caller's own pass, re-verified by the tool, is used.
          if (landed?.status === "connected" || landed?.status === "processing") {
            const pass = landed.session ?? (hinted && landed.request_id === hinted ? args.session : null);
            if (pass) {
              try { return await callInner(name, { ...args, session: pass }, opts); }
              catch (retryError) { error = retryError; }
            }
            // The connection is approved but the tool still cannot use it (a lost
            // Wirex user token, a closed signing grant): only a fresh tap mends that.
            if (error?.connect_required || SESSION_DEAD.test(String(error?.message))) landed = (await callInner("connect_wallet", {}, opts)).structuredContent;
          }
          // An approved connection whose retry failed for another reason (a provider error) answers that
          // error below, never a link that was already tapped.
          if (landed && landed.status !== "connected" && landed.status !== "processing") {
            const data = publicAnswer(connectRequired(name, landed, args));
            return { content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: data, isError: false };
          }
        } catch (connectError) { error = connectError; } // e.g. broker_unreachable from register (:338): mapped below
      }
      const result = refusalResult(error, args);
      if (result) return result;
      throw error;
    }
  }

  async function callInner(name, args = {}, { signal, deadline = Date.now() + 25_000 } = {}) {
    signal?.throwIfAborted();
    const entry = byName.get(name);
    if (entry) {
      if (typeof args?.session === "string") {
        // Identity handoff: a pass minted by another service qualifies here first (src/identity-handoff.mjs).
        await identity?.ensure?.(args.session, { signal }).catch(() => false);
        // A broker-bound connect link a tool handed out with its pass (wallet balance guest claim,
        // lost-key relink): adopt a delivered result first, the same hydrate as the request_id path (:339).
        if (broker) {
          let link = null;
          try { link = bridge.requireSession(args.session.split(".")[0]); } catch { link = null; }
          if ((link?.status === "pending" || (broker.consumerId === "wallet" && link?.status === "approved" && link.context?.walletId)) && link.brokerRequestId && link.context?.kind === "mcp_connection" && !link.context.grantFor
            && (Date.now() < link.expiresAt || link.context.walletId))
          {
            const hydration = await broker.hydrate(args.session.split(".")[0], { signal, deadline }).catch((error) => {
              logEvent("warn", "root_signer_hydrate_failed", { error: String(error?.message || error).slice(0, 80) });
              return { status: "pending" };
            });
            if (hydration?.status === "pending" && broker.consumerId === "wallet" && link.context.walletId) {
              const data = { ok: true, status: "pending", request_id: args.session.split(".")[0], message: "Still connecting. Call again with the same session." };
              return { content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: data, isError: false };
            }
          }
        }
        if (name === "bank" || name === "account") { const grant = await bankGrant(args.session, { signal }); if (grant) return { content: [{ type: "text", text: JSON.stringify(grant) }], structuredContent: grant, isError: false }; }
        // Expiry UX (D-QUORUM C): a session-only tool whose connection ran out (or was
        // purged) answers with the connect link, not a two-hop "call account".
        if (SESSION_TOOLS.has(name)) {
          try { accountFlow?.authorized?.(args.session, { signingGrant: false }); }
          catch (error) { if (/^(connection_expired|reconnect_required)/.test(String(error?.message))) throw connectRequiredSignal(); }
        }
      }
      // D-TOOLS-PAID: a priced action is paid from the caller's Agent Safe BEFORE it runs, once per
      // request (src/tool-prices.mjs). Unpaid (empty Safe, pending tap) = the action does not run.
      const charged = charges?.enabled ? await charges.charge(name, args, { signal }) : null;
      if (charged && !charged.run) return { content: [{ type: "text", text: JSON.stringify(publicAnswer(charged.answer)) }], structuredContent: publicAnswer(charged.answer), isError: publicAnswer(charged.answer).status === "failed" };
      // wallet_key is only a payer handle for tools whose own schema does not take it; they would refuse it.
      if (!entry.tool.inputSchema?.properties?.wallet_key && args && Object.hasOwn(args, "wallet_key")) { const { wallet_key, ...rest } = args; args = rest; }
      let data = publicAnswer(await entry.call(args, { signal, deadline }));
      if (charged?.paid && data && typeof data === "object" && !Array.isArray(data)) {
        charges.remember(name, charged, data);
        data = { ...data, fee: charged.paid };
      }
      return { content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: data, isError: data.status === "failed" }; // pending/tap/connect are steps, not errors: clients lock a tool after repeated errors (live 2026-09-28)
    }
    if (name !== "connect_wallet") throw new Error(`connection_tool_unavailable: That tool is not offered here. Call ${catalog.map((entry) => entry.tool.name).join(", ")}.`);
    if (!args || typeof args !== "object" || Array.isArray(args)
      || Object.keys(args).some((key) => key !== "request_id" && key !== "partner")) throw new Error("connection_arguments_invalid: That request contained something unexpected. Send it again with only the request_id from the earlier answer.");

    let partner = "nuri";
    if (Object.hasOwn(args, "partner")) {
      if (args.partner !== "nuri" && args.partner !== "wirex") throw new Error("connection_partner_invalid: That partner is not one we support. Try again leaving it out, unless the person named one.");
      if (Object.hasOwn(args, "request_id")) throw new Error("connection_arguments_invalid: A request_id cannot be sent together with a partner. Send the request_id on its own.");
      partner = args.partner;
    }
    let id = args.request_id;
    let credential;
    if (!Object.hasOwn(args, "request_id")) {
      const minted = await mintConnectApproval(bridge, { partner });
      id = minted.request_id;
      credential = minted.session;
    }
    if (typeof id !== "string" || !CONNECT_REF.test(id)) throw new Error("connection_required: The request_id is missing or damaged. Start a new connection.");
    let session;
    try {
      session = bridge.requireSession(id);
    } catch (error) {
      if (String(error?.message) !== "session_not_found") throw error;
      throw new Error("connection_not_found: That request_id is unknown here. Call the tool again without it to get one new link, and show the person only that link.");
    }
    if (session.context.kind !== "mcp_connection") throw new Error("connection_type_mismatch: That request_id belongs to a different kind of link. Start a new connection.");
    // A bank-grant child (bankGrant above) is never a pass of its own.
    if (session.context.grantFor) throw new Error("connection_type_mismatch: That request_id belongs to a different kind of link. Start a new connection.");
    if (session.signerAdapter !== "privy") throw new Error("connection_type_mismatch: That request_id was tapped a different way. Start a new connection.");
    // Root signer broker (C0 §1 amendment): registration and hydration are explicit async steps at
    // this MCP boundary. The sync createSession above already persisted the row, so nothing here
    // is a Promise-as-session. Legacy (pre-broker) pending rows have no brokerRequestId and keep
    // the original callback path untouched.
    const waitDeadline = Math.min(deadline, Date.now() + 25_000);
    let hydration = null;
    if (broker && (session.status === "pending" || (broker.consumerId === "wallet" && session.status === "approved" && session.context.walletId))
      && (Date.now() < session.expiresAt || (session.brokerRequestId && session.context.walletId))) {
      if (!session.brokerRequestId && !Object.hasOwn(args, "request_id")) await broker.register(id, { signal, deadline: waitDeadline });
      else if (session.brokerRequestId) hydration = await broker.hydrate(id, { signal, deadline: waitDeadline }).catch((error) => {
        logEvent("warn", "root_signer_hydrate_failed", { error: String(error?.message || error).slice(0, 80) });
        return { status: "pending" };
      });
    }
    if (Object.hasOwn(args, "request_id") && session.status === "pending" && Date.now() < session.expiresAt) {
      if (waitingChecks >= 64) throw new Error("connection_checks_busy: Too many checks are running at once. Try again in a moment.");
      waitingChecks++;
      try {
        // Wait quietly for the approval to land, at most ~25 s per call, so the
        // model never has to ask the person whether they tapped the link.
        const deadline = Math.min(waitDeadline, session.expiresAt);
        let probedAt = 0;
        while (session.status === "pending" && Date.now() < deadline) {
          await sleep(Math.min(250, deadline - Date.now()), undefined, { signal });
          if (session.status !== "pending" || Date.now() - probedAt < 1_000) continue;
          probedAt = Date.now();
          if (broker && session.brokerRequestId) hydration = await broker.hydrate(id, { signal, deadline }).catch(() => ({ status: "pending" }));
          await bridge.readStatus(id);
        }
      } finally { waitingChecks--; }
    }

    if (hydration?.status === "pending" && broker?.consumerId === "wallet" && session.context.walletId) {
      const data = { ok: true, status: "pending", request_id: id, message: "Still connecting. Call again with the same request_id." };
      return { content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: data, isError: false };
    }
    const owned = session.status === "approved" && Boolean(session.result?.signer);
    if (owned && Date.now() < session.expiresAt) {
      session.context.connectedAt ??= Date.now();
      const connectedUntil = session.context.connectedAt + connectionTtlMs();
      if (session.expiresAt < connectedUntil) {
        bridge.extendSessionExpiry?.(id, connectedUntil);
        session.expiresAt = connectedUntil;
      }
    }
    if (Date.now() >= session.expiresAt) {
      if (owned) throw new Error("connection_expired: That connection has run out. Start a new connection.");
      throw new Error("connection_expired: The link has expired. Start a new connection.");
    }

    credential ??= sessionCredential(id, session);
    if (owned) await wirexUserLogin(id, session);
    // Wallet service (C0 §3): identity comes from the approved local session alone; no Wirex
    // account advance, no banking JWT on a wallet-only connect.
    const accountInfo = owned ? (connectAdvance ? await accountFlow.advance(id) : { status: "connected" }) : null;
    signal?.throwIfAborted();
    if (Date.now() >= session.expiresAt) {
      if (owned) throw new Error("connection_expired: That connection has run out. Start a new connection.");
      throw new Error("connection_expired: The link has expired. Start a new connection.");
    }
    const connected = accountInfo?.status === "connected";

    const freshRequest = !Object.hasOwn(args, "request_id");
    const data = withAddressLabels({
      ok: true, status: connected ? "connected" : owned ? "processing" : "approval_required", request_id: id,
      message: connected
        ? "Your wallet is connected."
        : owned ? "Finishing setup on the connection page."
        : freshRequest
          ? "Open the link and approve the connection on your device."
          : "Not tapped yet. Call the same tool again with the same request_id right away; it answers by itself the moment the tap lands. Do not ask the person whether they tapped, and do not tell them to wait.",
      expires_at: new Date(session.expiresAt).toISOString(),
      expires_hint: "The request_id and the session work until expires_at. When less than five minutes are left, or the time has passed, start one new connection.",
      ...(credential ? { session: credential } : {}),
      ...(connected ? { account_exists: accountInfo.account_exists, smart_account_address: accountInfo.smart_account_address,
        wallet: walletReceiveInfo(chainId, session.result.signer),
        route: "email",
        partner: session.context.partner === "wirex" ? "wirex" : "nuri" }
        : !owned ? { approval_url: session.context.approvalUrl,
          route: "email",
          // The request_id continuation (in `call`) strips request_id and re-runs
          // the named tool with the resolved session, so a hint must name a call
          // that tool actually accepts. wallet requires action, so the old bare
          // { request_id } poll was refused the moment the connection landed.
          next_action: openLinkThen(session.context.approvalUrl,
            { ...continueCall(name, id), until: "the connection is approved" }),
          poll: (({ tool, args }) => pollFor(tool, args))(continueCall("wallet", id)) } : {}),
    }, { smart_account_address: ACCOUNT_WALLET_WORDS });
    if (connected) data.address_labels = { ...data.address_labels, "wallet.address": CONNECTED_WALLET_WORDS };
    return { content: [{ type: "text", text: JSON.stringify(data) }], structuredContent: data, isError: false };
  }

  return { tools, call, bankGrant };

  function refusalResult(error, args = {}) {
    const message = String(error?.message || error);
    const data = { ok: false, error: message.replace(/^wirex_(?!signer_not_configured)/, "provider_") };
    if (Array.isArray(error?.allowed_merchants)) data.allowed_merchants = error.allowed_merchants;
    // Root signer broker down (src/root-signer-client.mjs:23 code broker_unreachable): no link was
    // issued and nothing ran, so the answer says so instead of the transport text ("fetch failed").
    if (error?.code === "broker_unreachable") data.error = "broker_unreachable: The sign-in service is not answering. Nothing was sent. Try again in a moment.";
    else if (isWirexUserNotFound(error)) {
      data.error = "account_missing: No account yet. Call account with action verify to start the identity check.";
      data.next_action = { type: "call", tool: "account", args: { action: "verify", ...(args.session ? { session: args.session } : {}) } };
    }
    else if (error?.next_action && typeof error.next_action === "object") data.next_action = error.next_action;
    else if (message.startsWith("kyc_required:")) {
      let kycUrl;
      try { kycUrl = args.session ? accountFlow?.authorized?.(args.session)?.context?.kycUrl : undefined; } catch {  }
      if (!kycUrl) return null;
      data.approval_url = kycUrl;
      data.next_action = openLinkThen(kycUrl,
        { tool: "account", args: { action: "status", ...(args.session ? { session: args.session } : {}) }, until: "the identity check is approved" });
    }
    else return null;
    const spoken = String(data.error).split(/^[a-z0-9_]+(?::[a-z0-9_]+)*(?::\s+|\s*—\s*)/).pop();
    data.message = spoken && spoken !== String(data.error) ? spoken : String(data.error);
    return { content: [{ type: "text", text: JSON.stringify(publicAnswer(data)) }], structuredContent: publicAnswer(data), isError: true };
  }
}
