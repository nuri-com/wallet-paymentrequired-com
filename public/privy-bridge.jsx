import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { PrivyProvider, useAuthorizationSignature, useCreateWallet, useLogin, usePrivy, useSignMessage, useWallets } from "@privy-io/react-auth";
import { approvalActionLabel, approvalFailure, approvalFailureMessage } from '../src/privy-bridge-display.mjs';
// Pinned to AGENT_SIGNER_MESSAGE in src/agent-signer-derivation.mjs (browser bundle cannot import node:crypto).
const AGENT_SIGNER_MESSAGE = "Nuri agent signer v1";

import {
  BRIDGE_VERSION,
  completeWalletConnection,
  connectionAttempt,
  readBridgeParams,
  encryptForServer,
  loadBridgeParams,
  refreshBridgeParams,
  mergeApprovalPayload,
  messageForAddress,
  personalSignInput,
  personalSignTextInput,
  prepareBridgeSigning,
  resolveBridgeWallet,
  bridgeSelectionBinding,
  wirexLoginRequest,
} from "../src/privy-bridge-client.mjs";

const config = window.__NURI_PRIVY_CONFIG__ || {};


const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const isAddress = value => typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value);
const isIdentifier = value => typeof value === 'string' && value.length > 0 && value === value.trim();

// Revalidate stored requests with the same parser as server-loaded approvals.
// Keep only immutable request fields; resumeAddress is transient UI state.
function agentRequest(params) {
  if (!isRecord(params)) throw new Error('Agent retry request is invalid');
  const link = Object.fromEntries(['origin', 'basePath', 'sessionId', 'state', 'intent', 'callback', 'clientPublicKey', 'expires']
    .map(key => [key, params[key]]));
  const request = mergeApprovalPayload(link, {
    signer_adapter: 'privy', approval_type: params.approvalType, wallet_connection: params.walletConnection,
    connection_address: params.connectionAddress, siwe: params.siwe, sign_text: params.signText,
    sign_hash: params.signHash, sign_typed_data: params.signTypedData, consent_text: params.consentText,
    expected_address: params.expectedAddress, privy_agent_signer_id: params.privyAgentSignerId,
    privy_root_address: params.privyRootAddress,
  });
  // Acceptance is progress, not consent. Validate it before excluding it from
  // immutable bindings; legacy requests predate this field entirely.
  if (Object.hasOwn(params, 'approvalStatus') && !['pending', 'approved'].includes(params.approvalStatus)) {
    throw new Error('Agent retry status is invalid');
  }
  delete request.approvalStatus;
  if (!request.privyAgentSignerId || request.walletConnection
    || Object.keys(params).some(key => !Object.hasOwn(request, key) && !['approvalStatus', 'resumeAddress'].includes(key))
    || Object.keys(request).some(key => !Object.hasOwn(params, key) || JSON.stringify(params[key]) !== JSON.stringify(request[key]))) {
    throw new Error('Agent retry request is invalid');
  }
  return request;
}

function agentBinding(params, owner, userId) {
  const request = agentRequest(params);
  if (!isIdentifier(userId) || !isAddress(owner) || owner.toLowerCase() !== request.privyRootAddress.toLowerCase()) {
    throw new Error('Agent retry identity is invalid');
  }
  return JSON.stringify([request, owner.toLowerCase(), userId]);
}

function validateAgentAttempt(saved, params, owner, userId) {
  const binding = agentBinding(params, owner, userId);
  if (!isRecord(saved) || saved.version !== 1 || !['creating', 'created', 'submitted', 'done'].includes(saved.phase)
    // Check the ORIGINAL full request/status/owner/user binding before comparing
    // status-free consent. Never regenerate a mismatched historical binding.
    || saved.binding !== JSON.stringify([saved.request, owner.toLowerCase(), userId])
    || saved.userId !== userId || !isAddress(saved.rootAddress)
    || saved.rootAddress.toLowerCase() !== owner.toLowerCase()
    || agentBinding(saved.request, owner, userId) !== binding
    || Object.hasOwn(saved.request, 'resumeAddress')
    || Object.keys(saved).some(key => !['version', 'phase', 'binding', 'userId', 'rootAddress', 'request', 'wallet'].includes(key))) {
    throw new Error('Agent retry checkpoint is invalid or unbound');
  }
  if (saved.phase === 'creating' ? Object.hasOwn(saved, 'wallet')
    : !isRecord(saved.wallet) || !isIdentifier(saved.wallet.id) || !isAddress(saved.wallet.address)
      || saved.wallet.address.toLowerCase() === owner.toLowerCase()
      || Object.keys(saved.wallet).some(key => !['id', 'address'].includes(key))) {
    throw new Error('Agent retry wallet metadata is invalid');
  }
  return saved;
}

// This is a retry journal, not authority to choose a wallet. In particular an
// unresolved create must never be inferred from ConnectedWallet order/index.
function agentAttempt(params, owner, userId) {
  if (!isIdentifier(userId)) throw new Error('Privy user is missing');
  if (!isAddress(owner) || !isAddress(params.privyRootAddress)
    || owner.toLowerCase() !== params.privyRootAddress.toLowerCase()) throw new Error('Agent approval owner changed');
  const key = `privy-agent-create:${params.sessionId}:${params.state}`;
  const binding = agentBinding(params, owner, userId);
  const storage = window.sessionStorage;
  const raw = storage.getItem(key);
  // Only a missing storage entry is absent. JSON null/false/0/arrays, parse
  // errors and unsupported versions remain uncertainty, never a new create.
  const saved = raw === null ? null : validateAgentAttempt(JSON.parse(raw), params, owner, userId);
  if (!Number.isSafeInteger(params.expires) || Date.now() >= params.expires) throw new Error('Agent approval expired');
  return {
    saved,
    write(value) {
      const record = validateAgentAttempt({ ...value, version: 1,
        binding: Object.hasOwn(value, 'binding') ? value.binding : binding }, params, owner, userId);
      const text = JSON.stringify(record);
      storage.setItem(key, text);
      if (storage.getItem(key) !== text) throw new Error('Agent retry checkpoint unavailable');
      return record;
    },
  };
}

async function agentApprovalAccepted(params, attempt) {
  validateAgentAttempt(attempt, params, attempt.rootAddress, attempt.userId);
  const response = await fetch(`${params.origin}${params.basePath}/api/browser-sessions/${encodeURIComponent(params.sessionId)}`, {
    method: 'GET', credentials: 'same-origin', cache: 'no-store', headers: { accept: 'application/json' },
  });
  if (!response.ok) throw new Error('Approval status unavailable');
  const status = await response.json();
  if (status.session_id !== params.sessionId || status.ok !== true) throw new Error('Approval status mismatch');
  if (status.status === 'pending') {
    if (attempt.phase === 'done') throw new Error('Completed approval no longer matches server status');
    return false;
  }
  const result = status.result;
  if (status.status !== 'approved' || result?.signer_adapter !== 'privy' || result.signature_matches_address !== true
    || result.signer?.toLowerCase() !== attempt.wallet.address.toLowerCase() || result.provider_wallet_id !== attempt.wallet.id
    || result.provider_user_id !== attempt.userId || result.root_address?.toLowerCase() !== attempt.rootAddress.toLowerCase()
    || result.address?.toLowerCase() !== attempt.wallet.address.toLowerCase()
    || result.message !== messageForAddress(params, attempt.wallet.address)
    || (params.consentText && (result.consent_message !== params.consentText || result.consent_signature_matches_address !== true))) {
    throw new Error('Approval result is not bound to the checkpointed wallet');
  }
  return true;
}

async function loadApproval() {
  try { return await loadBridgeParams(window.location.href); }
  catch (error) {
    // Generic approval payloads become unavailable after acceptance. On reload,
    // recover only our exact submitted checkpoint AND a matching server result.
    const link = readBridgeParams(window.location.href);
    if (!link) throw error;
    const saved = JSON.parse(window.sessionStorage.getItem(`privy-agent-create:${link.sessionId}:${link.state}`));
    if (!saved?.wallet || !['submitted', 'done'].includes(saved.phase) || !saved.request
      || Object.keys(link).some(key => saved.request[key] !== link[key])) throw error;
    validateAgentAttempt(saved, saved.request, saved.rootAddress, saved.userId);
    if (!await agentApprovalAccepted(saved.request, saved)) throw error;
    return saved.request;
  }
}

// Tell an embedding page (iframe parent) or the opener that the approval finished, so it can close the bridge.
// Targets are restricted to the origins the server allows to embed us; nothing is sent otherwise.
function notifyHost(state) {
  const targets = Array.isArray(config.embedOrigins) ? config.embedOrigins : [];
  if (!targets.length) return;
  const message = { type: "nuri-bridge", state };
  for (const origin of targets) {
    try { if (window.parent !== window) window.parent.postMessage(message, origin); } catch {}
    try { if (window.opener) window.opener.postMessage(message, origin); } catch {}
  }
}

// A wallet_pay quote whose remaining window is shorter than this is never
// offered for signing: a person cannot read, decide and sign inside it. The
// page asks for the fresh quote of the SAME payment instead (#151).
const QUOTE_SIGN_MARGIN_MS = 90_000;
const PAYMENT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// The payment a wallet_pay approval belongs to. The approval link carries it
// as `lineage`; the consent sentence names it too, so a short link that hides
// the query still resolves to the same payment.
function paymentLineage(params) {
  try {
    const fromUrl = new URL(window.location.href).searchParams.get("lineage");
    if (fromUrl && PAYMENT_ID_PATTERN.test(fromUrl)) return fromUrl;
  } catch {}
  const fromConsent = /\(payment ([0-9a-fA-F-]{36})\)/.exec(params?.consentText || "");
  return fromConsent && PAYMENT_ID_PATTERN.test(fromConsent[1]) ? fromConsent[1] : null;
}

// The freshest open approval of the SAME payment, or null. A quote that was
// re-fetched after this link was minted leaves a NEWER pending approval on
// the same payment id; while one is open this page must point at it — never
// report "Done." and never offer to sign the dead quote. Two sources, in
// order: the approval GET's own raw answer (a server that re-binds on read
// answers the fresh link directly; mergeApprovalPayload keeps only signing
// fields, so this reads the raw JSON), and the self-healing lineage lookup
// every deployment already serves.
async function openReboundApproval(params) {
  try {
    const response = await fetch(`${params.origin}${params.basePath}/api/browser-sessions/${encodeURIComponent(params.sessionId)}/approval?state=${encodeURIComponent(params.state)}`, {
      cache: "no-store", headers: { accept: "application/json" },
    });
    if (response.ok) {
      const raw = await response.json();
      // The wallet_pay read path adds payment extras to the session's own
      // payload: approval_url + payment_id means the quote moved to a fresh
      // approval of the SAME payment (never a second payment).
      if (typeof raw?.approval_url === "string" && raw.approval_url && typeof raw?.payment_id === "string") {
        return raw.approval_url;
      }
      if (raw?.approval_status === "approved" && raw?.payment?.approval_status === "pending"
        && typeof raw.payment?.approval_url === "string" && raw.payment.approval_url) return raw.payment.approval_url;
    }
  } catch { /* fall through to the lineage lookup */ }
  const lineage = paymentLineage(params);
  if (!lineage) return null;
  try {
    const response = await fetch(`${params.origin}${params.basePath}/api/browser-sessions/pending?lineage=${encodeURIComponent(lineage)}`, {
      cache: "no-store", headers: { accept: "application/json" },
    });
    if (!response.ok) return null;
    const body = await response.json();
    const url = body?.approval_url;
    // This page's own still-pending link is not a rebound; only a DIFFERENT
    // session's link means the payment moved on.
    return typeof url === "string" && url && !url.includes(`session_id=${params.sessionId}`) ? url : null;
  } catch { return null; }
}

function Bridge() {
  const { ready, authenticated, user, getAccessToken } = usePrivy();
  const { ready: walletsReady, wallets } = useWallets();
  const walletsRef = useRef(wallets);
  walletsRef.current = wallets;
  const { createWallet } = useCreateWallet();
  const { signMessage } = useSignMessage();
  const { generateAuthorizationSignature } = useAuthorizationSignature();
  const [params, setParams] = useState(null);
  const [reboundUrl, setReboundUrl] = useState(null); const [card, setCard] = useState(null); // D-CARD-REVEAL: numbers from the callback, RAM only
  const [quoteLapsed, setQuoteLapsed] = useState(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const loadInFlight = useRef(true);
  const [invalidLink, setInvalidLink] = useState(false);
  const submissionAttempted = useRef(false);
  const [choice, setChoice] = useState(null);
  const [retryUnavailable, setRetryUnavailable] = useState(false);
  const binding = bridgeSelectionBinding(params, user?.id);
  const savedConnection = params?.walletConnection ? connectionAttempt(params, 'read') : null;
  // Agent creation selects the root; expectedAddress can name its distinct
  // signing wallet. Ordinary/connection pins all constrain the same signer.
  const pins = params?.privyAgentSignerId ? [params.privyRootAddress]
    : [params?.expectedAddress, params?.connectionAddress, params?.resumeAddress,
      savedConnection?.address, choice?.address];
  const selection = resolveBridgeWallet(wallets, user?.linkedAccounts, pins);
  const bindingChanged = (choice && choice.binding !== binding)
    || (savedConnection?.binding && savedConnection.binding !== binding);
  const wallet = authenticated && binding && !bindingChanged ? selection.wallet : undefined;
  // A pinned UserOp-hash approval (wallet send from an owned Safe, bank send, account deployment):
  // one tap signs it. Live 2026-09-26: this shape needed Log in, then a second press on the page,
  // then two Privy confirm modals (the hash, then the consent text); the owner stopped after the
  // login and the send stayed pending. Now the page's single button logs in if needed and signs both
  // silently, like the connection tap. The pin (expectedAddress) keeps any other wallet out.
  // Same for a pinned text approval (limits, card close, new card, a fee): live 2026-09-28 the owner
  // "had to click twice at Privy" for these while a send took one tap.
  const hashApproval = Boolean((params?.signHash || params?.signText) && params.expectedAddress && !params.walletConnection
    && !params.privyAgentSignerId && !params.signTypedData && !params.approvalType && !params.siwe);
  const oneTap = Boolean(params?.walletConnection || hashApproval);
  const approvalStarted = useRef(false);
  const identityInvalidated = useRef(false);
  const identityRef = useRef(null);
  const identity = { authenticated, userId: user?.id, owner: wallet?.address?.toLowerCase(), binding };
  if (approvalStarted.current && identityRef.current
    && Object.keys(identity).some(key => identity[key] !== identityRef.current[key])) identityInvalidated.current = true;
  identityRef.current = identity;
  const [status, setStatus] = useState("Loading request");
  const [state, setStateRaw] = useState("busy");
  const setState = (next) => { setStateRaw(next); if (next === "done" || next === "error") notifyHost(next); };
  const [busy, setBusy] = useState(false);
  const agentCheckpoint = useRef(null);
  const [recoveryRequired, setRecoveryRequired] = useState(false);
  const [failure, setFailure] = useState(null);
  const [connectRequested, setConnectRequested] = useState(false);
  const connectionStarted = useRef(false);
  const { login } = useLogin({ onError: () => {
    setConnectRequested(false);
  } });

  useEffect(() => {
    let active = true;
    loadApproval()
      .then(async (loaded) => {
        if (!active) return;
        if (!loaded) {
          setInvalidLink(true);
          throw new Error("This link isn't valid.");
        }
        const attempt = loaded.walletConnection ? connectionAttempt(loaded, "read") : null;
        const withResume = { ...loaded, resumeAddress: attempt?.address };
        setParams(withResume);
        if (loaded.approvalStatus === 'approved' && !loaded.walletConnection && !loaded.privyAgentSignerId) {
          // The approved-shortcut must not fire while a rebound approval for
          // the same payment is still open: that fresh link is the next step,
          // never "Done.".
          const rebound = await openReboundApproval(withResume);
          if (!active) return;
          if (rebound) { setReboundUrl(rebound); return; }
          setState('done');
          return;
        }
        // Just-in-time quoting: a quote whose window is dead or nearly dead is
        // never offered for signing. Ask for the fresh quote of the SAME
        // payment (same amount, same payee) and point at it.
        const validBeforeMs = Number(loaded.signTypedData?.message?.validBefore) * 1000;
        if (!loaded.walletConnection && loaded.signTypedData && Number.isSafeInteger(validBeforeMs)
          && validBeforeMs > 0 && validBeforeMs - Date.now() <= QUOTE_SIGN_MARGIN_MS) {
          const rebound = await openReboundApproval(withResume);
          if (!active) return;
          if (rebound) { setReboundUrl(rebound); return; }
          setQuoteLapsed(true);
          return;
        }
        // Reloading a failed request never starts signing by itself.
        if (loadAttempt === 0 && (loaded.connectionAddress || (attempt && !attempt.retryOnly))) setConnectRequested(true);
        setStatus("Ready");
        setState("ready");
      })
      .catch((error) => {
        if (!active) return;
        if (error.terminal) setInvalidLink(true);
        setFailure(approvalFailure('load_request', error));
        setStatus(approvalFailureMessage(approvalFailure('load_request', error)));
        setState("error");
      }).finally(() => { if (active) loadInFlight.current = false; });
    return () => { active = false; };
  }, [loadAttempt]);

  function retryLoad() {
    if (loadInFlight.current || params || invalidLink) return;
    loadInFlight.current = true;
    setFailure(null);
    setState('busy');
    setLoadAttempt(value => value + 1);
  }

  // Continue a clicked or already verified connection. Other approvals stay manual.
  useEffect(() => {
    if (oneTap && connectRequested && ready && authenticated && walletsReady && wallet
      && state === "ready" && !connectionStarted.current) {
      connectionStarted.current = true;
      void approve();
    }
  }, [params, oneTap, connectRequested, ready, authenticated, walletsReady, wallet, state]);

  function connectWallet() {
    if (busy || approvalStarted.current || identityInvalidated.current || submissionAttempted.current) return;
    if (params.walletConnection) connectionAttempt(params, "start");
    connectionStarted.current = false;
    setConnectRequested(true);
    setState("ready");
    if (!authenticated) login();
  }


  function chooseWallet(candidate) {
    if (!params?.walletConnection || pins.some(Boolean) || !binding || busy
      || bindingChanged || !selection.choices.includes(candidate)) return;
    // A durable exact-request/user pin is required before a choice can sign.
    const attempt = connectionAttempt(params, 'start', candidate.address, undefined, binding);
    if (!attempt) { setRetryUnavailable(true); return; }
    setChoice({ address: candidate.address, binding });
    setParams({ ...params, resumeAddress: candidate.address });
    connectionStarted.current = false;
    setConnectRequested(true);
    setState('ready');
  }

  function retrySelection() {
    if (busy || bindingChanged || identityInvalidated.current || !connectionAttempt(params, 'retry')) { setRetryUnavailable(true); return; }
    window.location.reload();
  }


  async function waitForConnectedWallet(address) {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      const connected = walletsRef.current.find((candidate) =>
        candidate.address.toLowerCase() === address.toLowerCase() && typeof candidate.getEthereumProvider === "function",
      );
      if (connected) return connected;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw Object.assign(new Error("The connected wallet did not become available"), { code: 'privy_agent_wallet_not_connected' });
  }

  async function approve() {
    if (!params || !wallet || busy || approvalStarted.current || identityInvalidated.current || submissionAttempted.current) return;
    approvalStarted.current = true;
    setBusy(true);
    setState("busy");
    setFailure(null);
    let stage = 'connect_wallet';
    let journal, attempt;
    const assertAgentIdentity = () => {
      if (identityInvalidated.current || !identityRef.current.authenticated || identityRef.current.binding !== binding
        || identityRef.current.userId !== user?.id || identityRef.current.owner !== wallet.address.toLowerCase()
        || Date.now() >= params.expires) {
        throw new Error('Authenticated Privy identity changed');
      }
    };
    try {
      let signingWallet = wallet;
      assertAgentIdentity();
      let agentPayload = {};
      if (params.privyAgentSignerId) {
        assertAgentIdentity();
        journal = agentAttempt(params, wallet.address, user?.id);
        attempt = agentCheckpoint.current || journal.saved;
        if (agentCheckpoint.current && JSON.stringify(agentCheckpoint.current) !== JSON.stringify(journal.saved)) {
          throw new Error('Agent retry checkpoint changed or disappeared');
        }
        if (attempt && !attempt.wallet) {
          // The challenge has no authoritative owner/quorum/slot lookup. Fail
          // closed until that lookup can reconcile the unknown provider result.
          setRecoveryRequired(true);
          throw new Error('Agent creation needs owner/quorum/slot reconciliation');
        }
        // Submitted recovery can work even when the consumed approval payload
        // is unavailable: check the exact server result before refetching it.
        if (attempt?.phase === 'submitted' || attempt?.phase === 'done') {
          stage = 'submit_approval';
          if (await agentApprovalAccepted(params, attempt)) {
            assertAgentIdentity();
            agentCheckpoint.current = journal.write({ ...attempt, phase: 'done' });
            setState('done');
            setStatus('Done.');
            return;
          }
        }
        // Reconcile acceptance BEFORE any create. A generic accepted shortcut
        // cannot establish which provider wallet was created for this request.
        const current = await refreshBridgeParams(params);
        assertAgentIdentity();
        if (current.approvalStatus === 'approved') {
          if (!attempt?.wallet || !await agentApprovalAccepted(params, attempt)) {
            throw new Error('Accepted agent approval has no matching wallet checkpoint');
          }
          assertAgentIdentity();
          agentCheckpoint.current = journal.write({ ...attempt, phase: 'done' });
          setState('done');
          setStatus('Done.');
          return;
        }
        if (!attempt) {
          setStatus("Creating your wallet");
          stage = 'create_wallet';
          // Persist intent BEFORE calling Privy: timeout/reload is not proof of failure.
          attempt = journal.write({ phase: 'creating', userId: user.id, rootAddress: wallet.address, request: agentRequest(params) });
          agentCheckpoint.current = attempt;
          const created = await createWallet({
            createAdditional: true,
            signers: [{ signerId: params.privyAgentSignerId, policyIds: [] }],
          });
          stage = 'connect_wallet';
          if (!isIdentifier(created?.id) || !isAddress(created?.address)
            || created.address.toLowerCase() === wallet.address.toLowerCase()) {
            throw Object.assign(new Error("Privy Agent wallet metadata is missing"), { code: 'privy_agent_wallet_metadata_missing' });
          }
          // Capture exact server ID/address before ANY provider connection or signature.
          attempt = { ...attempt, phase: 'created', wallet: { id: created.id, address: created.address } };
          agentCheckpoint.current = attempt;
          attempt = journal.write(attempt);
          assertAgentIdentity();
        }
        stage = 'connect_wallet';
        assertAgentIdentity();
        signingWallet = await waitForConnectedWallet(attempt.wallet.address);
        assertAgentIdentity();
        agentPayload = {
          providerWalletId: attempt.wallet.id,
          providerUserId: attempt.userId,
          rootAddress: attempt.rootAddress,
        };
      }
      setStatus(params.walletConnection ? "Connecting your wallet" : "Approving your request");
      if (params.walletConnection) {
        // Retain the signing pin even when the callback or provider fails.
        const checkpoint = connectionAttempt(params, "start", signingWallet.address, undefined, binding);
        if (!checkpoint) throw new Error('Wallet recovery checkpoint unavailable');
        setParams(current => ({ ...current, resumeAddress: signingWallet.address }));
      }
      const simpleSigning = oneTap || ["card_details", "card_pin", "read_session"].includes(params.approvalType);
      const provider = simpleSigning ? null : await signingWallet.getEthereumProvider();
      const signAndSubmit = async (request) => {
        stage = 'prepare_signature';
        request = await refreshBridgeParams(request);
        assertAgentIdentity();
        if (request.approvalStatus === 'approved') {
          if (journal && !await agentApprovalAccepted(request, attempt)) throw new Error('Agent approval is not accepted');
          return;
        }
        request = await prepareBridgeSigning(request);
        assertAgentIdentity();
        const message = messageForAddress(request, signingWallet.address);
        stage = 'sign_request';
        // The user's connection click covers ownership and its bound deployment; no second modal.
        const signature = simpleSigning
          ? (await signMessage({ message: personalSignInput(request, message) }, {
              address: signingWallet.address, uiOptions: { showWalletUIs: false },
            })).signature
          : request.signTypedData
          ? await provider.request({
              method: "eth_signTypedData_v4",
              params: [signingWallet.address, JSON.stringify(request.signTypedData)],
            })
          : await provider.request({
              method: "personal_sign",
              params: [personalSignInput(request, message), signingWallet.address],
            });
        if (typeof signature !== "string") throw new Error("Privy did not return a signature");
        assertAgentIdentity();
        let consentPayload = {};
        if (request.consentText) {
          stage = 'sign_consent';
          const consentSignature = simpleSigning
            ? (await signMessage({ message: personalSignTextInput(request.consentText) }, {
                address: signingWallet.address, uiOptions: { showWalletUIs: false },
              })).signature
            : await provider.request({
                method: "personal_sign",
                params: [personalSignTextInput(request.consentText), signingWallet.address],
              });
          if (typeof consentSignature !== "string") throw new Error("Privy did not return a consent signature");
          assertAgentIdentity();
          consentPayload = { consentMessage: request.consentText, consentSignature };
        }
        // Same tap, second signature: the agent signer (share 1) is derived on the
        // server from this signature and kept in RAM only. Optional — a failure
        // here must never stop the connection.
        let agentSignerPayload = {};
        if (request.walletConnection) {
          assertAgentIdentity();
          try {
            const { signature: agentSignerSignature } = await signMessage({ message: personalSignTextInput(AGENT_SIGNER_MESSAGE) }, {
              address: signingWallet.address, uiOptions: { showWalletUIs: false },
            });
            if (typeof agentSignerSignature === "string") agentSignerPayload = { agentSignerSignature };
          } catch { /* wallet connects without an active agent signer */ }
          assertAgentIdentity();
        }
        // Same tap, one more signature (#150): the Wirex login message, so the server can hold a
        // user token for this wallet without a partner secret. Optional like the agent signer.
        let wirexLoginPayload = {};
        if (request.walletConnection && request.wirexLogin) {
          try {
            const { nonce, message: wirexMessage } = wirexLoginRequest(request.wirexLogin, signingWallet.address);
            const { signature: wirexLoginSignature } = await signMessage({ message: personalSignTextInput(wirexMessage) }, {
              address: signingWallet.address, uiOptions: { showWalletUIs: false },
            });
            if (typeof wirexLoginSignature === "string") wirexLoginPayload = { wirexLoginSignature, wirexLoginNonce: nonce };
          } catch { /* wallet connects without a Wirex user token; the server falls back */ }
        }
        const payload = {
          version: BRIDGE_VERSION,
          state: request.state,
          intent: request.intent,
          address: signingWallet.address,
          message,
          signature,
          ...consentPayload,
          ...agentPayload,
          ...agentSignerPayload,
          ...wirexLoginPayload,
          ...(request.walletConnection ? {
            privyAccessToken: await getAccessToken(),
          } : {}),
        };
        setStatus("Finishing");
        stage = 'submit_approval';
        const envelope = await encryptForServer(payload, request.clientPublicKey, request.state);
        assertAgentIdentity();
        if (journal) {
          attempt = journal.write({ ...attempt, phase: 'submitted' });
          agentCheckpoint.current = attempt;
        }
        // Freeze signing after submission; uncertain outcomes reconcile by read.
        submissionAttempted.current = true;
        try {
          const response = await fetch(request.callback, {
            method: "POST",
            mode: "cors",
            credentials: "omit",
            cache: "no-store",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(envelope),
          });
          if (!response.ok) throw Object.assign(new Error('Approval callback failed'), { status: response.status });
          // A wallet_pay tap that landed after its quote's window re-binds on
          // the callback: the answer carries the SAME payment with a FRESH
          // approval link (same amount, same payee, dead nonce discarded).
          // While any approval for this payment is still open that link is the
          // only honest next step — never "Done.".
          const continuation = await response.json().catch(() => null);
          if (continuation?.card || continuation?.card_error) return { card: continuation.card ?? { error: continuation.card_error } };
          if (continuation?.payment?.approval_status === "pending"
            && typeof continuation.payment.approval_url === "string" && continuation.payment.approval_url) {
            setReboundUrl(continuation.payment.approval_url);
            return { rebound: continuation.payment.approval_url };
          }
        } catch (error) {
          // A lost response can still mean accepted. A read never submits again.
          const current = await refreshBridgeParams(request);
          assertAgentIdentity();
          if (current.approvalStatus !== 'approved'
            || (journal && !await agentApprovalAccepted(current, attempt))) throw error;
        }
        if (request.walletConnection) stage = 'connect_account';
      };
      if (params.walletConnection) {
        setStatus("Setting up your account");
        stage = 'connect_account';
        await completeWalletConnection(params, signingWallet.address, signAndSubmit, { authorize: async (...args) => {
          assertAgentIdentity();
          stage = 'authorize_session';
          const result = await generateAuthorizationSignature(...args);
          assertAgentIdentity();
          stage = 'connect_account';
          return result;
        } });
      } else {
        const submitted = await signAndSubmit(params);
        if (submitted?.card) setCard(submitted.card);
        // The payment re-bound: the render shows the fresh approval link.
        if (submitted?.rebound) return;
      }
      assertAgentIdentity();
      if (journal) {
        attempt = journal.write({ ...attempt, phase: 'done' });
        agentCheckpoint.current = attempt;
      }
      connectionAttempt(params, "clear");
      setState("done");
      setStatus(params.walletConnection ? "Connected." : "Done.");
    } catch (error) {
      if (error.terminal) setInvalidLink(true);
      setFailure(approvalFailure(stage, error));
      setConnectRequested(false);
      setState("error");
      setStatus(approvalFailureMessage(approvalFailure(stage, error)));
      setBusy(false);
      approvalStarted.current = false;
    }
  }

  async function recheckQuote() {
    if (busy || !params) return;
    setBusy(true);
    try {
      const rebound = await openReboundApproval(params);
      if (rebound) setReboundUrl(rebound);
    } finally { setBusy(false); }
  }

  if (!params) return <main>
    <p role="status">{state === 'error' ? invalidLink ? 'This link is invalid or has expired.' : 'This request is unavailable.' : 'Connecting…'}</p>
    {state === 'error' && !invalidLink && <button type="button" onClick={retryLoad}>Try again</button>}
  </main>;
  // A rebound approval for this same payment is still open: point at the fresh
  // link, never "Done." and never the dead quote.
  if (reboundUrl) return (
    <main>
      <p role="status">The first quote expired before it was approved. The amount and recipient are unchanged.</p>
      <a role="button" href={reboundUrl}>New quote — sign again</a>
    </main>
  );
  if (quoteLapsed) return (
    <main>
      <p role="status">This quote expired before it could be approved. Your assistant can continue the same payment — it fetches the fresh quote at the moment you approve.</p>
      <button type="button" onClick={recheckQuote} disabled={busy}>{busy ? 'Checking…' : 'Check for a new quote'}</button>
    </main>
  );
  if (card || (state === 'done' && params.approvalType === 'card_details')) return <CardDetails card={card ?? { error: 'Your card details could not be shown. Ask your assistant for a new link.' }} />;
  if (state === 'done') return <Page params={params} state="done" />;
  if (invalidLink) return <main><p role="status">This approval is no longer available.</p></main>;
  if (!ready || !walletsReady) return <main><p role="status">Connecting…</p></main>;
  if (!authenticated) {
    return (
      <Page params={params} status={status} state={state}>
        {cardText(params)}<button type="button" onClick={oneTap ? connectWallet : login}>{oneTap ? approvalActionLabel(params) : "Log in"}</button>
      </Page>
    );
  }
  if (!wallet) {
    const selectionFailure = approvalFailure('select_wallet', {
      code: `privy_selection_${bindingChanged ? 'identity_changed' : selection.reason}`,
    });
    return (
      <Page params={params} failure={selectionFailure} state="error">
        {!bindingChanged && params.walletConnection && !pins.some(Boolean)
          && selection.choices.map(candidate => <button type="button" key={candidate.address}
            style={{ overflowWrap: 'anywhere' }} onClick={() => chooseWallet(candidate)}>Use {candidate.address}</button>)}
        {!bindingChanged && !identityInvalidated.current && !retryUnavailable && !connectionAttempt(params, 'read')?.recovered
          && <button type="button" className="secondary" onClick={retrySelection}>Check again</button>}
        {(retryUnavailable || connectionAttempt(params, 'read')?.recovered)
          && <p role="status">This wallet cannot be recovered here yet.</p>}
      </Page>
    );
  }
  const actionLabel = approvalActionLabel(params);
  const blocked = recoveryRequired || identityInvalidated.current || submissionAttempted.current;
  const canPress = !busy && !blocked && state !== "done" && !(oneTap && connectRequested);
  return (
    <Page params={params} failure={failure} state={connectRequested && state === "ready" ? "busy" : state}>
      {cardText(params)}{canPress && <button type="button" onClick={params.walletConnection ? connectWallet : approve}>{state === 'error' ? 'Try again' : actionLabel}</button>}
      {state === 'error' && !busy && !identityInvalidated.current && submissionAttempted.current
        && <button type="button" onClick={() => window.location.reload()}>Check again</button>}
    </Page>
  );
}

function Page({ params, failure, state, children }) {
  return (
    <main>
      {children}
      {state !== 'ready' && <p role="status" aria-live="polite">{state === 'done' ? params?.walletConnection ? 'Connected.' : 'Done.' : state === 'error' ? approvalFailureMessage(failure) : 'Connecting…'}</p>}
    </main>
  );
}

// D-CARD-REVEAL: what a card_details approval asks for, shown before the tap. The chat variant shows the exact
// consent text the person signs (src/mcp-bank-tool.mjs CHAT_CONSENT); the page variant signs only the Wirex challenge.
function cardText(params) {
  if (params?.approvalType !== 'card_details') return null;
  return <p>{params.consentText || 'Show your full card number, expiry date and security code on this page.'}</p>;
}

// The numbers arrive once, in the callback answer: shown here, hidden after 60 s, never stored or sent elsewhere.
function CardDetails({ card }) {
  const [hidden, setHidden] = useState(false);
  useEffect(() => { const timer = setTimeout(() => setHidden(true), 60_000); return () => clearTimeout(timer); }, []);
  if (card.error) return <main><p role="status">{card.error}</p></main>;
  if (hidden) return <main><p role="status">Hidden. Ask your assistant for a new link to see your card again.</p></main>;
  const rows = [['Card number', card.number], ['Valid until', card.expiry], ['Security code', card.cvv], ['Name on card', card.holder]].filter(([, value]) => value);
  return (
    <main>
      <dl>{rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd style={{ overflowWrap: 'anywhere' }}>{value}{' '}
        <button type="button" className="secondary" onClick={() => navigator.clipboard?.writeText(value)}>Copy</button></dd></div>)}</dl>
      <p role="status">Hidden again in 60 seconds. Keep these numbers private.</p>
      <button type="button" onClick={() => setHidden(true)}>Hide now</button>
    </main>
  );
}

class BridgeErrorBoundary extends React.Component {
  state = { failed: false, recovering: false };

  static getDerivedStateFromError() { return { failed: true }; }

  retry = () => {
    const params = readBridgeParams(window.location.href);
    if (connectionAttempt(params, "retry")) window.location.reload();
    else this.setState({ recovering: true });
  };

  render() {
    if (this.state.failed) return (
      <main>
        <p role="status">{this.state.recovering ? "This wallet cannot be recovered here yet." : "Couldn't connect."}</p>
        {!this.state.recovering && <button type="button" onClick={this.retry}>Check again</button>}
      </main>
    );
    return this.props.children;
  }
}

const root = document.getElementById("root");
if (!config.appId) {
  createRoot(root).render(<main><p>Connection unavailable.</p></main>);
} else {
  createRoot(root).render(
    <BridgeErrorBoundary>
    <PrivyProvider
      appId={config.appId}
      clientId={config.clientId || undefined}
      config={{
        embeddedWallets: { ethereum: { createOnLogin: "all-users" } },
        loginMethods: ["email", "wallet"],
        appearance: { theme: "light", accentColor: "#3258d8", showWalletLoginFirst: false },
      }}
    >
      <Bridge />
    </PrivyProvider>
    </BridgeErrorBoundary>,
  );
}
