// SIGNER CLIENT
//
// One signer, one route: the Privy login (the owner's EOA signature) taken in
// the browser through the local bridge. There is no second adapter and no
// remote signer service — the tool signs with the wallet the person logged in
// with, and nothing else.
//
// This module is the thin seam every MCP tool talks to: it exposes the same
// method surface the bridge does, so a tool never has to know whether it holds
// the bridge itself or an adapter around it.

import { MAX_TIMEOUT_MS, connectionTtlMs } from "./browser-bridge.mjs";
import { createPrivyUserWalletAccount, discoverPrivyAgentWallet, privyAgentAssignments } from "./privy-wallet-signer.mjs";


export { MAX_TIMEOUT_MS, connectionTtlMs };


// Re-exported so the MCP tools take their Privy helpers from one place.
export { createPrivyUserWalletAccount, discoverPrivyAgentWallet, privyAgentAssignments };


// The minimum a signer must offer to serve a tool call.
export const SIGNER_METHODS = Object.freeze(["createSession", "requireSession", "approved", "readStatus", "sign"]);


// Everything the server and the MCP tools call on the signer client.
export const SIGNER_CLIENT_METHODS = Object.freeze([
  ...SIGNER_METHODS,
  "getExtra",
  "setExtra",
  "readApprovalPayload",
  "prepareApproval",
  "newestPendingApproval",
  "prepare",
  "complete",
  // Session rows survive a restart, so an approval link a person already holds
  // keeps working: these two keep the stored row in step.
  "persistSession",
  "extendSessionExpiry",
]);


// The adapter around the in-process browser bridge: the only signing route.
export function createLocalSignerAdapter({ bridge, connectionSigner } = {}) {
  if (!bridge || typeof bridge.createSession !== "function") throw new Error("signer_bridge_required");
  if (!connectionSigner || typeof connectionSigner.sign !== "function") throw new Error("signer_connection_signer_required");
  return {
    createSession: (options) => bridge.createSession(options),
    requireSession: (sessionId) => bridge.requireSession(sessionId),
    approved: (sessionId) => bridge.approved(sessionId),
    readStatus: (sessionId) => bridge.readStatus(sessionId),
    readApprovalPayload: (sessionId, state) => bridge.readApprovalPayload(sessionId, state),
    prepareApproval: (sessionId, state) => bridge.prepareApproval(sessionId, state),
    // One person, one open link: the newest pending approval of a lineage.
    newestPendingApproval: (lineage) => bridge.newestPendingApproval(lineage),
    getExtra: (sessionId) => bridge.getExtra(sessionId),
    setExtra: (sessionId, extra) => bridge.setExtra(sessionId, extra),
    prepare: (session) => connectionSigner.prepare(session),
    complete: (session, input) => connectionSigner.complete(session, input),
    sign: (session, message) => connectionSigner.sign(session, message),
    persistSession: (sessionId) => bridge.persistSession(sessionId),
    extendSessionExpiry: (sessionId, expiresAt) => bridge.extendSessionExpiry(sessionId, expiresAt),

    get publicOrigin() { return bridge.publicOrigin; },
    get publicBase() { return bridge.publicBase; },
  };
}


// The signer this deployment uses: always the local Privy route.
export function createSignerClient({ bridge, connectionSigner } = {}) {
  const local = createLocalSignerAdapter({ bridge, connectionSigner });
  local.defaultSigner = "privy";
  return local;
}


export function validateEthereumAddress(value, name) {
  const address = String(value ?? "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`${name}_must_be_evm_address`);
  return address;
}
