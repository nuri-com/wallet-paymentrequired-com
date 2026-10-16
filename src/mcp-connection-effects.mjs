// Product side effects of an approved connect tap (D-SIGNER-SEAM-1A). The bridge
// (src/browser-bridge.mjs acceptCallback) runs them in this order:
//   prePersist  -> TTL + persistSession -> postPersist -> zeroize/status/result -> detached.
// Every hook sees { sessionId, session, payload, result, wirexLogin } and only acts on
// `mcp_connection` sessions; a bridge built without effects runs none of them.
import { verifyMessage } from "ethers";
import { deriveAgentSignerFromSignature } from "./agent-signer-derivation.mjs";
import { sealWithPass } from "./mcp-session.mjs";
import { wirexLoginMessage, WIREX_LOGIN_NONCE_WINDOW_S } from "./wirex-public.mjs";

export function createConnectionEffects({ onConnected = null, recordConnected = null } = {}) {
  return {
    // Before the persist, so what is captured here survives a restart.
    prePersist({ sessionId, session, payload, result }) {
      if (session.context.kind !== "mcp_connection") return;
      if (session.signerAdapter === "privy" && payload.privyAccessToken !== undefined) {
        const accessToken = requiredString(payload.privyAccessToken, "privy_access_token");
        if (accessToken.length > 16384) throw new Error("Invalid signing authorization.");
        session.context.privy = { accessToken };
      }
      // LLM key after connect (D-CUSTODY-V2, owner 2026-09-25): the server keeps NO copy of the
      // EOA-derived key. Every connect tap seals the derived key under this session's pass (only
      // the caller's pass opens it), so `wallet balance` with the session can hand a lost key back.
      const agentSignature = agentSignatureOf(session, payload);
      if (agentSignature && session.context.secret) {
        try {
          const { scalar } = deriveAgentSignerFromSignature(result.signer, agentSignature);
          try { session.context.agentKeyBox = sealWithPass(sessionId, session.context.secret, scalar.toString("base64url")); } finally { scalar.fill(0); }
        } catch { /* a bad signature seals nothing; the connection itself stands */ }
      }
    },
    // Same tap, one more signature (#150): the Wirex login message. Verified here, exchanged
    // for a user token by the MCP process (src/mcp-connection.mjs). Optional like the agent
    // signer: a bad or missing signature never fails the connection.
    postPersist({ session, payload, result, wirexLogin }) {
      if (session.context.kind !== "mcp_connection" || !wirexLogin || payload.wirexLoginSignature === undefined) return;
      const login = verifiedWirexLogin(payload, result.signer, wirexLogin);
      if (login) session.context.wirexLogin = login;
    },
    // Broker adoption waits for the local owner/box transaction, never the provider hand-over.
    recordBroker({ session, payload, result, signal, deadline }) {
      if (typeof recordConnected !== "function") throw new Error("guest_tap_recorder_required");
      recordConnected({ ...session, result }, agentSignatureOf(session, payload), { signal, deadline });
    },
    // The service runs the guest-wallet hand-over itself, in the background (D-QUORUM A); a
    // failure is retried by the next wallet call.
    detached({ sessionId, session, payload }) {
      if (session.context.kind !== "mcp_connection" || !session.context.walletId || typeof onConnected !== "function") return;
      const agentSignature = agentSignatureOf(session, payload);
      Promise.resolve().then(() => onConnected(session, agentSignature, sessionId)).catch(() => {});
    },
  };
}

function agentSignatureOf(session, payload) {
  return session.context.kind === "mcp_connection" && typeof payload.agentSignerSignature === "string" ? payload.agentSignerSignature : undefined;
}

function verifiedWirexLogin(payload, owner, { company_id, chain_id }) {
  const signature = payload.wirexLoginSignature;
  const nonce = payload.wirexLoginNonce;
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) return null;
  if (!Number.isSafeInteger(nonce) || Math.abs(Math.floor(Date.now() / 1000) - nonce) > WIREX_LOGIN_NONCE_WINDOW_S) return null;
  try {
    const message = wirexLoginMessage({ owner, companyId: company_id, chainId: chain_id, nonce });
    if (verifyMessage(message, signature).toLowerCase() !== owner.toLowerCase()) return null;
  } catch { return null; }
  return { signature, nonce };
}

function requiredString(value, name) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name}_is_required`);
  return value.trim();
}
