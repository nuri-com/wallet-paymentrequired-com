// IDENTITY HANDOFF (C0 §3): a person's private pass minted by one service (legacy, wallet or
// banking) works on the other services without a new tap and without any shared DB.
//
//   recipient: no local row for the pass id -> asks each peer's private helper { op: "identity" }
//   owner:     authorizes the pass against ITS OWN hashed row (src/mcp-session.mjs authorizeSession)
//              and answers only public, already-signed facts (consent text, root address, signature)
//   recipient: re-verifies the root signature itself, pins the same id / root / app / partner /
//              expiry, stores sha256(pass) it computed from the pass it holds, persists the row.
//
// Never crosses: the pass hash, Privy access token, Wirex token or seal, agent key box, walletId.
// A handed-off row is never re-exported (no laundering chain); a peer that is down answers nothing,
// so the caller gets the normal connect link, never a new unverified owner.
import { createHash } from "node:crypto";
import { verifyMessage } from "ethers";
import { SESSION_PATTERN } from "./mcp-session.mjs";

const PASS = new RegExp(SESSION_PATTERN);
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const RESULT_FIELDS = ["signer_adapter", "address", "message", "signature", "signer", "public_key", "bitcoin_public_key",
  "signature_matches_address", "consent_message", "consent_signature", "consent_signature_matches_address",
  "provider_wallet_id", "provider_user_id", "root_address"];

const pick = (source, names) => Object.fromEntries(names.filter((name) => source?.[name] === null
  || ["string", "number", "boolean"].includes(typeof source?.[name])).map((name) => [name, source[name]]));

// Owner side. accountFlow.authorized = the owner's own row + timing-safe hashed pass check.
export function qualifiedIdentity(accountFlow, credential) {
  const session = accountFlow.authorized(credential, { signingGrant: false });
  if (session.context?.qualifiedFrom) throw new Error("identity_unknown");
  const context = pick(session.context, ["kind", "signer", "partner", "connectedAt"]);
  if (session.context?.accountReady) context.accountReady = pick(session.context.accountReady, ["account_exists", "smart_account_address", "deployment_tx_hash"]);
  return {
    session_id: credential.split(".")[0], expires_at: session.expiresAt, sign_text: session.signText,
    privy_app_id: session.privyAppId ?? null, partner: session.partner ?? "nuri",
    approval_url: session.approvalUrl ?? session.context?.approvalUrl ?? null, lineage: session.lineage ?? null,
    result: pick(session.result, RESULT_FIELDS), context,
  };
}

// Recipient side: the answer must prove itself (same id, live, root signature over the consent text).
export function verifiedIdentity(answer, id, now = Date.now()) {
  const result = answer?.result, text = answer?.sign_text;
  if (!answer || answer.session_id !== id || !Number.isSafeInteger(answer.expires_at) || answer.expires_at <= now) return null;
  if (typeof text !== "string" || !text.trim() || result?.message !== text || result?.signer_adapter !== "privy") return null;
  if (!ADDRESS.test(String(result.address)) || String(result.signer).toLowerCase() !== String(result.address).toLowerCase()) return null;
  if (answer.context?.kind !== "mcp_connection" || answer.context?.signer !== "privy") return null;
  if (answer.privy_app_id !== null && typeof answer.privy_app_id !== "string") return null;
  try { if (verifyMessage(text, result.signature).toLowerCase() !== result.address.toLowerCase()) return null; } catch { return null; }
  return answer;
}

export function createIdentityHandoff({ bridge, peers = [] } = {}) {
  const live = peers.filter((peer) => peer?.client);
  const inFlight = new Map();
  async function ensure(credential, { signal } = {}) {
    if (!live.length || typeof credential !== "string" || !PASS.test(credential)) return false;
    const [id, secret] = credential.split(".");
    try { bridge.requireSession(id); return false; } catch (error) { if (String(error?.message) !== "session_not_found") return false; }
    if (inFlight.has(id)) return inFlight.get(id);
    const run = (async () => {
      for (const peer of live) {
        let answer;
        try { answer = await peer.client.call({ op: "identity", session: credential }, { signal }); } catch { continue; }
        const record = verifiedIdentity(answer, id);
        if (!record) continue;
        bridge.importQualifiedSession(id, { ...record, secretSha256: createHash("sha256").update(secret).digest("hex"), qualifiedFrom: peer.name });
        return true;
      }
      return false;
    })();
    inFlight.set(id, run);
    try { return await run; } finally { inFlight.delete(id); }
  }
  // The pin a fresh grant for a handed-off row must carry: the same verified root and partner.
  function pinOf(credential) {
    if (typeof credential !== "string" || !PASS.test(credential)) return null;
    try {
      const session = bridge.requireSession(credential.split(".")[0]);
      return session.context?.qualifiedFrom && ADDRESS.test(String(session.result?.address))
        ? { expectedAddress: session.result.address, partner: session.context.partner === "wirex" ? "wirex" : "nuri" } : null;
    } catch { return null; }
  }
  return { ensure, pinOf };
}
