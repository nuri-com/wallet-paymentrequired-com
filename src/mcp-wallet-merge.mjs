// One wallet per person (owner 2026-09-28): the person's NEWEST usable wallet is THE wallet ("die
// neueste immer nehmen"). Called by `wallet balance` with the person's session: this chat's temporary
// guest wallet sends its USDC on Base to the newest one with its own guest key (no tap). Older
// connected wallets are swept by the agent key (src/mcp-agent-wallet.mjs newest()). Nothing of this
// reaches the model or the person: no link, no sentence (owner: "die Komplexität bleibt im MCP").
// Returns null (answer for this wallet) or { first } (answer for the newest one instead).
// ponytail: only USDC on Base moves; a Gateway balance stays where it is (rare, still the person's).
import { logEvent } from "./log.mjs";

export async function mergeIntoFirst({ agentWallet, opRequestId, unitsToDecimal }, args, wallet, { signal } = {}) {
  if (typeof args.session !== "string" || !args.session) return null;
  const listed = await agentWallet().call({ action: "list", session: args.session }, { signal }).catch(() => null);
  const first = (listed?.ok ? listed.wallets ?? [] : []).findLast(w => w.usable !== false); // newest usable (list is oldest first)
  if (!first?.wallet_id) return null; // no wallet yet: this chat's wallet becomes the person's (today's hand-over)
  if (wallet.id === first.wallet_id) return null;
  if (!wallet.claimed && typeof wallet.token === "string") {
    // A balance that cannot be read is not an empty wallet (live 2026-09-28: two wallets were skipped as "0").
    const state = await agentWallet().call({ action: "status", wallet_id: wallet.id, wallet_key: wallet.token }, { signal }).catch(() => null);
    const units = state?.operation?.balance_units;
    if (typeof units !== "string" || !/^\d+$/.test(units)) logEvent("warn", "wallet_merge_unreadable", { status: state?.operation?.status ?? state?.status ?? null, error: state?.error ?? null });
    else if (BigInt(units) > 0n) {
      const amount = unitsToDecimal(units, 6);
      // The label carries the amount: a repeat continues the same send, never a second one.
      const result = await agentWallet().call({ action: "send", wallet_id: wallet.id, wallet_key: wallet.token, request_id: opRequestId(wallet.id, `merge-into-${first.wallet_id}-${units}`), to: first.address, amount }, { signal }).catch(() => null);
      const status = result?.operation?.status;
      logEvent(status === "sent" ? "info" : "warn", status === "sent" ? "wallet_merge_moved" : "wallet_merge_open", { amount, status: status ?? null, reason: result?.operation?.reason ?? result?.error ?? null });
    }
  }
  return { first: { id: first.wallet_id, address: first.address, claimed: true, owner: first.owner_address, session: args.session, token: undefined, created: false } };
}

// Ask before a wallet exists (owner 2026-09-28): a bare `wallet balance` (no wallet_key, no session)
// no longer mints a guest wallet for every "hi" — it answers the plain connect link. A new wallet
// comes only with new: true; a person who already has one keeps their first (resolveWallet).
// No link in this answer (owner 2026-09-28): with a link in it, models just showed the link and never asked.
export async function askFirst() {
  return { ok: true, status: "done", next: "Have a session? Resend with it. Else ask: new or existing?" };
}

// A wallet_key from an older chat can open a wallet that is not the person's first one. With the
// person's session every money call uses the newest wallet only; `wallet balance` hands out its key.
export async function notYourWallet(agentWallet, args, keyed, { signal } = {}) {
  if (args.action === "balance" || typeof args.session !== "string" || !args.session) return false;
  const listed = await agentWallet().call({ action: "list", session: args.session }, { signal }).catch(() => null);
  const first = (listed?.ok ? listed.wallets ?? [] : []).findLast(w => w.usable !== false);
  return Boolean(first?.wallet_id) && first.wallet_id !== keyed?.wallet_id;
}
