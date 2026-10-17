

// Instructions for ONE split server, short on purpose: every line is read on every turn, and the
// weak-model bench (2026-10-17) showed longer text = more thinking tokens, not more correct calls.
// instructions(toolNames) names only this server's tools and where the others live.
const ALWAYS_TOOLS = ["wallet", "account", "bank"];
const HOME = { wallet: "wallet.paymentrequired.com/mcp", account: "banking.paymentrequired.com/mcp", bank: "banking.paymentrequired.com/mcp" };

const WHICH = {
  wallet: "- wallet: the agent's own USDC (not the person's bank). balance, fund, pay (paid API), send (USDC to 0x), discover (find paid APIs first), history, bridge.",
  bank: "- bank: the person's card and account. card, iban (IBAN + balance), send, swap (10 or more), transactions, manage (op: freeze, unfreeze, activate, set-limit, add-payout-card, payout-cards, 3ds_status, …).",
  account: "- account: connect (status), identity check (verify), spending limits (limits).",
};

// Ask → call. Only the shapes small models got wrong in the bench.
const EXAMPLES = [
  [["bank"], "money? → bank iban. Say holdings (\"19.59 euros\"); balance_value is the same money, not extra."],
  [["bank"], "dad's card → manage add-payout-card (card_number, cardholder_name, card_label, request_id) → tap → send card_id=recipient_id"],
  [["bank"], "my new card → manage activate (card_number_last4, expiry_date as printed)"],
  [["bank"], "card limit → manage set-limit, limits {daily_limit: 500}"],
  [["bank"], "card check / 3-D Secure → manage 3ds_status"],
  [["account"], "agent limits → account limits"],
  [["wallet"], "agent wallet → wallet balance (session)"],
];

export function instructions(toolNames = ALWAYS_TOOLS) {
  const names = toolNames.filter(name => name !== "connect_wallet");
  const here = new Set(names);
  const away = ALWAYS_TOOLS.filter(name => !here.has(name));
  const other = [...new Set(away.map(name => HOME[name]))].map(url => `${away.filter(name => HOME[name] === url).join(", ")}: https://${url}`);
  const connect = here.has("account") ? "only if you hold no session: account status → show link → after tap, the same call with its request_id gives the session." : "only if you hold no session: wallet balance new:true.";
  return `Tools here: ${names.join(", ")}.${other.length ? ` Elsewhere (separate MCP server, same session): ${other.join("; ")}.` : ""}
${names.map(name => WHICH[name]).filter(Boolean).join("\n")}

RULES
1. Hold a session: send it on every call and go straight to the tool. Connect ${connect}
2. approval_url in an answer: show it, wait for "done", then repeat the SAME call with the SAME request_id. A NEW link can follow: show it.
3. Do what next says. Failed: say the error as written, don't guess a cause.
4. Never invent card numbers, IBANs, names or ids: ask.
5. Money moves need request_id: any short label, reused after the tap.

EXAMPLES
${EXAMPLES.filter(([need]) => need.every(name => here.has(name))).map(([, text]) => `- ${text}`).join("\n")}

Reply short, in the person's language, one link per message.`;
}

export const INSTRUCTIONS_TEXT = instructions();
