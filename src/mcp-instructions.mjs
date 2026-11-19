

// Instructions for ONE split server, short on purpose: every line is read on every turn, and the
// weak-model bench showed shorter, clearer instructions beat long docs — especially inside 64k local models.
// instructions(toolNames) names only this server's tools plus a compact directory of companion MCP servers.
const ALWAYS_TOOLS = ["wallet", "account", "bank"];
const HOME = { wallet: "wallet.paymentrequired.com/mcp", account: "banking.paymentrequired.com/mcp", bank: "banking.paymentrequired.com/mcp" };

const WHICH = {
  wallet: "- wallet: the agent's own Base USDC + Bitcoin Lightning/Arkade/on-chain wallet (4 actions: balance, receive, pay, history). Cross-rail USDC <-> Bitcoin/Lightning converts automatically.",
  bank: "- bank: the person's card and account. card, iban (IBAN + balance), send, swap (10 or more), transactions, manage (op: freeze, unfreeze, activate, set-limit, add-payout-card, payout-cards, 3ds_status, …).",
  account: "- account: connect (status), identity check (verify), agent spending limits (limits). Never for money or cards.",
};

// Ask → call. Only the shapes small models got wrong in the bench.
const EXAMPLES = [
  [["bank"], "money? → bank iban. Say holdings (\"19.59 euros\"); balance_value is the same money, not extra."],
  [["bank"], "dad's card → manage add-payout-card (card_number, cardholder_name, card_label, request_id) → tap → send card_id=recipient_id"],
  [["bank"], "my new card → manage activate (card_number_last4, expiry_date as printed)"],
  [["bank"], "card limit → manage set-limit, limits {daily_limit: 500}"],
  [["bank"], "card check / 3-D Secure → manage 3ds_status"],
  [["account"], "agent limits → account limits"],
  [["wallet"], "setup / balance → wallet {action: \"balance\"} (no wallet_key starts create/connect; with wallet_key shows USDC + sats)"],
  [["wallet"], "receive → wallet {action: \"receive\", wallet_key, rail: \"lightning\"|\"usdc\"|\"arkade\", amount_sats?}"],
  [["wallet"], "pay 402 API → wallet {action: \"pay\", wallet_key, to: \"https://...\", max_amount?/max_sats?, dry_run?, request_id}. Over-cap: retry with a NEW request_id and a higher max_amount."],
  [["wallet"], "pay invoice / address → wallet {action: \"pay\", wallet_key, to: \"lnbc...\"|\"user@domain\"|\"bc1...\"|\"ark1...\"|\"0x...\", amount?/amount_sats?, request_id} (0x... = USDC in amount; bc1... = BTC directly in amount e.g. \"0.00025\" or amount_sats; user@domain/ark1... = amount_sats)."],
];

const COMPANION_DIRECTORY = [
  "- SwapKit (https://swapkit.nuri.com/mcp): swap or pay Monero XMR, ETH, SOL, EURC, etc.",
  "- Banking (https://banking.paymentrequired.com/mcp): euro IBAN, debit card, SEPA, limits (account, bank).",
  "- Browser / checkout: for web stores, use a browser tool to get the BOLT11 or bc1.../bitcoin: address, then pay with wallet pay.",
];

export function instructions(toolNames = ALWAYS_TOOLS) {
  const names = toolNames.filter(name => name !== "connect_wallet");
  const here = new Set(names);

  // Dedicated wallet-only server: keep rules 100% focused on wallet_key + Passkey create/connect + companion directory.
  if (here.size === 1 && here.has("wallet")) {
    return `Tool here: wallet.
${WHICH.wallet}

RULES
1. No wallet_key yet: call wallet {action: "balance"}. Show BOTH create_url (new to Nuri) and approval_url (existing Passkey). After approval, repeat wallet {action: "balance", request_id} to get your deterministic wallet_key (npw1_...).
2. Hold a wallet_key: send it on every call (balance, receive, pay, history).
3. wallet pay accepts ANY destination in \`to\`: https:// 402 API (x402/L402/MPP), lnbc... BOLT11, user@domain, bc1.../bitcoin:... on-chain Bitcoin, ark1... Arkade, or 0x... Base USDC. Always include a short request_id.
4. Over-cap error: STOP and tell the person the exact price; NEVER raise max_amount/max_sats without asking them first. Once they approve, send again with a NEW request_id and a higher max_amount. Other failures: report the exact error. Do what next says.

EXAMPLES
${EXAMPLES.filter(([need]) => need.every(name => here.has(name))).map(([, text]) => `- ${text}`).join("\n")}

COMPANION TOOLS (separate MCPs — NEVER pass companion MCP URLs like swapkit.nuri.com/mcp or XMR addresses into wallet pay; reply with the companion URL)
${COMPANION_DIRECTORY.join("\n")}

Reply short, in the person's language.`;
  }

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
