// Role homepages for the split origins (wallet., banking., signer.paymentrequired.com).
// Static HTML, no script, no state: name, purpose, links. The apex keeps public/index.html;
// each owner serves its own public /mcp (approved-scope.md: apex /mcp no longer serves tools).
const APEX = "https://paymentrequired.com";
const ROLES = {
  wallet: {
    title: "Wallet for AI agents",
    purpose: "This is the wallet service of paymentrequired.com. It runs the <code>wallet</code> tool: balance, fund, pay, send, history, bridge and discover. The agent Safe pays x402 services from here; you connect it with one Privy sign-in through the link your agent gives you.",
    here: "This origin serves the approval pages your agent links you to (<code>/bridge/privy</code>) and short links (<code>/s</code>). There is nothing to click here without such a link.",
  },
  banking: {
    title: "Card and euro account for AI agents",
    purpose: "This is the banking service of paymentrequired.com. It runs the <code>account</code> tool (status, verify, limits) and the <code>bank</code> tool (card, iban, send, swap, transactions, manage) on the Wirex account that holds your Visa card and euro IBAN.",
    here: "This origin serves the approval pages your agent links you to (<code>/bridge/privy</code>, <code>/bridge/privy/wirex</code>) and short links (<code>/s</code>). There is nothing to click here without such a link.",
  },
  signer: {
    title: "Root signer for AI agents",
    purpose: "This is the root signer of paymentrequired.com. It shows you exactly what your agent asks you to approve and lets you sign it with your Privy root account. It holds no keys and no money.",
    here: "An approval page opens only from a link your agent issued (<code>/bridge/privy?request_id=…&amp;state=…</code>). Without that link there is nothing to sign here.",
  },
};

export function serviceIndexHtml(role) {
  const r = ROLES[role];
  if (!r) throw new Error(`service_index_role_unknown: ${role}`);
  const others = Object.keys(ROLES).filter((name) => name !== role)
    .map((name) => `<a href="https://${name}.paymentrequired.com/">${name}.paymentrequired.com</a>`).join(" · ");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${role}.paymentrequired.com — ${r.title}</title>
<link rel="icon" href="data:,">
<style>
html,body{margin:0;padding:0;background:#fdf6e3;color:#073642}
body{font:17px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;overflow-x:hidden}
main{max-width:680px;margin:0 auto;padding:2.5rem 1.25rem 4rem}
h1{font-size:34px;line-height:1.15;color:#002b36;margin:0 0 1.25rem}
p{margin:0 0 1rem}
code{font:17px/1.6 ui-monospace,Menlo,Monaco,Consolas,monospace;overflow-wrap:anywhere}
a{color:#1f6fb2;text-decoration:none}
a:hover{text-decoration:underline}
</style>
</head>
<body>
<main>
<p><a href="${APEX}/">paymentrequired.com</a> · ${role}</p>
<h1>${r.title}</h1>
<p>${r.purpose}</p>
<p>${r.here}</p>
${role === "signer" ? "" : `<p>MCP endpoint for agents: <code>https://${role}.paymentrequired.com/mcp</code></p>\n`}
<p>Docs: <a href="${APEX}/docs">docs</a> · <a href="${APEX}/llms.txt">llms.txt</a> · <a href="${APEX}/llms-full.txt">llms-full.txt</a></p>
<p>Other services: ${others}</p>
</main>
</body>
</html>
`;
}
