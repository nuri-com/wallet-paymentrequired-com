// Role homepages and host-aware agent discovery docs (/llms.txt, /skill.md)
// for wallet origins (wallet.paymentrequired.com, wallet.nuri.com, nuriwallet.com)
// plus legacy role homepages (banking, signer).
const APEX = "https://paymentrequired.com";
const DEFAULT_WALLET_HOST = "wallet.paymentrequired.com";
export const WALLET_HOSTS = Object.freeze([
  "wallet.paymentrequired.com",
  "wallet.nuri.com",
  "nuriwallet.com",
]);
const ALLOWED_WALLET_HOSTS = new Set(WALLET_HOSTS);

export function resolveWalletOrigin(reqOrHost) {
  let raw = "";
  if (typeof reqOrHost === "string") {
    raw = reqOrHost;
  } else if (reqOrHost && typeof reqOrHost === "object") {
    const headers = reqOrHost.headers || reqOrHost;
    raw = String(headers["x-forwarded-host"] || headers.host || "");
  }
  const first = raw.split(",")[0].trim().toLowerCase().replace(/:\d+$/, "");
  const host = ALLOWED_WALLET_HOSTS.has(first) ? first : DEFAULT_WALLET_HOST;
  return `https://${host}`;
}

function walletOriginInfo(origin) {
  const safe = resolveWalletOrigin(
    typeof origin === "string" ? origin.replace(/^https?:\/\//i, "").replace(/\/.*$/, "") : "",
  );
  return { origin: safe, host: new URL(safe).host };
}

export function walletLlmsTxt(origin) {
  const { origin: base, host } = walletOriginInfo(origin);
  return `# Agent Wallet (${host})

Non-custodial AI agent wallet for Base USDC (x402, EVM MPP) and Bitcoin Lightning/Arkade/on-chain \`bc1...\` (L402, Lightning MPP, BOLT11, \`user@domain\`). Auto cross-rail USDC <-> BTC/Lightning. Backed by Nuri Passkey PRF (Touch ID / Face ID / smartcard).

## Path A — You have MCP
1. Connect MCP endpoint (Streamable HTTP): \`${base}/mcp\`
2. Call \`wallet { "action": "balance" }\` (no \`wallet_key\` yet).
3. Show the person BOTH \`create_url\` (new Nuri Passkey) and \`approval_url\` (existing Passkey).
4. Once they say "done", repeat \`wallet { "action": "balance", "request_id": "<same>" }\` to get deterministic \`wallet_key\` (\`npw1_...\`), then pass \`wallet_key\` on every call.
- NEVER send the person to \`${base}/\` when you have MCP.

## Path B — No MCP connector yet (e.g. web ChatGPT)
Tell the person EITHER:
- (a) Add \`${base}/mcp\` as an MCP connector in their client, OR
- (b) Open \`${base}/\` and click **"Create / Connect Agent Wallet"** (1-click Nuri Passkey flow right in the browser with addresses, Lightning funding invoice, and setup prompt).

## Tool: \`wallet\` (4 actions: \`balance\`, \`receive\`, \`pay\`, \`history\`)
- Balance: \`wallet { "action": "balance", "wallet_key": "npw1_..." }\`
- Receive: \`wallet { "action": "receive", "wallet_key": "npw1_...", "rail": "lightning"|"usdc"|"arkade", "amount_sats": 1000 }\`
- Pay 402 API: \`wallet { "action": "pay", "wallet_key": "npw1_...", "to": "https://...", "max_amount": "0.25", "request_id": "p1" }\`
- Pay invoice/address: \`wallet { "action": "pay", "wallet_key": "npw1_...", "to": "lnbc..."|"user@domain"|"bc1..."|"bitcoin:..."|"ark1..."|"0x...", "amount": "0.00025", "request_id": "p2" }\`
  - \`0x...\`: USDC in \`amount\`. \`bc1...\`/\`bitcoin:...\`: pass BTC decimal directly in \`amount\` (e.g. \`"0.00025"\` — never convert BTC to sats in your head) or \`amount_sats\`. \`user@domain\`/\`ark1...\`: \`amount_sats\`.
  - Over-cap error: STOP and ask the person first; if approved, retry with a NEW \`request_id\` and higher \`max_amount\`/\`max_sats\`.
- History: \`wallet { "action": "history", "wallet_key": "npw1_..." }\`

## Companion x402 / MCP Services
- Agent email (\`0.01 USDC\` x402 via \`wallet pay\`): \`https://mail.paymentrequired.com/v1/create_inbox\`
- Paid Chromium browser (\`0.01 USDC\` x402 via \`wallet pay\`): \`https://browser.paymentrequired.com/v1/browser/open\`
- Encrypted agent vault: \`https://vault.paymentrequired.com\`
- Monero XMR / SOL / ETH swaps (separate MCP): \`https://swapkit.nuri.com/mcp\`
- Euro IBAN & debit card (separate MCP): \`https://banking.paymentrequired.com/mcp\`
- NEVER pass Monero/XMR addresses or companion MCP URLs (\`swapkit.nuri.com/mcp\`, \`banking.paymentrequired.com/mcp\`) into \`wallet pay\`.
`;
}

export function walletSkillMd(origin) {
  const { origin: base } = walletOriginInfo(origin);
  return `---
name: agent-wallet
description: Non-custodial AI agent wallet for Base USDC (x402, EVM MPP) and Bitcoin Lightning/Arkade/on-chain BTC (L402, Lightning MPP, BOLT11, user@domain) backed by Nuri Passkey PRF.
mcp_endpoint: ${base}/mcp
---

${walletLlmsTxt(base)}`;
}

function walletIndexHtml(origin) {
  const { origin: base, host } = walletOriginInfo(origin);
  const mcpUrl = `${base}/mcp`;
  const llmsUrl = `${base}/llms.txt`;
  const skillUrl = `${base}/skill.md`;
  const agentPrompt = [
    `Connect the MCP server at ${mcpUrl} (instructions: ${llmsUrl}).`,
    "Use the wallet tool (balance, receive, pay, history) for Base USDC (x402, EVM MPP) and Bitcoin Lightning/Arkade/on-chain BTC (L402, Lightning MPP, BOLT11, user@domain).",
    'If no wallet_key is set yet, call wallet { "action": "balance" } and show me both create_url and approval_url.',
  ].join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${host} — Agent Wallet</title>
<link rel="icon" href="data:,">
<style>
:root{--bg:#f8fafc;--card:#ffffff;--ink:#0f172a;--muted:#475569;--line:#e2e8f0;--accent:#0f172a;--accent-hover:#1e293b;--blue:#1d4ed8;--blue-soft:#eff6ff;--warn-bg:#fffbeb;--warn-border:#fcd34d;--warn-ink:#92400e;--ok-bg:#f0fdf4;--ok-border:#86efac;--ok-ink:#166534;--err-bg:#fef2f2;--err-border:#fca5a5;--err-ink:#991b1b}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--ink)}
body{font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:760px;margin:0 auto;padding:2rem 1.25rem 4rem}
header{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:1.75rem}
.brand{font-weight:700;font-size:15px;color:var(--ink);text-decoration:none;letter-spacing:-.01em}
.nav{display:flex;gap:1rem;font-size:14px}
.nav a{color:var(--muted);text-decoration:none}
.nav a:hover{color:var(--ink);text-decoration:underline}
h1{font-size:clamp(28px,5vw,38px);line-height:1.12;letter-spacing:-.025em;margin:0 0 .75rem}
h2{font-size:19px;line-height:1.3;margin:0 0 .65rem;letter-spacing:-.01em}
h3{font-size:15px;line-height:1.35;margin:1.1rem 0 .4rem;color:var(--ink)}
p{margin:0 0 .85rem}
.lead{font-size:18px;color:var(--muted);margin:0 0 1.5rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.35rem 1.4rem;margin:0 0 1.25rem;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.row{display:flex;flex-wrap:wrap;gap:.65rem;align-items:center}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;font:inherit;font-size:15px;font-weight:600;padding:.65rem 1.05rem;border-radius:10px;border:1px solid transparent;cursor:pointer;text-decoration:none;transition:background .12s,border-color .12s}
.btn:disabled{opacity:.6;cursor:wait}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover:not(:disabled){background:var(--accent-hover)}
.btn-secondary{background:#fff;color:var(--ink);border-color:#cbd5e1}
.btn-secondary:hover:not(:disabled){background:#f1f5f9}
.btn-sm{font-size:13px;padding:.4rem .7rem;border-radius:8px}
.muted{color:var(--muted);font-size:14px}
.code-box{display:flex;align-items:center;justify-content:space-between;gap:.6rem;background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:.55rem .75rem;margin:.35rem 0 .75rem}
.code-box code{font:13.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;overflow-wrap:anywhere;word-break:break-all;flex:1}
code{font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;overflow-wrap:anywhere}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.85rem;margin:.75rem 0 1rem}
.stat{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:.85rem 1rem}
.stat-label{font-size:12.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:.25rem}
.stat-val{font-size:22px;font-weight:700;letter-spacing:-.02em}
.stat-sub{font-size:13px;color:var(--muted);margin-top:.15rem}
.banner{border-radius:10px;padding:.8rem .95rem;margin:.75rem 0;font-size:14px}
.banner-info{background:var(--blue-soft);border:1px solid #bfdbfe;color:#1e3a8a}
.banner-ok{background:var(--ok-bg);border:1px solid var(--ok-border);color:var(--ok-ink)}
.banner-warn{background:var(--warn-bg);border:1px solid var(--warn-border);color:var(--warn-ink)}
.banner-err{background:var(--err-bg);border:1px solid var(--err-border);color:var(--err-ink)}
.input-sats{font:inherit;font-size:15px;padding:.55rem .75rem;border:1px solid #cbd5e1;border-radius:10px;width:140px;background:#fff;color:var(--ink)}
ul{margin:.4rem 0 .6rem;padding-left:1.25rem}
li{margin:.35rem 0}
a{color:var(--blue)}
.hidden{display:none!important}
.sep{border:0;border-top:1px solid var(--line);margin:1.1rem 0}
.footer{font-size:13.5px;color:var(--muted);margin-top:1.5rem}
</style>
</head>
<body>
<main>
<header>
  <a class="brand" href="${base}/">${host}</a>
  <nav class="nav" aria-label="Agent docs">
    <a href="${llmsUrl}">llms.txt</a>
    <a href="${skillUrl}">skill.md</a>
    <a href="#for-agents">For AI Agents</a>
  </nav>
</header>

<h1>Agent Wallet</h1>
<p class="lead">Bitcoin Lightning + Base USDC wallet for AI agents. Non-custodial Nuri Passkey. Pays x402, L402, MPP, BOLT11, and on-chain BTC.</p>

<section class="card" id="setup-widget" aria-labelledby="setup-heading">
  <h2 id="setup-heading">Create / Connect Agent Wallet</h2>
  <p class="muted">Non-custodial Nuri Passkey PRF (Touch ID, Face ID, or smartcard). Set up or connect your wallet right here, fund it over Base USDC or Bitcoin Lightning, and hand the MCP URL to your AI agent.</p>

  <div id="error-box" class="banner banner-err hidden" role="alert"></div>

  <div id="view-idle">
    <div class="row" style="margin-top:.9rem">
      <button id="btn-create" type="button" class="btn btn-primary">Create New Passkey Wallet</button>
      <button id="btn-connect" type="button" class="btn btn-secondary">Connect Existing Nuri Passkey</button>
    </div>
    <p class="muted" style="margin:.75rem 0 0">Opens <code>connect.nuri.com</code> in a new tab and automatically detects approval here.</p>
  </div>

  <div id="view-pending" class="hidden">
    <div class="banner banner-info" id="pending-status" role="status">Waiting for Nuri Passkey approval… checking every 2.5s.</div>
    <div class="row">
      <a id="pending-open-link" class="btn btn-primary" href="#" target="_blank" rel="noopener noreferrer">Open Nuri Passkey &rarr;</a>
      <button id="btn-poll-now" type="button" class="btn btn-secondary">Check now</button>
      <button id="btn-cancel" type="button" class="btn btn-secondary">Start over</button>
    </div>
    <p class="muted" style="margin:.75rem 0 0">
      <span id="pending-alt-wrap" class="hidden">Wrong path? <a id="pending-alt-link" href="#" target="_blank" rel="noopener noreferrer"></a></span>
    </p>
  </div>

  <div id="view-connected" class="hidden">
    <div class="row" style="justify-content:space-between;margin-bottom:.75rem">
      <div class="banner banner-ok" style="margin:0;padding:.45rem .8rem;font-weight:600">Wallet connected</div>
      <div class="row">
        <button id="btn-refresh" type="button" class="btn btn-secondary btn-sm">Refresh Balance</button>
        <button id="btn-disconnect" type="button" class="btn btn-secondary btn-sm">Disconnect</button>
      </div>
    </div>

    <div class="grid2">
      <div class="stat">
        <div class="stat-label">Base USDC</div>
        <div class="stat-val" id="bal-usdc">0 USDC</div>
        <div class="stat-sub">Pays x402, EVM MPP, 0x… + auto-bridges to BTC/LN</div>
      </div>
      <div class="stat">
        <div class="stat-label">Bitcoin (Lightning / Arkade)</div>
        <div class="stat-val" id="bal-sats">0 sats</div>
        <div class="stat-sub" id="bal-btc">0 BTC · Pays L402, LN MPP, BOLT11, bc1…</div>
      </div>
    </div>

    <h3>Deposit Addresses</h3>
    <div class="muted">Base USDC (Base network)</div>
    <div class="code-box">
      <code id="addr-usdc">—</code>
      <button type="button" class="btn btn-secondary btn-sm" data-copy-el="addr-usdc">Copy</button>
    </div>
    <div id="ark-addr-wrap">
      <div class="muted">Arkade BTC</div>
      <div class="code-box">
        <code id="addr-arkade">—</code>
        <button type="button" class="btn btn-secondary btn-sm" data-copy-el="addr-arkade">Copy</button>
      </div>
    </div>

    <h3>Fund via Bitcoin Lightning</h3>
    <div class="row">
      <label for="ln-sats" class="muted" style="margin:0">Sats</label>
      <input id="ln-sats" class="input-sats" type="number" min="100" step="100" value="5000" inputmode="numeric">
      <button id="btn-ln-invoice" type="button" class="btn btn-primary btn-sm">Create Lightning Funding Invoice (sats)</button>
    </div>
    <div id="ln-invoice-box" class="hidden" style="margin-top:.75rem">
      <div class="muted" id="ln-invoice-meta"></div>
      <div class="code-box">
        <code id="ln-invoice-text"></code>
        <button type="button" class="btn btn-secondary btn-sm" data-copy-el="ln-invoice-text">Copy</button>
      </div>
      <div class="row">
        <a id="ln-wallet-uri" class="btn btn-secondary btn-sm hidden" href="#">Open in Lightning Wallet</a>
        <span id="ln-watch-status" class="muted"></span>
      </div>
    </div>

    <hr class="sep">

    <h3>Agent <code>wallet_key</code></h3>
    <div class="code-box">
      <code id="wallet-key-display">npw1_•••••••••••••••••••••••••••••••••••••••••••</code>
      <button id="btn-reveal-key" type="button" class="btn btn-secondary btn-sm">Reveal</button>
      <button id="btn-copy-key" type="button" class="btn btn-secondary btn-sm">Copy</button>
    </div>
    <div class="banner banner-warn" id="wallet-key-warn">
      <strong>Keep private:</strong> anyone with your <code>wallet_key</code> can spend within your Passkey policy limits. Only paste it into a trusted AI agent or MCP client.
    </div>

    <h3>Use With Your AI Agent</h3>
    <div class="row">
      <button type="button" class="btn btn-primary btn-sm" data-copy-text="mcp">Copy MCP URL</button>
      <button type="button" class="btn btn-secondary btn-sm" data-copy-text="prompt">Copy Agent Prompt</button>
    </div>
  </div>
</section>

<section class="card" id="for-agents" aria-labelledby="agents-heading">
  <h2 id="agents-heading">For AI Agents</h2>
  <p>MCP endpoint (Streamable HTTP):</p>
  <div class="code-box">
    <code id="mcp-endpoint-code">${mcpUrl}</code>
    <button type="button" class="btn btn-secondary btn-sm" data-copy-text="mcp">Copy MCP URL</button>
    <button type="button" class="btn btn-secondary btn-sm" data-copy-text="prompt">Copy Agent Prompt</button>
  </div>
  <p class="muted">Agent instructions: <a href="${llmsUrl}">${llmsUrl}</a> · <a href="${skillUrl}">${skillUrl}</a></p>
  <ul>
    <li><strong>If you have MCP:</strong> connect <code>${mcpUrl}</code> and call <code>wallet { "action": "balance" }</code> directly. Show the user both <code>create_url</code> (new Passkey) and <code>approval_url</code> (existing Passkey), then repeat with the same <code>request_id</code> after approval. Never send the user to <code>${base}/</code> when you have MCP.</li>
    <li><strong>If you do not have an MCP connector yet (e.g. web ChatGPT):</strong> tell the user to either add <code>${mcpUrl}</code> as an MCP connector in their client, or open <code>${base}/</code> and click <strong>Create / Connect Agent Wallet</strong> above.</li>
    <li><strong>4 actions:</strong> <code>balance</code>, <code>receive</code> (<code>lightning</code>, <code>usdc</code>, <code>arkade</code>), <code>pay</code> (any <code>https://</code> 402 API, <code>lnbc…</code>, <code>user@domain</code>, <code>bc1…</code>/<code>bitcoin:…</code>, <code>ark1…</code>, <code>0x…</code> with automatic cross-rail USDC &harr; BTC/Lightning), and <code>history</code>.</li>
    <li><strong>Companion services:</strong> <a href="https://mail.paymentrequired.com">mail.paymentrequired.com</a> (x402 agent email), <a href="https://browser.paymentrequired.com">browser.paymentrequired.com</a> (x402 Chromium browser), <a href="https://vault.paymentrequired.com">vault.paymentrequired.com</a> (agent vault), <code>https://swapkit.nuri.com/mcp</code> (separate MCP for Monero XMR / SOL / ETH), and <code>https://banking.paymentrequired.com/mcp</code> (separate MCP for euro IBAN &amp; debit card).</li>
  </ul>
</section>

<p class="footer">Non-custodial Nuri Passkey PRF + 2-of-4 Base Safe USDC + 2-of-2 Arkade Bitcoin/Lightning.</p>
</main>
<script>
(() => {
  const MCP_URL = ${JSON.stringify(mcpUrl)};
  const AGENT_PROMPT = ${JSON.stringify(agentPrompt)};
  const PENDING_KEY = "nuri_wallet_pending_v1";
  const CONNECTED_KEY = "nuri_wallet_connected_v1";
  const MASKED_KEY = "npw1_•••••••••••••••••••••••••••••••••••••••••••";
  const BOLT11_RE = /^ln(?:bc|tb|bcrt|tbs)[0-9a-z]+$/i;

  const $ = (id) => document.getElementById(id);
  const el = {
    err: $("error-box"),
    idle: $("view-idle"),
    pending: $("view-pending"),
    connected: $("view-connected"),
    btnCreate: $("btn-create"),
    btnConnect: $("btn-connect"),
    btnPollNow: $("btn-poll-now"),
    btnCancel: $("btn-cancel"),
    pendingStatus: $("pending-status"),
    pendingOpen: $("pending-open-link"),
    pendingAltWrap: $("pending-alt-wrap"),
    pendingAlt: $("pending-alt-link"),
    btnRefresh: $("btn-refresh"),
    btnDisconnect: $("btn-disconnect"),
    balUsdc: $("bal-usdc"),
    balSats: $("bal-sats"),
    balBtc: $("bal-btc"),
    addrUsdc: $("addr-usdc"),
    addrArkade: $("addr-arkade"),
    arkWrap: $("ark-addr-wrap"),
    lnSats: $("ln-sats"),
    btnLnInvoice: $("btn-ln-invoice"),
    lnBox: $("ln-invoice-box"),
    lnMeta: $("ln-invoice-meta"),
    lnText: $("ln-invoice-text"),
    lnUri: $("ln-wallet-uri"),
    lnWatch: $("ln-watch-status"),
    keyDisplay: $("wallet-key-display"),
    btnReveal: $("btn-reveal-key"),
    btnCopyKey: $("btn-copy-key"),
  };

  let pending = readStore(PENDING_KEY);
  let connected = readStore(CONNECTED_KEY);
  let keyRevealed = false;
  let pollTimer = null;
  let pollBusy = false;
  let lnWatchTimer = null;
  let lnWatchRemaining = 0;
  let lnStartSats = 0;

  function readStore(key) {
    try { const raw = sessionStorage.getItem(key); return raw ? JSON.parse(raw) : null; } catch { return null; }
  }
  function writeStore(key, val) {
    try { if (val === null) sessionStorage.removeItem(key); else sessionStorage.setItem(key, JSON.stringify(val)); } catch {}
  }
  function safeHttpsUrl(value) {
    if (typeof value !== "string" || !value) return "";
    try {
      const u = new URL(value, location.origin);
      if (u.protocol === "https:" || u.origin === location.origin) return u.href;
    } catch {}
    return "";
  }
  function showError(msg) {
    if (!msg) { el.err.classList.add("hidden"); el.err.textContent = ""; return; }
    el.err.textContent = String(msg);
    el.err.classList.remove("hidden");
  }
  async function copyText(text, btn) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch {}
      document.body.removeChild(ta);
    }
    if (btn) {
      const orig = btn.dataset.origLabel || btn.textContent;
      btn.dataset.origLabel = orig;
      btn.textContent = "Copied!";
      clearTimeout(btn._copyT);
      btn._copyT = setTimeout(() => { btn.textContent = orig; }, 1600);
    }
  }
  async function callWallet(args) {
    const res = await fetch("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: Date.now() + Math.floor(Math.random() * 1000),
        method: "tools/call",
        params: { name: "wallet", arguments: args },
      }),
    });
    const json = await res.json().catch(() => null);
    if (!res.ok || !json) throw new Error("Wallet server did not answer (HTTP " + res.status + ").");
    if (json.error) throw new Error(json.error.message || "Wallet RPC error.");
    const data = json.result && json.result.structuredContent
      ? json.result.structuredContent
      : JSON.parse((json.result && json.result.content && json.result.content[0] && json.result.content[0].text) || "{}");
    return data;
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }
  function stopLnWatch() {
    if (lnWatchTimer) { clearInterval(lnWatchTimer); lnWatchTimer = null; }
    lnWatchRemaining = 0;
  }

  function render() {
    el.idle.classList.add("hidden");
    el.pending.classList.add("hidden");
    el.connected.classList.add("hidden");

    if (connected) {
      el.connected.classList.remove("hidden");
      const usdc = connected.available !== undefined && connected.available !== null ? String(connected.available) : "0";
      const satsNum = Number(connected.sats || 0);
      const btc = connected.btc !== undefined && connected.btc !== null ? String(connected.btc) : "0";
      el.balUsdc.textContent = usdc + " USDC";
      el.balSats.textContent = satsNum.toLocaleString() + " sats";
      el.balBtc.textContent = btc + " BTC · Pays L402, LN MPP, BOLT11, bc1…";
      el.addrUsdc.textContent = connected.address || "—";
      if (connected.arkade_address) {
        el.arkWrap.classList.remove("hidden");
        el.addrArkade.textContent = connected.arkade_address;
      } else {
        el.arkWrap.classList.add("hidden");
      }
      const hasKey = Boolean(connected.wallet_key);
      el.keyDisplay.textContent = hasKey ? (keyRevealed ? connected.wallet_key : MASKED_KEY) : "(wallet_key already issued in an earlier session)";
      el.btnReveal.disabled = !hasKey;
      el.btnReveal.textContent = keyRevealed ? "Hide" : "Reveal";
      el.btnCopyKey.disabled = !hasKey;
      el.btnLnInvoice.disabled = !hasKey;
      return;
    }

    if (pending && pending.request_id) {
      el.pending.classList.remove("hidden");
      const isCreate = pending.mode === "create";
      const primaryUrl = safeHttpsUrl(isCreate ? (pending.create_url || pending.approval_url) : (pending.approval_url || pending.create_url));
      const altUrl = safeHttpsUrl(isCreate ? pending.approval_url : pending.create_url);
      el.pendingOpen.href = primaryUrl || "#";
      el.pendingOpen.textContent = isCreate ? "Open Nuri Passkey (Create) →" : "Open Nuri Passkey (Connect) →";
      if (altUrl && altUrl !== primaryUrl) {
        el.pendingAltWrap.classList.remove("hidden");
        el.pendingAlt.href = altUrl;
        el.pendingAlt.textContent = isCreate ? "Connect existing Nuri Passkey instead" : "Create a new Nuri Passkey instead";
      } else {
        el.pendingAltWrap.classList.add("hidden");
      }
      return;
    }

    el.idle.classList.remove("hidden");
  }

  function applyConnected(res, fallbackKey) {
    stopPolling();
    pending = null;
    writeStore(PENDING_KEY, null);
    connected = {
      wallet_key: res.wallet_key || fallbackKey || (connected && connected.wallet_key) || "",
      address: res.address || (connected && connected.address) || "",
      arkade_address: res.arkade_address || (connected && connected.arkade_address) || "",
      available: res.available !== undefined ? res.available : (connected ? connected.available : "0"),
      sats: res.sats !== undefined ? res.sats : (connected ? connected.sats : 0),
      btc: res.btc !== undefined ? res.btc : (connected ? connected.btc : "0"),
    };
    writeStore(CONNECTED_KEY, connected);
    showError("");
    render();
  }

  async function pollOnce() {
    if (!pending || !pending.request_id || pollBusy) return;
    pollBusy = true;
    try {
      const res = await callWallet({ action: "balance", request_id: pending.request_id });
      if (res.ok && res.status === "done") {
        applyConnected(res);
        return;
      }
      if (res.status === "connect_required") {
        pending.create_url = res.create_url || pending.create_url;
        pending.approval_url = res.approval_url || pending.approval_url;
        writeStore(PENDING_KEY, pending);
        render();
        return;
      }
      if (res.ok === false || res.status === "failed") {
        stopPolling();
        pending = null;
        writeStore(PENDING_KEY, null);
        showError(res.error || "Passkey approval expired. Click a button below to try again.");
        render();
      }
    } catch (err) {
      el.pendingStatus.textContent = "Waiting for Nuri Passkey approval… retrying (" + (err.message || err) + ")";
    } finally {
      pollBusy = false;
    }
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(pollOnce, 2500);
  }

  async function beginOnboarding(mode) {
    showError("");
    el.btnCreate.disabled = true;
    el.btnConnect.disabled = true;
    let pop = null;
    try {
      pop = window.open("", "_blank");
      if (pop) {
        pop.document.title = "Opening Nuri Passkey…";
        pop.document.body.textContent = "Opening Nuri Passkey…";
      }
    } catch {}
    try {
      const res = await callWallet({ action: "balance" });
      if (res.ok && res.status === "done") {
        if (pop && !pop.closed) try { pop.close(); } catch {}
        applyConnected(res);
        return;
      }
      if (!res.request_id || (!res.create_url && !res.approval_url)) {
        if (pop && !pop.closed) try { pop.close(); } catch {}
        throw new Error(res.error || "Could not start Nuri Passkey onboarding.");
      }
      pending = {
        mode,
        request_id: res.request_id,
        create_url: res.create_url || "",
        approval_url: res.approval_url || "",
      };
      writeStore(PENDING_KEY, pending);
      const targetUrl = safeHttpsUrl(mode === "create" ? (pending.create_url || pending.approval_url) : (pending.approval_url || pending.create_url));
      if (pop && !pop.closed && targetUrl) {
        try { pop.opener = null; pop.location.replace(targetUrl); } catch {}
      } else if (pop && !pop.closed) {
        try { pop.close(); } catch {}
      }
      render();
      startPolling();
    } catch (err) {
      if (pop && !pop.closed) try { pop.close(); } catch {}
      showError(err.message || String(err));
    } finally {
      el.btnCreate.disabled = false;
      el.btnConnect.disabled = false;
    }
  }

  async function refreshBalance(silent) {
    if (!connected || !connected.wallet_key) return;
    if (!silent) el.btnRefresh.disabled = true;
    try {
      const res = await callWallet({ action: "balance", wallet_key: connected.wallet_key });
      if (res.ok && res.status === "done") {
        applyConnected(res, connected.wallet_key);
      } else if (!silent) {
        showError(res.error || "Could not refresh balance.");
      }
    } catch (err) {
      if (!silent) showError(err.message || String(err));
    } finally {
      if (!silent) el.btnRefresh.disabled = false;
    }
  }

  async function createLightningInvoice() {
    if (!connected || !connected.wallet_key) return;
    showError("");
    const sats = Number.parseInt(el.lnSats.value, 10);
    if (!Number.isSafeInteger(sats) || sats <= 0) {
      showError("Enter a positive whole number of sats (for example 5000).");
      return;
    }
    el.btnLnInvoice.disabled = true;
    stopLnWatch();
    try {
      const res = await callWallet({
        action: "receive",
        wallet_key: connected.wallet_key,
        rail: "lightning",
        amount_sats: sats,
      });
      if (!res.ok || !res.invoice) {
        throw new Error(res.error || "Could not create Lightning invoice.");
      }
      el.lnBox.classList.remove("hidden");
      const paySats = res.amount_sats ?? sats;
      const feeSats = res.fee_sats ?? 0;
      const netSats = res.expected_sats ?? sats;
      el.lnMeta.textContent = "Pay " + paySats + " sats (fee " + feeSats + " sats · nets " + netSats + " sats into Arkade custody)";
      el.lnText.textContent = res.invoice;
      if (BOLT11_RE.test(res.invoice)) {
        el.lnUri.href = "lightning:" + res.invoice;
        el.lnUri.classList.remove("hidden");
      } else {
        el.lnUri.classList.add("hidden");
      }
      lnStartSats = Number(connected.sats || 0);
      lnWatchRemaining = 75;
      el.lnWatch.textContent = "Waiting for Lightning payment…";
      lnWatchTimer = setInterval(async () => {
        if (!connected || !connected.wallet_key || lnWatchRemaining <= 0) {
          stopLnWatch();
          return;
        }
        lnWatchRemaining -= 1;
        await refreshBalance(true);
        if (connected && Number(connected.sats || 0) > lnStartSats) {
          el.lnWatch.textContent = "Payment received! Balance updated.";
          stopLnWatch();
        }
      }, 4000);
    } catch (err) {
      showError(err.message || String(err));
    } finally {
      el.btnLnInvoice.disabled = false;
    }
  }

  el.btnCreate.addEventListener("click", () => beginOnboarding("create"));
  el.btnConnect.addEventListener("click", () => beginOnboarding("connect"));
  el.btnPollNow.addEventListener("click", () => pollOnce());
  el.btnCancel.addEventListener("click", () => {
    stopPolling();
    pending = null;
    writeStore(PENDING_KEY, null);
    showError("");
    render();
  });
  el.btnRefresh.addEventListener("click", () => refreshBalance(false));
  el.btnDisconnect.addEventListener("click", () => {
    stopPolling();
    stopLnWatch();
    pending = null;
    connected = null;
    keyRevealed = false;
    writeStore(PENDING_KEY, null);
    writeStore(CONNECTED_KEY, null);
    el.lnBox.classList.add("hidden");
    showError("");
    render();
  });
  el.btnLnInvoice.addEventListener("click", () => createLightningInvoice());
  el.btnReveal.addEventListener("click", () => {
    if (!connected || !connected.wallet_key) return;
    keyRevealed = !keyRevealed;
    render();
  });
  el.btnCopyKey.addEventListener("click", () => {
    if (connected && connected.wallet_key) copyText(connected.wallet_key, el.btnCopyKey);
  });

  document.addEventListener("click", (ev) => {
    const btn = ev.target && ev.target.closest ? ev.target.closest("button") : null;
    if (!btn) return;
    if (btn.dataset.copyEl) {
      const target = $(btn.dataset.copyEl);
      if (target && target.textContent && target.textContent !== "—") copyText(target.textContent, btn);
    } else if (btn.dataset.copyText === "mcp") {
      copyText(MCP_URL, btn);
    } else if (btn.dataset.copyText === "prompt") {
      copyText(AGENT_PROMPT, btn);
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    if (pending && pending.request_id) pollOnce();
    else if (lnWatchTimer && connected && connected.wallet_key) refreshBalance(true);
  });
  window.addEventListener("focus", () => {
    if (pending && pending.request_id) pollOnce();
  });

  render();
  if (connected && connected.wallet_key) {
    refreshBalance(true);
  } else if (pending && pending.request_id) {
    pollOnce();
    startPolling();
  }
})();
</script>
</body>
</html>
`;
}

const LEGACY_ROLES = {
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

export function serviceIndexHtml(role, { origin } = {}) {
  if (role === "wallet") return walletIndexHtml(origin);
  const r = LEGACY_ROLES[role];
  if (!r) throw new Error(`service_index_role_unknown: ${role}`);
  const others = ["wallet", ...Object.keys(LEGACY_ROLES)].filter((name) => name !== role)
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
