// Role homepages and host-aware agent discovery docs (/llms.txt, /skill.md)
// for wallet origins (agent.nuri.com, wallet.nuri.com, nuriwallet.com, wallet.paymentrequired.com)
// plus legacy role homepages (banking, signer).
const APEX = "https://paymentrequired.com";
const DEFAULT_WALLET_HOST = "wallet.paymentrequired.com";
export const WALLET_HOSTS = Object.freeze([
  "agent.nuri.com",
  "wallet.nuri.com",
  "nuriwallet.com",
  "wallet.paymentrequired.com",
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

function resolveIsL1Mode(btcCustodyMode = process.env.AGENT_BTC_CUSTODY_MODE) {
  return String(btcCustodyMode || "arkade").trim().toLowerCase() === "l1_0conf";
}

export function walletLlmsTxt(origin, { btcCustodyMode } = {}) {
  const { origin: base, host } = walletOriginInfo(origin);
  const isL1 = resolveIsL1Mode(btcCustodyMode);
  const payList = isL1
    ? "`lnbc...`, `user@domain`, `bc1...`/`bitcoin:...`, and Base/Solana USDC `0x...`"
    : "`lnbc...`, `user@domain`, `bc1...`/`bitcoin:...`, `ark1...`, and Base/Solana USDC `0x...`";
  const recvRails = isL1 ? '"lightning"|"btc"|"usdc"|"solana"' : '"lightning"|"usdc"|"arkade"|"btc"|"solana"';
  const payToList = isL1
    ? '"lnbc..."|"user@domain"|"bc1..."|"bitcoin:..."|"0x..."'
    : '"lnbc..."|"user@domain"|"bc1..."|"bitcoin:..."|"ark1..."|"0x..."';
  const satRails = isL1 ? "`user@domain`" : "`user@domain`/`ark1...`";
  const introSub = isL1
    ? "Non-custodial Bitcoin L1 (2-of-2 MuSig2+CSV, instant 0-conf Lightning) + Base/Solana USDC wallet for AI agents in 60s."
    : "Non-custodial Bitcoin Lightning + Base/Solana USDC wallet for AI agents in 60s.";
  return `# Agent Wallet (${host})

${introSub} Passkey-secured (Face ID / Touch ID / smartcard), no seed phrase. Pays x402/L402/MPP URLs, ${payList}; auto-converts USDC <-> BTC/Lightning.

## Setup (0 -> 1 -> first payment — pick the path that fits your tools)
- **Path 1 — MCP (\`${base}/mcp\`):** Call \`wallet { "action": "balance" }\`. Show \`approval_url\` (sign in with your existing Nuri Passkey to reconnect your exact wallet, or click "Create Passkey" on that same page). After the person says "done", repeat with the same \`request_id\` to get \`wallet_key\` (\`npw1_...\`), save it, and pass it on every call. NEVER send the person to \`${base}/\` when you already have MCP.
- **Path 2 — HTTP / curl / bash (zero MCP setup):** Plain JSON REST at \`POST ${base}/v1/wallet\` (or \`/v1/balance\`, \`/v1/receive\`, \`/v1/pay\`, \`/v1/history\`; OpenAPI: \`${base}/openapi.json\`). Start: \`curl -sX POST ${base}/v1/wallet -H 'content-type: application/json' -d '{"action":"balance"}'\`. Open \`approval_url\`, then repeat with \`request_id\` to get \`wallet_key\` (pass in body or \`Authorization: Bearer npw1_...\`).
- **Path 3 — Web chat with no tools (e.g. standard web ChatGPT / claude.ai):** Give 3 plain-English steps (no jargon): (1) Open **${base}/** and click **"Create / Connect Agent Wallet"** (Passkey setup, Lightning/USDC funding, and 1-click $0.01 test payment right on the page). (2) Add **\`${base}/mcp\`** as a connector in AI settings (Auth: None), OR copy the prompt on ${base}/ into an MCP/curl client. (3) Ask me to pay any x402 API, Lightning invoice, or checkout.

## 4 Actions (\`balance\`, \`receive\`, \`pay\`, \`history\`)
- \`balance\`: \`{"action":"balance","wallet_key":"npw1_..."}\` (omit \`wallet_key\` to start; pass \`request_id\` after approval; reports all rails plus any registered \`username@nuriwallet.com\` \`lnurl\`).
- \`receive\`: \`{"action":"receive","wallet_key":"npw1_...","rail":${recvRails},"amount_sats":5000}\` — or register a permanent Lightning Address: \`{"action":"receive","wallet_key":"npw1_...","lnurl_username":"yourname"}\` (\`yourname@nuriwallet.com\`).
- \`pay\` (402 URL): \`{"action":"pay","wallet_key":"npw1_...","to":"https://...","max_amount":"0.25","request_id":"p1"}\`
- \`pay\` (address/invoice): \`{"action":"pay","wallet_key":"npw1_...","to":${payToList},"amount":"0.00025","request_id":"p2"}\`
  - \`0x...\`: USDC in \`amount\`. \`bc1...\`/\`bitcoin:...\`: BTC decimal in \`amount\` (e.g. \`"0.00025"\` — never convert BTC to sats in your head) or \`amount_sats\`. ${satRails}: \`amount_sats\`.
  - Over-cap error: STOP, ask the person first; if approved, retry with a NEW \`request_id\` and higher \`max_amount\`/\`max_sats\`.
- \`history\`: \`{"action":"history","wallet_key":"npw1_..."}\`

## Companion Services
- Agent email (\`0.01 USDC\` x402 via \`wallet pay\`): \`https://mail.paymentrequired.com/v1/create_inbox\`
- Paid Chromium browser (\`0.01 USDC\` x402 via \`wallet pay\`): \`https://browser.paymentrequired.com/v1/browser/open\`
- Encrypted agent vault: \`https://vault.paymentrequired.com\`
- Monero XMR / SOL / ETH swaps (separate MCP — NEVER pass into \`wallet pay\`): \`https://swapkit.nuri.com/mcp\`
- Euro IBAN & debit card (separate MCP — NEVER pass into \`wallet pay\`): \`https://banking.paymentrequired.com/mcp\`
- Optional Nuri Smartcard CLI (only if the user explicitly uses \`nuricard\`): \`nuricard connect <approval_url>\`
`;
}

export function walletSkillMd(origin, { btcCustodyMode } = {}) {
  const { origin: base } = walletOriginInfo(origin);
  const isL1 = resolveIsL1Mode(btcCustodyMode);
  const btcDesc = isL1
    ? "Bitcoin L1 (2-of-2 MuSig2+CSV) + 0-conf Lightning"
    : "Bitcoin Lightning/Arkade/on-chain BTC";
  return `---
name: agent-wallet
description: Non-custodial AI agent wallet for Base + Solana USDC (x402, EVM MPP) and ${btcDesc} (L402, Lightning MPP, BOLT11, user@domain) backed by Nuri Passkey PRF. Works via MCP or plain HTTP REST (${base}/v1/wallet).
mcp_endpoint: ${base}/mcp
rest_endpoint: ${base}/v1/wallet
openapi: ${base}/openapi.json
---

${walletLlmsTxt(base, { btcCustodyMode })}`;
}

export function walletOpenApiJson(origin, { btcCustodyMode } = {}) {
  const { origin: base, host } = walletOriginInfo(origin);
  const isL1 = resolveIsL1Mode(btcCustodyMode);
  const btcLabel = isL1 ? "Bitcoin L1 (2-of-2 MuSig2+CSV) + 0-conf Lightning" : "Bitcoin Lightning/Arkade/on-chain BTC";
  const recvSummary = isL1
    ? "Get a Lightning invoice (sats), Bitcoin L1 (bc1p...) address, Base/Solana USDC address, or register username@nuriwallet.com"
    : "Get a Lightning invoice (sats), Base/Solana USDC address, Arkade/L1 address, or register username@nuriwallet.com";
  const paySummary = isL1
    ? "Pay any x402/L402/MPP URL, BOLT11 invoice, Lightning Address, bc1.../bitcoin: BTC, or 0x... Base USDC"
    : "Pay any x402/L402/MPP URL, BOLT11 invoice, Lightning Address, bc1.../bitcoin: BTC, ark1..., or 0x... Base USDC";
  const toDesc = isL1
    ? "https:// 402 URL, lnbc..., user@domain, bc1.../bitcoin:..., or 0x..."
    : "https:// 402 URL, lnbc..., user@domain, bc1.../bitcoin:..., ark1..., or 0x...";
  const satsDesc = isL1 ? "Sats for user@domain or bc1..." : "Sats for user@domain, ark1..., or bc1...";
  const railEnum = isL1 ? ["lightning", "btc", "usdc", "solana"] : ["lightning", "usdc", "arkade", "btc", "solana"];
  return {
    openapi: "3.1.0",
    info: {
      title: `Agent Wallet (${host})`,
      version: "2.0.0",
      description:
        `Non-custodial AI agent wallet for Base + Solana USDC (x402, EVM MPP) and ${btcLabel} (L402, Lightning MPP, BOLT11, user@domain). Auto cross-rail USDC <-> BTC/Lightning. Pass wallet_key in the body or as Authorization: Bearer npw1_...`,
    },
    servers: [{ url: base }],
    paths: {
      "/v1/wallet": {
        post: {
          operationId: "walletAction",
          summary: "Run a wallet action (balance, receive, pay, or history)",
          description:
            "Start Passkey setup by calling action=balance without wallet_key, then repeat with the returned request_id after approval to obtain wallet_key (npw1_...).",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/WalletRequest" },
              },
            },
          },
          responses: {
            "200": {
              description: "Wallet result",
              content: { "application/json": { schema: { type: "object", additionalProperties: true } } },
            },
          },
        },
      },
      "/v1/balance": {
        post: {
          operationId: "walletBalance",
          summary: `Create/connect Passkey wallet or check Base/Solana USDC + ${btcLabel} balance`,
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    wallet_key: { type: "string", description: "npw1_... key (omit on first call to start Passkey setup)" },
                    request_id: { type: "string", description: "Repeat with the same request_id after Passkey approval" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Connect links (connect_required) or live balances (done)",
              content: { "application/json": { schema: { type: "object", additionalProperties: true } } },
            },
          },
        },
      },
      "/v1/receive": {
        post: {
          operationId: "walletReceive",
          summary: recvSummary,
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    wallet_key: { type: "string" },
                    rail: { type: "string", enum: railEnum },
                    amount_sats: { type: "integer", minimum: isL1 ? 340 : 100, description: "Required for rail=lightning" },
                    lnurl_username: { type: "string", description: "Register permanent username@nuriwallet.com handle" },
                    request_id: { type: "string" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Invoice or deposit address",
              content: { "application/json": { schema: { type: "object", additionalProperties: true } } },
            },
          },
        },
      },
      "/v1/pay": {
        post: {
          operationId: "walletPay",
          summary: paySummary,
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["to"],
                  properties: {
                    wallet_key: { type: "string" },
                    to: { type: "string", description: toDesc },
                    url: { type: "string", description: "Optional alias for to on https:// URLs" },
                    invoice: { type: "string", description: "Optional alias for to on BOLT11 lnbc... invoices" },
                    amount: { type: "string", description: "USDC for 0x..., or decimal BTC for bc1... (e.g. '0.00025')" },
                    amount_sats: { type: "integer", description: satsDesc },
                    max_amount: { type: "string", description: "Max USD cap for 402/invoice payments" },
                    max_sats: { type: "integer", description: "Max sats cap for 402/invoice payments" },
                    prefer: { type: "string", description: "Optional rail preference on multi-rail 402 URLs" },
                    method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
                    body: { description: "JSON or string request body for 402 HTTP calls" },
                    dry_run: { type: "boolean" },
                    request_id: { type: "string", description: "Idempotency key (new id after raising a cap)" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Payment receipt and upstream response",
              content: { "application/json": { schema: { type: "object", additionalProperties: true } } },
            },
          },
        },
      },
      "/v1/history": {
        post: {
          operationId: "walletHistory",
          summary: "List recent payments and receives",
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    wallet_key: { type: "string" },
                    limit: { type: "integer", minimum: 1, maximum: 50 },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Recent history entries",
              content: { "application/json": { schema: { type: "object", additionalProperties: true } } },
            },
          },
        },
      },
    },
    components: {
      schemas: {
        WalletRequest: {
          type: "object",
          required: ["action"],
          properties: {
            action: { type: "string", enum: ["balance", "receive", "pay", "history"] },
            wallet_key: { type: "string", description: "npw1_... key (or send Authorization: Bearer npw1_...)" },
            request_id: { type: "string" },
            rail: { type: "string", enum: railEnum },
            lnurl_username: { type: "string" },
            to: { type: "string" },
            url: { type: "string" },
            invoice: { type: "string" },
            amount: { type: "string" },
            amount_sats: { type: "integer" },
            max_amount: { type: "string" },
            max_sats: { type: "integer" },
            prefer: { type: "string" },
            method: { type: "string" },
            body: {},
            dry_run: { type: "boolean" },
            new: { type: "boolean" },
            index: { type: "integer" },
            limit: { type: "integer", minimum: 1, maximum: 50 },
          },
        },
      },
    },
  };
}

function walletIndexHtml(origin, { btcCustodyMode } = {}) {
  const { origin: base, host } = walletOriginInfo(origin);
  const isL1 = resolveIsL1Mode(btcCustodyMode);
  const metaBtcSummary = isL1 ? "Bitcoin L1 (2-of-2 MuSig2+CSV), 0-conf Lightning" : "Bitcoin Lightning, Arkade, on-chain BTC";
  const statBtcLabel = isL1 ? "Bitcoin (L1 + Lightning)" : "Bitcoin (Lightning / Arkade)";
  const featureTitle = isL1 ? "2-of-4 Safe + 2-of-2 Bitcoin L1" : "2-of-4 Safe + 2-of-2 Arkade";
  const featureBody = isL1
    ? "Base USDC lives in your Safe v1.5.0 smart account and Bitcoin lives directly on Bitcoin L1 (2-of-2 MuSig2+CSV) with instant 0-conf Lightning and per-tx Rust cosigner policy limits."
    : "Base USDC lives in your Safe v1.5.0 smart account and Bitcoin lives in Arkade/Lightning custody with per-tx Rust cosigner policy limits.";
  const lnRailItem = isL1
    ? '<li><span class="ri">⚡</span><div><strong>Bitcoin Lightning (0-Conf L1)</strong><p>Pay and receive real BOLT11 invoices (<code>lnbc…</code>), Lightning addresses (<code>user@nuriwallet.com</code>), L402, and Lightning MPP straight from Bitcoin L1 UTXOs.</p></div></li>'
    : '<li><span class="ri">⚡</span><div><strong>Bitcoin Lightning &amp; Arkade</strong><p>Pay and receive real BOLT11 invoices (<code>lnbc…</code>), Lightning addresses (<code>user@domain</code>), L402, Lightning MPP, and <code>ark1…</code>.</p></div></li>';
  const btcRailItem = isL1
    ? '<li><span class="ri">₿</span><div><strong>On-chain Bitcoin L1 (<code>bc1p…</code>)</strong><p>Hold, receive (<code>bc1p…</code>), and send native Bitcoin (<code>bc1…</code> / <code>bitcoin:</code> BIP21 URIs) using BTC decimals (e.g. <code>0.00025</code>) or sats.</p></div></li>'
    : '<li><span class="ri">₿</span><div><strong>On-chain Bitcoin</strong><p>Send to native SegWit <code>bc1…</code> addresses or <code>bitcoin:</code> BIP21 URIs using BTC decimals (e.g. <code>0.00025</code>) or sats.</p></div></li>';
  const toolBalanceCopy = isL1
    ? "Omit <code>wallet_key</code> to start Passkey onboarding (returns <code>approval_url</code>). Pass <code>wallet_key</code> to inspect Base/Solana USDC + Bitcoin L1/Lightning balances."
    : "Omit <code>wallet_key</code> to start Passkey onboarding (returns <code>approval_url</code>). Pass <code>wallet_key</code> to inspect Base/Solana USDC + Bitcoin Lightning/Arkade balances.";
  const toolReceiveCopy = isL1
    ? 'Get Base/Solana USDC or Bitcoin L1 (<code>bc1p…</code>) deposit addresses, register <code>username@nuriwallet.com</code>, or mint a Lightning BOLT11 invoice (<code>rail: "lightning", amount_sats</code>).'
    : 'Get Base/Solana USDC or Arkade deposit addresses, register <code>username@nuriwallet.com</code>, or mint a fresh Lightning BOLT11 funding invoice (<code>rail: "lightning", amount_sats</code>).';
  const toolPayCopy = isL1
    ? "Universal pay: pass <code>to</code> as any <code>https://</code> 402 URL, <code>lnbc…</code>, <code>user@domain</code>, <code>bc1…</code>/<code>bitcoin:…</code>, or <code>0x…</code>. Enforces <code>max_amount</code>/<code>max_sats</code> caps."
    : "Universal pay: pass <code>to</code> as any <code>https://</code> 402 URL, <code>lnbc…</code>, <code>user@domain</code>, <code>bc1…</code>/<code>bitcoin:…</code>, <code>ark1…</code>, or <code>0x…</code>. Enforces <code>max_amount</code>/<code>max_sats</code> caps.";
  const toolHistoryCopy = isL1
    ? "Recent receipts across Base USDC, Bitcoin L1, Lightning, and cross-rail bridges with settlement proofs."
    : "Recent receipts across Base USDC, Lightning, Arkade, and cross-rail bridges with settlement proofs.";
  const footerLine = isL1
    ? "Nuri Agent Wallet · Non-custodial Passkey PRF + 2-of-4 Base Safe USDC + 2-of-2 Bitcoin L1 / 0-conf Lightning."
    : "Nuri Agent Wallet · Non-custodial Passkey PRF + 2-of-4 Base Safe USDC + 2-of-2 Arkade Bitcoin/Lightning.";
  const mcpUrl = `${base}/mcp`;
  const restUrl = `${base}/v1/wallet`;
  const openapiUrl = `${base}/openapi.json`;
  const llmsUrl = `${base}/llms.txt`;
  const skillUrl = `${base}/skill.md`;
  const agentPrompt = `Use my Nuri Agent Wallet at ${base} (read ${llmsUrl} and start wallet balance).`;
  const cursorCfg = Buffer.from(JSON.stringify({ url: mcpUrl }), "utf8").toString("base64");
  const cursorDeepLink = `cursor://anysphere.cursor-deeplink/mcp/install?name=nuri-wallet&config=${encodeURIComponent(cursorCfg)}`;
  const vscodeCfg = encodeURIComponent(JSON.stringify({ name: "nuri-wallet", type: "http", url: mcpUrl }));
  const vscodeDeepLink = `vscode:mcp/install?${vscodeCfg}`;
  const claudeCodeCmd = `claude mcp add --transport http nuri-wallet ${mcpUrl}`;
  const codexCmd = `codex mcp add nuri-wallet --url ${mcpUrl}`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${host} — Agent Wallet</title>
<meta name="description" content="One passkey gives any AI agent non-custodial ${metaBtcSummary}, and Base USDC via 4 MCP actions or plain HTTP REST. No OAuth, no seed phrase, no custody.">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/x-icon" href="/favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta property="og:title" content="${host} — Agent Wallet">
<meta property="og:description" content="Non-custodial ${metaBtcSummary}, and Base USDC wallet for AI agents. Authless MCP + plain HTTP REST.">
<meta property="og:image" content="${base}/apple-touch-icon.png">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#08090b; --panel:#0f1114; --panel2:#14171c; --line:#1e2228; --line2:#2a3038;
  --fg:#f4f6f8; --dim:#9aa4b2; --faint:#697280;
  --btc:#f7931a; --acc:#5ce1b9; --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,monospace;
  --ok-bg:rgba(92,225,185,.12); --ok-border:rgba(92,225,185,.4); --ok-ink:#5ce1b9;
  --info-bg:rgba(96,165,250,.12); --info-border:rgba(96,165,250,.38); --info-ink:#93c5fd;
  --warn-bg:rgba(247,147,26,.12); --warn-border:rgba(247,147,26,.4); --warn-ink:#fbbf24;
  --err-bg:rgba(248,113,113,.12); --err-border:rgba(248,113,113,.4); --err-ink:#fca5a5;
}
@media(prefers-color-scheme:light){:root{
  --bg:#fbfbfc; --panel:#fff; --panel2:#f4f6f8; --line:#e6e8ec; --line2:#d3d7de;
  --fg:#0b0d10; --dim:#4d5663; --faint:#7b8492;
  --ok-bg:#f0fdf4; --ok-border:#86efac; --ok-ink:#166534;
  --info-bg:#eff6ff; --info-border:#bfdbfe; --info-ink:#1e3a8a;
  --warn-bg:#fffbeb; --warn-border:#fcd34d; --warn-ink:#92400e;
  --err-bg:#fef2f2; --err-border:#fca5a5; --err-ink:#991b1b;
}}
:root[data-theme=light]{
  --bg:#fbfbfc; --panel:#fff; --panel2:#f4f6f8; --line:#e6e8ec; --line2:#d3d7de;
  --fg:#0b0d10; --dim:#4d5663; --faint:#7b8492;
  --ok-bg:#f0fdf4; --ok-border:#86efac; --ok-ink:#166534;
  --info-bg:#eff6ff; --info-border:#bfdbfe; --info-ink:#1e3a8a;
  --warn-bg:#fffbeb; --warn-border:#fcd34d; --warn-ink:#92400e;
  --err-bg:#fef2f2; --err-border:#fca5a5; --err-ink:#991b1b;
}
:root[data-theme=dark]{
  --bg:#08090b; --panel:#0f1114; --panel2:#14171c; --line:#1e2228; --line2:#2a3038;
  --fg:#f4f6f8; --dim:#9aa4b2; --faint:#697280;
  --ok-bg:rgba(92,225,185,.12); --ok-border:rgba(92,225,185,.4); --ok-ink:#5ce1b9;
  --info-bg:rgba(96,165,250,.12); --info-border:rgba(96,165,250,.38); --info-ink:#93c5fd;
  --warn-bg:rgba(247,147,26,.12); --warn-border:rgba(247,147,26,.4); --warn-ink:#fbbf24;
  --err-bg:rgba(248,113,113,.12); --err-border:rgba(248,113,113,.4); --err-ink:#fca5a5;
}
html{-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--fg);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;overflow-x:hidden}
a{color:inherit}
code{font-family:var(--mono);font-size:.88em;overflow-wrap:anywhere}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px;position:relative}
section{padding:68px 0;border-top:1px solid var(--line)}
h2{font-size:clamp(22px,3.4vw,30px);letter-spacing:-.02em;margin-bottom:8px}
h2+.sub{color:var(--dim);margin-bottom:32px;max-width:64ch}
h3{font-size:15px;letter-spacing:-.01em;margin:20px 0 8px}

/* topbar + hero */
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;
  padding:20px 0 0;font-size:13.5px;font-family:var(--mono)}
.brand{font-weight:600;text-decoration:none;color:var(--fg);display:inline-flex;align-items:center;gap:8px}
.nav{display:flex;gap:18px;flex-wrap:wrap;padding-right:42px}
.nav a{color:var(--dim);text-decoration:none}
.nav a:hover{color:var(--fg)}
header{position:relative;overflow:hidden;padding:0 0 72px}
header::before{content:"";position:absolute;inset:-40% 30% 40% -20%;
  background:radial-gradient(circle at 30% 40%,rgba(247,147,26,.16),transparent 60%);pointer-events:none}
header::after{content:"";position:absolute;inset:20% -20% -40% 40%;
  background:radial-gradient(circle at 60% 50%,rgba(92,225,185,.13),transparent 60%);pointer-events:none}
.hero-body{padding-top:52px}
.badge{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line2);
  border-radius:999px;padding:6px 14px;font-size:12.5px;color:var(--dim);
  font-family:var(--mono);background:var(--panel)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--acc);
  box-shadow:0 0 0 3px rgba(92,225,185,.18)}
h1{font-size:clamp(38px,7.2vw,72px);line-height:1.02;letter-spacing:-.035em;
  font-weight:680;margin:24px 0 18px}
h1 em{font-style:normal;background:linear-gradient(96deg,var(--btc),var(--acc));
  -webkit-background-clip:text;background-clip:text;color:transparent}
.lede{font-size:clamp(17px,2.1vw,21px);color:var(--dim);max-width:58ch}
.lede b{color:var(--fg);font-weight:600}

/* endpoint strip */
.ep{margin:34px 0 12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.ep-url{display:flex;align-items:center;gap:12px;background:var(--panel);
  border:1px solid var(--line2);border-radius:12px;padding:12px 15px;
  font-family:var(--mono);font-size:14.5px;min-width:0;max-width:100%}
.ep-url span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ep-url b{color:var(--acc);font-weight:500}
button{font:inherit;cursor:pointer;border:0;background:none;color:inherit}
.copy{border:1px solid var(--line2);border-radius:8px;padding:5px 11px;font-size:12px;
  color:var(--dim);font-family:var(--mono);white-space:nowrap;transition:.15s}
.copy:hover{color:var(--fg);border-color:var(--faint)}
.copy.done{color:var(--acc);border-color:var(--acc)}
.noauth{display:flex;gap:10px;flex-wrap:wrap;font-size:13px;color:var(--faint);
  font-family:var(--mono);margin-top:14px}
.noauth i{font-style:normal;color:var(--acc)}
.hero-cta{margin-top:26px;display:flex;flex-wrap:wrap;gap:10px;align-items:center}

/* interactive wallet widget */
.widget{background:var(--panel);border:1px solid var(--line2);border-radius:16px;padding:26px}
.row{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;font:inherit;
  font-size:14.5px;font-weight:600;padding:10px 16px;border-radius:10px;
  border:1px solid transparent;cursor:pointer;text-decoration:none;transition:.15s}
.btn:disabled{opacity:.55;cursor:wait}
.btn-primary{background:linear-gradient(96deg,var(--btc),#ffad42);color:#0b0d10;border-color:transparent}
.btn-primary:hover:not(:disabled){filter:brightness(1.06)}
.btn-secondary{background:var(--panel2);color:var(--fg);border-color:var(--line2)}
.btn-secondary:hover:not(:disabled){border-color:var(--faint)}
.btn-sm{font-size:12.5px;padding:6px 11px;border-radius:8px;font-family:var(--mono);font-weight:500}
.muted{color:var(--dim);font-size:14px}
.code-box{display:flex;align-items:center;justify-content:space-between;gap:10px;
  background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:10px 13px;margin:6px 0 12px}
.code-box code{font-size:13px;line-height:1.45;word-break:break-all;flex:1;color:var(--acc)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:14px 0 18px}
.stat{background:var(--bg);border:1px solid var(--line);border-radius:12px;padding:16px}
.stat-label{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--faint);font-family:var(--mono);margin-bottom:4px}
.stat-val{font-size:24px;font-weight:700;letter-spacing:-.02em}
.stat-sub{font-size:13px;color:var(--dim);margin-top:3px}
.banner{border-radius:10px;padding:11px 14px;margin:12px 0;font-size:14px}
.banner-info{background:var(--info-bg);border:1px solid var(--info-border);color:var(--info-ink)}
.banner-ok{background:var(--ok-bg);border:1px solid var(--ok-border);color:var(--ok-ink)}
.banner-warn{background:var(--warn-bg);border:1px solid var(--warn-border);color:var(--warn-ink)}
.banner-err{background:var(--err-bg);border:1px solid var(--err-border);color:var(--err-ink)}
.input-sats{font:inherit;font-family:var(--mono);font-size:14.5px;padding:8px 11px;
  border:1px solid var(--line2);border-radius:9px;width:130px;background:var(--bg);color:var(--fg)}
.hidden{display:none!important}
.sep{border:0;border-top:1px solid var(--line);margin:20px 0}

/* grids */
.g{display:grid;gap:14px}
.g3{grid-template-columns:repeat(auto-fit,minmax(258px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px}
.card h3{font-size:15px;letter-spacing:-.01em;margin:0 0 7px;display:flex;gap:9px;align-items:center}
.card h3 span{color:var(--btc);font-size:17px}
.card p{color:var(--dim);font-size:14.5px}

/* rails */
.rails{list-style:none;display:grid;gap:2px;
  grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
  border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--line)}
.rails li{display:flex;gap:15px;padding:20px;background:var(--panel)}
.ri{font-size:19px;color:var(--btc);line-height:1.3;flex-shrink:0;width:22px}
.rails strong{font-size:14.5px;font-weight:600}
.rails p{color:var(--dim);font-size:13.5px;margin-top:3px}
.rails code{background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:1px 5px;color:var(--acc)}
.rails a{color:var(--acc);text-decoration:none;border-bottom:1px solid var(--line2)}

/* flow */
.flow{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(232px,1fr));counter-reset:s}
.step{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;position:relative}
.step::before{counter-increment:s;content:counter(s);position:absolute;top:16px;right:18px;
  font-family:var(--mono);font-size:12px;color:var(--faint)}
.step b{display:block;font-family:var(--mono);font-size:13px;color:var(--acc);margin-bottom:7px}
.step p{color:var(--dim);font-size:14px}

/* tools */
.tools{display:grid;gap:2px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  background:var(--line);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.tool{background:var(--panel);padding:18px 20px}
.tool code{color:var(--btc);font-size:13.5px;font-weight:600}
.tool p{color:var(--dim);font-size:13.5px;margin-top:5px}

/* code block + prompts */
pre{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:18px;overflow-x:auto;font-family:var(--mono);font-size:13px;line-height:1.7}
pre .c{color:var(--faint)}
pre .k{color:var(--acc)}
pre .s{color:var(--btc)}
.two{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(330px,1fr))}
.two h4{font-size:13px;font-family:var(--mono);color:var(--dim);margin-bottom:9px;font-weight:500}
.pr{list-style:none;display:grid;gap:9px}
.pr li{background:var(--panel);border:1px solid var(--line);border-left:2px solid var(--btc);
  border-radius:0 10px 10px 0;padding:13px 17px;font-size:14.5px}
.pr span{color:var(--faint);font-family:var(--mono);font-size:12.5px;display:block;margin-top:4px}
.agent-list{margin-top:18px;padding-left:20px;color:var(--dim);font-size:14.5px}
.agent-list li{margin:8px 0}
.agent-list strong{color:var(--fg)}
.agent-list a{color:var(--acc)}

footer{border-top:1px solid var(--line);padding:44px 0 60px;color:var(--faint);font-size:13.5px}
footer a{color:var(--dim);text-decoration:none;border-bottom:1px solid var(--line2)}
footer a:hover{color:var(--fg)}
.fl{display:flex;gap:22px;flex-wrap:wrap;margin-top:12px}
.theme{position:fixed;top:16px;right:16px;z-index:9;border:1px solid var(--line2);
  background:var(--panel);border-radius:8px;width:32px;height:32px;font-size:14px;color:var(--dim)}
.theme:hover{color:var(--fg);border-color:var(--faint)}
</style>
</head>
<body>
<button class="theme" id="tt" type="button" aria-label="Toggle theme">◐</button>

<header><div class="wrap">
  <div class="topbar">
    <a class="brand" href="${base}/"><img src="/favicon.svg" alt="" width="20" height="20" style="border-radius:5px">${host}</a>
    <nav class="nav" aria-label="Agent docs">
      <a href="#setup-widget">setup</a>
      <a href="${llmsUrl}">llms.txt</a>
      <a href="${skillUrl}">skill.md</a>
      <a href="${openapiUrl}">openapi.json</a>
      <a href="#for-agents">for agents</a>
    </nav>
  </div>
  <div class="hero-body">
    <div class="badge"><span class="dot"></span>live · non-custodial · MCP + plain HTTP REST</div>
    <h1>A real money account<br>for <em>any AI agent</em>.</h1>
    <p class="lede">One Passkey gives any AI agent <b>${metaBtcSummary},
    and Base USDC</b> — with automatic cross-rail conversion, 4 tiny actions, and zero seed phrases.
    Nothing is custodied. Works with MCP or plain <code>curl</code>.</p>

    <div class="ep">
      <div class="ep-url"><span>MCP <b>${mcpUrl}</b></span>
        <button type="button" class="copy" data-copy-text="mcp">Copy MCP URL</button></div>
      <div class="ep-url"><span>REST <b>POST ${restUrl}</b></span>
        <button type="button" class="copy" data-copy-text="curl">Copy cURL</button></div>
    </div>
    <div class="noauth">
      <i>✓</i> no OAuth <i>✓</i> no client registration <i>✓</i> no seed phrase
      <i>✓</i> auto USDC &harr; BTC/Lightning <i>✓</i> zero-MCP REST fallback
    </div>
    <div class="hero-cta">
      <a href="#setup-widget" class="btn btn-primary">Create / Connect Agent Wallet &darr;</a>
      <a href="${cursorDeepLink}" class="btn btn-secondary">1-Click Cursor</a>
      <a href="${vscodeDeepLink}" class="btn btn-secondary">1-Click VS Code</a>
      <button type="button" class="btn btn-secondary" data-copy-text="claude-code">Claude Code 1-liner</button>
      <button type="button" class="btn btn-secondary" data-copy-text="codex">Codex 1-liner</button>
      <button type="button" class="btn btn-secondary" data-copy-text="prompt">Copy 1-line Prompt</button>
    </div>
  </div>
</div></header>

<section id="setup-widget" aria-labelledby="setup-heading"><div class="wrap">
  <h2 id="setup-heading">Create / Connect Agent Wallet</h2>
  <p class="sub">Non-custodial Nuri Passkey (Face ID, Touch ID, or smartcard). Set up or connect right here, top up with Lightning or Base USDC, reveal your <code>wallet_key</code>, and test a real $0.01 agent payment.</p>

  <div class="widget">
    <div id="error-box" class="banner banner-err hidden" role="alert"></div>

    <div id="view-idle">
      <div class="row">
        <button id="btn-create" type="button" class="btn btn-primary">Create New Passkey Wallet</button>
        <button id="btn-connect" type="button" class="btn btn-secondary">Connect Existing Nuri Passkey</button>
      </div>
      <p class="muted" style="margin-top:12px">Opens <code>connect.nuri.com</code> in a new tab and automatically detects approval here.</p>
    </div>

    <div id="view-pending" class="hidden">
      <div class="banner banner-info" id="pending-status" role="status">Waiting for Nuri Passkey approval… checking every 2.5s.</div>
      <div class="row">
        <a id="pending-open-link" class="btn btn-primary" href="#" target="_blank" rel="noopener noreferrer">Open Nuri Passkey &rarr;</a>
        <button id="btn-poll-now" type="button" class="btn btn-secondary">Check now</button>
        <button id="btn-cancel" type="button" class="btn btn-secondary">Start over</button>
      </div>
      <p class="muted" style="margin-top:12px">
        <span id="pending-alt-wrap" class="hidden">Wrong path? <a id="pending-alt-link" href="#" target="_blank" rel="noopener noreferrer"></a></span>
      </p>
    </div>

    <div id="view-connected" class="hidden">
      <div class="row" style="justify-content:space-between;margin-bottom:12px">
        <div class="banner banner-ok" style="margin:0;padding:6px 12px;font-weight:600">Wallet connected</div>
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
          <div class="stat-label">${statBtcLabel}</div>
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
        <div class="muted" id="addr-btc-label">${isL1 ? "Bitcoin L1 (2-of-2 MuSig2+CSV)" : "Arkade BTC"}</div>
        <div class="code-box">
          <code id="addr-arkade">—</code>
          <button type="button" class="btn btn-secondary btn-sm" data-copy-el="addr-arkade">Copy</button>
        </div>
      </div>
      <div id="lnurl-addr-wrap" class="hidden">
        <div class="muted">Lightning Address (LNURL)</div>
        <div class="code-box">
          <code id="addr-lnurl">—</code>
          <button type="button" class="btn btn-secondary btn-sm" data-copy-el="addr-lnurl">Copy</button>
        </div>
      </div>

      <h3>Fund via Bitcoin Lightning</h3>
      <div class="row">
        <label for="ln-sats" class="muted">Sats</label>
        <input id="ln-sats" class="input-sats" type="number" min="${isL1 ? 340 : 100}" step="100" value="5000" inputmode="numeric">
        <button id="btn-ln-invoice" type="button" class="btn btn-primary btn-sm">Create Lightning Funding Invoice (sats)</button>
      </div>
      <div id="ln-invoice-box" class="hidden" style="margin-top:12px">
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

      <h3>Test First Payment ($0.01 x402 Agent Inbox)</h3>
      <p class="muted" style="margin-bottom:10px">Once funded, verify everything end-to-end with one click — pays $0.01 USDC (or auto-bridges from Lightning) to create a live agent email inbox at <code>mail.paymentrequired.com</code>.</p>
      <div class="row">
        <button id="btn-test-pay" type="button" class="btn btn-secondary btn-sm">Test $0.01 Payment (Create Inbox)</button>
        <span id="test-pay-status" class="muted"></span>
      </div>
      <div id="test-pay-result" class="banner banner-ok hidden" style="margin-top:10px"></div>

      <hr class="sep">

      <h3>Use With Your AI Agent (1-Click Install)</h3>
      <div class="row">
        <a href="${cursorDeepLink}" class="btn btn-primary btn-sm">Install in Cursor</a>
        <a href="${vscodeDeepLink}" class="btn btn-secondary btn-sm">Install in VS Code</a>
        <button type="button" class="btn btn-secondary btn-sm" data-copy-text="claude-code">Claude Code 1-liner</button>
        <button type="button" class="btn btn-secondary btn-sm" data-copy-text="codex">Codex 1-liner</button>
        <button type="button" class="btn btn-secondary btn-sm" data-copy-text="mcp">Copy MCP URL</button>
        <button type="button" class="btn btn-secondary btn-sm" data-copy-text="prompt">Copy 1-line Prompt</button>
        <button type="button" class="btn btn-secondary btn-sm" data-copy-text="curl">Copy cURL</button>
      </div>
      <p class="muted" style="margin-top:10px">
        <strong>Claude / ChatGPT web:</strong> Settings &rarr; Connectors / Apps &rarr; Add Custom Connector &rarr; <code>${mcpUrl}</code> (Auth: None).<br>
        <strong>Goose / Claude Code / Codex (zero MCP setup):</strong> just tell your agent <code>Use my Nuri Agent Wallet at ${base}</code> — it calls <code>POST ${restUrl}</code> directly.
      </p>
    </div>
  </div>
</div></section>

<section><div class="wrap">
  <h2>Authless on purpose</h2>
  <p class="sub">Most money MCPs make you register an OAuth client before an agent can even list tools. Connect <code>${mcpUrl}</code> or call <code>POST ${restUrl}</code> immediately — custody stays on your Passkey, never on this server.</p>
  <div class="g g3">
    <div class="card"><h3><span>⚿</span>Passkey PRF</h3><p>Root keys are derived in your browser from WebAuthn PRF (Face ID, Touch ID, or smartcard) and never touch our server.</p></div>
    <div class="card"><h3><span>⛉</span>${featureTitle}</h3><p>${featureBody}</p></div>
    <div class="card"><h3><span>◇</span>Zero-MCP REST + MCP</h3><p>Works natively in MCP clients (Claude, ChatGPT, Goose, Cursor) and over plain HTTP JSON (<code>${restUrl}</code>) with any agent that has <code>curl</code>.</p></div>
  </div>
</div></section>

<section><div class="wrap">
  <h2>Everything it pays &amp; connects to</h2>
  <p class="sub">Real live rails — pay any machine-payable URL or crypto rail directly, and plug into live Nuri companion services.</p>
  <ul class="rails">
    ${lnRailItem}
    ${btcRailItem}
    <li><span class="ri">◈</span><div><strong>Base USDC &amp; x402 / MPP</strong><p>Pay any HTTP <code>402 Payment Required</code> API (x402, EVM MPP) or <code>0x…</code> address on Base. Gas sponsored.</p></div></li>
    <li><span class="ri">⇄</span><div><strong>Auto cross-rail</strong><p>Hold only Bitcoin? Pay a USDC x402 API. Hold only USDC? Pay a Lightning invoice or <code>bc1…</code> address. Converts automatically under the hood.</p></div></li>
    <li><span class="ri">☎</span><div><strong>Paid Calls &amp; SMS</strong><p>Live companion at <a href="https://calls.nuri.com">calls.nuri.com</a> — outbound voice calls &amp; SMS paid per call via x402.</p></div></li>
    <li><span class="ri">✉</span><div><strong>Agent Email &amp; Browser</strong><p>Pay $0.01 USDC via <code>wallet pay</code> for <a href="https://mail.paymentrequired.com">mail.paymentrequired.com</a> inboxes or <a href="https://browser.paymentrequired.com">browser.paymentrequired.com</a> Chromium sessions.</p></div></li>
    <li><span class="ri">⛨</span><div><strong>Encrypted Agent Vault</strong><p><a href="https://vault.paymentrequired.com">vault.paymentrequired.com</a> — paid encrypted key-value storage verifying Base Safe owners (<code>isOwner</code> / ERC-1271).</p></div></li>
    <li><span class="ri">▦</span><div><strong>Swaps &amp; Euro Banking MCPs</strong><p>Separate companion MCPs: <code>https://swapkit.nuri.com/mcp</code> (Monero XMR / SOL / ETH) and <code>https://banking.paymentrequired.com/mcp</code> (Euro IBAN &amp; debit card).</p></div></li>
  </ul>
</div></section>

<section><div class="wrap">
  <h2>One tool, four actions</h2>
  <p class="sub">Tiny footprint (&lt;2.3% of a 64k context window) so even small 9B local models never get lost.</p>
  <div class="tools">
    <div class="tool"><code>balance</code><p>${toolBalanceCopy}</p></div>
    <div class="tool"><code>receive</code><p>${toolReceiveCopy}</p></div>
    <div class="tool"><code>pay</code><p>${toolPayCopy}</p></div>
    <div class="tool"><code>history</code><p>${toolHistoryCopy}</p></div>
  </div>
</div></section>

<section id="for-agents" aria-labelledby="agents-heading"><div class="wrap">
  <h2 id="agents-heading">Try it in one call</h2>
  <p class="sub">No OAuth, no API key. Works via MCP (<code>${mcpUrl}</code>) or plain HTTP REST (<code>POST ${restUrl}</code>).</p>
  <div class="code-box">
    <code id="mcp-endpoint-code">${mcpUrl}</code>
    <button type="button" class="btn btn-secondary btn-sm" data-copy-text="mcp">Copy MCP URL</button>
    <button type="button" class="btn btn-secondary btn-sm" data-copy-text="prompt">Copy Agent Prompt</button>
  </div>
  <div class="code-box">
    <code id="rest-endpoint-code">POST ${restUrl}</code>
    <button type="button" class="btn btn-secondary btn-sm" data-copy-text="curl">Copy cURL</button>
  </div>
  <div class="two" style="margin-top:20px">
    <div>
      <h4>curl (plain HTTP REST — zero MCP needed)</h4>
      <pre><span class="c"># start Passkey setup (returns approval_url)</span>
curl -sX POST <span class="s">${restUrl}</span> \\
  -H <span class="s">'content-type: application/json'</span> \\
  -d <span class="s">'{"action":<span class="k">"balance"</span>}'</span>

<span class="c"># after approval, pass wallet_key (or Authorization: Bearer npw1_...)</span>
curl -sX POST <span class="s">${base}/v1/pay</span> \\
  -H <span class="s">'authorization: Bearer npw1_...'</span> \\
  -H <span class="s">'content-type: application/json'</span> \\
  -d <span class="s">'{"to":"https://mail.paymentrequired.com/v1/create_inbox","method":"POST","body":{"request_id":"p1"},"max_amount":"0.05","request_id":"p1"}'</span></pre>
    </div>
    <div>
      <h4>then just talk to your agent</h4>
      <ul class="pr">
        <li>check my balance and get a 5000 sat Lightning invoice<span>&rarr; balance + receive (rail: "lightning")</span></li>
        <li>pay $0.01 to create an agent email inbox<span>&rarr; pay https://mail.paymentrequired.com/v1/create_inbox</span></li>
        <li>send 0.00025 BTC to bc1q…<span>&rarr; pay on-chain BTC (auto-bridges from USDC if needed)</span></li>
        <li>read ${llmsUrl} and set up my wallet<span>&rarr; 1-URL onboarding for Claude, ChatGPT, Codex &amp; Goose</span></li>
      </ul>
    </div>
  </div>
  <ul class="agent-list">
    <li><strong>MCP clients:</strong> connect <code>${mcpUrl}</code> and call <code>wallet { "action": "balance" }</code>. Show <code>approval_url</code> (sign in with an existing Passkey or click "Create Passkey" on that same page), then repeat with the same <code>request_id</code>.</li>
    <li><strong>HTTP / curl / bash agents:</strong> use <code>POST ${restUrl}</code> (or <code>/v1/balance</code>, <code>/v1/receive</code>, <code>/v1/pay</code>, <code>/v1/history</code>) — full OpenAPI 3.1.0 at <a href="${openapiUrl}">${openapiUrl}</a>.</li>
    <li><strong>Web-only chat (no tools):</strong> guide the user to open <code>${base}/</code>, click <strong>Create / Connect Agent Wallet</strong>, fund with Lightning or Base USDC, then connect <code>${mcpUrl}</code> (Auth: None).</li>
  </ul>
</div></section>

<footer><div class="wrap">
  <div>${footerLine}</div>
  <div class="fl">
    <a href="${llmsUrl}">llms.txt</a>
    <a href="${skillUrl}">skill.md</a>
    <a href="${openapiUrl}">openapi.json</a>
    <a href="/healthz">health</a>
    <a href="https://calls.nuri.com">calls.nuri.com</a>
    <a href="https://nuri.com">nuri.com</a>
  </div>
</div></footer>

<script>
(() => {
  const rootEl = document.documentElement;
  const themeBtn = document.getElementById("tt");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const dark = rootEl.dataset.theme === "dark" || (!rootEl.dataset.theme && matchMedia("(prefers-color-scheme:dark)").matches);
      rootEl.dataset.theme = dark ? "light" : "dark";
    });
  }
  const MCP_URL = ${JSON.stringify(mcpUrl)};
  const REST_URL = ${JSON.stringify(restUrl)};
  const AGENT_PROMPT = ${JSON.stringify(agentPrompt)};
  const CLAUDE_CODE_CMD = ${JSON.stringify(claudeCodeCmd)};
  const CODEX_CMD = ${JSON.stringify(codexCmd)};
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
    addrBtcLabel: $("addr-btc-label"),
    arkWrap: $("ark-addr-wrap"),
    lnurlWrap: $("lnurl-addr-wrap"),
    addrLnurl: $("addr-lnurl"),
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
    btnTestPay: $("btn-test-pay"),
    testPayStatus: $("test-pay-status"),
    testPayResult: $("test-pay-result"),
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
      const displayBtcAddr = connected.btc_address || connected.arkade_address || "";
      if (displayBtcAddr) {
        el.arkWrap.classList.remove("hidden");
        if (el.addrBtcLabel) {
          el.addrBtcLabel.textContent = connected.btc_address ? "Bitcoin L1 (2-of-2 MuSig2+CSV)" : "Arkade BTC";
        }
        el.addrArkade.textContent = displayBtcAddr;
      } else {
        el.arkWrap.classList.add("hidden");
      }
      if (el.lnurlWrap && el.addrLnurl) {
        if (connected.lnurl) {
          el.lnurlWrap.classList.remove("hidden");
          el.addrLnurl.textContent = connected.lnurl;
        } else {
          el.lnurlWrap.classList.add("hidden");
        }
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
      const primaryUrl = safeHttpsUrl(pending.approval_url);
      el.pendingOpen.href = primaryUrl || "#";
      el.pendingOpen.textContent = "Open Nuri Passkey →";
      el.pendingAltWrap.classList.add("hidden");
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
      btc_custody_mode: res.btc_custody_mode || (connected && connected.btc_custody_mode) || "",
      btc_address: res.btc_address || (connected && connected.btc_address) || "",
      arkade_address: res.arkade_address || (connected && connected.arkade_address) || "",
      lnurl: res.lnurl || (connected && connected.lnurl) || "",
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
      if (!res.request_id || !res.approval_url) {
        if (pop && !pop.closed) try { pop.close(); } catch {}
        throw new Error(res.error || "Could not start Nuri Passkey onboarding.");
      }
      pending = {
        mode,
        request_id: res.request_id,
        approval_url: res.approval_url || "",
      };
      writeStore(PENDING_KEY, pending);
      const targetUrl = safeHttpsUrl(pending.approval_url);
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
      const custodyLabel = res.btc_custody_mode === "l1_0conf" ? "into your Bitcoin L1 wallet" : "into Arkade custody";
      el.lnMeta.textContent = "Pay " + paySats + " sats (fee " + feeSats + " sats · nets " + netSats + " sats " + custodyLabel + ")";
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

  function buildCurlSnippet() {
    const key = (connected && connected.wallet_key) ? connected.wallet_key : "npw1_YOUR_WALLET_KEY";
    const body = JSON.stringify({ action: "balance", wallet_key: key });
    return "curl -sS -X POST " + REST_URL + " -H 'Content-Type: application/json' -d '" + body + "'";
  }

  async function runTestPayment() {
    if (!connected || !connected.wallet_key) return;
    showError("");
    el.btnTestPay.disabled = true;
    el.testPayResult.classList.add("hidden");
    el.testPayResult.textContent = "";
    el.testPayStatus.textContent = "Paying $0.01 USDC to mail.paymentrequired.com…";
    try {
      const reqId = "test-inbox-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 6);
      const data = await callWallet({
        action: "pay",
        wallet_key: connected.wallet_key,
        to: "https://mail.paymentrequired.com/v1/create_inbox",
        method: "POST",
        body: { request_id: reqId },
        max_amount: "0.05",
        request_id: reqId,
      });
      if (data.ok && (data.status === "done" || data.status === "paid" || data.resource || data.receipt)) {
        let body = data.resource ?? data.response ?? data;
        if (typeof body === "string") { try { body = JSON.parse(body); } catch {} }
        const email = (body && typeof body === "object")
          ? (body.address || body.email || (body.data && body.data.address) || "")
          : "";
        el.testPayStatus.textContent = "Paid $0.01!";
        el.testPayResult.textContent = email
          ? "First payment succeeded! Live agent inbox created: " + email
          : "First payment succeeded! Your wallet can now pay any x402 API, Lightning invoice, or Bitcoin address.";
        el.testPayResult.classList.remove("hidden");
        refreshBalance(true);
      } else {
        el.testPayStatus.textContent = "";
        showError(data.error || data.message || "Test payment did not complete. Make sure your wallet has at least $0.02 USDC or ~100 sats.");
      }
    } catch (err) {
      el.testPayStatus.textContent = "";
      showError(err.message || String(err));
    } finally {
      el.btnTestPay.disabled = false;
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
    el.testPayResult.classList.add("hidden");
    el.testPayStatus.textContent = "";
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
  if (el.btnTestPay) el.btnTestPay.addEventListener("click", () => runTestPayment());

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
    } else if (btn.dataset.copyText === "claude-code") {
      copyText(CLAUDE_CODE_CMD, btn);
    } else if (btn.dataset.copyText === "codex") {
      copyText(CODEX_CMD, btn);
    } else if (btn.dataset.copyText === "curl") {
      copyText(buildCurlSnippet(), btn);
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

export function serviceIndexHtml(role, { origin, btcCustodyMode } = {}) {
  if (role === "wallet") return walletIndexHtml(origin, { btcCustodyMode });
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
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/x-icon" href="/favicon.ico" sizes="any">
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
