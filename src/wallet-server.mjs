// WALLET SERVICE ENTRYPOINT (wallet.paymentrequired.com, loopback 8798).
//
// Extracted from the monolith's src/server.mjs (source c16ab56) by keeping exactly the code paths
// that run when SERVICE_MODE=wallet there, and nothing else. Every construction below names the
// source line it comes from. No Wirex client, no bank/account tool modules, no wallet_payments
// writer: the banking repository owns those and is reached only over the private loopback RPC.

import http from "node:http";
import { AsyncLocalStorage } from "node:async_hooks";
import { readFileSync } from "node:fs";
import { verifyMessage } from "ethers";
import packageInfo from "../package.json" with { type: "json" };

import { loadDotEnv, parseCorsExtraOrigins } from "./env.mjs";
import { createBrowserBridge } from "./browser-bridge.mjs";
import { createConnectionEffects } from "./mcp-connection-effects.mjs";
import { createBrowserSessionStore } from "./browser-session-store.mjs";
import { createSignerClient } from "./signer-client.mjs";
import { readServiceMode } from "./service-mode.mjs";
import { resolveWalletOrigin, serviceIndexHtml, walletLlmsTxt, walletOpenApiJson, walletSkillMd, WALLET_HOSTS } from "./service-index.mjs";
import { createServiceRpcServer, createRemoteTool } from "./service-rpc.mjs";
import { createIdentityHandoff, qualifiedIdentity } from "./identity-handoff.mjs";
import { readRootSignerConfig, createRootSignerHook } from "./signer-broker-hook.mjs";
import { readAaConfig } from "./aa-register.mjs";
import { createMcpAccount } from "./mcp-account.mjs";
import { createMcpConnection } from "./mcp-connection.mjs";
import { instructions } from "./mcp-instructions.mjs";
import { createMcpWalletTool, WALLET_TOOL } from "./mcp-wallet-tool.mjs";
import { createToolCharges, walletToolSafePayer } from "./tool-prices.mjs";
import { createShortLinks } from "./short-links.mjs";
import { createSpendPolicy } from "./spend-policy.mjs";
import { assertAgentCustodyBootEnv } from "./server-boot-check.mjs";
import { createPrivyConnectionSigner } from "./privy-wallet-signer.mjs";
import { readPrivyApp } from "./privy-apps.mjs";
import { logEvent } from "./log.mjs";
import { createKycCapabilityLimiter, kycCapabilityFingerprint } from "./kyc-capability.mjs";

loadDotEnv();

// This process is the wallet role only. readServiceMode keeps the monolith's boot boundary
// (src/service-mode.mjs:24-28: WIREX_TOKEN_URL/COMPANY_ID/CLIENT_ID/CLIENT_SECRET refused here).
if (process.env.SERVICE_MODE && process.env.SERVICE_MODE.trim().toLowerCase() !== "wallet") throw new Error("SERVICE_MODE_invalid: this is the wallet service (SERVICE_MODE=wallet or unset)");
const SERVICE = readServiceMode({ ...process.env, SERVICE_MODE: "wallet" });
// Agent custody keys are required where the agent Safe is operated (source server.mjs:58).
assertAgentCustodyBootEnv();

const VERSION = packageInfo.version;
const GIT_SHA = (process.env.GIT_SHA || "dev").slice(0, 12);
const SERVICES_JSON = readFileSync(new URL("../public/services.json", import.meta.url), "utf8");
const SHORT_LINK_HTML = readFileSync(new URL("../public/short-link.html", import.meta.url));
const SHORT_LINK_JS = readFileSync(new URL("../public/short-link.mjs", import.meta.url));
const FAVICON_SVG = readFileSync(new URL("../public/favicon.svg", import.meta.url));
const FAVICON_ICO = readFileSync(new URL("../public/favicon.ico", import.meta.url));
const APPLE_TOUCH_ICON_PNG = readFileSync(new URL("../public/apple-touch-icon.png", import.meta.url));

const HOST = process.env.HOST || "127.0.0.1";
const PORT = SERVICE.port;
const MAX_BODY_BYTES = 256 * 1024;
const MCP_PROTOCOL_VERSION = "2025-11-25";
const SUPPORTED_MCP_VERSIONS = new Set(["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]);
const PUBLIC_CORS_PATHS = new Set(["/mcp", "/v1/wallet", "/v1/balance", "/v1/receive", "/v1/pay", "/v1/history"]);
const PUBLIC_ORIGIN = new URL(process.env.PUBLIC_ORIGIN || `http://localhost:${PORT}`).origin;
const CORS_EXTRA_ORIGINS = parseCorsExtraOrigins(process.env.CORS_EXTRA_ORIGINS);

const aaConfig = readAaConfig();

// One state file for every wallet store (source server.mjs:101). The agent Safe ledger opens
// `${STATE_DB_PATH}.chain-<id>` sidecars for every extra payable chain (src/mcp-agent-wallet.mjs:225).
const STATE_DB_PATH = process.env.SHORT_LINKS_DB || "state/short-links.sqlite";
const browserSessionStore = createBrowserSessionStore({ path: STATE_DB_PATH });
process.once("exit", () => browserSessionStore?.close());
// A connect tap on a guest Safe's link is the claim; the wallet tool runs it (source server.mjs:106-111).
const browserBridge = createBrowserBridge({ publicOrigin: PUBLIC_ORIGIN, sessionStore: browserSessionStore,
  effects: createConnectionEffects({ onConnected: (session, signature) => walletLocal ? walletLocal.onTap(session, signature) : null,
    recordConnected: (session, signature, options) => walletLocal.recordTap(session, signature, options) }) });

const privyConnectionSigner = createPrivyConnectionSigner();
const signerClient = createSignerClient({ bridge: browserBridge, connectionSigner: privyConnectionSigner });
const shortLinks = createShortLinks({ publicBase: browserBridge.publicBase, path: STATE_DB_PATH });
process.once("exit", () => shortLinks.close());

// Identity only (source server.mjs:140-145 with wirexBaas=null, onboardingFollowup=null): the wallet
// uses accountFlow.authorized/completeAuthorization; account advance/create are banking-only.
const mcpAccount = createMcpAccount({ bridge: signerClient, wirexBaas: null, aaConfig, connectionSigner: signerClient });

const closables = [];
process.once("exit", () => { for (const closable of closables) closable.close(); });
const onExit = (closable) => { if (closable?.close) closables.push(closable); return closable; };
// Safe limits: keys safe:<address> (source server.mjs:160).
const spendPolicy = onExit(createSpendPolicy({ path: STATE_DB_PATH }));

// Private RPC peers (source server.mjs:182-191). The wallet owns no banking tool.
const rpcPeer = (url, tool) => (url && SERVICE.rpcSecret ? createRemoteTool({ baseUrl: url, secret: SERVICE.rpcSecret, tool }) : null);
const HELPER = { name: "helper" };
const bankingHelper = rpcPeer(SERVICE.bankingRpcUrl, HELPER);
const legacyHelper = rpcPeer(SERVICE.legacyRpcUrl, HELPER);
const identityHandoff = createIdentityHandoff({ bridge: browserBridge,
  peers: [{ name: "banking", client: bankingHelper }, { name: "legacy", client: legacyHelper }] });
// Bank top-up from the person's account (src/mcp-wallet-tool.mjs:436-440) goes to banking's bank tool.
const bankTool = rpcPeer(SERVICE.bankingRpcUrl, { name: "bank" });
// Reads of the person's own bank account (reserve in balance, funding): the same four method
// names, served by banking for the owner its row proves (source server.mjs:193-198, 276-279).
const walletCallContext = new AsyncLocalStorage();
const WIREX_READS = ["getUserV2", "getWallet", "listWallets", "createGlobalWallet"];
const walletWirex = bankingHelper ? Object.fromEntries(WIREX_READS.map((method) => [method, (owner, ...rest) =>
  bankingHelper.call({ op: "wirex_read", method, owner, rest, session: walletCallContext.getStore() ?? null })])) : null;

// Root signer broker consumer "wallet" (source server.mjs:247-248); unset ROOT_SIGNER_URL = local taps only.
const rootSignerHook = await createRootSignerHook({ bridge: browserBridge, config: readRootSignerConfig(process.env, { consumerId: "wallet" }) });
// The wallet tool (source server.mjs:203-206; walletPay=null there: bank-root pay is banking's).
// consolidate=false: the split wallet never sends from older wallets (src/mcp-wallet-tool.mjs:207).
const walletLocal = createMcpWalletTool({ accountFlow: mcpAccount, chainId: aaConfig.chainId, path: STATE_DB_PATH, wirexBaas: walletWirex, bridge: signerClient, walletPay: null, spendPolicy,
  publicBase: browserBridge.publicBase, bank: bankTool, services: JSON.parse(SERVICES_JSON), safeLimits: spendPolicy, consolidate: false,
  broker: rootSignerHook }); // guest claim links register with the signer like connect links (src/mcp-wallet-tool.mjs connectLink)
const walletTool = { ...walletLocal, call: (args, ctx) => walletCallContext.run(typeof args?.session === "string" ? args.session : null, () => walletLocal.call(args, ctx)) };
process.once("exit", () => { walletTool?.close?.(); bankTool?.close?.(); });

// Unattended LNURL claim sweep: pending username@nuriwallet.com receives are
// claimed into their wallet's Arkade VTXOs without any Passkey session.
walletLocal.startLnurlAutoClaim?.();

// Tool prices: the one tool_charges journal lives here, paid by the agent Safe (source server.mjs:221).
const toolCharges = createToolCharges({ env: process.env, path: STATE_DB_PATH, chainId: aaConfig.chainId, payWithSafe: walletToolSafePayer(walletLocal) });
process.once("exit", () => toolCharges.close());
if (toolCharges.enabled) console.log(`tool prices: ${toolCharges.prices.size} priced entr${toolCharges.prices.size === 1 ? "y" : "ies"}, paid to ${toolCharges.payTo}`);

// The wallet's own loopback /mcp lists the wallet tool; account and bank are served by banking.
const mcpConnection = createMcpConnection({ bridge: signerClient, accountFlow: mcpAccount, wallet: walletTool, chainId: aaConfig.chainId, wirexBaas: null, charges: toolCharges,
  broker: rootSignerHook, connectAdvance: false, identity: identityHandoff });

// Private RPC server (source server.mjs:253-295, wallet branches): wallet (+pay_fee), helper, bridge.
const rpcTools = new Map();
rpcTools.set(WALLET_TOOL.name, { tool: WALLET_TOOL, call: (args, ctx) => args?.action === "pay_fee" ? walletLocal.payFee(args) : walletTool.call(args, ctx) });
rpcTools.set(HELPER.name, { tool: HELPER, call: async (args, { signal } = {}) => {
  if (args.op === "identity") return qualifiedIdentity(mcpAccount, args.session);
  if (args.op === "safe_address") return walletLocal.safeAddressFor(args.session, { signal });
  if (args.op === "charge") return toolCharges.charge(String(args.name), args.args ?? {}, { signal });
  if (args.op === "remember") return toolCharges.remember(String(args.name), args.charged, args.answer) ?? null;
  if (args.op === "l1_pool_status") return walletLocal.l1PoolStatus();
  if (args.op === "on_tap") {
    // Bound to the wallet's OWN row for the tapped link: walletId, consent text, pinned root and app
    // come from that row, never from the caller. The row stays as is.
    const tap = args.tap ?? {};
    let row; try { row = browserBridge.requireSession(String(tap.session_id)); } catch { throw new Error("tap_unknown"); }
    const walletId = row.context?.walletId;
    if (row.context?.kind !== "mcp_connection" || typeof walletId !== "string" || typeof row.signText !== "string" || tap.message !== row.signText) throw new Error("tap_unbound");
    const signer = verifyMessage(row.signText, String(tap.signature));
    if (signer.toLowerCase() !== String(tap.owner).toLowerCase() || (row.expectedAddress && row.expectedAddress.toLowerCase() !== signer.toLowerCase())
      || (row.privyAppId && tap.privy_app_id && row.privyAppId !== tap.privy_app_id)) throw new Error("tap_unverified");
    return walletLocal.onTap({ context: { walletId }, result: { signer } }, typeof tap.agent_signature === "string" ? tap.agent_signature : undefined);
  }
  throw new Error("helper_op_unknown");
} });
// Bridge callbacks the legacy facade forwards for rows this wallet holds: replayed against the
// same route handler as a direct tap (source server.mjs:284-292).
rpcTools.set("bridge", { tool: { name: "bridge" }, call: async ({ session_id, suffix, method, body, query }) => {
  const target = new URL(`/api/browser-sessions/${encodeURIComponent(session_id)}${suffix || ""}`, `http://127.0.0.1:${PORT}`);
  for (const [key, value] of Object.entries(query || {})) target.searchParams.set(key, value);
  const response = await fetch(target, { method, headers: body ? { "content-type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  const text = await response.text();
  let json; try { json = JSON.parse(text); } catch { json = { error: text.slice(0, 200) }; }
  if (/session_unknown|session_not_found/.test(text)) throw new Error("session_unknown"); // not this owner's row: facade tries the other owner
  return { status: response.status, body: json };
} });
const serviceRpc = createServiceRpcServer({ secret: SERVICE.rpcSecret, readJson, writeJson, tools: rpcTools,
  ensure: (session, ctx) => identityHandoff.ensure(session, ctx) });

const mcpTools = mcpConnection.tools();
const WIRE_TOOLS = mcpTools.map(({ outputSchema, ...tool }) => tool);
const INITIALIZE_INSTRUCTIONS = instructions(mcpTools.map((tool) => tool.name));
const HOME_BY_ORIGIN = new Map(WALLET_HOSTS.map((h) => [`https://${h}`, serviceIndexHtml("wallet", { origin: `https://${h}` })]));
const LLMS_BY_ORIGIN = new Map(WALLET_HOSTS.map((h) => [`https://${h}`, walletLlmsTxt(`https://${h}`)]));
const SKILL_BY_ORIGIN = new Map(WALLET_HOSTS.map((h) => [`https://${h}`, walletSkillMd(`https://${h}`)]));
const OPENAPI_BY_ORIGIN = new Map(WALLET_HOSTS.map((h) => [`https://${h}`, JSON.stringify(walletOpenApiJson(`https://${h}`), null, 2)]));
const REST_ACTION_ROUTES = new Map([
  ["/v1/wallet", null],
  ["/v1/balance", "balance"],
  ["/v1/receive", "receive"],
  ["/v1/pay", "pay"],
  ["/v1/history", "history"],
]);
const pendingApprovalLimiter = createKycCapabilityLimiter();
const FRONTER_STATUS_CACHE_TTL_MS = 15_000;
let cachedFronterStatus = null;
let cachedFronterStatusAt = 0;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || `${HOST}:${PORT}`}`);
    if (req.method === "OPTIONS") return writeJson(req, res, 204, {});
    if (url.pathname === "/s" && req.method === "GET") return writeHtml(req, res, 200, SHORT_LINK_HTML);
    if (url.pathname === "/short-link.mjs" && req.method === "GET") return writeRaw(req, res, 200, SHORT_LINK_JS, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
    if (url.pathname === "/s" && req.method === "POST") {
      const target = shortLinks.resolve((await readJson(req))?.token);
      return writeJson(req, res, target ? 200 : 404, target ? { url: target } : { error: "link_unavailable" });
    }
    if (await serviceRpc(req, res, url)) return;
    if (url.pathname === "/healthz") {
      return writeJson(req, res, 200, { ok: true, version: VERSION, git_sha: GIT_SHA, built_at: process.env.BUILT_AT || null, built_by: process.env.BUILT_BY || null, release_phase: "prototyping",
        tools: mcpTools.map((tool) => tool.name), service_mode: SERVICE.mode, public_base: browserBridge.publicBase, aa_rpc: aaConfig.bundlerUrl,
        btc_custody_mode: String(process.env.AGENT_BTC_CUSTODY_MODE || "arkade").trim().toLowerCase(), l1_0conf_fronter_supported: true,
        l1_pool_configured: Boolean(process.env.FRONTER_ARKADE_PRIVKEY_HEX && (process.env.FRONTER_L1_DEPOSIT_ADDRESS || process.env.FRONTER_L1_PRIVKEY_HEX || process.env.FRONTER_ARKADE_PRIVKEY_HEX)) });
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/v1/fronter/status") {
      const custodyMode = String(process.env.AGENT_BTC_CUSTODY_MODE || "arkade").trim().toLowerCase();
      if (custodyMode !== "l1_0conf") {
        return writeJson(req, res, 200, { ok: true, btc_custody_mode: custodyMode, enabled: false });
      }
      const now = Date.now();
      if (!cachedFronterStatus || now - cachedFronterStatusAt > FRONTER_STATUS_CACHE_TTL_MS) {
        const status = await walletLocal.l1PoolStatus();
        cachedFronterStatus = {
          ok: true,
          btc_custody_mode: "l1_0conf",
          enabled: true,
          cached_at: new Date(now).toISOString(),
          ...status,
        };
        cachedFronterStatusAt = now;
      }
      return writeJson(req, res, 200, cachedFronterStatus);
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/") {
      const origin = resolveWalletOrigin(req);
      return writeHtml(req, res, 200, HOME_BY_ORIGIN.get(origin) || serviceIndexHtml("wallet", { origin }), {
        "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
        Vary: "Host, X-Forwarded-Host",
      });
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/llms.txt") {
      const origin = resolveWalletOrigin(req);
      return writeText(req, res, 200, LLMS_BY_ORIGIN.get(origin) || walletLlmsTxt(origin), "text/plain; charset=utf-8");
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/skill.md") {
      const origin = resolveWalletOrigin(req);
      return writeText(req, res, 200, SKILL_BY_ORIGIN.get(origin) || walletSkillMd(origin), "text/markdown; charset=utf-8");
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/openapi.json") {
      const origin = resolveWalletOrigin(req);
      return writeText(req, res, 200, OPENAPI_BY_ORIGIN.get(origin) || JSON.stringify(walletOpenApiJson(origin), null, 2), "application/json; charset=utf-8");
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/favicon.svg") {
      return writeAsset(req, res, 200, FAVICON_SVG, "image/svg+xml");
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/favicon.ico") {
      return writeAsset(req, res, 200, FAVICON_ICO, "image/x-icon");
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/apple-touch-icon.png") {
      return writeAsset(req, res, 200, APPLE_TOUCH_ICON_PNG, "image/png");
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/robots.txt") {
      const origin = resolveWalletOrigin(req);
      return writeText(req, res, 200, `User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`, "text/plain; charset=utf-8");
    }
    if ((req.method === "GET" || req.method === "HEAD") && url.pathname === "/sitemap.xml") {
      const origin = resolveWalletOrigin(req);
      const urls = ["/", "/llms.txt", "/skill.md", "/openapi.json"]
        .map((p) => `  <url><loc>${origin}${p}</loc></url>`).join("\n");
      return writeText(req, res, 200, `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`, "application/xml; charset=utf-8");
    }
    // LNURL-pay for username@nuriwallet.com: public, no auth (source of truth is
    // the PRF handle registry; payments settle as Arkade VTXOs via the RFQ solver).
    {
      const lnurlMatch = /^\/(?:\.well-known\/lnurlp|lnurl\/callback)\/([A-Za-z0-9._-]{1,64})$/.exec(url.pathname);
      if (req.method === "GET" && lnurlMatch) {
        const isCallback = url.pathname.startsWith("/lnurl/callback/");
        const result = await walletTool.call({
          action: "lnurl",
          lnurl_username: lnurlMatch[1],
          ...(isCallback ? { lnurl_op: "callback", amount_msat: Number(url.searchParams.get("amount")) } : {}),
        });
        if (!result?.ok) {
          const status = Number(result?.status) || (String(result?.error) === "lnurl_handle_unknown" ? 404 : 400);
          return writeJson(req, res, status, { status: "ERROR", reason: String(result?.error || "lnurl_failed") });
        }
        if (isCallback) {
          if (typeof result.pr !== "string" || !result.pr) {
            return writeJson(req, res, 502, { status: "ERROR", reason: "lnurl_invoice_failed" });
          }
          return writeJson(req, res, 200, { status: "OK", pr: result.pr, routes: [] });
        }
        return writeJson(req, res, 200, result.payRequest);
      }
    }
    if (REST_ACTION_ROUTES.has(url.pathname)) {
      return await handleRestWallet(req, res, REST_ACTION_ROUTES.get(url.pathname));
    }
    if ((url.pathname === "/bridge/privy" || url.pathname === "/bridge/privy/") && req.method === "GET") {
      return writePrivyHtml(req, res, 200, await browserBridge.privyBridgeHtml());
    }
    // Retained partner-"wirex" connect links keep their page (src/browser-bridge.mjs:247).
    if ((url.pathname === "/bridge/privy/wirex" || url.pathname === "/bridge/privy/wirex/") && req.method === "GET") {
      return writePrivyHtml(req, res, 200, await browserBridge.privyBridgeHtml("wirex"));
    }
    if (url.pathname === "/bridge/privy.js" && req.method === "GET") {
      return writeRaw(req, res, 200, await browserBridge.privyBridgeJs(), { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" });
    }
    if (url.pathname === "/api/browser-sessions/pending" && req.method === "GET") {
      const lineage = url.searchParams.get("lineage") || "";
      if (pendingApprovalLimiter.isLimited(kycCapabilityFingerprint(lineage))) {
        return writeJson(req, res, 429, { ok: false, error: "rate_limited" }, { "Cache-Control": "no-store", "Retry-After": "60" });
      }
      return writePageJson(req, res, 200, signerClient.newestPendingApproval(lineage), { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
    }
    const match = /^\/api\/browser-sessions\/([A-Za-z0-9_-]{16,128})(\/(?:callback|approval|connection))?$/.exec(url.pathname);
    if (match) {
      const [, sessionId, suffix] = match;
      if (suffix === "/connection") {
        if (req.method !== "POST") throw new HttpError(405, "method_not_allowed");
        const pageJson = (status, body) => writePageJson(req, res, status, body, { "Cache-Control": "no-store" });
        const session = signerClient.requireSession(sessionId);
        const body = await readJson(req);
        if (session.context.kind !== "mcp_connection" || session.signerAdapter !== "privy"
          || body.state !== session.state || Date.now() >= session.expiresAt) throw new HttpError(403, "connection_unavailable");
        if (Object.keys(body).some(key => !["state", "authorization", "payment_id", "payment_signature"].includes(key))) throw new HttpError(400, "connection_arguments_invalid");
        if (body.authorization) await mcpAccount.completeAuthorization(sessionId, body.authorization);
        // Buy continuations (wallet_payments) belong to banking: an explicit refusal, never a fake "connected" (source server.mjs:463).
        if (body.payment_signature !== undefined || typeof session.context.buyPaymentId === "string") throw new HttpError(409, "payment_continuation_unavailable");
        if (session.status === "pending") return pageJson(200, { status: "ownership_required" });
        // The approved tap is the whole wallet connection: no account advance here (source server.mjs:474).
        return pageJson(200, { status: "connected" });
      }
      if (suffix === "/callback") {
        if (req.method !== "POST") throw new HttpError(405, "method_not_allowed");
        const accepted = await browserBridge.acceptCallback(sessionId, await readJson(req));
        const approved = await signerClient.approved(sessionId);
        // Bank-root pay approvals continue on banking only (source server.mjs:487-491 with walletPay=null).
        if (approved?.context?.kind === "mcp_wallet_pay") {
          return writeJson(req, res, 200, { ...accepted, payment: { payment_id: approved.context.paymentId, state: "unconfirmed", error: "payment_continuation_blocked" } }, { "Cache-Control": "no-store" });
        }
        return writeJson(req, res, 200, accepted, { "Cache-Control": "no-store" });
      }
      if (suffix === "/approval") {
        if (!["GET", "POST"].includes(req.method)) throw new HttpError(405, "method_not_allowed");
        // GET is the approval page's read (src/privy-bridge-client.mjs:51-58); a non-pay row reads the
        // bridge payload, exactly what the pay module delegates to (source mcp-wallet-pay.mjs:1597-1599).
        const payload = req.method === "POST"
          ? signerClient.prepareApproval(sessionId, (await readJson(req))?.state || "")
          : signerClient.readApprovalPayload(sessionId, url.searchParams.get("state") || "");
        return writeJson(req, res, 200, payload, { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
      }
      if (req.method !== "GET") throw new HttpError(405, "method_not_allowed");
      return writeJson(req, res, 200, await signerClient.readStatus(sessionId));
    }
    // An agent given only the host (banking.paymentrequired.com) POSTs to "/": serve MCP there too,
    // so the bare host is a working MCP URL. GET "/" stays the human page.
    if (url.pathname === "/mcp" || (url.pathname === "/" && req.method !== "GET" && req.method !== "HEAD")) return await handleMcp(req, res);
    writeJson(req, res, 404, { ok: false, error: "not_found" });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    logRequestError(req, status, error);
    writeJson(req, res, status, errorBody(error));
  }
});

process.on("unhandledRejection", (reason) => console.error("[unhandledRejection]", reason));

for (const partner of ["nuri", "wirex"]) {
  const app = readPrivyApp(process.env, partner);
  const prefix = partner === "wirex" ? "WIREX_PRIVY_" : "PRIVY_";
  if (app.proxyUrl && app.appSecret) console.log(`${prefix}APP_SECRET is ignored while ${prefix}PROXY_URL is set — remove it from the wallet env.`);
  if (app.proxyUrl) delete process.env[`${prefix}APP_SECRET`];
}

server.listen(PORT, HOST, () => {
  console.log(`paymentrequired wallet listening on http://${HOST}:${PORT} | public base: ${browserBridge.publicBase} | service: ${SERVICE.mode}`);
});

async function handleRestWallet(req, res, fixedAction) {
  const reqOrigin = resolveWalletOrigin(req);
  if (req.method === "GET" || req.method === "HEAD") {
    return writeText(
      req,
      res,
      200,
      `# Plain HTTP REST Wallet Endpoint (${reqOrigin}${req.url || "/v1/wallet"})\n\nSend POST JSON here (no OAuth, no MCP required). Full instructions:\n\n${LLMS_BY_ORIGIN.get(reqOrigin) || walletLlmsTxt(reqOrigin)}`,
      "text/plain; charset=utf-8",
    );
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST, OPTIONS");
    return writeJson(req, res, 405, { ok: false, error: "method_not_allowed", hint: `POST JSON to this URL. Docs: ${reqOrigin}/llms.txt | OpenAPI: ${reqOrigin}/openapi.json` });
  }
  const body = await readJson(req);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return writeJson(req, res, 400, { ok: false, error: "invalid_request", message: "Request body must be a JSON object." });
  }
  const args = { ...body };
  if (fixedAction) args.action = fixedAction;
  else if (!args.action) args.action = "balance";
  if (!args.wallet_key && typeof req.headers.authorization === "string") {
    const m = /^Bearer\s+(npw1_\S+)$/i.exec(req.headers.authorization.trim());
    if (m) args.wallet_key = m[1];
    else if (!args.session) args.session = req.headers.authorization;
  }
  if (res.destroyed) return;
  const controller = new AbortController();
  const cancel = () => controller.abort();
  res.once("close", cancel);
  try {
    const result = await mcpConnection.call("wallet", args, { signal: controller.signal });
    if (!res.destroyed) {
      const payload = result.structuredContent ?? { ok: !result.isError };
      return writeJson(req, res, result.isError ? 400 : 200, payload);
    }
  } catch (error) {
    const data = { ok: false, status: "failed", error: String(error.message || error).replace(/^wirex_/, "provider_") };
    if (error?.next_action && typeof error.next_action === "object") data.next_action = error.next_action;
    if (Array.isArray(error?.allowed_merchants)) data.allowed_merchants = error.allowed_merchants;
    if (!res.destroyed) return writeJson(req, res, 400, data);
  } finally { res.off("close", cancel); }
}

async function handleMcp(req, res) {
  const reqOrigin = resolveWalletOrigin(req);
  if (req.method === "GET" || req.method === "HEAD") {
    const accept = String(req.headers.accept || "").toLowerCase();
    // Streamable HTTP MCP clients probing GET SSE stream expect 405 when SSE is unsupported.
    // Web fetchers / LLMs / browsers (Accept: */*, text/html, text/plain) get 200 + full setup instructions.
    const wantsSseOnly = accept.includes("text/event-stream") && !accept.includes("text/html") && !accept.includes("*/*");
    if (wantsSseOnly) {
      res.setHeader("Allow", "POST, OPTIONS");
      return writeJson(req, res, 405, { ok: false, error: "method_not_allowed", hint: `POST JSON-RPC to this URL. Start: ${reqOrigin}/llms.txt` });
    }
    return writeText(
      req,
      res,
      200,
      `# Live Remote MCP Server — ${reqOrigin}/mcp\n\nThis URL is a real, live, authless Streamable HTTP MCP endpoint (POST JSON-RPC, Auth: None, no OAuth).\nTo connect in Claude or ChatGPT: Settings -> Connectors / Apps -> Add Custom Connector -> URL: ${reqOrigin}/mcp (Auth: None).\n\n${LLMS_BY_ORIGIN.get(reqOrigin) || walletLlmsTxt(reqOrigin)}`,
      "text/plain; charset=utf-8",
    );
  }
    if (req.method === "DELETE") {
      return writeJson(req, res, 204, {});
    }
    if (req.method !== "POST") {
      res.setHeader("Allow", "GET, POST, DELETE, OPTIONS");
      return writeJson(req, res, 405, { ok: false, error: "method_not_allowed", hint: `POST JSON-RPC to this URL. Start: ${reqOrigin}/llms.txt` });
    }
    const message = await readJson(req);
    if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") return writeJson(req, res, 200, mcpError(message?.id ?? null, -32600, "Invalid Request"));
    if (message.method === "notifications/initialized") return writeJson(req, res, 202, {});
    if (message.method === "initialize") {
      const requestedVersion = typeof message.params?.protocolVersion === "string" ? message.params.protocolVersion.trim() : "";
      const protocolVersion = SUPPORTED_MCP_VERSIONS.has(requestedVersion) ? requestedVersion : MCP_PROTOCOL_VERSION;
      return writeJson(req, res, 200, mcpResult(message.id, {
        protocolVersion,
        capabilities: { tools: {} },
        serverInfo: {
          name: "paymentrequired-wallet",
          title: `${new URL(reqOrigin).host} — wallet for AI agents`,
          version: VERSION,
          websiteUrl: reqOrigin,
          icons: [
            { src: `${reqOrigin}/favicon.svg`, mimeType: "image/svg+xml" },
            { src: `${reqOrigin}/apple-touch-icon.png`, mimeType: "image/png", sizes: ["180x180"] },
          ],
        },
        instructions: INITIALIZE_INSTRUCTIONS,
      }));
    }
  if (message.method === "tools/list") return writeJson(req, res, 200, mcpResult(message.id, { tools: WIRE_TOOLS }));
  if (message.method === "tools/call") {
    const name = message.params?.name;
    const input = message.params?.arguments ?? {};
    if (typeof name !== "string" || !mcpTools.some((tool) => tool.name === name)) {
      return writeJson(req, res, 200, mcpError(message.id, -32602, `There is no tool called ${JSON.stringify(name ?? null)} here. The tools this service offers are: ${mcpTools.map((tool) => tool.name).join(", ")}.`));
    }
    if (typeof input !== "object" || Array.isArray(input) || message.params?.arguments === null) {
      return writeJson(req, res, 200, mcpError(message.id, -32602, "The arguments must be one JSON object holding the tool's fields, sent as the arguments member of the request."));
    }
    const args = { ...input };
    if (!args.session && req.headers.authorization) args.session = req.headers.authorization;
    if (res.destroyed) return;
    const controller = new AbortController();
    const cancel = () => controller.abort();
    res.once("close", cancel);
    try {
      const result = await mcpConnection.call(name, args, { signal: controller.signal });
      if (!res.destroyed) return writeJson(req, res, 200, mcpResult(message.id, toolResult(result.structuredContent, result.isError)));
    } catch (error) {
      const data = { ok: false, status: "failed", error: String(error.message || error).replace(/^wirex_/, "provider_") };
      if (error?.next_action && typeof error.next_action === "object") data.next_action = error.next_action;
      if (Array.isArray(error?.allowed_merchants)) data.allowed_merchants = error.allowed_merchants;
      if (!res.destroyed) return writeJson(req, res, 200, mcpResult(message.id, toolResult(data, true)));
    } finally { res.off("close", cancel); }
    return;
  }
  writeJson(req, res, 200, mcpError(message.id, -32601, `Method not found: ${message.method}`));
}

async function readJson(req) {
  if (req.body !== undefined) return req.body;
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, "request_body_too_large");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  try { return JSON.parse(text); }
  catch { throw new HttpError(400, "That request body is not valid JSON, so nothing ran. Check the body and send it again."); }
}

function writeJson(_req, res, status, body, extraHeaders = {}) {
  sendJson(_req, res, status, JSON.stringify(shortLinks.format(body), null, 2), extraHeaders);
}
function writePageJson(req, res, status, body, extraHeaders = {}) {
  sendJson(req, res, status, JSON.stringify(body, null, 2), extraHeaders);
}
function sendJson(req, res, status, payload, extraHeaders = {}) {
  const pathname = String(req.url || "/").split("?")[0];
  const isPublicStateless = PUBLIC_CORS_PATHS.has(pathname);
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Methods": isPublicStateless ? "GET, POST, DELETE, OPTIONS" : "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, authorization, mcp-protocol-version, mcp-session-id, last-event-id",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders,
  };
  if (isPublicStateless) {
    headers["Access-Control-Allow-Origin"] = "*";
    headers["Access-Control-Expose-Headers"] = "mcp-protocol-version, mcp-session-id";
  } else {
    const origin = allowedCorsOrigin(req.headers.origin);
    if (origin) { headers["Access-Control-Allow-Origin"] = origin; headers.Vary = "Origin"; }
  }
  res.writeHead(status, headers);
  if (status === 204 || req.method === "HEAD") return res.end();
  res.end(payload);
}
function writeAsset(req, res, status, body, contentType) {
  const headers = {
    "Content-Type": contentType,
    "Cache-Control": "public, max-age=86400",
    "Cross-Origin-Resource-Policy": "cross-origin",
    "X-Content-Type-Options": "nosniff",
  };
  res.writeHead(status, headers);
  if (req.method === "HEAD") return res.end();
  res.end(body);
}
function writeHtml(req, res, status, body, extraHeaders = {}) {
  writeRaw(req, res, status, body, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": [
      "default-src 'none'", "base-uri 'none'", "connect-src 'self' http://127.0.0.1:* http://localhost:*",
      "form-action 'none'", "frame-ancestors 'none'", "img-src 'self' data:", "object-src 'none'",
      "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'", "worker-src blob:",
    ].join("; "),
    ...extraHeaders,
  });
}
function writeText(req, res, status, body, contentType) {
  writeRaw(req, res, status, body, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "cross-origin",
    Vary: "Host, X-Forwarded-Host",
  });
}
const EMBED_ANCESTORS = ["'self'", ...CORS_EXTRA_ORIGINS].join(" ");
const EMBED_PERMISSIONS = ["self", ...[...CORS_EXTRA_ORIGINS].map((origin) => `"${origin}"`)].join(" ");
function writePrivyHtml(req, res, status, body) {
  writeRaw(req, res, status, body, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
    ...(CORS_EXTRA_ORIGINS.size ? { "X-Frame-Options": null, "Cross-Origin-Resource-Policy": "cross-origin" } : {}),
    "Permissions-Policy": `publickey-credentials-get=(${EMBED_PERMISSIONS}), publickey-credentials-create=(${EMBED_PERMISSIONS})`,
    "Content-Security-Policy": [
      "default-src 'self'",
      "base-uri 'self'",
      "child-src https://auth.privy.io https://verify.walletconnect.com https://verify.walletconnect.org",
      "connect-src 'self' http://127.0.0.1:* http://localhost:* https://auth.privy.io wss://relay.walletconnect.com wss://relay.walletconnect.org wss://www.walletlink.org https://*.rpc.privy.systems https://explorer-api.walletconnect.com https://challenges.cloudflare.com",
      "form-action 'self'",
      `frame-ancestors ${EMBED_ANCESTORS}`,
      "frame-src https://auth.privy.io https://verify.walletconnect.com https://verify.walletconnect.org https://challenges.cloudflare.com",
      "img-src 'self' data: blob:",
      "object-src 'none'",
      "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
      "style-src 'self' 'unsafe-inline'",
      "worker-src 'self' blob:",
    ].join("; "),
  });
}
function writeRaw(_req, res, status, body, extraHeaders = {}) {
  const headers = {
    "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    ...extraHeaders,
  };
  for (const [name, value] of Object.entries(headers)) if (value === null) delete headers[name];
  res.writeHead(status, headers);
  res.end(body);
}
function allowedCorsOrigin(origin) {
  if (!origin) return "";
  try {
    const url = new URL(origin);
    if (isNuriHost(url.hostname)) return url.origin;
    if ((url.protocol === "http:" || url.protocol === "https:") && isLocalDevHost(url.hostname)) return url.origin;
    if (CORS_EXTRA_ORIGINS.has(url.origin)) return url.origin;
  } catch { return ""; }
  return "";
}
function isNuriHost(h) { h = String(h || "").toLowerCase(); return h === "nuri.com" || h.endsWith(".nuri.com"); }
function isLocalDevHost(h) { return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]"; }
function mcpResult(id, result) { return { jsonrpc: "2.0", id, result }; }
function mcpError(id, code, message) { return { jsonrpc: "2.0", id, error: { code, message } }; }
function toolResult(data, isError = data?.ok === false) { data = shortLinks.format(data); return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }], structuredContent: data, isError }; }
function errorBody(error) {
  const next = error?.next_action && typeof error.next_action === "object" ? { next_action: error.next_action } : {};
  const merchants = Array.isArray(error?.allowed_merchants) ? { allowed_merchants: error.allowed_merchants } : {};
  return { ok: false, error: error instanceof Error ? error.message : String(error), ...next, ...merchants };
}
function logRequestError(req, status, error) {
  if (status < 500) return;
  const url = String(req.url || "").replace(/\/api\/browser-sessions\/[A-Za-z0-9_-]+/g, "/api/browser-sessions/<session>").replace(/([?&]state=)[A-Za-z0-9_-]+/g, "$1<state>");
  logEvent("error", "request_failed", { method: req.method, url, status, error: error instanceof Error ? error.message : String(error) });
}
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
