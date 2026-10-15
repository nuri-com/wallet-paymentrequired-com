// PRIVATE SERVICE RPC (C0 §3): the explicit authenticated HTTP boundary between the wallet
// process, the banking process and the legacy facade. One route, POST /rpc/tool, one shape:
// { tool, args } -> the tool's own answer, unchanged (same ids, same statuses). Nothing is
// public: the route needs the shared SERVICE_RPC_SECRET (timing-safe) and binds to 127.0.0.1.
//
// Identity handoff (C0 §3): the caller forwards the person's private pass (args.session)
// exactly as the client sent it; the recipient authorizes it against ITS OWN session row, so
// no root is ever asserted across the boundary. A row that only exists on the other side is
// first qualified by `ensure` (src/identity-handoff.mjs: the owning service authorizes the pass
// against its hashed row, the recipient re-verifies the root signature); a peer that is down
// leaves it absent, which is the normal connect_required answer, never an elevation.

import crypto from "node:crypto";

function timingSafeEqualStrings(a, b) {
  const left = Buffer.from(String(a ?? "")), right = Buffer.from(String(b ?? ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

// Server side: returns a handler the http server calls first; false when the url is not ours.
export function createServiceRpcServer({ secret, tools = new Map(), readJson, writeJson, ensure = null } = {}) {
  if (!secret || String(secret).length < 32) throw new Error("SERVICE_RPC_SECRET_required_32_chars");
  return async function handle(req, res, url) {
    if (url.pathname !== "/rpc/tool") return false;
    if (req.method !== "POST") { writeJson(req, res, 405, { ok: false, error: "method_not_allowed" }); return true; }
    const auth = String(req.headers.authorization || "");
    if (!auth.startsWith("Bearer ") || !timingSafeEqualStrings(auth.slice(7), secret)) { writeJson(req, res, 401, { ok: false, error: "unauthorized" }); return true; }
    const body = await readJson(req);
    const entry = typeof body?.tool === "string" ? tools.get(body.tool) : null;
    if (!entry) { writeJson(req, res, 404, { ok: false, error: "tool_unknown" }); return true; }
    const args = body.args && typeof body.args === "object" && !Array.isArray(body.args) ? body.args : {};
    const controller = new AbortController();
    const cancel = () => controller.abort();
    res.once("close", cancel);
    try {
      // The identity op itself never triggers a handoff (no A->B->A loop): it answers from this row only.
      if (ensure && typeof args.session === "string" && args.op !== "identity") await ensure(args.session, { signal: controller.signal }).catch(() => false);
      const data = await entry.call(args, { signal: controller.signal });
      if (!res.destroyed) writeJson(req, res, 200, { ok: true, data });
    } catch (error) {
      if (!res.destroyed) writeJson(req, res, 200, { ok: false, error: String(error?.message || error), ...(error?.next_action ? { next_action: error.next_action } : {}) });
    } finally { res.off("close", cancel); }
    return true;
  };
}

// Client side: looks exactly like a local tool entry ({ tool, call }) so the legacy facade and
// the cross-service consumers (wallet -> bank top-up, account limits -> wallet safe address)
// keep their current call sites. A remote outage is an error answer, never a duplicate send.
export function createRemoteTool({ baseUrl, secret, tool, fetchImpl = globalThis.fetch } = {}) {
  if (typeof baseUrl !== "string" || !/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(baseUrl.replace(/\/+$/, ""))) throw new Error("service_rpc_url_must_be_loopback");
  if (!secret || String(secret).length < 32) throw new Error("SERVICE_RPC_SECRET_required_32_chars");
  if (!tool || typeof tool.name !== "string") throw new Error("service_rpc_tool_required");
  const root = baseUrl.replace(/\/+$/, "");
  // The call may have run: never "nothing was sent"; the same request_id continues the same operation.
  const unknown = () => ({ ok: false, status: "unknown", error: `service_unconfirmed: the ${tool.name} service did not confirm this call, so it may have run. Repeat the same call with the same request_id to see its result; do not start a new one.` });
  async function call(args = {}, { signal } = {}) {
    let response;
    try {
      response = await fetchImpl(`${root}/rpc/tool`, { method: "POST", signal, cache: "no-store",
        headers: { authorization: `Bearer ${secret}`, "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ tool: tool.name, args }) });
    } catch (error) {
      // Only a refused connection proves the call never arrived; anything later may have run.
      if (error?.cause?.code === "ECONNREFUSED") return { ok: false, status: "failed", error: `service_unavailable: the ${tool.name} service is not running. Nothing was sent. Try again in a moment.` };
      return unknown();
    }
    let json = null;
    try { json = await response.json(); } catch { json = null; }
    if (!response.ok || !json || typeof json !== "object") return unknown();
    if (json.ok === false) { const error = new Error(json.error || "service_error"); if (json.next_action) error.next_action = json.next_action; throw error; }
    return json.data;
  }
  return { tool, call, remote: true, close() {} };
}
