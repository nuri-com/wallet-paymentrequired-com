import { connectionTtlMs } from "./browser-bridge.mjs";









export const NEXT_ACTION_SCHEMA = { type: ["object", "string"], properties: {
  type: { type: "string" }, tool: { type: "string" }, args: { type: "object" },
  url: { type: "string" }, signer: { type: "string" }, address: { type: "string" },
  chain_id: { type: "integer" }, asset: { type: "string" }, amount: { type: "string" },
  
  
  
  
  then: { type: ["object", "string"], properties: {
    type: { type: "string" }, tool: { type: "string" }, args: { type: "object" },
    after_seconds: { type: "number" }, until: { type: "string" },
  } },
} };






export const OPEN_TASKS_SCHEMA = { type: "array",
  description: "Unfinished items for this caller, newest first.",
  items: { type: "object", additionalProperties: true,
    properties: { kind: { type: "string" }, id: { type: "string" }, status: { type: "string" }, since: { type: ["number", "null"] } },
    required: ["kind", "id", "status"] } };

export const MCP_RESULT_SCHEMA = {
  type: "object", additionalProperties: true, required: ["ok"],
  properties: {
    ok: { type: "boolean", description: "True when the step worked; false results carry error and next." },
    error: { type: "string" },
    status: { type: "string" },
    approval_url: { type: "string", format: "uri" },
    estimate_id: { type: "string" },
    payment_id: { type: "string" },
    withdrawal_id: { type: "string" },
    request_id: { type: "string" },
    
    
    
    
    poll: { type: "object", properties: {
      tool: { type: "string" }, args: { type: "object" },
      every_seconds: { type: "integer", minimum: 1 },
      until: { type: "string" },
    }, required: ["tool", "args", "every_seconds", "until"] },
    open_tasks: OPEN_TASKS_SCHEMA,
    
    
    
    session_expires_in_seconds: { type: "integer", minimum: 0, description: "How many whole seconds the connection's private pass still works for. When it runs out, every later step is refused until a new connection is made." },
    message: { type: "string" },
  },
};





export const CONNECT_REQUIRED_PROPERTIES = {
  request_id: { type: "string" },
  approval_url: { type: "string", format: "uri" },
  route: { type: "string" },
  session: { type: "string", description: "Never show this to the person and never ask them for it; it comes only from the account tool's answer (account status)." },
  expires_at: { type: "string", format: "date-time" },
  expires_hint: { type: "string" },
  open_tasks: OPEN_TASKS_SCHEMA,
};

const OPEN_TASK_READERS = [];
export function registerOpenTasksReader(read) { OPEN_TASK_READERS.push(read); }
export function collectOpenTasks(owner) {
  if (!owner) return undefined;
  const seen = new Set(), items = [];
  for (const read of OPEN_TASK_READERS) {
    try {
      for (const item of read(owner) || []) {
        
        
        if (typeof item.since === "number" && item.since < Date.now() - connectionTtlMs()) continue;
        const key = `${item.kind}:${item.id}`;
        if (!seen.has(key)) { seen.add(key); items.push(item); }
      }
    } catch {  }
  }
  items.sort((a, b) => (b.since ?? 0) - (a.since ?? 0));
  return items.slice(0, 10);
}


export function humanUntil(ts, now = Date.now()) {
  const ms = (typeof ts === "number" ? (ts < 1e12 ? ts * 1000 : ts) : new Date(ts).getTime()) - now;
  if (!Number.isFinite(ms) || ms <= 0) return "already expired";
  const s = Math.round(ms / 1000);
  if (s < 90) return `in ${s} seconds`;
  const m = Math.round(s / 60);
  if (m < 90) return `in about ${m} minute${m === 1 ? "" : "s"}`;
  const h = Math.round(m / 60);
  if (h < 48) return `in about ${h} hours`;
  const d = Math.round(h / 24);
  return `in ${d} days`;
}

export function withExpiresHuman(obj, key = "expires_at") {
  if (obj && obj[key] != null) return { ...obj, expires_human: humanUntil(obj[key]) };
  return obj;
}





export const SESSION_EXPIRY_HINT_SECONDS = 600;
export function sessionExpiryFields(expiresAt, now = Date.now()) {
  if (expiresAt == null) return {};
  const ms = (typeof expiresAt === "number" ? (expiresAt < 1e12 ? expiresAt * 1000 : expiresAt) : new Date(expiresAt).getTime()) - now;
  if (!Number.isFinite(ms)) return {};
  const seconds = Math.max(0, Math.floor(ms / 1000));
  return seconds < SESSION_EXPIRY_HINT_SECONDS
    ? { session_expires_in_seconds: seconds, hint: "session expires soon; reconnect before long tasks" }
    : { session_expires_in_seconds: seconds };
}





export function openLinkThen(url, call) {
  return { type: "open_link", url,
    then: { type: "call", after_seconds: 10, ...call } };
}





export function pollFor(tool, args, until = "status is not approval_required") {
  return { tool, args, every_seconds: 5, until };
}
