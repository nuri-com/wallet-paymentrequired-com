// D-TOOLS-PAID (owner 2026-09-25): every action of our own tools can carry a price, and the caller's
// Agent Safe pays it. Nobody else pays: guests pay from the Safe their wallet_key opens, connected
// people from their own Safe (session). All prices default to 0, so nothing changes until the owner
// sets TOOL_PRICES_JSON.
//
//   TOOL_PRICES_JSON = {"bank.send":"0.01","account.limits":"0.001","bank":"0.50"}
//     key "tool.action" prices one action; key "tool" prices every action of that tool
//     (the action key wins). Missing or "0" = free. USDC, at most 6 decimals.
//   TOOL_PRICE_PAYTO = 0x… our treasury address. Required as soon as any price is above 0.
//
// The charge runs in-process before the action (no HTTP round trip), through one payer hook: the wallet
// tool's payFee (src/mcp-wallet-tool.mjs) → the Safe's agent spender, one USDC transfer, no tap. It is recorded like an x402 payment — scheme exact, network, asset,
// amount, payTo, payer, transaction — in a sqlite ledger keyed by the request, so the same request is
// never charged twice.
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

const AMOUNT = /^(0|[1-9]\d{0,11})(\.\d{1,6})?$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
// Approval / connect references are minted session ids (43 chars base64url, src/mcp-connection.mjs:86).
// A second call that only adds one continues the SAME request, so it is not part of the charge key.
const APPROVAL_REF = /^[A-Za-z0-9_-]{43}$/;
export const USDC_BY_CHAIN = { 8453: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 84532: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" };

export function toUnits(amount) {
  const [whole, fraction = ""] = amount.split(".");
  return BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
}
export function fromUnits(units) {
  const whole = units / 1_000_000n, fraction = (units % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}

// Throws on a malformed table: a money setting that cannot be read must stop the boot, not
// silently run everything for free or charge the wrong amount.
export function readToolPrices(env = process.env) {
  const raw = String(env.TOOL_PRICES_JSON ?? "").trim();
  const prices = new Map();
  if (raw) {
    let table;
    try { table = JSON.parse(raw); } catch { throw new Error("tool_prices_invalid: TOOL_PRICES_JSON is not valid JSON"); }
    if (!table || typeof table !== "object" || Array.isArray(table)) throw new Error("tool_prices_invalid: TOOL_PRICES_JSON must be an object of \"tool.action\": \"amount\"");
    for (const [key, value] of Object.entries(table)) {
      if (!/^[a-z_]+(\.[a-z_-]+)?$/.test(key)) throw new Error(`tool_prices_invalid: bad key ${JSON.stringify(key)}`);
      const amount = typeof value === "number" ? String(value) : value;
      if (typeof amount !== "string" || !AMOUNT.test(amount)) throw new Error(`tool_prices_invalid: ${key} must be a USDC amount like "0.01"`);
      const units = toUnits(amount);
      if (units > 0n) prices.set(key, units);
    }
  }
  const payTo = String(env.TOOL_PRICE_PAYTO ?? "").trim();
  if (prices.size && !ADDRESS.test(payTo)) throw new Error("tool_prices_invalid: TOOL_PRICE_PAYTO must be a 0x address when any tool price is above 0");
  return { prices, payTo: prices.size ? payTo : null };
}

export function priceUnits(prices, name, action) {
  if (typeof action === "string" && prices.has(`${name}.${action}`)) return prices.get(`${name}.${action}`);
  return prices.get(name) ?? 0n;
}

// Tool description suffix, generated from the table so the price a model reads is the price charged.
export function pricedTool(tool, prices) {
  const actions = tool.inputSchema?.properties?.action?.enum ?? [];
  const named = actions.map((action) => [action, priceUnits(prices, tool.name, action)]).filter(([, units]) => units > 0n);
  if (!actions.length && prices.has(tool.name)) named.push([null, prices.get(tool.name)]);
  if (!named.length) return tool;
  const words = named.map(([action, units]) => `${action ? `${action} costs` : "each call costs"} ${fromUnits(units)} USDC`).join(", ");
  const out = { ...tool, description: `${tool.description} Price: ${words}, paid from your agent wallet before it runs; the same request_id is never charged twice.` };
  // The Safe signs with the caller's wallet_key (guest key, or after connect the connected LLM key —
  // D-CUSTODY-V2: the server holds no key), so every priced tool takes it; the connection layer strips
  // it before a tool whose own schema does not know it.
  const props = tool.inputSchema?.properties;
  if (props && !props.wallet_key) {
    out.inputSchema = { ...tool.inputSchema, properties: { ...props,
      wallet_key: { type: "string", description: "The newest wallet_key from the wallet tool (also after connect): its agent wallet pays this action's price." } } };
  }
  return out;
}

// One charge per request. The request is named by, in order: an approval reference (a send continues
// after the tap), the caller's own request_id label. A call with none of them is a new request every time.
// Returns null for "new request": the caller then gets a fresh key and aliases from its answer.
export function requestRef(args) {
  if (typeof args?.request_id === "string" && APPROVAL_REF.test(args.request_id)) return `ref:${args.request_id}`;
  if (typeof args?.request_id === "string" && args.request_id.trim()) return `rid:${args.request_id.trim()}`;
  return null;
}
export function chargeKey(payer, name, ref) {
  return createHash("sha256").update(`tool-charge\n${payer}\n${name}\n${ref}`).digest("hex");
}

// payWithSafe({ who, amountUnits, payTo, reference, signal }) →
//   { status: "paid", tx, payer }            — the Safe paid (agent spender, settlement checked)
//   { status: "insufficient", address }      — the Safe holds less than the price; nothing was sent
//   { status: "connect_required", approval_url?, next } — a connected Safe and no (or a wrong) wallet_key
//   { status: "failed", error }
// `reference` is stable per request, so a retried charge continues the same payment.
export function createToolCharges({ env = process.env, path, payWithSafe, chainId = 8453 } = {}) {
  const { prices, payTo } = readToolPrices(env);
  const enabled = prices.size > 0;
  if (enabled && typeof payWithSafe !== "function") throw new Error("tool_prices_invalid: tool prices are set but no Safe payer is wired");
  let db = null;
  function store() {
    if (db) return db;
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    db = new DatabaseSync(path);
    db.exec(`CREATE TABLE IF NOT EXISTS tool_charges (key TEXT PRIMARY KEY, payer TEXT NOT NULL, tool TEXT NOT NULL,
      action TEXT, amount_units TEXT NOT NULL, pay_to TEXT NOT NULL, state TEXT NOT NULL, tx TEXT, receipt TEXT,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`);
    return db;
  }
  const inFlight = new Set();

  // The wallet_key picks and signs for the Safe (guest and connected alike); the session alone only
  // names a connected owner's Safe, whose signing then asks for the key (connect_required).
  function payerOf(args) {
    const key = typeof args?.wallet_key === "string" && args.wallet_key ? args.wallet_key : null;
    const session = typeof args?.session === "string" && args.session ? args.session : null;
    if (!key && !session) return null;
    const who = { ...(session ? { session } : {}), ...(key ? { wallet_key: key } : {}) };
    return { who, id: key ? `key:${createHash("sha256").update(key).digest("hex").slice(0, 32)}` : `session:${session.split(".")[0]}` };
  }

  // Returns null when the action is free or already paid (run it), otherwise the answer to give
  // INSTEAD of running it. On success the fee receipt rides along in `paid`.
  async function charge(name, args, { signal } = {}) {
    if (!enabled) return { run: true };
    const action = typeof args?.action === "string" ? args.action : null;
    const units = priceUnits(prices, name, action);
    if (units === 0n) return { run: true };
    const price = fromUnits(units);
    const payer = payerOf(args);
    // No payer yet. A session tool answers with its connect link by itself (then the paid retry
    // carries the session). wallet balance/fund without a key CREATE the Safe that pays later, so
    // they run; every other priced wallet action needs the key first.
    if (!payer) {
      if (["bank", "account"].includes(name)) return { run: true, unpaid: true };
      if (name === "wallet" && ["balance", "fund"].includes(action)) return { run: true, unpaid: true };
      return { run: false, answer: blocked(name, action, price, { error: `This action costs ${price} USDC from your agent wallet — send its wallet_key (or connect) and try again.`,
        next: "Call wallet {action: \"balance\"} to get a wallet_key, fund it, then repeat this call with wallet_key." }) };
    }
    const ref = requestRef(args);
    const key = chargeKey(payer.id, name, ref ?? `new:${randomUUID()}`);
    const row = store().prepare("SELECT * FROM tool_charges WHERE key=?").get(key);
    if (row?.state === "paid") return { run: true, paid: feeOf(row), repeat: true, key, payerId: payer.id };
    if (inFlight.has(key)) return { run: false, answer: blocked(name, action, price, { error: "The price for this request is being paid right now — repeat the call in a moment with the same request_id." }) };
    inFlight.add(key);
    try {
      const now = Date.now();
      store().prepare(`INSERT INTO tool_charges(key,payer,tool,action,amount_units,pay_to,state,created_at,updated_at) VALUES(?,?,?,?,?,?,'pending',?,?)
        ON CONFLICT(key) DO UPDATE SET state='pending', updated_at=excluded.updated_at`).run(key, payer.id, name, action, units.toString(), payTo, now, now);
      let paid;
      try { paid = await payWithSafe({ who: payer.who, amountUnits: units, payTo, reference: `fee-${key.slice(0, 40)}`, signal }); }
      catch (error) { paid = { status: "failed", error: String(error?.message || error) }; }
      if (paid?.status === "paid") {
        const receipt = { protocol: "x402", scheme: "exact", network: `eip155:${chainId}`, asset: USDC_BY_CHAIN[chainId] ?? null,
          amount: units.toString(), payTo, payer: paid.payer ?? null, transaction: paid.tx ?? null, resource: `mcp:${name}${action ? `.${action}` : ""}` };
        store().prepare("UPDATE tool_charges SET state='paid', tx=?, receipt=?, updated_at=? WHERE key=?").run(paid.tx ?? null, JSON.stringify(receipt), Date.now(), key);
        return { run: true, paid: feeOf(store().prepare("SELECT * FROM tool_charges WHERE key=?").get(key)), key, payerId: payer.id };
      }
      const state = paid?.status === "connect_required" ? "connect_required" : paid?.status === "insufficient" ? "insufficient" : "failed";
      store().prepare("UPDATE tool_charges SET state=?, updated_at=? WHERE key=?").run(state, Date.now(), key);
      if (state === "insufficient") return { run: false, answer: blocked(name, action, price, {
        error: `Your agent wallet holds less than the ${price} USDC this action costs, so it did not run.`,
        ...(paid.address ? { address: paid.address } : {}),
        next: paid.address ? `Send USDC to ${paid.address} (or call wallet {action: "fund"}), then repeat this call with the same request_id.` : "Call wallet {action: \"fund\"}, then repeat this call with the same request_id." }) };
      if (state === "connect_required") return { run: false, answer: blocked(name, action, price, { status: "connect_required",
        ...(paid.approval_url ? { approval_url: paid.approval_url } : {}),
        error: `This action costs ${price} USDC from your agent wallet, and paying it needs the wallet's newest wallet_key.`,
        next: paid.next ?? "Repeat this call with the newest wallet_key and the same request_id." }) };
      return { run: false, answer: blocked(name, action, price, { error: `The ${price} USDC price for this action could not be paid, so it did not run — try again in a moment with the same request_id.` }) };
    } finally { inFlight.delete(key); }
  }

  // After a charged action ran: its answer may name the reference the NEXT call continues with
  // (an approval request_id). Record that reference as the same paid charge.
  function remember(name, charged, answer) {
    if (!charged?.key || !answer || typeof answer !== "object") return;
    const refs = [];
    if (typeof answer.request_id === "string" && APPROVAL_REF.test(answer.request_id)) refs.push(`ref:${answer.request_id}`);
    const row = store().prepare("SELECT * FROM tool_charges WHERE key=?").get(charged.key);
    if (!row) return;
    for (const ref of refs) {
      store().prepare(`INSERT OR IGNORE INTO tool_charges(key,payer,tool,action,amount_units,pay_to,state,tx,receipt,created_at,updated_at)
        VALUES(?,?,?,?,?,?,'paid',?,?,?,?)`).run(chargeKey(charged.payerId, name, ref), row.payer, row.tool, row.action, row.amount_units, row.pay_to, row.tx, row.receipt, Date.now(), Date.now());
    }
  }

  function blocked(name, action, price, extra) {
    return { ok: false, status: "payment_required", price: { amount: price, currency: "USDC" }, ...extra,
      for_tools_only: { x402: { scheme: "exact", network: `eip155:${chainId}`, asset: USDC_BY_CHAIN[chainId] ?? null, payTo, resource: `mcp:${name}${action ? `.${action}` : ""}` } } };
  }
  function feeOf(row) {
    return { amount: fromUnits(BigInt(row.amount_units)), currency: "USDC", ...(row.tx ? { tx: row.tx } : {}) };
  }
  const ledger = () => (db ? db.prepare("SELECT key,payer,tool,action,amount_units,state,tx,receipt FROM tool_charges ORDER BY created_at").all() : []);
  return { enabled, prices, payTo, charge, remember, describe: (tool) => (enabled ? pricedTool(tool, prices) : tool), ledger, close: () => { db?.close(); db = null; } };
}

// The payer: the wallet tool's payFee (src/mcp-wallet-tool.mjs) — the Safe's agent spender moves the fee
// in one UserOp (runtime.fee, src/agent-kernel-runtime.mjs), no tap on an owned Safe, no limit.
export function walletToolSafePayer(walletTool) {
  if (typeof walletTool?.payFee !== "function") throw new Error("tool_prices_invalid: the wallet tool has no payFee");
  return (args) => walletTool.payFee(args);
}
