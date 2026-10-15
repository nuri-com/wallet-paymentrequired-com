// wallet.fund path (a): the connected wallet holds USDC, so move it into the
// agent wallet (D-D, issue #166).
//
// Approval mechanism: the established connected-wallet send machinery
// (src/mcp-wallet.mjs) — an EIP-3009 TransferWithAuthorization signed by the
// person through a bridge approval link, then settled gasless through the
// x402 facilitator. Reused, not invented.
//
// Contract with src/mcp-wallet-tool.mjs (fixed, do not change):
//   export async function fundFromConnectedWallet(deps, { walletAddress, amountUnits = null })
// - returns null when the path does not apply (no connected session, no USDC,
//   or balance below amountUnits), so the tool falls through to the next path;
// - returns { funded: true, from: 'wallet', tx } once the transfer settled;
// - throws Error(one sentence + next action) when a transfer was attempted
//   but did not finish. A pending human approval throws with .approval_url and
//   .next_action set, exactly like the other approval-carrying errors, so the
//   tool (or the connection wrapper's refusalResult) can surface the link.
//
// Connected session discovery: the wallet tool resolves the session for the
// call and passes it on the deps object it owns — deps.session (a session
// credential string, checked through accountFlow.authorized) or an already
// resolved session object as deps.connectionSession. When deps.bridge is the
// raw browser bridge, its session table is scanned as a fallback. With none
// of these there is no connected wallet and the path does not apply.

import { randomUUID, randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { getAddress, createPublicClient, http, parseAbi } from "viem";
import { verifyTypedData } from "ethers";
import { CHAIN_ASSETS, VIEM_CHAIN_BY_ID, unitsToDecimal } from "./wallet-units.mjs";
import { openLinkThen } from "./mcp-tool-results.mjs";
import { MAX_TIMEOUT_MS } from "./signer-client.mjs";
import { resolveFacilitatorUrl } from "./x402-facilitator-resolver.mjs";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
const TX_HASH = /^0x[0-9a-fA-F]{64}$/;
const UNITS = /^(0|[1-9][0-9]*)$/;
const SEND_WINDOW_SECONDS = 600;
const APPROVAL_POLL_MS = 3_000; // a repeat after the tap finds the signature at once; waiting longer only stalls balance (live 2026-09-28)

// Same x402 v1 network names the connected-wallet send uses.
const X402_V1_NETWORK = new Map([[8453, "base"], [84532, "base-sepolia"]]);

const erc20BalanceAbi = parseAbi(["function balanceOf(address) view returns (uint256)"]);
const NONCE_STATE_ABI = parseAbi(["function authorizationState(address authorizer, bytes32 nonce) view returns (bool)"]);

const memoryFunds = new Map();

function openStore(path) {
  if (typeof path !== "string" || !path) {
    return {
      get: key => memoryFunds.get(key) ?? null,
      put: (key, value) => memoryFunds.set(key, value),
      drop: key => memoryFunds.delete(key),
      close: () => {},
    };
  }
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  if (path !== ":memory:") chmodSync(path, 0o600);
  db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS wallet_connected_funds(
      key TEXT PRIMARY KEY, state TEXT NOT NULL, record TEXT NOT NULL);`);
  const getStmt = db.prepare("SELECT state, record FROM wallet_connected_funds WHERE key=?");
  const putStmt = db.prepare("INSERT INTO wallet_connected_funds(key,state,record) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET state=excluded.state, record=excluded.record");
  const dropStmt = db.prepare("DELETE FROM wallet_connected_funds WHERE key=?");
  return {
    get(key) {
      const row = getStmt.get(key);
      if (!row) return null;
      try { return { state: row.state, ...JSON.parse(row.record) }; } catch { return null; }
    },
    put(key, value) {
      const { state, ...record } = value;
      putStmt.run(key, state, JSON.stringify(record));
    },
    drop: key => dropStmt.run(key),
    close: () => db.close(),
  };
}

function resolveConnectedSession(deps) {
  const { accountFlow, bridge } = deps ?? {};
  for (const credential of [deps?.session, deps?.credential, deps?.sessionCredential]) {
    if (typeof credential !== "string" || !credential) continue;
    try {
      const session = accountFlow?.authorized?.(credential, { signingGrant: false });
      if (session?.result?.signer && ADDRESS.test(session.result.signer)) return session;
    } catch { /* not this one */ }
  }
  const held = deps?.connectionSession ?? deps?.connectedSession;
  if (held?.status === "approved" && held?.result?.signer && ADDRESS.test(held.result.signer)
    && Number.isSafeInteger(held.expiresAt) && Date.now() < held.expiresAt) return held;
  const sessions = bridge?.sessions;
  if (sessions instanceof Map) {
    let newest = null;
    for (const session of sessions.values()) {
      if (session?.status !== "approved" || session?.context?.kind !== "mcp_connection") continue;
      if (!session?.result?.signer || !ADDRESS.test(session.result.signer)) continue;
      if (!Number.isSafeInteger(session.expiresAt) || Date.now() >= session.expiresAt) continue;
      const at = session.context?.connectedAt ?? session.createdAt ?? 0;
      if (!newest || at >= (newest.context?.connectedAt ?? newest.createdAt ?? 0)) newest = session;
    }
    if (newest) return newest;
  }
  return null;
}

function typedDataFor({ asset, chainId, owner, to, amountUnits, validBefore, nonce }) {
  return { domain: { name: asset.transfer?.name ?? "USDC", version: asset.transfer?.version ?? "2",
      chainId, verifyingContract: asset.address },
    primaryType: "TransferWithAuthorization",
    types: { TransferWithAuthorization: [
      { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] },
    message: { from: owner, to, value: String(amountUnits),
      validAfter: "0", validBefore: String(validBefore), nonce } };
}

function paymentRequirementsFor({ asset, chainId, network, to, amountUnits, fundId, publicBase }) {
  return { scheme: "exact", network, maxAmountRequired: String(amountUnits),
    resource: `${publicBase}/wallet/fund/${fundId}`, description: "wallet fund", mimeType: "application/json",
    payTo: to, maxTimeoutSeconds: SEND_WINDOW_SECONDS, asset: asset.address,
    extra: { name: asset.transfer?.name ?? "USDC", version: asset.transfer?.version ?? "2" } };
}

function paymentPayloadFor({ network, typed_data, signature }) {
  const m = typed_data.message;
  return { x402Version: 1, scheme: "exact", network,
    payload: { signature,
      authorization: { from: m.from, to: m.to, value: String(m.value), validAfter: String(m.validAfter),
        validBefore: String(m.validBefore), nonce: m.nonce } } };
}

function transferStalledError() {
  return new Error("The transfer did not go through. Try again or send USDC to your wallet address directly.");
}

function approvalPendingError(url) {
  const error = new Error("The transfer is waiting for your signature. Open the approval link to sign it, then fund the wallet again.");
  error.approval_url = url;
  error.next_action = openLinkThen(url,
    { tool: "wallet", args: { action: "fund" }, until: "the transfer is no longer waiting for a signature" });
  return error;
}

export async function fundFromConnectedWallet(deps, { walletAddress, amountUnits = null } = {}) {
  const { accountFlow, chainId, path, bridge } = deps ?? {};
  if (!accountFlow || !bridge?.createSession) return null;
  const asset = CHAIN_ASSETS.get(chainId);
  const network = X402_V1_NETWORK.get(chainId);
  const viemChain = VIEM_CHAIN_BY_ID.get(chainId);
  if (!asset || !network || !viemChain) return null;
  if (typeof walletAddress !== "string" || !ADDRESS.test(walletAddress)) throw new Error("fund_wallet_address_invalid: The wallet address is missing or damaged. Read the balance first and copy the address exactly.");
  const to = getAddress(walletAddress);
  let amount = null;
  if (amountUnits !== null) {
    if (typeof amountUnits !== "string" || !UNITS.test(amountUnits)) throw new Error("fund_amount_invalid: Give the amount as whole USDC units, for example 1000000 for 1 USDC.");
    amount = BigInt(amountUnits);
    if (amount <= 0n) throw new Error("fund_amount_invalid: The amount must be above zero.");
  }

  const session = resolveConnectedSession(deps);
  if (!session) return null;
  const owner = getAddress(session.result.signer);
  if (owner.toLowerCase() === to.toLowerCase()) return null;

  const env = process.env;
  const client = createPublicClient({ chain: viemChain, transport: http(env.AA_PUBLIC_RPC_URL) });
  let balance;
  try { balance = await client.readContract({ address: getAddress(asset.address), abi: erc20BalanceAbi, functionName: "balanceOf", args: [owner] }); }
  catch { return null; }
  if (balance <= 0n) return null;
  if (amount === null) amount = balance;
  if (balance < amount) return null;

  const store = openStore(path);
  try {
    const key = `${chainId}:${owner.toLowerCase()}:${to.toLowerCase()}:${amount.toString()}`;
    const now = Math.floor(Date.now() / 1000);
    let fund = store.get(key);
    if (fund && fund.state === "awaiting_approval" && Number(fund.valid_before) <= now) {
      store.drop(key);
      fund = null;
    }

    if (!fund) {
      const typed_data = typedDataFor({ asset, chainId, owner, to, amountUnits: amount.toString(),
        validBefore: now + SEND_WINDOW_SECONDS, nonce: `0x${randomBytes(32).toString("hex")}` });
      const approval = await bridge.createSession({ intent: "auth", adapter: session.signerAdapter,
        partner: session.context?.partner, expectedAddress: owner,
        signTypedData: JSON.parse(JSON.stringify(typed_data)), timeoutMs: MAX_TIMEOUT_MS,
        lineage: `fund:${to.toLowerCase()}`,
        consentText: `Move ${unitsToDecimal(amount.toString(), asset.decimals)} USDC from your connected wallet to your agent wallet ${to} on ${viemChain?.name ?? asset.network}. The signature moves exactly this amount to this address and nothing else.`,
        context: { kind: "mcp_wallet_fund", walletAddress: to },
        });
      fund = { state: "awaiting_approval", approval_id: approval.session_id, approval_url: approval.approval_url,
        typed_data, valid_before: Number(typed_data.message.validBefore) };
      store.put(key, fund); throw approvalPendingError(fund.approval_url); // the link first: nobody can sign before seeing it (live 2026-09-28: 20 s wait)
    }

    let signature = null;
    const deadline = Date.now() + APPROVAL_POLL_MS;
    for (;;) {
      let approved = null;
      try { approved = await bridge.approved(fund.approval_id); } catch { approved = null; }
      const candidate = approved?.result?.signature;
      if (typeof candidate === "string" && SIGNATURE.test(candidate)) {
        let signed = null;
        try { signed = JSON.parse(approved.result.message); } catch { signed = null; }
        if (signed?.message?.nonce === fund.typed_data.message.nonce) { signature = candidate.toLowerCase(); break; }
      }
      if (Date.now() >= deadline) throw approvalPendingError(fund.approval_url);
      await sleep(1_000);
    }

    let recovered;
    try { recovered = verifyTypedData(fund.typed_data.domain, fund.typed_data.types, fund.typed_data.message, signature); }
    catch { recovered = null; }
    if (!recovered || recovered.toLowerCase() !== owner.toLowerCase()) {
      store.drop(key);
      throw new Error("The signature did not come from the connected wallet. Fund again to start a fresh approval.");
    }

    // Already moved by an earlier attempt? Then do not settle twice.
    let consumed = null;
    try { consumed = await client.readContract({ address: getAddress(asset.address), abi: NONCE_STATE_ABI,
      functionName: "authorizationState", args: [owner, fund.typed_data.message.nonce] }); }
    catch { consumed = null; }
    if (consumed === true) {
      store.drop(key);
      if (typeof fund.transaction_hash === "string" && TX_HASH.test(fund.transaction_hash)) {
        return { funded: true, from: "wallet", tx: fund.transaction_hash };
      }
      throw new Error("The money already moved to the wallet. Check the balance instead of funding again.");
    }

    const facilitatorUrl = resolveFacilitatorUrl(chainId, { env });
    const fundId = randomUUID();
    const paymentRequirements = paymentRequirementsFor({ asset, chainId, network, to, amountUnits: amount.toString(), fundId, publicBase: deps?.publicBase ?? "https://paymentrequired.com" });
    const paymentPayload = paymentPayloadFor({ network, typed_data: fund.typed_data, signature });
    const callFacilitator = async (pathname) => {
      const response = await fetch(`${facilitatorUrl}${pathname}`, { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ x402Version: 1, paymentPayload, paymentRequirements }),
        signal: AbortSignal.timeout(20_000) });
      if (!response.ok) throw transferStalledError();
      return response.json();
    };
    const verified = await callFacilitator("/verify").catch(() => null);
    if (verified?.isValid !== true) throw transferStalledError();
    const settled = await callFacilitator("/settle").catch(() => null);
    if (settled?.success === true && TX_HASH.test(settled.transaction ?? "")) {
      store.drop(key);
      return { funded: true, from: "wallet", tx: settled.transaction };
    }
    throw transferStalledError();
  } finally {
    store.close();
  }
}
