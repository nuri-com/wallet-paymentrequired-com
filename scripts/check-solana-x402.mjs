import assert from "node:assert/strict";
import { createServer } from "node:http";
import { classifyHttp402Response, createPrfHttp402Payer } from "../src/agent-lightning-pay.mjs";
import { parseSolanaChallenge, payWithSolana, solanaSignerFromAgentKey, SOLANA_MAINNET, SOLANA_USDC_MINT } from "../src/safe-pay-solana.mjs";
import { TOKEN_PROGRAM_ADDRESS } from "@solana-program/token";

// Public Brij shape, 2026-11-19. Test key is fixed and never used in production.
const required = { x402Version: 2, resource: { url: "https://travel.brij.fi/air/search" }, accepts: [{
  scheme: "exact", network: SOLANA_MAINNET, asset: SOLANA_USDC_MINT, amount: "100000",
  payTo: "4WvcrHiCTLEqWod3PeW3iFfjmJFsCbprQfkeNb2Rq59b", maxTimeoutSeconds: 300,
  extra: { feePayer: "6Rkm9H4v4NqKB6v8SQrt8PE9bfd4PBhWpAQ2bi8P8AM" },
}] };
const headers = { "payment-required": Buffer.from(JSON.stringify(required)).toString("base64") };
const parsed = parseSolanaChallenge({ headers });
assert.equal(parsed.offers[0].amount, "100000");
assert.equal(classifyHttp402Response({ headers }).kind, "x402-solana");
assert.equal(classifyHttp402Response({ headers, prefer: "solana" }).rail, "solana-usdc");
assert.equal(parseSolanaChallenge({ headers: {}, bodyText: JSON.stringify({ ...required, accepts: [{ ...required.accepts[0], network: "eip155:8453" }] }) }), null);

const key = "11".repeat(32);
const signerA = await solanaSignerFromAgentKey(key);
const signerB = await solanaSignerFromAgentKey(`0x${key}`);
assert.equal(signerA.address, signerB.address);

let tokenUnits = "100000";
const rpc = createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => { body += chunk; });
  req.on("end", () => {
    const call = JSON.parse(body);
    const value = call.method === "getTokenAccountBalance" ? { amount: tokenUnits, decimals: 6, uiAmount: 0.1, uiAmountString: "0.1" }
      : call.method === "getLatestBlockhash" ? { blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 1 }
      : call.method === "getAccountInfo" ? { data: [(() => { const mint = Buffer.alloc(82); mint[44] = 6; return mint.toString("base64"); })(), "base64"],
        executable: false, lamports: 1_000_000, owner: TOKEN_PROGRAM_ADDRESS, rentEpoch: 0, space: 82 }
      : null;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: call.id, result: { context: { slot: 1 }, value } }));
  });
});
await new Promise((resolve) => rpc.listen(0, "127.0.0.1", resolve));
const rpcUrl = `http://127.0.0.1:${rpc.address().port}`;
try {
  const signed = await payWithSolana({ offer: parsed.offers[0], required: parsed.required, agentEthPrivateKeyHex: key, rpcUrl });
  assert.equal(signed.payerAddress, signerA.address);
  assert.ok(signed.headers["PAYMENT-SIGNATURE"]);

  let paidHeader;
  const payer = createPrfHttp402Payer({ solanaRpcUrl: rpcUrl, merchantFetch: async (_url, options = {}) => {
    if (!options.headers?.["PAYMENT-SIGNATURE"]) return { status: 402, headers, bytes: Buffer.alloc(0) };
    paidHeader = options.headers["PAYMENT-SIGNATURE"];
    return { status: 200, headers: { "content-type": "application/json" }, bytes: Buffer.from('{"ok":true}') };
  } });
  const paid = await payer.payHttpResource({ walletRecord: {}, secrets: { agentEthPrivHex: key },
    url: "https://travel.brij.fi/air/search", method: "POST", maxAmountUnits: 100000, opId: "test" });
  assert.equal(paid.status, "done");
  assert.equal(paid.rail, "solana-usdc");
  assert.ok(paidHeader);
  await assert.rejects(payer.payHttpResource({ walletRecord: {}, secrets: { agentEthPrivHex: key },
    url: "https://travel.brij.fi/air/search", method: "POST", maxAmountUnits: 99999, opId: "cap-test" }),
    (err) => err.code === "over_max_amount");
  tokenUnits = "99999";
  await assert.rejects(payWithSolana({ offer: parsed.offers[0], required: parsed.required, agentEthPrivateKeyHex: key, rpcUrl }),
    (err) => err.code === "insufficient_solana_usdc" && err.solanaAddress === signerA.address);
} finally {
  await new Promise((resolve) => rpc.close(resolve));
}
console.log("solana x402 check ok: Brij challenge, deterministic Ed25519 key, exact signing, caps");
