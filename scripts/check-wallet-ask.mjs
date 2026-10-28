// Offline integration: real wallet ask + durable kernel ledger + x402 parser/signer.
// Fake wallet adapter, RPC, Kernel account and Privy signer; no usable keys or network.
// Run: node --experimental-test-module-mocks scripts/check-wallet-ask.mjs
import assert from 'node:assert/strict';
import { mock } from 'node:test';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as viem from 'viem';
import * as kernel from '../src/agent-kernel-wallet.mjs';
import * as privy from '../src/privy-agent-app-signer.mjs';
import * as relay from '../src/safe-pay-relay.mjs';

const SAFE = '0x1111111111111111111111111111111111111111';
const SELLER = '0x2222222222222222222222222222222222222222';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const KEY = 'A'.repeat(44); // Synthetic, never usable as a real wallet credential.
assert.equal(KEY.length, 44);
const state = { signatures: 0, payments: 0, calls: [], invoices: new Map(), nonces: new Set(), receipts: new Map(), loseBody: false, badAnswer: false, recovery402: false, block: 100n, noReceipt: false, wrongNonce: false, badTransfer: null };
globalThis.fetch = async () => { throw new Error('Unexpected network access in offline ask check'); };
mock.module('viem', { namedExports: { ...viem, createPublicClient: () => ({
  getChainId: async () => 8453,
  getBlockNumber: async () => state.block,
  getLogs: async ({ address, args, fromBlock, toBlock }) => {
    assert.equal(address, USDC); assert.deepEqual(args, { from: SAFE, to: SELLER });
    return [...state.receipts.values()].filter(r => r.blockNumber >= fromBlock && r.blockNumber <= toBlock)
      .map(r => ({ transactionHash: r.transactionHash, args: { value: 2070n }, removed: false }));
  },
  getCode: async () => '0x01',
  readContract: async ({ functionName, args }) => {
    if (functionName === 'balanceOf') return 1000000n;
    if (functionName === 'permissionConfig') return { signer: SAFE };
    if (functionName === 'authorizationState') return state.nonces.has(args[1]);
    throw new Error(`Unexpected fake RPC: ${functionName}`);
  },
  getTransaction: async ({ hash }) => state.receipts.get(hash).transaction,
  waitForTransactionReceipt: async ({ hash, confirmations }) => {
    assert.equal(confirmations, 2);
    assert.ok(state.receipts.has(hash), 'Only known synthetic settlements may confirm');
    return state.receipts.get(hash);
  },
}) } });
mock.module('../src/agent-kernel-wallet.mjs', { namedExports: { ...kernel,
  createAgentKernelWallet: async () => ({ agentAccount: { signTypedData: async () => {
    state.signatures++;
    return `0x${'11'.repeat(64)}1b`; // Deliberately synthetic, never sent to a network.
  } } }),
} });
mock.module('../src/privy-agent-app-signer.mjs', { namedExports: { ...privy, connectedSafeAgentSigner: async () => ({ address: SAFE }) } });
mock.module('../src/safe-pay-relay.mjs', { namedExports: { ...relay, safeSignatureAccepted: async () => true } });
const { createKernelRuntime } = await import('../src/agent-kernel-runtime.mjs');
const { createMcpWalletTool, WALLET_TOOL, ASK_URL, ASK_MODELS } = await import('../src/mcp-wallet-tool.mjs');
const { decimalToUnits } = await import('../src/wallet-units.mjs');
const { instructions } = await import('../src/mcp-instructions.mjs');
const { askFirst } = await import('../src/mcp-wallet-merge.mjs');

async function fakeRouter(url, headers, onHeaders, shape) {
  assert.equal(url, ASK_URL);
  assert.equal(shape.method, 'POST');
  const body = JSON.parse(shape.bytes.toString());
  assert.equal(body.stream, false);
  assert.deepEqual(Object.keys(body).sort(), ['messages', 'model', 'stream']);
  assert.equal(body.messages[0].role, 'user');
  const id = headers['Idempotency-Key'];
  assert.match(id, /^[a-z0-9-]{36}$/i);
  state.calls.push({ id, headers, body });
  let invoice = state.invoices.get(id);
  if (!invoice) {
    invoice = { body: JSON.stringify(body), paid: false, answer: state.badAnswer ? {} : { choices: [{ message: { content: 'Synthetic router answer.' } }], model: body.model } };
    state.invoices.set(id, invoice);
  }
  assert.equal(invoice.body, JSON.stringify(body), 'Same invoice must bind the same prompt and model');
  const signature = headers['PAYMENT-SIGNATURE'] ?? headers['payment-signature'];
  if (signature) {
    assert.equal(invoice.paid, false, 'The fake router must never be paid twice');
    const payment = JSON.parse(Buffer.from(signature, 'base64').toString());
    assert.equal(payment.accepted.amount, '2070');
    assert.equal(payment.resource.url, `${ASK_URL}?invoice=${id}`);
    state.nonces.add(payment.payload.authorization.nonce);
    invoice.paid = true;
    state.payments++;
    const tx = `0x${state.payments.toString(16).padStart(64, '0')}`;
    invoice.receipt = { success: true, network: 'eip155:8453', transaction: tx, payer: SAFE };
    state.block += 2n;
    state.receipts.set(tx, { transactionHash: tx, status: 'success', blockNumber: state.block, logs: [{
      address: state.badTransfer === 'asset' ? SELLER : USDC,
      topics: viem.encodeEventTopics({ abi: viem.parseAbi(['event Transfer(address indexed from,address indexed to,uint256 value)']), eventName: 'Transfer', args: { from: SAFE, to: state.badTransfer === 'to' ? SAFE : SELLER } }),
      data: viem.encodeAbiParameters([{ type: 'uint256' }], [state.badTransfer === 'amount' ? 2071n : 2070n]),
    }, {
      address: USDC,
      topics: viem.encodeEventTopics({ abi: viem.parseAbi(['event AuthorizationUsed(address indexed authorizer,bytes32 indexed nonce)']), eventName: 'AuthorizationUsed',
        args: { authorizer: SAFE, nonce: state.wrongNonce ? `0x${'ff'.repeat(32)}` : payment.payload.authorization.nonce } }), data: '0x',
    }] });
    if (state.badTransfer === 'missing-event-unrelated-tx') {
      const receipt = state.receipts.get(tx);
      receipt.logs.pop();
      receipt.transaction = { to: USDC, input: viem.encodeFunctionData({
        abi: viem.parseAbi(['function transfer(address,uint256) returns(bool)']), functionName: 'transfer', args: [SELLER, 2070n] }) };
    }
  }
  if (!invoice.paid || (!signature && state.recovery402)) {
    const required = { x402Version: 2, resource: { url: `${ASK_URL}?invoice=${id}`, mimeType: 'application/json' }, accepts: [{
      scheme: 'exact', network: 'eip155:8453', asset: USDC, amount: '2070', payTo: SELLER, maxTimeoutSeconds: 300,
      extra: { name: 'USD Coin', version: '2', assetTransferMethod: 'eip3009' },
    }] };
    return { status: 402, headers: { 'payment-required': Buffer.from(JSON.stringify(required)).toString('base64') }, bytes: Buffer.from('{}') };
  }
  const responseHeaders = { 'content-type': 'application/json', ...(!state.noReceipt ? { 'payment-response': Buffer.from(JSON.stringify(invoice.receipt)).toString('base64') } : {}) };
  onHeaders?.(200, responseHeaders);
  if (signature && state.loseBody) { state.loseBody = false; throw new Error('Synthetic disconnect after settlement headers'); }
  return { status: 200, headers: responseHeaders, bytes: Buffer.from(JSON.stringify(invoice.answer)) };
}
const dir = mkdtempSync(join(tmpdir(), 'wallet-ask-'));
const path = join(dir, 'ledger.sqlite');
const row = { id: 'synthetic-wallet', address: SAFE, claimed: true, record: { chainId: 8453, maxTransferUnits: kernel.NO_LIMIT, permit2Enabled: true, policyVersion: '0.0.5', initialOwnerAddress: SAFE, agentAddress: SAFE } };
let runtime;
function openTool() {
  runtime = createKernelRuntime({ path, env: { AGENT_KERNEL_ALPHA: 'true' }, store: { getKernelWallet: id => id === row.id ? row : null }, merchantFetch: fakeRouter });
  // Only credential resolution and the inner MCP field projection are synthetic.
  // All challenge parsing, ceiling enforcement, signing and journal replay are real.
  return createMcpWalletTool({ path, chainId: 8453, accountFlow: { authorized: async () => null }, agentWalletFactory: () => ({
    newest: async () => null,
    close: () => runtime.close(),
    call: async args => {
      assert.equal(args.wallet_key, KEY);
      if (args.action === 'create') return { ok: true, wallet: { wallet_id: row.id, address: SAFE, claimed: true } };
      assert.equal(args.action, 'pay');
      assert.notEqual(args.dry_run, true, 'Ask must not generate an extra preflight invoice');
      const op = await runtime.pay({ walletId: row.id, requestId: args.request_id, url: args.url, method: args.method, body: args.body, maxAmountUnits: decimalToUnits(args.max_amount, 6) });
      return { ok: true, operation: { status: op.status, reason: op.reason, amount_units: op.amountUnits, to: op.to,
        transaction_hash: op.transaction, resource: op.resource, content_delivered: op.contentDelivered, http_status: op.httpStatus } };
    },
  }) });
}
let tool = openTool();
const ask = { action: 'ask', wallet_key: KEY, prompt: 'Explain this in one sentence.', max_amount: '0.05', request_id: 'ask-once' };
try {
  const invalid = await tool.call({ action: 'ask', quality: 'unknown' });
  assert.equal(invalid.ok, false);
  for (const field of ['wallet_key', 'prompt', 'max_amount', 'quality', 'request_id']) assert.ok(invalid.error.includes(field));
  assert.equal(state.calls.length, 0);
  for (const max_amount of ['0', '-1', '0.0000001', 0.05]) {
    assert.equal((await tool.call({ ...ask, max_amount })).ok, false);
  }
  assert.equal((await tool.call({ ...ask, url: 'https://other.example/' })).ok, true, 'Unrelated schema fields cannot override the fixed router URL');
  const result = await tool.call(ask);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.answer, 'Synthetic router answer.');
  assert.equal(result.cost, '0.00207');
  assert.equal(result.model, ASK_MODELS.fast);
  assert.equal(result.receipt.to, SELLER);
  assert.match(result.receipt.tx, /^0x[0-9a-f]{64}$/);
  assert.equal(state.payments, 1);
  assert.equal(state.signatures, 1);
  assert.equal(state.calls.length, 2, 'One 402 and one signed retry');
  const replay = await Promise.all([tool.call(ask), tool.call(ask)]);
  for (const value of replay) assert.deepEqual(value, result);
  tool.close(); tool = openTool();
  assert.deepEqual(await tool.call(ask), result, 'Replay survives a runtime restart');
  assert.equal(state.calls.length, 2);
  assert.equal(state.payments, 1);
  const conflict = await tool.call({ ...ask, prompt: 'Different question' });
  assert.equal(conflict.ok, false);
  await assert.rejects(runtime.pay({ walletId: row.id, requestId: state.calls[0].id, url: ASK_URL, method: 'POST',
    body: { ...state.calls[0].body, messages: [{ role: 'user', content: 'Different question' }] }, maxAmountUnits: '50000' }), /request_id_conflict/);
  assert.equal(state.payments, 1, 'A conflicting prompt cannot pay again');

  const capped = { ...ask, request_id: 'too-small', max_amount: '0.001' };
  const refused = await tool.call(capped);
  assert.equal(refused.ok, false);
  assert.match(refused.error, /send again with a NEW request_id and a higher max_amount/);
  assert.ok(instructions(['wallet']).includes('NEW request_id and a higher max_amount'));
  // Live 2026-10-28: creation refusals are not payment retries. A duplicate reason key at the
  // payment block silently replaced the creation text with "same request_id" advice, and creation
  // has no request ID to reuse. Schema and bare-balance answer must name the instant first call.
  const toolSource = readFileSync(new URL('../src/mcp-wallet-tool.mjs', import.meta.url), 'utf8');
  assert.equal(toolSource.split('operator_admission_budget_exhausted:').length - 1, 1, 'Reason key must be mapped once');
  const admission = toolSource.split('\n').find(line => line.includes('operator_admission_budget_exhausted:'));
  assert.match(admission, /No new wallet can be opened right now/);
  assert.doesNotMatch(admission, /request_id/);
  const instant = 'call balance with new:true and no wallet_key or session';
  assert.ok(WALLET_TOOL.description.includes(instant), 'Tool description must name the instant first call');
  assert.match(WALLET_TOOL.description, /After the first answer, always send wallet_key/);
  assert.match(WALLET_TOOL.inputSchema.properties.new.description, /First call only/);
  assert.match(WALLET_TOOL.inputSchema.properties.action.description, /new:true it opens an instant wallet/);
  assert.match(WALLET_TOOL.inputSchema.properties.wallet_key.description, /Not needed on the first call/);
  const bare = await askFirst();
  assert.ok(bare.next.includes('call wallet {action:"balance", new:true}'), bare.next);
  assert.match(bare.next, /no wallet_key and no session; no signup/);
  assert.match(bare.next, /After the first answer, always send wallet_key/);
  assert.doesNotMatch(bare.next, /new or existing/);
  assert.equal(state.payments, 1);
  assert.equal(state.signatures, 1, 'Over-cap invoice must be rejected before signing');
  const failed = runtime.history(row.id).find(op => op.reason === 'payment_exceeds_max_amount');
  assert.equal(failed.status, 'failed', 'Over-cap operation is durable and final');
  assert.deepEqual(await tool.call(capped), refused);
  assert.equal((await tool.call({ ...capped, max_amount: '0.05' })).ok, false, 'Changing an immutable binding cannot silently spend');
  const higher = await tool.call({ ...capped, request_id: 'higher-cap-new-id', max_amount: '0.05' });
  assert.equal(higher.ok, true, JSON.stringify(higher));
  assert.equal(state.payments, 2);

  const smart = await tool.call({ ...ask, request_id: 'smart-answer', quality: 'smart' });
  assert.equal(smart.ok, true, JSON.stringify(smart));
  assert.equal(smart.model, ASK_MODELS.smart);
  assert.equal(state.calls.at(-1).body.model, ASK_MODELS.smart);

  state.loseBody = true;
  const lostArgs = { ...ask, request_id: 'lost-body' };
  const lost = await tool.call(lostArgs);
  assert.equal(lost.ok, false);
  assert.ok(lost.receipt, 'Original paid receipt survives response loss');
  const paidCount = state.payments, signedCount = state.signatures;
  state.recovery402 = true;
  assert.equal((await tool.call(lostArgs)).ok, false, 'A recovery 402 must never trigger payment');
  state.recovery402 = false;
  tool.close(); tool = openTool();
  const recovered = await tool.call(lostArgs);
  assert.equal(recovered.ok, true, JSON.stringify(recovered));
  assert.equal(recovered.answer, result.answer);
  assert.equal(recovered.cost, result.cost);
  assert.deepEqual(recovered.receipt, lost.receipt);
  assert.equal(state.payments, paidCount);
  assert.equal(state.signatures, signedCount);
  assert.deepEqual(Object.keys(state.calls.at(-1).headers), ['Idempotency-Key'], 'Recovery can only read, never authorize payment');

  state.badAnswer = true;
  const emptyArgs = { ...ask, request_id: 'empty-answer' };
  const empty = await tool.call(emptyArgs);
  assert.equal(empty.ok, false);
  assert.match(empty.error, /no answer/);
  assert.ok(empty.receipt);
  assert.deepEqual(await tool.call(emptyArgs), empty);
  state.noReceipt = true; state.badAnswer = false;
  const pay = { action: 'pay', wallet_key: KEY, url: ASK_URL, method: 'POST',
    body: { messages: [{ role: 'user', content: 'Receipt-free payment' }], model: ASK_MODELS.fast, stream: false }, max_amount: '0.05' };
  const discovered = await tool.call({ ...pay, request_id: 'receipt-free' });
  assert.equal(discovered.status, 'done', JSON.stringify(discovered));
  assert.ok(runtime.history(row.id).some(op => op.status === 'paid' && op.settlement === 'chain_discovered'));
  const count = state.payments;
  tool.close(); tool = openTool();
  assert.deepEqual(await tool.call({ ...pay, request_id: 'receipt-free' }), discovered);
  assert.equal(state.payments, count, 'Discovered settlement is durable; replay never repays');
  for (const mismatch of ['nonce', 'missing-event-unrelated-tx', 'asset', 'to', 'amount']) {
    state.wrongNonce = mismatch === 'nonce'; state.badTransfer = mismatch;
    const unverified = await tool.call({ ...pay, request_id: `receipt-free-wrong-${mismatch}` });
    assert.equal(unverified.status, 'delivered_unverified', JSON.stringify(unverified));
    assert.ok(unverified.resource); assert.match(unverified.next, /settlement is not confirmed/);
    assert.ok(runtime.history(row.id).some(op => op.status === 'unknown' && op.reason === 'settlement_unconfirmed'));
    // Supply the missing evidence and reconcile the same request before another spend.
    const receipt = [...state.receipts.values()].at(-1);
    receipt.logs[0] = { ...receipt.logs[0], address: USDC,
      topics: viem.encodeEventTopics({ abi: viem.parseAbi(['event Transfer(address indexed from,address indexed to,uint256 value)']), eventName: 'Transfer', args: { from: SAFE, to: SELLER } }),
      data: viem.encodeAbiParameters([{ type: 'uint256' }], [2070n]) };
    const authorization = JSON.parse(Buffer.from(state.calls.at(-1).headers['PAYMENT-SIGNATURE'], 'base64').toString()).payload.authorization;
    receipt.logs[1] = { address: USDC, data: '0x', topics: viem.encodeEventTopics({ abi: viem.parseAbi(['event AuthorizationUsed(address indexed authorizer,bytes32 indexed nonce)']), eventName: 'AuthorizationUsed', args: { authorizer: SAFE, nonce: authorization.nonce } }) };
    assert.equal((await tool.call({ ...pay, request_id: `receipt-free-wrong-${mismatch}` })).status, 'done');
  }
  console.log('settlement fallback ok: receipt-free -> chain_discovered/paid; durable replay; wrong nonce/asset/payTo/amount stay unknown and surface delivered_unverified content; 2 confirmations required');
  console.log(`wallet ask ok: 402 -> signed 200; ${state.payments} synthetic payments; cap rejects before signing; new-id higher-cap retry; durable replay; fast/smart; lost-body recovery without payment; validation and malformed answer`);
  const runtimeSource = readFileSync(new URL('../src/agent-kernel-runtime.mjs', import.meta.url), 'utf8');
  assert.ok(runtimeSource.includes('url === ROUTER_CHAT_URL ? 190000 : 20000'), 'Router receives a generation-sized bounded timeout');
} finally {
  tool.close();
  rmSync(dir, { recursive: true, force: true });
}
