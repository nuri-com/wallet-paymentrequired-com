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
const state = { signatures: 0, payments: 0, calls: [], invoices: new Map(), nonces: new Set(), receipts: new Map(), loseBody: false, badAnswer: false, recovery402: false };
globalThis.fetch = async () => { throw new Error('Unexpected network access in offline ask check'); };
mock.module('viem', { namedExports: { ...viem, createPublicClient: () => ({
  getChainId: async () => 8453,
  getBlockNumber: async () => 100n,
  getCode: async () => '0x01',
  readContract: async ({ functionName, args }) => {
    if (functionName === 'balanceOf') return 1000000n;
    if (functionName === 'permissionConfig') return { signer: SAFE };
    if (functionName === 'authorizationState') return state.nonces.has(args[1]);
    throw new Error(`Unexpected fake RPC: ${functionName}`);
  },
  waitForTransactionReceipt: async ({ hash }) => {
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
const { createMcpWalletTool, ASK_URL, ASK_MODELS } = await import('../src/mcp-wallet-tool.mjs');
const { decimalToUnits } = await import('../src/wallet-units.mjs');
const { instructions } = await import('../src/mcp-instructions.mjs');

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
    state.receipts.set(tx, { transactionHash: tx, status: 'success', blockNumber: 101n, logs: [{
      address: USDC,
      topics: viem.encodeEventTopics({ abi: viem.parseAbi(['event Transfer(address indexed from,address indexed to,uint256 value)']), eventName: 'Transfer', args: { from: SAFE, to: SELLER } }),
      data: viem.encodeAbiParameters([{ type: 'uint256' }], [2070n]),
    }] });
  }
  if (!invoice.paid || (!signature && state.recovery402)) {
    const required = { x402Version: 2, resource: { url: `${ASK_URL}?invoice=${id}`, mimeType: 'application/json' }, accepts: [{
      scheme: 'exact', network: 'eip155:8453', asset: USDC, amount: '2070', payTo: SELLER, maxTimeoutSeconds: 300,
      extra: { name: 'USD Coin', version: '2', assetTransferMethod: 'eip3009' },
    }] };
    return { status: 402, headers: { 'payment-required': Buffer.from(JSON.stringify(required)).toString('base64') }, bytes: Buffer.from('{}') };
  }
  const responseHeaders = { 'content-type': 'application/json', 'payment-response': Buffer.from(JSON.stringify(invoice.receipt)).toString('base64') };
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
  assert.match(conflict.error, /request_id_conflict/);

  const capped = { ...ask, request_id: 'too-small', max_amount: '0.001' };
  const refused = await tool.call(capped);
  assert.equal(refused.ok, false);
  assert.match(refused.error, /send again with a NEW request_id and a higher max_amount/);
  assert.ok(instructions(['wallet']).includes('NEW request_id and a higher max_amount'));
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
  console.log(`wallet ask ok: 402 -> signed 200; ${state.payments} synthetic payments; cap rejects before signing; new-id higher-cap retry; durable replay; fast/smart; lost-body recovery without payment; validation and malformed answer`);
  const runtimeSource = readFileSync(new URL('../src/agent-kernel-runtime.mjs', import.meta.url), 'utf8');
  assert.ok(runtimeSource.includes('url === ROUTER_CHAT_URL ? 190000 : 20000'), 'Router receives a generation-sized bounded timeout');
} finally {
  tool.close();
  rmSync(dir, { recursive: true, force: true });
}
