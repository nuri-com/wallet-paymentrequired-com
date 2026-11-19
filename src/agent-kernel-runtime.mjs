// Trusted-server Base alpha. Authentication belongs to the MCP wrapper, never this module.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import { BlockList, isIP } from 'node:net';
import { isDeepStrictEqual } from 'node:util';
import { isUtf8 } from 'node:buffer';
import { createHash } from 'node:crypto';
import { createPublicClient, createWalletClient, http, parseAbi, encodeFunctionData,
  getAddress, keccak256, hashTypedData, decodeFunctionData, parseEventLogs, parseErc6492Signature, zeroAddress, recoverMessageAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { addressToEmptyAccount } from '@zerodev/sdk';
import { entryPoint07Abi, toPackedUserOperation, getUserOperationHash } from 'viem/account-abstraction';
import { createKernelAccount } from '@zerodev/sdk';
import { getEntryPoint, KERNEL_V3_1 } from '@zerodev/sdk/constants';
import { signerToEcdsaValidator } from '@zerodev/ecdsa-validator';
import { PERMIT2_ADDRESS, x402ExactPermit2ProxyABI, x402UptoPermit2ProxyABI } from '@x402/evm';
import { decodePaymentResponseHeader } from '@x402/core/http';
import { createAgentKernelWallet, NO_LIMIT } from './agent-kernel-wallet.mjs';
import { parseChallenge, selectOffer, quoteOffer, payWithSafe, nonceUsed, registerPaymentScheme, STANDING_PERMIT2_ALLOWANCE } from './safe-pay.mjs';
import { registerCircleSchemes, signGatewayDeposit, signSafeBurnIntent, requestGatewayAttestation, gatewayMintCall, gatewayAttestationDead, gatewayBalances, gatewayFor, gatewayAvailable, GATEWAY_DOMAINS } from './safe-pay-circle.mjs';
import { safeSignatureAccepted, relayPay, finishRelay } from './safe-pay-relay.mjs';
import { safeChain } from './safe-pay-chains.mjs';
import { detectProtocol, parseMppChallenges, selectMppOffer, quoteMppOffer, hopCall, payMppCharge } from './safe-pay-mpp.mjs';
import { connectedSafeAgentSigner, guestSafeAgentSigner } from './privy-agent-app-signer.mjs';

const EP = getEntryPoint('0.7');
const abi = parseAbi(['function transfer(address,uint256) returns(bool)', 'function approve(address,uint256) returns(bool)',
  'function balanceOf(address) view returns(uint256)', 'function allowance(address,address) view returns(uint256)',
  'event Transfer(address indexed from,address indexed to,uint256 value)']);
const permitAbi = parseAbi(['function nonceBitmap(address,uint256) view returns(uint256)',
  'function approve(address token,address spender,uint160 amount,uint48 expiration)']);
const permissionAbi = parseAbi(['function permissionConfig(bytes4) view returns ((bytes2 permissionFlag,address signer,bytes22[] policyData))']);
const sudoAbi = parseAbi(['function ecdsaValidatorStorage(address) view returns (address)']);
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? String(v) : v);
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
const check = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { runtimeCode: code }); };
const units = value => { check(typeof value === 'string' && /^[1-9][0-9]{0,77}$/.test(value) && BigInt(value) < 2n ** 256n, 'invalid_amount_units'); return BigInt(value); };
const address = value => { check(typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value) && !same(value, zeroAddress), 'invalid_address'); return getAddress(value); };
const call = (to, contractAbi, functionName, args) => ({ to, value: 0n, data: encodeFunctionData({ abi: contractAbi, functionName, args }) });
const transfer = (token, to, amount) => call(token, abi, 'transfer', [to, amount]);
const approve = (token, amount) => call(token, abi, 'approve', [PERMIT2_ADDRESS, amount]);
const denied = new BlockList();
for (const [ip, bits] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],
  ['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.88.99.0',24],['192.168.0.0',16],
  ['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]]) denied.addSubnet(ip,bits,'ipv4');
function merchantUrl(value) {
  check(typeof value === 'string' && value.length <= 4096, 'invalid_merchant_url');
  const u = new URL(value);
  check(u.protocol === 'https:' && !u.username && !u.password && !u.hash && !u.port && u.href === value
    && !isIP(u.hostname) && /^[a-z0-9.-]+$/.test(u.hostname) && u.hostname.includes('.')
    && !/(^|\.)(localhost|local|internal|home|lan|test|invalid)$/.test(u.hostname), 'invalid_merchant_url');
  return u;
}
// Deliberately IPv4-only. DNS is resolved once per request, every A answer checked,
// then pinned into TLS lookup; no redirects, proxy environment, cookies or retries.
// D-SAFE-NO-LIMITS: any method, optional body. The body travels with an RFC 9530
// Content-Digest, so the same bytes are bound to the unpaid and the paid request.
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const ROUTER_CHAT_URL = 'https://router.paymentrequired.com/v1/chat/completions';
function looksLikeJsonString(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return false;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed !== null && typeof parsed === 'object';
  } catch {
    return false;
  }
}
export function requestShape({ method = 'GET', body, contentType } = {}) {
  check(METHODS.includes(method), 'invalid_http_method');
  if (body === undefined || body === null) return { method, headers: {}, bytes: null };
  const bytes = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
  check(bytes.length <= 262144 && !['GET', 'HEAD'].includes(method), 'invalid_request_body');
  const resolvedType = contentType || (typeof body === 'string'
    ? (looksLikeJsonString(body) ? 'application/json' : 'text/plain; charset=utf-8')
    : 'application/json');
  return { method, bytes, headers: { 'Content-Type': resolvedType,
    'Content-Length': String(bytes.length), 'Content-Digest': `sha-256=:${createHash('sha256').update(bytes).digest('base64')}:` } };
}
// Every merchant request (quote and paid) names its client: live 2026-09-29 a merchant behind an AWS load
// balancer (mapbox.x402.paywithlocus.com) answered 403 without a User-Agent and 402 with one.
export const MERCHANT_HEADERS = { Accept: '*/*', 'Accept-Encoding': 'identity', 'User-Agent': 'paymentrequired/1.0 (+https://paymentrequired.com)' };
async function merchantGet(url, headers = {}, onHeaders = () => {}, shape = requestShape()) {
  const u = merchantUrl(url);
  const answers = await Promise.race([lookup(u.hostname, { all: true, family: 4 }),
    new Promise((_, reject) => { const t = setTimeout(() => reject(new Error('dns_timeout')), 10000); t.unref(); })]);
  check(answers.length > 0 && answers.every(a => a.family === 4 && !denied.check(a.address, 'ipv4')), 'nonpublic_merchant');
  const pinned = answers[0];
  return new Promise((resolve, reject) => {
    let timer;
    const req = request(u, { method: shape.method, agent: false, maxHeaderSize: 49152,
      headers: { ...MERCHANT_HEADERS, ...shape.headers, ...headers },
      lookup: (_host, options, cb) => options.all ? cb(null, [pinned]) : cb(null, pinned.address, 4),
    }, res => {
      try {
        onHeaders(res.statusCode, res.headers); // Settlement evidence survives unsupported bodies/redirects.
        check(res.statusCode < 300 || res.statusCode >= 400, 'merchant_redirect_forbidden');
        check(!res.headers['content-encoding'] || res.headers['content-encoding'] === 'identity', 'encoded_body_unsupported');
      } catch (e) { res.destroy(e); req.destroy(e); return; }
      const chunks = []; let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 262144) { req.destroy(new Error('merchant_body_too_large')); res.destroy(); }
        else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => { clearTimeout(timer); resolve({ status: res.statusCode, headers: res.headers, bytes: Buffer.concat(chunks) }); });
      res.on('aborted', () => reject(new Error('merchant_body_aborted')));
    });
    // The postpriced router generates the answer BEFORE returning its 402 (up to 180 s).
    timer = setTimeout(() => req.destroy(new Error('merchant_timeout')), url === ROUTER_CHAT_URL ? 190000 : 20000);
    req.on('error', e => { clearTimeout(timer); reject(e); }); req.end(shape.bytes ?? undefined);
  });
}
// Paid but not delivered: the merchant's own words, short and as text only (untrusted data, live 2026-09-28: fal HTTP 403).
const merchantExcerpt = r => /^(text\/|application\/(json|[^;]+\+json))/.test(r.headers['content-type'] || '') && isUtf8(r.bytes) ? r.bytes.toString('utf8').slice(0, 300) : undefined;
function resource(response) {
  const type = response.headers['content-type'] || 'application/octet-stream';
  const text = /^(text\/|application\/(json|[^;]+\+json))/.test(type) && isUtf8(response.bytes);
  return { content_type: type, encoding: text ? 'utf8' : 'base64', body: response.bytes.toString(text ? 'utf8' : 'base64'), size_bytes: response.bytes.length };
}
// What a signature from the Safe may authorize: exactly the picked offer, nothing else.
// Deadline = Permit2 deadline or EIP-3009 validBefore.
const deadlineOf = td => td?.message?.deadline ?? td?.message?.validBefore;
// D-SAFE-CIRCLE: Circle Nanopayments ('exact' + GatewayWalletBatched) join main's scheme hook.
registerCircleSchemes(registerPaymentScheme);
function validateTypedData(td, offer, chainId, safe) {
  const d = td?.domain, m = td?.message, now = Math.floor(Date.now() / 1000);
  check(Number(d?.chainId) === chainId, 'invalid_signing_domain');
  if (offer.handler === 'circle-gateway-batched') {
    // Signed by the Agent EOA (`safe` here = the payer address) against the GatewayWallet domain.
    // Circle requires >= 7 days validity (MIN_VALIDITY, src/safe-pay-circle.mjs), so no offer-timeout bound.
    check(d.name === 'GatewayWalletBatched' && same(d.verifyingContract, offer.extra.verifyingContract) && td.primaryType === 'TransferWithAuthorization', 'invalid_signing_domain');
    check(same(m.from, safe) && same(m.to, offer.payTo) && String(m.value) === offer.amount, 'invalid_signing_terms');
    check(Number(m.validBefore) > now && Number(m.validBefore) <= now + 8 * 24 * 3600, 'invalid_signing_expiry_or_nonce');
    return;
  }
  if (td.primaryType === 'TransferWithAuthorization') {
    check(same(d.verifyingContract, offer.asset) && same(m.from, safe) && same(m.to, offer.payTo) && String(m.value) === offer.amount, 'invalid_signing_terms');
  } else {
    check(d.name === 'Permit2' && same(d.verifyingContract, PERMIT2_ADDRESS) && td.primaryType === 'PermitWitnessTransferFrom', 'invalid_signing_domain');
    check(same(m.permitted?.token, offer.asset) && String(m.permitted.amount) === offer.amount && same(m.witness?.to, offer.payTo), 'invalid_signing_terms');
  }
  const deadline = Number(deadlineOf(td));
  check(Number.isSafeInteger(deadline) && deadline > now && deadline <= now + offer.maxTimeoutSeconds + 1, 'invalid_signing_expiry_or_nonce');
}

// home: the chain wallets are created on (AGENT_KERNEL_RPC_URL applies there only). A runtime for
// another chain of src/safe-pay-chains.mjs pays from the same Safe address with its own ledger file.
// merchantFetch: the merchant HTTP seam (default merchantGet); proofs inject a mocked merchant here.
export function createKernelRuntime({ path, store, env = process.env, chainId = 8453, privyApp, home = true, merchantFetch = merchantGet }) {
  check(typeof path === 'string' && path.length > 0 && store?.getKernelWallet, 'runtime_store_required');
  const network = safeChain(chainId, env);
  check(network.callPolicy && network.usdc, 'unsupported_chain');
  const usdc = network.usdc.address;
  const eip155 = network.network;
  // D-SAFE-NO-LIMITS: no per-payment cap. AGENT_KERNEL_MAX_PAYMENT_UNITS is gone on purpose;
  // the only ceiling left is the operator's own gas budget below.
  const budget = units(env.AGENT_KERNEL_GAS_BUDGET_WEI || '30000000000000');
  const ownerExitReserve = 10000000000000n; // Per-wallet earmark, not a Base L1 fee guarantee.
  check(budget <= 100000000000000000n, 'operator_budget_too_large');
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;
    CREATE TABLE IF NOT EXISTS agent_kernel_alpha_ops (
      wallet TEXT NOT NULL, request TEXT NOT NULL, kind TEXT NOT NULL, binding TEXT NOT NULL,
      state TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY(wallet,request));
    DROP INDEX IF EXISTS agent_kernel_alpha_one_spend;
    CREATE UNIQUE INDEX IF NOT EXISTS agent_kernel_alpha_one_spend_link ON agent_kernel_alpha_ops(wallet, json_extract(binding,'$.url'))
      WHERE kind='pay' AND state NOT IN ('paid','not_required','failed');
    CREATE TABLE IF NOT EXISTS agent_kernel_alpha_txs (
      id TEXT PRIMARY KEY, wallet TEXT NOT NULL, request TEXT NOT NULL, step TEXT NOT NULL,
      operator TEXT NOT NULL, state TEXT NOT NULL, reserve TEXT NOT NULL, data TEXT NOT NULL,
      UNIQUE(wallet,request,step));
    CREATE UNIQUE INDEX IF NOT EXISTS agent_kernel_alpha_operator_pending ON agent_kernel_alpha_txs(operator)
      WHERE state IN ('preparing','signed');
    CREATE TABLE IF NOT EXISTS agent_kernel_alpha_budget (id INTEGER PRIMARY KEY CHECK(id=1), committed TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS agent_kernel_alpha_exit (wallet TEXT PRIMARY KEY, reserve TEXT NOT NULL,
      address TEXT, readiness TEXT NOT NULL DEFAULT '0', admission INTEGER NOT NULL DEFAULT 0);
    INSERT OR IGNORE INTO agent_kernel_alpha_budget VALUES(1,'0');`);
  const client = createPublicClient({ chain: network.chain, transport: http((home && env.AGENT_KERNEL_RPC_URL) || network.rpc, { retryCount: 0, timeout: 15000 }) });
  let closed = false, busy = 0;
  const active = new Set();
  const transaction = fn => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
  const getOp = (wallet, requestId) => {
    const row = db.prepare('SELECT * FROM agent_kernel_alpha_ops WHERE wallet=? AND request=?').get(wallet, requestId);
    return row ? { ...row, data: JSON.parse(row.data) } : null;
  };
  const save = (op, state = op.state) => { op.state = state; db.prepare('UPDATE agent_kernel_alpha_ops SET state=?,data=? WHERE wallet=? AND request=?').run(state, json(op.data), op.wallet, op.request); };
  function wallet(id, { capped = false } = {}) { // capped: an older Safe with a transfer cap, allowed only to read and for the owner's own tapped send-out
    check(!closed, 'runtime_closed'); const row = store.getKernelWallet(id); check(row, 'wallet_not_found');
    // Every Safe is no-limit with one chain-free record (same address and permission everywhere): it is
    // served on any payable chain, seen through this chain's id.
    check((row.record.maxTransferUnits === NO_LIMIT || capped) && (row.record.chainId === chainId || !home) && row.record.permit2Enabled === true && row.record.policyVersion === '0.0.5', 'unsupported_wallet_configuration');
    return row.record.chainId === chainId ? row : { ...row, record: { ...row.record, chainId } };
  }
  const read = (contract, contractAbi, functionName, args, blockNumber) => client.readContract({ address: contract, abi: contractAbi, functionName, args, ...(blockNumber === undefined ? {} : { blockNumber }) });
  const balance = (a, block) => read(usdc, abi, 'balanceOf', [a], block);
  const allowance = (a, block) => read(usdc, abi, 'allowance', [a, PERMIT2_ADDRESS], block);
  const permission = (r, block) => read(r.address, permissionAbi, 'permissionConfig', [r.permissionId], block);
  const enabled = () => check(env.AGENT_KERNEL_ALPHA === 'true', 'agent_kernel_alpha_disabled');
  const chain = async () => check(await client.getChainId() === chainId, 'rpc_chain_mismatch');
  function publicOp(op) {
    const res = op.data.result || {};
    // Ops that never landed still name amount and recipient: from the stored
    // binding (send/fee, JSON text) or the priced offer (pay).
    let binding = {};
    try { binding = JSON.parse(op.binding || '{}'); } catch { }
    const to = binding.to ?? op.data.offer?.payTo;
    const amountUnits = binding.amountUnits ?? op.data.offer?.amount;
    return { walletId: op.wallet, requestId: op.request, action: op.kind, status: op.state === 'not_required' ? 'confirmed' : op.state,
      ...res,
      ...(res.to === undefined && to !== undefined ? { to: String(to) } : {}),
      ...(res.amountUnits === undefined && amountUnits !== undefined ? { amountUnits: String(amountUnits) } : {}),
      ...(op.data.reason ? { reason: op.data.reason } : {}),
      ...(op.data.offer ? { amountUnits: op.data.offer.amount, scheme: op.data.offer.scheme, rail: op.data.offer.method } : {}),
      ...(op.data.quote ? { quote: op.data.quote } : {}),
      ...(op.data.paymentReceipt?.transaction && !res.transaction ? { transaction: op.data.paymentReceipt.transaction } : {}),
      createdAt: op.created };
  }
  function start(walletId, requestId, kind, binding) {
    check(typeof requestId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(requestId), 'invalid_request_id');
    return transaction(() => {
      const old = getOp(walletId, requestId);
      if (old) { check(old.kind === kind && old.binding === json(binding), 'request_id_conflict'); return { op: old, fresh: false }; }
      if (kind === 'pay') {
        // A permit2 authorization whose deadline has passed is cryptographically
        // dead: it can never settle on-chain, so no double payment is possible.
        // Such requests are closed as failed (never paid) and no longer block.
        for (const b of db.prepare("SELECT request, state, data FROM agent_kernel_alpha_ops WHERE wallet=? AND kind='pay' AND state NOT IN ('paid','not_required','failed')").all(walletId)) {
          const data = JSON.parse(b.data || '{}');
          if (b.state === 'unknown' && !data?.paymentReceipt?.transaction && !data?.relay
              && deadlineOf(data?.typedData) !== undefined
              && BigInt(deadlineOf(data.typedData)) < BigInt(Math.floor(Date.now() / 1000))) {
            db.prepare("UPDATE agent_kernel_alpha_ops SET state='failed', data=? WHERE wallet=? AND request=?")
              .run(JSON.stringify({ ...data, reason: 'payment_authorization_expired' }), walletId, b.request);
          }
        }
        check(!db.prepare("SELECT 1 FROM agent_kernel_alpha_ops WHERE wallet=? AND kind='pay' AND state NOT IN ('paid','not_required','failed') AND json_extract(binding,'$.url')=?").get(walletId, binding?.url ?? ''), 'unresolved_payment_blocks_new_spend'); // one open pay per wallet AND link, the same rule as the index agent_kernel_alpha_one_spend_link: a refused but still-valid authorization blocks only its link (review 2026-09-29)
      }
      const op = { wallet: walletId, request: requestId, kind, binding: json(binding), state: 'pending', data: {}, created: new Date().toISOString() };
      db.prepare('INSERT INTO agent_kernel_alpha_ops VALUES(?,?,?,?,?,?,?)').run(walletId, requestId, kind, op.binding, op.state, '{}', op.created);
      return { op, fresh: true };
    });
  }
  function saveTx(t, state) {
    t.state = state; db.prepare('UPDATE agent_kernel_alpha_txs SET state=?,data=? WHERE id=?').run(state, json(t.data), t.id);
  }
  function txRows(sql, ...args) { return db.prepare(sql).all(...args).map(t => ({ ...t, data: JSON.parse(t.data) })); }
  async function txReceipt(t, wait = false) {
    if (!t.data.hash) return null;
    let r;
    try { r = wait ? await client.waitForTransactionReceipt({ hash: t.data.hash, confirmations: 2, timeout: 90000 }) : await client.getTransactionReceipt({ hash: t.data.hash }); }
    catch { return null; }
    if (!wait && await client.getBlockNumber() <= r.blockNumber) return null;
    check(same(r.transactionHash, t.data.hash) && same(r.from, t.operator), 'operator_receipt_mismatch');
    const mined = await client.getTransaction({ hash: t.data.hash });
    check(mined.nonce === t.data.nonce && await client.getTransactionCount({ address: t.operator, blockNumber: r.blockNumber }) > t.data.nonce, 'operator_nonce_unconfirmed');
    const outerSuccess = r.status === 'success';
    let ok = outerSuccess, reimbursement = 0n;
    if (outerSuccess && t.data.userOpHash) {
      const decoded = decodeFunctionData({ abi: entryPoint07Abi, data: mined.input });
      const packed = decoded.args?.[0];
      check(same(mined.to, EP.address) && decoded.functionName === 'handleOps'
        && same(decoded.args[1], t.operator) && packed?.length === 1
        && same(packed[0].sender, t.data.sender) && String(packed[0].nonce) === t.data.userOpNonce
        && packed[0].paymasterAndData === '0x', 'operator_reimbursement_call_mismatch');
      check(same(await read(EP.address, entryPoint07Abi, 'getUserOpHash', [packed[0]], r.blockNumber), t.data.userOpHash), 'operator_userop_hash_mismatch');
      const events = parseEventLogs({ abi: entryPoint07Abi, eventName: 'UserOperationEvent', logs: r.logs })
        .filter(e => same(e.address, EP.address) && same(e.args.userOpHash, t.data.userOpHash));
      check(events.length === 1 && same(events[0].args.sender, t.data.sender)
        && String(events[0].args.nonce) === t.data.userOpNonce && same(events[0].args.paymaster, zeroAddress), 'operator_reimbursement_event_mismatch');
      reimbursement = events[0].args.actualGasCost;
      ok = events[0].args.success; // Inner revert still reimburses the outer beneficiary.
    }
    t.data.receipt = { hash: r.transactionHash, block: String(r.blockNumber), success: !!ok };
    check(!network.opStack || (r.l1Fee !== undefined && r.l1Fee !== null), 'operator_l1_fee_unconfirmed');
    const outerFee = r.gasUsed * r.effectiveGasPrice + BigInt(r.l1Fee ?? 0);
    const actual = outerFee + (outerSuccess ? BigInt(mined.value) : 0n) - reimbursement;
    transaction(() => {
      const current = db.prepare('SELECT * FROM agent_kernel_alpha_txs WHERE id=?').get(t.id);
      const saved = JSON.parse(current.data);
      if (!saved.accounted && current.state === 'signed') {
        const used = BigInt(db.prepare('SELECT committed FROM agent_kernel_alpha_budget WHERE id=1').get().committed);
        const previous = BigInt(current.reserve);
        db.prepare('UPDATE agent_kernel_alpha_budget SET committed=? WHERE id=1').run(String(used + actual - previous));
        const held = db.prepare('SELECT reserve,readiness FROM agent_kernel_alpha_exit WHERE wallet=?').get(t.wallet);
        if (held) {
          const owner = getOp(t.wallet, t.request)?.kind !== 'pay';
          // Actual lifetime owner usage (outer fees of every non-pay operation).
          const ownerFees = owner ? txRows(`SELECT t.* FROM agent_kernel_alpha_txs t
            JOIN agent_kernel_alpha_ops o ON o.wallet=t.wallet AND o.request=t.request
            WHERE t.wallet=? AND o.kind<>'pay' AND t.id<>?`, t.wallet, t.id)
            .reduce((n, row) => n + BigInt(row.data.accounted?.outerFee || 0), outerFee) : 0n;
          const remaining = owner ? ownerExitReserve - ownerFees : BigInt(held.reserve);
          // Signed net debit, including negative reimbursement, retains onboarding capacity.
          const readiness = BigInt(held.readiness) - (owner ? 0n : actual);
          db.prepare('UPDATE agent_kernel_alpha_exit SET reserve=?,readiness=? WHERE wallet=?')
            .run(String(remaining > 0n ? remaining : 0n), String(readiness), t.wallet);
        }
        t.data.accounted = { netDebit: String(actual), outerFee: String(outerFee), reimbursement: String(reimbursement) };
        saveTx(t, ok ? 'confirmed' : 'reverted');
      } else { t.state = current.state; t.data = saved; }
    }); return r;
  }
  async function reconcileOperator() {
    for (const t of txRows("SELECT * FROM agent_kernel_alpha_txs WHERE state='signed'")) await txReceipt(t);
  }
  // Admission shares the dispatch exclusion domain. A crash leaves a durable
  // pending hold, not an address published without capacity; never expire it blindly.
  async function admit(walletId, walletAddress) {
    enabled(); check(!closed, 'runtime_closed'); address(walletAddress);
    await chain(); await reconcileOperator();
    transaction(() => {
      check(!db.prepare("SELECT 1 FROM agent_kernel_alpha_txs WHERE state IN ('preparing','signed')").get()
        && !db.prepare('SELECT 1 FROM agent_kernel_alpha_exit WHERE admission=1').get(), 'operator_busy');
      db.prepare('INSERT INTO agent_kernel_alpha_exit(wallet,reserve,address,readiness,admission) VALUES(?,?,?,?,1)')
        .run(walletId, '0', walletAddress, '0');
    });
    busy++;
    try {
      const keyPath = env.AGENT_KERNEL_FUNDER_KEY_FILE; check(keyPath, 'operator_key_file_required');
      let key = readFileSync(keyPath, 'utf8').trim(); if (!key.startsWith('0x')) key = '0x' + key;
      const funder = privateKeyToAccount(key); key = null;
      const fees = await client.estimateFeesPerGas();
      check(fees.maxFeePerGas > 0n && fees.maxFeePerGas <= network.feeCeiling, 'operator_gas_price_ceiling');
      check(await client.getCode({ address: EP.address }), 'entrypoint_unavailable');
      // Minimum actionable readiness: first deployment prefund plus a real
      // depositTo gas estimate and its L1 reserve. Not a full activation promise.
      const prefund = 525000n * fees.maxFeePerGas;
      const estimated = await client.estimateGas({ account: funder.address, to: EP.address, value: prefund,
        data: encodeFunctionData({ abi: entryPoint07Abi, functionName: 'depositTo', args: [walletAddress] }) });
      const gas = estimated + estimated / 5n;
      check(gas <= 5000000n, 'operator_gas_limit_ceiling');
      const readiness = prefund + gas * fees.maxFeePerGas + 1000000000000n;
      const cash = await client.getBalance({ address: funder.address });
      transaction(() => {
        const used = BigInt(db.prepare('SELECT committed FROM agent_kernel_alpha_budget WHERE id=1').get().committed);
        const held = db.prepare('SELECT reserve,readiness FROM agent_kernel_alpha_exit WHERE wallet<>?').all(walletId)
          .reduce((n, r) => n + BigInt(r.reserve) + (BigInt(r.readiness) > 0n ? BigInt(r.readiness) : 0n), 0n);
        check(cash >= held + ownerExitReserve + readiness, 'operator_admission_balance_insufficient');
        check(used + held + ownerExitReserve + readiness <= budget, 'operator_admission_budget_exhausted');
        db.prepare('UPDATE agent_kernel_alpha_exit SET reserve=?,readiness=? WHERE wallet=? AND admission=1')
          .run(String(ownerExitReserve), String(readiness), walletId);
      });
    } catch (e) { cancelAdmission(walletId); throw e; }
    finally { busy--; }
  }
  function cancelAdmission(walletId) {
    transaction(() => {
      check(!store.getKernelWallet(walletId), 'published_admission_cannot_cancel');
      db.prepare('DELETE FROM agent_kernel_alpha_exit WHERE wallet=? AND admission=1').run(walletId);
    });
  }
  async function send(op, step, requestData, meta = {}) {
    enabled(); await chain();
    await reconcileOperator();
    let prior = txRows('SELECT * FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND step=?', op.wallet, op.request, step)[0];
    if (prior) { const r = await txReceipt(prior); check(r && prior.state === 'confirmed', 'operator_transaction_unknown'); return r; }
    const keyPath = env.AGENT_KERNEL_FUNDER_KEY_FILE; check(keyPath, 'operator_key_file_required');
    let key = readFileSync(keyPath, 'utf8').trim(); if (!key.startsWith('0x')) key = '0x' + key;
    const funder = privateKeyToAccount(key); key = null;
    check(!same(funder.address, wallet(op.wallet, { capped: true }).record.address), 'operator_must_not_be_wallet'); // capped: only the address is read (live 2026-09-28: an older Safe's tapped move-out failed here)
    const t = { id: randomUUID(), wallet: op.wallet, request: op.request, step, operator: funder.address, state: 'preparing', reserve: '0', data: { ...meta } };
    // Durable mutex, not a lease. A crash during nonce/signing preparation fails closed.
    transaction(() => {
      check(!db.prepare('SELECT 1 FROM agent_kernel_alpha_exit WHERE admission=1').get(), 'operator_admission_pending');
      check(!db.prepare("SELECT 1 FROM agent_kernel_alpha_txs WHERE state IN ('preparing','signed')").get(), 'operator_transaction_unknown');
      db.prepare('INSERT INTO agent_kernel_alpha_txs VALUES(?,?,?,?,?,?,?,?)').run(t.id, t.wallet, t.request, step, t.operator, t.state, t.reserve, json(t.data));
    });
    let signingStarted = false;
    try {
      const fees = await client.estimateFeesPerGas();
      check(fees.maxFeePerGas > 0n && fees.maxFeePerGas <= network.feeCeiling, 'operator_gas_price_ceiling');
      const estimated = await client.estimateGas({ ...requestData, account: funder.address });
      const gas = estimated + estimated / 5n;
      check(gas <= 5000000n, 'operator_gas_limit_ceiling');
      // Base L1 data fees have no user-specified on-chain cap. Keep a conservative
      // reserve and trip the lifetime ceiling on receipt overrun (documented alpha boundary).
      const l1Reserve = 1000000000000n;
      const reserve = gas * fees.maxFeePerGas + BigInt(requestData.value || 0) + l1Reserve;
      // The durable operator mutex excludes admission/dispatch while these reads run.
      const blockNumber = await client.getBlockNumber();
      const cash = await client.getBalance({ address: funder.address, blockNumber });
      const deposit = await read(EP.address, entryPoint07Abi, 'balanceOf', [wallet(op.wallet, { capped: true }).address], blockNumber);
      check(cash >= reserve, 'operator_balance_insufficient'); // EP ETH cannot pay upfront EOA gas.
      transaction(() => {
        const used = BigInt(db.prepare('SELECT committed FROM agent_kernel_alpha_budget WHERE id=1').get().committed);
        const held = db.prepare('SELECT wallet,reserve,readiness FROM agent_kernel_alpha_exit').all();
        const protectedWei = held.reduce((n, r) => {
          const own = r.wallet === op.wallet;
          const uncovered = BigInt(r.reserve) - (own ? deposit : 0n);
          return n + (own && op.kind !== 'pay' ? 0n : uncovered > 0n ? uncovered : 0n)
            + (!own && BigInt(r.readiness) > 0n ? BigInt(r.readiness) : 0n);
        }, 0n);
        check(cash >= reserve + protectedWei, 'operator_owner_exit_balance_required');
        check(used + reserve + protectedWei <= budget, 'operator_gas_budget_exhausted');
        db.prepare('UPDATE agent_kernel_alpha_budget SET committed=? WHERE id=1').run(String(used + reserve));
        db.prepare('UPDATE agent_kernel_alpha_txs SET reserve=? WHERE id=?').run(String(reserve), t.id);
      });
      t.reserve = String(reserve);
      const nonce = await client.getTransactionCount({ address: funder.address, blockTag: 'pending' });
      const operator = createWalletClient({ account: funder, chain: network.chain, transport: http((home && env.AGENT_KERNEL_RPC_URL) || network.rpc, { retryCount: 0, timeout: 15000 }) });
      signingStarted = true; // From here an uncertain signature is never cancelled.
      const raw = await operator.signTransaction({ ...requestData, chainId, type: 'eip1559', nonce, gas, ...fees });
      t.data = { ...t.data, nonce, raw, hash: keccak256(raw), value: String(requestData.value || 0), dispatched: true };
      saveTx(t, 'signed'); // Exact bytes + hash + dispatch marker committed before RPC.
      op.data.external = true; save(op);
        try { check(same(await client.sendRawTransaction({ serializedTransaction: raw }), t.data.hash), 'broadcast_hash_mismatch'); } catch { /* receipt is authoritative; never sign/send a replacement */ }
      const receipt = await txReceipt(t, true);
      check(receipt, 'operator_transaction_unknown'); check(t.state === 'confirmed', 'operator_transaction_reverted'); return receipt;
    } catch (e) {
      if (!signingStarted) transaction(() => {
        const current = db.prepare('SELECT state,reserve FROM agent_kernel_alpha_txs WHERE id=?').get(t.id);
        if (current.state === 'preparing') {
          const used = BigInt(db.prepare('SELECT committed FROM agent_kernel_alpha_budget WHERE id=1').get().committed);
          db.prepare('UPDATE agent_kernel_alpha_budget SET committed=? WHERE id=1').run(String(used - BigInt(current.reserve)));
          saveTx(t, 'aborted');
        }
      });
      throw e;
    }
  }
  // Guest (#285): sudo owner === spender === the Privy agent EOA behind a 2-of-2 quorum (server key +
  // the MODEL key from THIS call's wallet_key). Guest signers {owner, agent} are that one account.
  function guestSigners(row, given) {
    check(row.ownershipScope !== 'on-chain', 'owner_signature_required');
    check(same(row.record.initialOwnerAddress, row.record.agentAddress), 'unsupported_wallet_configuration');
    check(typeof given?.modelPrivateKey === 'string', 'wallet_key_required');
    const account = guestSafeAgentSigner({ walletId: row.id, store, modelPrivateKey: given.modelPrivateKey, app: privyApp, env });
    return { owner: account, agent: account };
  }
  async function ownerView(row, given) {
    const owner = guestSigners(row, given).owner;
    check(same(owner.address, row.record.initialOwnerAddress), 'bootstrap_owner_mismatch');
    const account = await createKernelAccount(client, { address: row.address, index: BigInt(row.record.index), entryPoint: EP, kernelVersion: KERNEL_V3_1,
      plugins: { sudo: await signerToEcdsaValidator(client, { signer: owner, entryPoint: EP, kernelVersion: KERNEL_V3_1 }) } });
    check(same(account.factoryAddress, row.record.factory) && same(await account.generateInitCode(), row.record.factoryData), 'owner_initialization_mismatch');
    return account;
  }
  async function operation(op, step, account, calls, deploy = false) {
    const prior = txRows('SELECT * FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND step=?', op.wallet, op.request, step)[0];
    if (prior) { const r = await txReceipt(prior); check(r && prior.state === 'confirmed', 'operator_transaction_unknown'); return r; }
    const nonce = await account.getNonce(), fees = await client.estimateFeesPerGas();
    check(fees.maxFeePerGas <= network.feeCeiling, 'operator_gas_price_ceiling');
    const userOp = { sender: account.address, nonce, callData: await account.encodeCalls(calls), callGasLimit: 200000n,
      verificationGasLimit: deploy ? 2000000n : (nonce >> 248n) === 1n ? 1500000n : 250000n, preVerificationGas: 75000n, ...fees,
      ...(deploy ? await account.getFactoryArgs() : {}) };
    await prefund(op, step, userOp);
    // No smart-account ETH transfer, USDC gas swap, or missing-prefund fallback.
    userOp.signature = await account.signUserOperation(userOp);
    return handleOps(op, step, userOp);
  }
  async function prefund(op, step, userOp) {
    const needed = (userOp.callGasLimit + userOp.verificationGasLimit + userOp.preVerificationGas) * userOp.maxFeePerGas;
    const deposited = await read(EP.address, entryPoint07Abi, 'balanceOf', [userOp.sender]);
    if (deposited < needed) await send(op, `${step}-gas`, { to: EP.address, value: needed - deposited,
      data: encodeFunctionData({ abi: entryPoint07Abi, functionName: 'depositTo', args: [userOp.sender] }) });
    check(await read(EP.address, entryPoint07Abi, 'balanceOf', [userOp.sender]) >= needed, 'operator_deposit_insufficient');
  }
  function handleOps(op, step, userOp) {
    const userOpHash = getUserOperationHash({ userOperation: userOp, entryPointAddress: EP.address, entryPointVersion: '0.7', chainId });
    const funderKey = readFileSync(env.AGENT_KERNEL_FUNDER_KEY_FILE, 'utf8').trim();
    const beneficiary = privateKeyToAccount(funderKey.startsWith('0x') ? funderKey : '0x' + funderKey).address;
    return send(op, step, { to: EP.address, data: encodeFunctionData({ abi: entryPoint07Abi, functionName: 'handleOps', args: [[toPackedUserOperation(userOp)], beneficiary] }) },
      { userOpHash, userOpNonce: String(userOp.nonce), sender: userOp.sender });
  }
  // D-OWNER-TAP: a claimed Safe's sudo owner is the person's EOA and the server holds no key
  // for it. The UserOp is prepared once per request, its hash goes to the owner's tap
  // (tap(hash, saved) → { approval } | { signature }), then the operator submits it. Every
  // on-chain step is keyed by (wallet, request, step), so a retry or restart never sends twice.
  const USEROP_BIG = ['nonce', 'callGasLimit', 'verificationGasLimit', 'preVerificationGas', 'maxFeePerGas', 'maxPriorityFeePerGas'];
  const userOpOf = saved => ({ ...saved, ...Object.fromEntries(USEROP_BIG.map(k => [k, BigInt(saved[k])])) });
  async function ownerTapSend(op, row, to, amount, tap) {
    await chain(); await reconcileOperator();
    const prior = txRows('SELECT * FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND step=?', op.wallet, op.request, 'send')[0];
    if (prior) {
      const r = await txReceipt(prior); check(r && prior.state === 'confirmed', 'operator_transaction_unknown');
      await finishOwnerOperation(op, row, to, r, amount); op.data.result.userOpHash = prior.data.userOpHash; op.data.result.custody = 'user-owned'; delete op.data.failure; save(op); return;
    }
    check(await client.getCode({ address: row.address }), 'account_not_deployed'); const root = await read(row.address, parseAbi(['function rootValidator() view returns (bytes21)']), 'rootValidator', []); check(same(await read(`0x${root.slice(4)}`, parseAbi(['function ecdsaValidatorStorage(address) view returns (address)']), 'ecdsaValidatorStorage', [row.address]), row.ownerAddress), 'owner_not_root_validator'); // the owner's tap can only move what the owner controls on chain (older Safes: a server key)
    const account = await createKernelAccount(client, { address: row.address, index: BigInt(row.record.index), entryPoint: EP, kernelVersion: KERNEL_V3_1,
      plugins: { sudo: await signerToEcdsaValidator(client, { signer: addressToEmptyAccount(row.ownerAddress), entryPoint: EP, kernelVersion: KERNEL_V3_1 }) } });
    const nonce = await account.getNonce();
    // A request whose nonce was used by another owner send can never land: prepare it again.
    if (!op.data.prepared || BigInt(op.data.prepared.userOp.nonce) !== nonce) {
      check(await balance(row.address) >= amount, 'insufficient_usdc');
      // The signed fee caps are the operator's own ceiling (operation() above): EntryPoint charges
      // only the fee actually paid, so any fee the operator accepts lands without a second tap.
      const ceiling = network.feeCeiling, fees = await client.estimateFeesPerGas();
      const userOp = { sender: row.address, nonce, callData: await account.encodeCalls([transfer(usdc, to, amount)]),
        callGasLimit: 200000n, verificationGasLimit: 250000n, preVerificationGas: 75000n,
        maxFeePerGas: ceiling, maxPriorityFeePerGas: fees.maxPriorityFeePerGas < ceiling ? fees.maxPriorityFeePerGas : ceiling, signature: '0x' };
      const userOpHash = getUserOperationHash({ userOperation: userOp, entryPointAddress: EP.address, entryPointVersion: '0.7', chainId });
      op.data.prepared = { userOp, userOpHash }; op.data.withdrawAmount = String(amount); delete op.data.approval; save(op, 'approval_required');
    }
    const { userOpHash } = op.data.prepared;
    if (!op.data.prepared.signature) {
      // The tapped signature is kept with the request, so a restart after the tap needs no second tap.
      check(tap, 'owner_signature_required');
      const answer = await tap(userOpHash, op.data.approval, row.ownerAddress);
      if (answer?.approval) {
        op.data.approval = answer.approval; op.data.result = { userOpHash, approvalUrl: answer.approval.url };
        delete op.data.reason; save(op, 'approval_required'); return;
      }
      check(typeof answer?.signature === 'string' && same(await recoverMessageAddress({ message: { raw: userOpHash }, signature: answer.signature }), row.ownerAddress), 'owner_signature_mismatch');
      op.data.prepared.signature = answer.signature; op.data.result = { userOpHash }; save(op);
    }
    const userOp = { ...userOpOf(op.data.prepared.userOp), signature: op.data.prepared.signature };
    check(await balance(row.address) >= amount, 'insufficient_usdc');
    // Fee moved past a ceiling last time: those steps were never signed (state 'aborted'), so
    // they are re-estimated from scratch now instead of blocking the request for good.
    db.prepare("DELETE FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND state='aborted'").run(op.wallet, op.request);
    await prefund(op, 'send', userOp);
    const r = await handleOps(op, 'send', userOp);
    await finishOwnerOperation(op, row, to, r, amount); op.data.result.userOpHash = userOpHash; op.data.result.custody = 'user-owned'; delete op.data.failure; save(op);
  }
  const readContract = args => client.readContract(args);
  const quoteAny = offer => offer.protocol === 'mpp' ? quoteMppOffer(offer) : quoteOffer(offer);
  const metaAbi = parseAbi(['function name() view returns (string)', 'function version() view returns (string)']);
  const tokenBalance = (token, a, block) => read(token, abi, 'balanceOf', [a], block);
  const tokenAllowance = (token, a, block) => read(token, abi, 'allowance', [a, PERMIT2_ADDRESS], block);
  // Evidence, not trust: a receipt must move the offer's token from the Safe to payTo
  // (upto: at most the signed ceiling) and use our nonce. Some merchants omit their receipt.
  const authorizationAbi = parseAbi(['event AuthorizationUsed(address indexed authorizer,bytes32 indexed nonce)']);
  async function verifyPayment(op) {
    const reported = op.data.paymentReceipt, row = wallet(op.wallet), offer = op.data.offer;
    if (!offer || op.data.beforeBlock === undefined || !op.data.typedData) return false;
    const usable = reported?.success === true && (reported.network === offer.network || reported.network === eip155)
      && (reported.payer === undefined || same(reported.payer, row.address))
      && /^0x[0-9a-fA-F]{64}$/.test(reported.transaction);
    const ceiling = BigInt(offer.amount);
    const matchesAmount = value => offer.scheme === 'upto' ? value > 0n && value <= ceiling : value === ceiling;
    async function confirm(hash, discovered = false) {
      let r; try { r = await client.waitForTransactionReceipt({ hash, confirmations: 2, timeout: 30000 }); } catch { return false; }
      check(same(r.transactionHash, hash) && r.status === 'success' && r.blockNumber >= BigInt(op.data.beforeBlock), 'settlement_receipt_invalid');
      const transfers = parseEventLogs({ abi, eventName: 'Transfer', logs: r.logs }).filter(e => same(e.address, offer.asset) && same(e.args.from, row.address));
      const value = transfers[0]?.args.value;
      check(transfers.length === 1 && same(transfers[0].args.to, offer.payTo) && matchesAmount(value), 'settlement_transfer_mismatch');
      const used = blockNumber => nonceUsed({ offer, typedData: op.data.typedData, safe: row.address, readContract, blockNumber });
      check(await used(r.blockNumber) === true, 'settlement_nonce_unused');
      if (discovered) {
        const authorizations = parseEventLogs({ abi: authorizationAbi, eventName: 'AuthorizationUsed', logs: r.logs }).filter(e => same(e.address, offer.asset));
        // Bind discovery to THIS authorization, not another equal payment by the same Safe.
        if (op.data.typedData.primaryType === 'TransferWithAuthorization' && authorizations.length) {
          check(authorizations.some(e => same(e.args.authorizer, row.address) && same(e.args.nonce, op.data.typedData.message.nonce)), 'settlement_nonce_mismatch');
        } else {
          const td = op.data.typedData, tx = await client.getTransaction({ hash });
          const eip3009 = td.primaryType === 'TransferWithAuthorization';
          const callAbi = eip3009 ? parseAbi([
            'function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,bytes signature)',
            'function receiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,bytes signature)',
            'function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)',
            'function receiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)',
          ]) : offer.scheme === 'upto' ? x402UptoPermit2ProxyABI : x402ExactPermit2ProxyABI;
          const decoded = decodeFunctionData({ abi: callAbi, data: tx.input });
          if (eip3009) check(same(tx.to, offer.asset) && same(decoded.args[0], row.address)
            && same(decoded.args[5], td.message.nonce), 'settlement_nonce_mismatch');
          else {
            check(td.primaryType === 'PermitWitnessTransferFrom' && ['settle', 'settleWithPermit'].includes(decoded.functionName)
              && same(tx.to, td.message.spender), 'settlement_nonce_mismatch');
            const args = decoded.functionName === 'settleWithPermit' ? decoded.args.slice(1) : decoded.args;
            const owner = offer.scheme === 'upto' ? args[2] : args[1];
            check(same(owner, row.address) && BigInt(args[0].nonce) === BigInt(td.message.nonce), 'settlement_nonce_mismatch');
          }
          check(await used(r.blockNumber - 1n) === false, 'settlement_nonce_already_used');
        }
      }
      op.data.result = { ...(op.data.result || {}), settlement: discovered ? 'chain_discovered' : 'verified', transaction: r.transactionHash, blockNumber: String(r.blockNumber),
        amountSettledUnits: String(value), contentDelivered: !!op.data.contentDelivered };
      delete op.data.reason; save(op, 'paid'); return true;
    }
    if (usable) { try { if (await confirm(reported.transaction)) return true; } catch { /* An unusable merchant receipt is not the only source of evidence. */ } }
    const latest = await client.getBlockNumber({ cacheTime: 0 });
    // Bounded RPC ranges also let old, interrupted requests reconcile without a giant getLogs.
    for (let fromBlock = BigInt(op.data.beforeBlock); fromBlock <= latest; fromBlock += 2000n) {
      const toBlock = fromBlock + 1999n < latest ? fromBlock + 1999n : latest;
      const logs = await client.getLogs({ address: offer.asset, event: abi.find(e => e.name === 'Transfer'),
        args: { from: row.address, to: offer.payTo }, fromBlock, toBlock, strict: true });
      for (const hash of new Set(logs.filter(e => !e.removed && matchesAmount(e.args.value)).map(e => e.transactionHash))) {
        try { if (await confirm(hash, true)) return true; } catch { /* Other transfers are not evidence for this authorization. */ }
      }
    }
    return false;
  }
  // The unpaid request, the 402 challenge and the offer the Safe would pay. Shared by pay and dry_run.
  async function challenge({ url, shape, requestId, prefer, maxAmountUnits }) {
    const response = await merchantFetch(url, requestId ? { 'Idempotency-Key': requestId } : {}, undefined, shape);
    if (response.status !== 402) return { response };
    const bodyText = response.bytes.toString('utf8');
    // D-SAFE-MPP: a 402 is x402 (PAYMENT-REQUIRED / JSON body) or MPP (WWW-Authenticate: Payment).
    if (detectProtocol({ headers: response.headers, bodyText, prefer }) === 'mpp') {
      const offer = selectMppOffer(parseMppChallenges({ headers: response.headers }), { chainIds: [chainId], prefer });
      if (maxAmountUnits !== undefined) check(BigInt(offer.amount) <= BigInt(maxAmountUnits), 'payment_exceeds_max_amount');
      return { response, required: null, offer };
    }
    const { required, offers } = parseChallenge({ headers: response.headers, bodyText });
    const offer = selectOffer(offers, { chainIds: [chainId], prefer });
    if (maxAmountUnits !== undefined) check(BigInt(offer.amount) <= BigInt(maxAmountUnits), 'payment_exceeds_max_amount');
    return { response, required, offer };
  }
  // Every spending wallet keeps the owner's exit gas reserved before the operator spends for it.
  function admitExitReserve(row) {
    transaction(() => {
      if (!db.prepare('SELECT 1 FROM agent_kernel_alpha_exit WHERE wallet=?').get(row.id)) {
        const used = BigInt(db.prepare('SELECT committed FROM agent_kernel_alpha_budget WHERE id=1').get().committed);
        const held = db.prepare('SELECT reserve FROM agent_kernel_alpha_exit').all().reduce((n, r) => n + BigInt(r.reserve), 0n);
        check(used + held + ownerExitReserve < budget, 'operator_owner_exit_reserve_required');
        db.prepare('INSERT INTO agent_kernel_alpha_exit(wallet,reserve,address) VALUES(?,?,?)').run(row.id, String(ownerExitReserve), row.address);
      }
    });
  }
  // D-TOOLS-PAID: a tool price paid by the Safe's AGENT SPENDER — one UserOp with USDC transfer(to, amount)
  // (hopCall, src/safe-pay-mpp.mjs), allowed by the no-limit CallPolicy, so an owned Safe pays with no tap.
  // Step 'fee' is keyed by (wallet, request): a retry returns the same receipt and never sends twice.
  async function feeFresh(op, row, to, amount, given) {
    await chain();
    const quorumAgent = await connectedSafeAgentSigner({ row, store, env, app: privyApp, userPrivateKey: given?.connectedPrivateKey });
    const prior = txRows('SELECT * FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND step=?', op.wallet, op.request, 'fee')[0];
    if (!prior) { check(await balance(row.address) >= amount, 'insufficient_usdc'); admitExitReserve(row); }
    const keys = quorumAgent ? null : guestSigners(row, given);
    const agent = quorumAgent || keys.agent;
    const selfOwned = same(row.record.initialOwnerAddress, row.record.agentAddress);
    const ownerSigner = keys ? keys.owner : selfOwned && quorumAgent ? quorumAgent : addressToEmptyAccount(row.record.initialOwnerAddress);
    const w = await createAgentKernelWallet({ client, record: row.record, ownerSigner, agentSigner: agent });
    const deployed = !!await client.getCode({ address: row.address });
    // Undeployed: only a guest (keys, or the self-owned quorum) may deploy; the fee rides in that same op.
    // A claimed Safe is deployed by its claim; an undeployed claimed one would need deploy-rotate first.
    if (!deployed) check(!row.claimed && (keys || (selfOwned && quorumAgent)), 'owner_signature_required');
    else if (!prior && same((await permission(row.record)).signer, zeroAddress)) check(keys, 'agent_permission_not_enabled');
    op.data.fee = { to, amountUnits: String(amount) }; op.data.dispatched = true; save(op, 'unknown');
    const r = await operation(op, 'fee', w.agentAccount, [hopCall(usdc, to, amount)], !deployed);
    const transfers = parseEventLogs({ abi, eventName: 'Transfer', logs: r.logs }).filter(e => same(e.address, usdc) && same(e.args.from, row.address));
    check(r.status === 'success' && transfers.length === 1 && same(transfers[0].args.to, to) && transfers[0].args.value === amount, 'settlement_transfer_mismatch');
    op.data.result = { settlement: 'verified', transaction: r.transactionHash, blockNumber: String(r.blockNumber), amountSettledUnits: String(amount), to };
    delete op.data.reason; save(op, 'paid');
  }
  async function payFresh(op, row, req, given) {
    await chain();
    // Connected Safe: the Privy 2-of-2 agent key signs (D-QUORUM B) with the LLM key from THIS call's
    // wallet_key (D-CUSTODY-V2, owner 2026-09-25: never from server RAM). Guest: null, guest key below.
    const quorumAgent = await connectedSafeAgentSigner({ row, store, env, app: privyApp, userPrivateKey: given?.connectedPrivateKey });
    const shape = requestShape(req), url = req.url;
    const { response, required, offer } = await challenge({ url, shape, requestId: op.request, prefer: req.prefer, maxAmountUnits: req.maxAmountUnits });
    if (!offer) {
      check(response.status >= 200 && response.status < 300, 'merchant_http_error');
      op.data.result = { httpStatus: response.status, resource: resource(response), contentDelivered: true }; save(op, 'not_required'); return;
    }
    // D-SAFE-NO-LIMITS: every Safe pays any amount in any token its spender policy allows.
    // batch-settlement is registered (src/safe-pay-relay.mjs registerRelaySchemes, via src/safe-pay.mjs) and
    // signs, but its channel state and deposit/voucher settlement checks are not in this runtime yet:
    // refuse before anything is signed or sent (it ranks last, so only a batch-only 402 or prefer hits this).
    check(offer.scheme !== 'batch-settlement', 'batch_settlement_not_in_runtime');
    check(await tokenBalance(offer.asset, row.address) >= BigInt(offer.amount), 'insufficient_usdc');
    admitExitReserve(row);
    op.data.offer = offer; op.data.required = required; op.data.quote = quoteAny(offer); save(op);
    // Claimed on chain: the owner is the user's EOA, never needed to pay; only its address shapes the view.
    // Guest: the Privy quorum account (guestSigners); the same x402 path either way.
    const keys = quorumAgent ? null : guestSigners(row, given);
    const agent = quorumAgent || keys.agent;
    // Custody v2: the Privy agent EOA is the Safe's INITIAL sudo on every chain (same counterfactual
    // address), so it can deploy the Safe on a chain it was never used on; a claimed Safe then hands
    // sudo to the owner's EOA there too (deploy-rotate), exactly like the claim on the home chain.
    const selfOwned = same(row.record.initialOwnerAddress, row.record.agentAddress);
    const ownerSigner = () => keys ? keys.owner : selfOwned && quorumAgent ? quorumAgent : addressToEmptyAccount(row.record.initialOwnerAddress);
    const build = () => createAgentKernelWallet({ client, record: row.record, ownerSigner: ownerSigner(), agentSigner: agent });
    await ensureDeployed(op, row, { keys, selfOwned, quorumAgent, build });
    // Reconstruct after deployment and between requests: plugin enabled flags must not be cached.
    const fresh = await build();
    const need = quoteAny(offer).needs.permit2Allowance;
    if (need !== undefined) {
      const current = await tokenAllowance(offer.asset, row.address);
      // One standing Permit2 approval per token, set once: payments never wait on an approve again,
      // and parallel payments do not race one allowance.
      if (current < need) {
        const r = await operation(op, 'approve', fresh.agentAccount, [approve(offer.asset, STANDING_PERMIT2_ALLOWANCE)]);
        check(await tokenAllowance(offer.asset, row.address, r.blockNumber) === STANDING_PERMIT2_ALLOWANCE, 'permit2_approval_unconfirmed');
      }
    }
    // EIP-3009 needs no transaction, but ERC-1271 only answers for an installed permission:
    // the first payment enables it (Kernel ENABLE mode, signed by the server-held sudo).
    if (same((await permission(row.record)).signer, zeroAddress)) {
      check(keys, 'agent_permission_not_enabled');
      await operation(op, 'enable', fresh.agentAccount, [approve(usdc, 0n)]);
    }
    const signing = await build();
    check(!same((await permission(row.record)).signer, zeroAddress), 'agent_permission_not_enabled');
    if (offer.protocol === 'mpp') return payMpp(op, row, offer, agent, signing, url, shape);
    if (offer.payer === 'agent-eoa') return payCircle(op, row, offer, required, agent, signing, url, shape);
    const paid = await payWithSafe({ offer, required, safe: row.address, readContract, signTypedData: async td => {
      validateTypedData(td, offer, chainId, row.address);
      const block = await client.getBlockNumber();
      check(await nonceUsed({ offer, typedData: td, safe: row.address, readContract, blockNumber: block }) === false, 'payment_nonce_already_used');
      check(await tokenBalance(offer.asset, row.address, block) >= BigInt(offer.amount), 'insufficient_usdc');
      op.data.typedData = td; op.data.beforeBlock = String(block); op.data.signing = true; save(op);
      return parseErc6492Signature(await signing.agentAccount.signTypedData(td)).signature;
    } });
    // D-SAFE-EOA-RELAY: the token itself refuses the Safe's ERC-1271 authorization (ecrecover-only
    // EIP-3009). That Safe signature can never settle, so it is dropped unsent and the Agent EOA pays.
    if (!await safeSignatureAccepted({ offer, payload: paid.payload, readContract })) return payRelay(op, row, offer, required, agent, signing, url, shape);
    op.data.authorization = Object.values(paid.headers)[0]; op.data.authorizationHash = hashTypedData(op.data.typedData); save(op);
    op.data.dispatched = true; save(op, 'unknown');
    try {
      const delivered = await merchantFetch(url, { 'Idempotency-Key': op.request, ...paid.headers }, (status, headers) => {
        op.data.httpStatus = status;
        const receipt = headers['payment-response'] ?? headers['x-payment-response'];
        if (typeof receipt === 'string') {
          try { op.data.paymentReceipt = decodePaymentResponseHeader(receipt); } catch { op.data.reason = 'invalid_merchant_receipt'; }
        }
        save(op); // Persist receipt before a body limit/disconnect can discard evidence.
      }, shape);
      op.data.contentDelivered = delivered.status >= 200 && delivered.status < 300;
      op.data.contentHash = keccak256(delivered.bytes);
      const promisedHash = op.data.paymentReceipt?.extensions?.['otto-content-receipt']?.receipt?.signedMessage?.contentHash;
      if (promisedHash !== undefined && !same(promisedHash, op.data.contentHash)) {
        op.data.contentDelivered = false; op.data.contentError = 'merchant_content_hash_mismatch';
      }
      op.data.result = { httpStatus: delivered.status, ...(op.data.contentDelivered ? { resource: resource(delivered) } : { merchantError: merchantExcerpt(delivered) }) }; save(op);
    } catch { op.data.reason = 'merchant_outcome_unknown'; save(op); }
    if (!await verifyPayment(op)) { op.data.reason = 'settlement_unconfirmed'; save(op, 'unknown'); }
  }
  // Counterfactual Safe, same address on every chain: first use deploys it (one agent UserOp
  // installs the permission + standing Permit2 approve); a claimed Safe's sudo rotates to the
  // owner's EOA there too (deploy-rotate), exactly like the claim on the home chain.
  async function ensureDeployed(op, row, { keys, selfOwned, quorumAgent, build }) {
    const w = await build();
    if (await client.getCode({ address: row.address })) return w;
    check(keys || (selfOwned && quorumAgent), 'owner_signature_required');
    // ONE agent UserOp deploys the Safe, installs the permission (ENABLE mode, sudo-signed)
    // and sets the standing Permit2 approve (scripts/prove-safe-pay-fork.mjs).
    await operation(op, 'deploy', w.agentAccount, [approve(usdc, STANDING_PERMIT2_ALLOWANCE)], true);
    if (row.claimed && !keys) {
      const rotating = await build(), calls = rotating.rotateOwnerCalls(row.ownerAddress);
      const r = await operation(op, 'deploy-rotate', rotating.ownerAccount, calls);
      check(same(await read(calls.at(-1).to, sudoAbi, 'ecdsaValidatorStorage', [row.address], r.blockNumber), row.ownerAddress), 'deploy_owner_rotation_unconfirmed');
    }
    return w;
  }
  // D-GATEWAY-BALANCE (b1): deposit into the Safe's unified USDC balance. The Safe signs a
  // ReceiveWithAuthorization for the GatewayWallet (ERC-1271; raw1271 strips 6492), the operator
  // relays depositWithAuthorization — keyed 'gateway-deposit' like every step, a retry reads back.
  async function gatewayDepositFresh(op, row, amount, given) {
    await chain();
    const quorumAgent = await connectedSafeAgentSigner({ row, store, env, app: privyApp, userPrivateKey: given?.connectedPrivateKey });
    const keys = quorumAgent ? null : guestSigners(row, given);
    const agent = quorumAgent || keys.agent;
    const selfOwned = same(row.record.initialOwnerAddress, row.record.agentAddress);
    const ownerSigner = () => keys ? keys.owner : selfOwned && quorumAgent ? quorumAgent : addressToEmptyAccount(row.record.initialOwnerAddress);
    const build = () => createAgentKernelWallet({ client, record: row.record, ownerSigner: ownerSigner(), agentSigner: agent });
    check(await balance(row.address) >= amount, 'insufficient_usdc');
    const w = await ensureDeployed(op, row, { keys, selfOwned, quorumAgent, build });
    admitExitReserve(row);
    const prior = txRows('SELECT * FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND step=?', op.wallet, op.request, 'gateway-deposit')[0];
    const deposit = prior ? null : await signGatewayDeposit({ signer: w.agentAccount, chainId, amountUnits: amount, from: row.address });
    if (deposit) { op.data.typedData = deposit.typedData; op.data.digest = deposit.digest; op.data.dispatched = true; save(op, 'unknown'); }
    const r = await send(op, 'gateway-deposit', deposit ? { to: deposit.call.to, data: deposit.call.data } : {});
    const gw = gatewayFor(chainId);
    op.data.result = { transaction: r.transactionHash, blockNumber: String(r.blockNumber), amountUnits: String(amount), depositor: row.address, gateway: gw.wallet };
    try { op.data.result.availableUnits = String(await gatewayAvailable({ client, chainId, depositor: row.address })); } catch { }
    delete op.data.reason; save(op, 'deposited');
  }
  // D-GATEWAY-BALANCE (b1): burn intent signed by the Safe as contract (ERC-1271, contractSigner:
  // true); Circle's TEE simulates isValidSignature on the source chain — the Safe must be deployed
  // there. The recipient is always the Safe's own address on the destination (no third-party
  // cross-chain send; D-OWNER-TAP holds). Off-chain only: nothing lands on chain here.
  async function gatewayBurnFresh(op, row, destinationChainId, amount, given) {
    await chain();
    const quorumAgent = await connectedSafeAgentSigner({ row, store, env, app: privyApp, userPrivateKey: given?.connectedPrivateKey });
    const keys = quorumAgent ? null : guestSigners(row, given);
    const agent = quorumAgent || keys.agent;
    const selfOwned = same(row.record.initialOwnerAddress, row.record.agentAddress);
    const ownerSigner = () => keys ? keys.owner : selfOwned && quorumAgent ? quorumAgent : addressToEmptyAccount(row.record.initialOwnerAddress);
    const build = () => createAgentKernelWallet({ client, record: row.record, ownerSigner: ownerSigner(), agentSigner: agent });
    const available = await gatewayAvailable({ client, chainId, depositor: row.address });
    op.data.gatewayAvailableUnits = String(available); save(op);
    // No operator gas on an empty Gateway balance: the deposit needed isValidSignature,
    // so a Safe with one is already deployed and ensureDeployed below is a no-op for it.
    check(available >= amount, 'insufficient_gateway_balance');
    const w = await ensureDeployed(op, row, { keys, selfOwned, quorumAgent, build });
    const signed = await signSafeBurnIntent({ safeAccount: w.agentAccount, sourceChainId: chainId, destinationChainId, recipient: row.address, amountUnits: amount });
    const attempt = op.data.result?.attestation ? (op.data.result.attempt || 1) + 1 : 1; // >1: the earlier attestation is dead (attestationDead)
    op.data.typedData = signed.typedData; op.data.digest = signed.digest; save(op);
    const { attestation, operatorSignature } = await requestGatewayAttestation({ requests: [signed.request], api: signed.api,
      headers: env.CIRCLE_GATEWAY_API_KEY ? { authorization: `Bearer ${env.CIRCLE_GATEWAY_API_KEY}` } : {} });
    op.data.result = { attestation, operatorSignature, minter: signed.minter, destinationChainId, amountUnits: String(amount), recipient: row.address, attempt };
    delete op.data.reason; save(op, 'attested');
  }
  // An attested burn whose attestation expired unminted (on-chain proof, gatewayAttestationDead) is
  // re-attested under the same request_id; any doubt (RPC error, other revert) keeps it as it is.
  async function attestationDead(op) {
    const r = op.data.result || {};
    try { const dst = gatewayFor(r.destinationChainId);
      return await gatewayAttestationDead({ client: createPublicClient({ chain: dst.chain, transport: http(dst.rpc, { retryCount: 0, timeout: 15000 }) }),
        minter: r.minter, attestation: r.attestation, operatorSignature: r.operatorSignature });
    } catch { return false; }
  }
  // D-GATEWAY-BALANCE (b1): the destination chain's runtime. gatewayMint is permissionless
  // (destinationCaller = 0x0), so the operator submits — keyed 'gateway-mint', never sent twice.
  async function gatewayMintFresh(op, row, { attestation, operatorSignature, minter }) {
    await chain();
    const r = await send(op, 'gateway-mint', gatewayMintCall({ minter, attestation, operatorSignature }));
    op.data.result = { transaction: r.transactionHash, blockNumber: String(r.blockNumber), destinationChainId: chainId };
    delete op.data.reason; save(op, 'minted');
  }
  // D-SAFE-EOA-RELAY (src/safe-pay-relay.mjs): keyed UserOp 'relay-fund' = hopCall (exactly the quote,
  // Safe → Agent EOA), the EOA signs the offer, the merchant settles, finishRelay proves it. Relay state
  // (op.data.relay + relayTypedData) is in the runtime ledger before anything is dispatched, so an
  // interrupted payment is finished by the same request_id (mutate → finishRelayOp), never paid twice.
  async function payRelay(op, row, offer, required, agent, signing, url, shape) {
    op.data.relayAgent = agent.address; save(op);
    const sendSafeCalls = async calls => (await operation(op, 'relay-fund', signing.agentAccount, calls)).transactionHash;
    const relayed = await relayPay({ offer, required, safe: row.address, agent, client, sendSafeCalls });
    op.data.relay = relayed.relay; op.data.relayTypedData = relayed.typedData;
    op.data.authorization = Object.values(relayed.headers)[0]; op.data.authorizationHash = hashTypedData(relayed.typedData); save(op);
    op.data.dispatched = true; save(op, 'unknown');
    try {
      const delivered = await merchantFetch(url, { 'Idempotency-Key': op.request, ...relayed.headers }, (status, headers) => {
        op.data.httpStatus = status;
        const receipt = headers['payment-response'] ?? headers['x-payment-response'];
        if (typeof receipt === 'string') { try { op.data.paymentReceipt = decodePaymentResponseHeader(receipt); } catch { op.data.reason = 'invalid_merchant_receipt'; } }
        save(op);
      }, shape);
      op.data.contentDelivered = delivered.status >= 200 && delivered.status < 300; op.data.contentHash = keccak256(delivered.bytes);
      op.data.result = { httpStatus: delivered.status, ...(op.data.contentDelivered ? { resource: resource(delivered) } : { merchantError: merchantExcerpt(delivered) }) }; save(op);
    } catch { op.data.reason = 'merchant_outcome_unknown'; save(op); }
    try { await finishRelayOp(op, row, null, agent); }
    catch (e) { op.data.reason = e.runtimeCode || 'settlement_unconfirmed'; save(op, 'unknown'); }
  }
  // Settled → verified receipt, state 'paid'. Not settled and validBefore passed → the funded amount goes
  // back to the Safe (EOA-signed EIP-3009, operator-submitted, keyed 'relay-return'), state 'failed'.
  // Still live → throws relay_authorization_still_live and the op stays 'unknown' (retry later).
  async function finishRelayOp(op, row, given, agentAccount) {
    const agent = agentAccount || (await connectedSafeAgentSigner({ row, store, env, app: privyApp, userPrivateKey: given?.connectedPrivateKey })) || guestSigners(row, given)?.agent;
    check(agent && same(agent.address, op.data.relay.eoa), 'relay_signer_required');
    const reported = op.data.paymentReceipt;
    const settlementTx = reported?.success === true && /^0x[0-9a-fA-F]{64}$/.test(reported.transaction ?? '') ? reported.transaction : undefined;
    const submit = async tx => (await send(op, 'relay-return', { to: tx.to, data: tx.data })).transactionHash;
    const done = await finishRelay({ offer: op.data.offer, safe: row.address, agent, client, relay: op.data.relay, typedData: op.data.relayTypedData, settlementTx, submit });
    op.data.relayReceipt = done;
    if (done.settleTx) {
      op.data.result = { ...(op.data.result || {}), settlement: 'verified', path: 'eoa_relay', payer: done.payer, transaction: done.settleTx,
        fundTx: done.fundTx, returnTx: done.returnTx, amountSettledUnits: done.settledUnits, contentDelivered: !!op.data.contentDelivered };
      delete op.data.reason; save(op, 'paid');
    } else { op.data.reason = 'relay_expired_returned_to_safe'; save(op, 'failed'); }
  }
  // D-SAFE-MPP (src/safe-pay-mpp.mjs): one agent UserOp moves exactly the charge from the Safe to its
  // Agent EOA ('mpp-hop', keyed like every step so a retry never hops twice), the Agent EOA signs the
  // stock MPP credential, the merchant settles, and the settlement is checked on chain.
  async function payMpp(op, row, offer, agent, signing, url, shape) {
    check(offer.method === 'evm' && offer.intent === 'charge', 'mpp_rail_needs_tempo_runtime');
    const [name, version] = await Promise.all([read(offer.asset, metaAbi, 'name', []), read(offer.asset, metaAbi, 'version', []).catch(() => '1')]);
    const block = await client.getBlockNumber();
    op.data.beforeBlock = String(block); op.data.mppAgent = agent.address; save(op);
    const hop = async (token, amount) => {
      const r = await operation(op, 'mpp-hop', signing.agentAccount, [hopCall(token, agent.address, amount)]);
      check(await tokenBalance(token, agent.address, r.blockNumber) >= BigInt(amount), 'mpp_hop_unconfirmed');
    };
    op.data.signing = true; save(op);
    const paid = await payMppCharge({ offer, agent, hop, evmAuthorization: { name, version },
      fetchPaid: async credential => {
        op.data.authorizationHash = keccak256(`0x${Buffer.from(credential).toString('hex')}`); op.data.dispatched = true; save(op, 'unknown');
        const res = await merchantFetch(url, { 'Idempotency-Key': op.request, Authorization: credential }, (status, headers) => {
          op.data.httpStatus = status;
          if (typeof headers['payment-receipt'] === 'string') op.data.mppReceipt = headers['payment-receipt'];
          save(op);
        }, shape);
        return new Response(res.bytes, { status: res.status, headers: Object.entries(res.headers).filter(([, v]) => typeof v === 'string') });
      } }).catch(e => { op.data.reason = e.runtimeCode || 'merchant_outcome_unknown'; save(op); return null; });
    if (paid) {
      const bytes = Buffer.from(await paid.response.arrayBuffer());
      op.data.contentDelivered = paid.response.status >= 200 && paid.response.status < 300; op.data.contentHash = keccak256(bytes);
      op.data.result = { httpStatus: paid.response.status, ...(op.data.contentDelivered ? { resource: resource({ headers: Object.fromEntries(paid.response.headers), bytes }) } : {}) };
      if (paid.receipt) op.data.paymentReceipt = { success: paid.receipt.status === 'success', transaction: paid.receipt.reference, network: offer.network, payer: agent.address, protocol: 'mpp' };
      save(op);
    }
    if (!await verifyMpp(op)) { op.data.reason = op.data.reason || 'settlement_unconfirmed'; save(op, 'unknown'); }
  }
  // D-SAFE-CIRCLE Nanopayments: Circle checks the authorization with ecrecover, so the Safe (ERC-1271)
  // cannot be the payer. Same exact hop as MPP: one agent UserOp moves exactly the amount Safe → Agent
  // EOA ('circle-hop', hopCall), the EOA signs a Gateway deposit that the operator relays
  // ('circle-deposit', permissionless depositWithAuthorization), then the EOA signs the
  // GatewayWalletBatched authorization through main's payWithSafe. Each step is keyed like every other
  // step, so a retry never hops or deposits twice. Nothing is left over: the batch spends the deposit.
  // Settlement is Circle's off-chain batch; there is no per-payment tx to verify (see DECISIONS).
  async function payCircle(op, row, offer, required, agent, signing, url, shape) {
    const gw = gatewayFor(offer.chainId);
    check(same(offer.asset, gw.usdc.address) && same(offer.extra.verifyingContract, gw.wallet), 'invalid_signing_domain');
    const amount = BigInt(offer.amount);
    op.data.circleAgent = agent.address; save(op);
    if (await gatewayAvailable({ client, chainId: offer.chainId, depositor: agent.address }) < amount) {
      const r = await operation(op, 'circle-hop', signing.agentAccount, [hopCall(offer.asset, agent.address, amount)]);
      check(await tokenBalance(offer.asset, agent.address, r.blockNumber) >= amount, 'circle_hop_unconfirmed');
      const prior = txRows('SELECT 1 FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND step=?', op.wallet, op.request, 'circle-deposit')[0];
      const call = prior ? null : (await signGatewayDeposit({ signer: agent, chainId: offer.chainId, amountUnits: amount })).call;
      await send(op, 'circle-deposit', call ? { to: call.to, data: call.data } : {});
      check(await gatewayAvailable({ client, chainId: offer.chainId, depositor: agent.address }) >= amount, 'circle_deposit_unconfirmed');
    }
    const paid = await payWithSafe({ offer, required, safe: row.address, payerAddress: agent.address, readContract, signTypedData: async td => {
      validateTypedData(td, offer, chainId, agent.address);
      op.data.typedData = td; op.data.beforeBlock = String(await client.getBlockNumber()); op.data.signing = true; save(op);
      return agent.signTypedData(td);
    } });
    op.data.authorization = Object.values(paid.headers)[0]; op.data.authorizationHash = hashTypedData(op.data.typedData);
    op.data.dispatched = true; save(op, 'unknown');
    const delivered = await merchantGet(url, { 'Idempotency-Key': op.request, ...paid.headers }, (status, headers) => {
      op.data.httpStatus = status;
      const receipt = headers['payment-response'] ?? headers['x-payment-response'];
      if (typeof receipt === 'string') { try { op.data.paymentReceipt = decodePaymentResponseHeader(receipt); } catch { op.data.reason = 'invalid_merchant_receipt'; } }
      save(op);
    }, shape).catch(() => null);
    if (!delivered) { op.data.reason = 'merchant_outcome_unknown'; save(op, 'unknown'); return; }
    op.data.contentDelivered = delivered.status >= 200 && delivered.status < 300; op.data.contentHash = keccak256(delivered.bytes);
    op.data.result = { httpStatus: delivered.status, ...(op.data.contentDelivered ? { resource: resource(delivered) } : {}) };
    if (!op.data.contentDelivered || op.data.paymentReceipt?.success === false) { op.data.reason = 'merchant_rejected_payment'; save(op, 'unknown'); return; }
    op.data.result = { ...op.data.result, settlement: 'gateway-batched', protocol: 'x402', payer: agent.address, amountSettledUnits: offer.amount, contentDelivered: true };
    delete op.data.reason; save(op, 'paid');
  }
  async function verifyMpp(op) {
    const reported = op.data.paymentReceipt, offer = op.data.offer;
    if (!reported?.transaction || !/^0x[0-9a-fA-F]{64}$/.test(reported.transaction)) return false;
    let r; try { r = await client.waitForTransactionReceipt({ hash: reported.transaction, confirmations: 2, timeout: 30000 }); } catch { return false; }
    check(r.status === 'success' && r.blockNumber >= BigInt(op.data.beforeBlock), 'settlement_receipt_invalid');
    const transfers = parseEventLogs({ abi, eventName: 'Transfer', logs: r.logs }).filter(e => same(e.address, offer.asset) && same(e.args.from, op.data.mppAgent));
    check(transfers.length === 1 && same(transfers[0].args.to, offer.payTo) && transfers[0].args.value === BigInt(offer.amount), 'settlement_transfer_mismatch');
    op.data.result = { ...(op.data.result || {}), settlement: 'verified', protocol: 'mpp', transaction: r.transactionHash, blockNumber: String(r.blockNumber),
      amountSettledUnits: offer.amount, contentDelivered: !!op.data.contentDelivered };
    delete op.data.reason; save(op, 'paid'); return true;
  }
  // Guest send: the Privy quorum account (sudo) moves the amount; a claimed Safe sends by owner tap (ownerTapSend).
  async function sendFresh(op, row, to, sendAmount, given) {
    await chain(); await reconcileOperator();
    const code = await client.getCode({ address: row.address });
    const prior = txRows('SELECT * FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND step=?', op.wallet, op.request, op.kind)[0];
    if (prior) {
      const r = await txReceipt(prior); check(r && prior.state === 'confirmed', 'operator_transaction_unknown');
      return finishSend(op, row, to, r, BigInt(op.data.withdrawAmount || 0));
    }
    const account = await ownerView(row, given);
    const amount = sendAmount; check(amount > 0n, 'nothing_to_send'); check(await balance(row.address) >= amount, 'insufficient_usdc');
    op.data.withdrawAmount = String(amount); save(op);
    const r = await operation(op, op.kind, account, [transfer(usdc, to, amount)], !code);
    return finishSend(op, row, to, r, amount);
  }
  async function finishSend(op, row, to, r, amount) {
    const transfers = parseEventLogs({ abi, eventName: 'Transfer', logs: r.logs }).filter(e => same(e.address, usdc) && same(e.args.from, row.address));
    check(transfers.length === 1 && same(transfers[0].args.to, to) && transfers[0].args.value === amount, 'send_receipt_unconfirmed');
    op.data.result = { transaction: r.transactionHash, blockNumber: String(r.blockNumber), amountUnits: String(amount), to };
    delete op.data.reason; save(op, 'sent');
  }
  // Owner-tap send landed: exactly one USDC transfer of `amount` from the Safe to `to`, then 'sent'.
  // Restored from before 6439a64 (D-NO-LEGACY deleted it with stop/withdraw; ownerTapSend still calls it).
  async function finishOwnerOperation(op, row, to, r, amount) {
    const transfers = parseEventLogs({ abi, eventName: 'Transfer', logs: r.logs }).filter(e => same(e.address, usdc) && same(e.args.from, row.address));
    check(transfers.length === 1 && same(transfers[0].args.to, to) && transfers[0].args.value === amount, 'send_receipt_unconfirmed');
    op.data.result = { transaction: r.transactionHash, blockNumber: String(r.blockNumber), amountUnits: String(amount), to };
    delete op.data.reason; save(op, 'sent');
  }
  // D-QUORUM A: the tap is the claim. Kernel v3.1 grants a permission's selector only in
  // ENABLE mode (root-signed), so: enable the quorum spender, then rotate sudo to the EOA.
  async function claimFresh(op, row, given, owner, agentAccount) {
    await chain(); await reconcileOperator();
    // The quorum was already swapped to the EOA-derived key, so the same Privy EOA (agentAccount) signs as sudo.
    check(same(row.record.initialOwnerAddress, row.record.agentAddress), 'unsupported_wallet_configuration');
    const temp = agentAccount;
    const { chainId: c, index, initialOwnerAddress, policyVersion, permit2Enabled } = row.record;
    // D-SAFE-NO-LIMITS: the guest record is already the no-limit spender; the claim keeps it.
    const next = await createAgentKernelWallet({ client, ownerSigner: temp, agentSigner: agentAccount,
      record: { chainId: c, index, initialOwnerAddress, maxTransferUnits: NO_LIMIT, policyVersion, permit2Enabled } });
    check(same(next.record.address, row.address) && !same(owner, next.record.agentAddress), 'claim_record_mismatch');
    op.data.nextRecord = next.record; save(op);
    if (!await client.getCode({ address: row.address })) await operation(op, 'claim-deploy', next.agentAccount, [approve(usdc, STANDING_PERMIT2_ALLOWANCE)], true);
    if (same((await permission(next.record)).signer, zeroAddress)) {
      const fresh = await createAgentKernelWallet({ client, ownerSigner: temp, agentSigner: agentAccount, record: next.record });
      await operation(op, 'claim-enable', fresh.agentAccount, [approve(usdc, STANDING_PERMIT2_ALLOWANCE)]);
    }
    const calls = [];
    calls.push(call(PERMIT2_ADDRESS, permitAbi, 'approve', [usdc, row.record.agentAddress, 0n, 0]), ...next.rotateOwnerCalls(owner));
    const sudo = calls.at(-1).to;
    const r = await operation(op, 'claim-rotate', (await createAgentKernelWallet({ client, ownerSigner: temp, agentSigner: agentAccount, record: next.record })).ownerAccount, calls);
    check(same(await read(sudo, sudoAbi, 'ecdsaValidatorStorage', [row.address], r.blockNumber), owner)
      && !same((await permission(next.record, r.blockNumber)).signer, zeroAddress), 'claim_receipt_unconfirmed');
    op.data.result = { transaction: r.transactionHash, blockNumber: String(r.blockNumber), to: owner, custody: 'user-owned' };
    delete op.data.reason; save(op, 'claimed');
    return next.record;
  }
  async function claim({ walletId, keys, ownerAddress, agentAccount }) {
    enabled(); const row = wallet(walletId), owner = address(ownerAddress);
    check(!row.claimed, 'kernel_claim_rejected');
    const requestId = `claim-${owner.toLowerCase()}`, slot = `${walletId}:${requestId}`;
    // First EOA to tap owns it: a second owner's claim is refused while one is open or done.
    check(!db.prepare("SELECT 1 FROM agent_kernel_alpha_ops WHERE wallet=? AND kind='claim' AND request<>? AND state<>'failed'").get(walletId, requestId), 'kernel_claim_rejected');
    const { op } = start(walletId, requestId, 'claim', { owner });
    if (op.state === 'claimed' || active.has(slot)) return { ...publicOp(op), record: op.data.nextRecord };
    active.add(slot); busy++;
    // A failed/unknown claim reruns: every step is keyed by (wallet, request, step), never sent twice.
    try { const record = await claimFresh(op, row, keys, owner, agentAccount); return { ...publicOp(op), record }; }
    catch (e) {
      op.data.reason = e.runtimeCode || 'runtime_execution_unconfirmed'; op.data.failure = { name: e.name, message: e.shortMessage || e.message };
      save(op, op.data.external ? 'unknown' : 'failed'); return publicOp(op);
    } finally { active.delete(slot); busy--; }
  }
  async function mutate({ walletId, requestId, url, method, body, contentType, prefer, maxAmountUnits, to, amountUnits, keys, tap, destinationChainId, attestation, operatorSignature, minter }, kind) {
    enabled(); const row = wallet(walletId, { capped: kind === 'send' && !keys });
    let req;
    if (kind === 'pay') {
      merchantUrl(url); const shape = requestShape({ method, body, contentType });
      // max_amount is the caller's own optional ceiling for this one request, never a wallet limit.
      req = { url, method: shape.method, body, contentType, prefer: prefer ?? undefined, maxAmountUnits: maxAmountUnits === undefined ? undefined : String(units(maxAmountUnits)),
        digest: shape.headers['Content-Digest'] ?? null };
    }
    if (kind === 'send') {
      to = address(to); amountUnits = units(amountUnits);
      check(row.claimed || keys, 'verified_owner_claim_required');
    }
    if (kind === 'fee') { to = address(to); amountUnits = units(amountUnits); }
    if (kind === 'gateway-deposit') amountUnits = units(amountUnits);
    if (kind === 'gateway-burn') { gatewayFor(destinationChainId); amountUnits = units(amountUnits); }
    if (kind === 'gateway-mint') {
      check(typeof attestation === 'string' && /^0x[0-9a-fA-F]+$/.test(attestation), 'invalid_attestation');
      check(typeof operatorSignature === 'string' && /^0x[0-9a-fA-F]+$/.test(operatorSignature), 'invalid_attestation');
      minter = address(minter);
    }
    const binding = kind === 'pay' ? { url, method: req.method, digest: req.digest, prefer: req.prefer ?? null, maxAmountUnits: req.maxAmountUnits ?? null } : kind === 'send' || kind === 'fee' ? { to, amountUnits: String(amountUnits) }
      : kind === 'gateway-deposit' ? { amountUnits: String(amountUnits) }
      : kind === 'gateway-burn' ? { destinationChainId: Number(destinationChainId), amountUnits: String(amountUnits) }
      : kind === 'gateway-mint' ? { attestation, operatorSignature, minter } : {};
    const { op, fresh } = start(walletId, requestId, kind, binding);
    if (active.has(`${walletId}:${requestId}`)) return publicOp(op);
    // D-TOOLS-PAID fee: every call with the same request_id moves it one step further; only 'paid' is final.
    // A failed fee sent nothing (no confirmed/unknown tx), so it simply reruns once the Safe is funded.
    if (kind === 'fee') {
      // A rerun never sends twice: operation() finds the keyed 'fee' tx and only reads its receipt.
      if (op.state === 'paid') return publicOp(op);
      active.add(`${walletId}:${requestId}`); busy++;
      try {
        db.prepare("DELETE FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND state='aborted'").run(walletId, requestId);
        await feeFresh(op, row, to, amountUnits, keys);
      } catch (e) {
        op.data.reason = e.runtimeCode || 'runtime_execution_unconfirmed';
        op.data.failure = { name: e.name, message: e.shortMessage || e.message };
        const dispatched = db.prepare("SELECT 1 FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND state<>'aborted'").get(walletId, requestId);
        save(op, dispatched ? 'unknown' : 'failed');
      } finally { active.delete(`${walletId}:${requestId}`); busy--; }
      return publicOp(op);
    }
    // D-OWNER-TAP: every call with the same request_id moves the send one step further;
    // only 'sent' is final. Nothing dispatched means the same request_id can simply retry.
    if (kind === 'send' && row.ownershipScope === 'on-chain' && !keys) {
      if (op.state === 'sent') return publicOp(op);
      active.add(`${walletId}:${requestId}`); busy++;
      try { await ownerTapSend(op, row, to, amountUnits, tap); }
      catch (e) {
        op.data.reason = e.runtimeCode || 'runtime_execution_unconfirmed';
        op.data.failure = { name: e.name, message: e.shortMessage || e.message };
        // Tapped but not landed: 'pending' keeps the signature, the same request_id finishes it.
        const dispatched = db.prepare("SELECT 1 FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND state<>'aborted'").get(walletId, requestId);
        save(op, dispatched ? 'unknown' : op.data.prepared?.signature ? 'pending' : op.data.prepared ? 'approval_required' : 'failed');
      } finally { active.delete(`${walletId}:${requestId}`); busy--; }
      return publicOp(op);
    }
    check(row.record.maxTransferUnits === NO_LIMIT, 'unsupported_wallet_configuration'); const retryMint = kind === 'gateway-mint' && !fresh && op.state === 'failed' && !db.prepare("SELECT 1 FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND state NOT IN ('aborted')").get(walletId, requestId); const reattest = kind === 'gateway-burn' && !fresh && op.state === 'attested' && await attestationDead(op); if (reattest && active.has(`${walletId}:${requestId}`)) return publicOp(op); if (!fresh && !retryMint && !reattest) { // a mint that sent nothing (e.g. no operator gas) may run again; the attestation mints once on chain
      if (['pending', 'unknown'].includes(op.state)) {
        // Read-only reconciliation: never regenerate signatures or redispatch HTTP/transactions.
        active.add(`${walletId}:${requestId}`); busy++;
        try {
          await chain(); await reconcileOperator();
          // D-SAFE-EOA-RELAY: an interrupted relay is finished from the ledger (settlement proven, or after
          // validBefore the funded amount goes back to the Safe). Never re-funds, never re-signs.
          if (kind === 'pay' && op.data.relay) await finishRelayOp(op, row, keys);
          else if (kind === 'pay' && (op.data.paymentReceipt || (op.data.offer && op.data.typedData))) await (op.data.offer?.protocol === 'mpp' ? verifyMpp(op) : verifyPayment(op));
          // A permit2 authorization whose deadline has passed is cryptographically
          // dead: it can never settle on-chain, so the request cannot be paid twice.
          // Marking it failed here (never 'paid') unblocks a NEW request.
          if (kind === 'pay' && op.state === 'unknown' && !op.data.paymentReceipt?.transaction && !op.data.relay
              && deadlineOf(op.data.typedData) !== undefined
              && BigInt(deadlineOf(op.data.typedData)) < BigInt(Math.floor(Date.now() / 1000))) {
            op.data.reason = 'payment_authorization_expired'; save(op, 'failed');
          }
          // A completed deployment is not a merchant payment. Only release this
          // request after positive evidence that no payment signing/dispatch began.
          // The caller may then start a NEW request; this replay never sends anything.
          if (kind === 'pay' && !op.data.signing && !op.data.authorization && !op.data.dispatched) {
            const prior = txRows('SELECT * FROM agent_kernel_alpha_txs WHERE wallet=? AND request=?', walletId, requestId);
            // The standing approve and the enable step authorize no payment by themselves.
            const setup = ['deploy-gas', 'deploy', 'approve-gas', 'approve', 'enable-gas', 'enable'];
            if (prior.length && prior.every(t => setup.includes(t.step)
                && (t.state === 'aborted' || (t.state === 'confirmed' && t.data.accounted)))) {
              op.data.reason = 'interrupted_before_payment_authorization'; save(op, 'failed');
            }
          }
          if (kind !== 'pay') {
            const prior = txRows('SELECT * FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND step=?', walletId, requestId, kind)[0];
            if (prior) {
              const r = await txReceipt(prior);
              if (r && prior.state === 'confirmed') {
                if (kind === 'gateway-deposit' || kind === 'gateway-mint') {
                  op.data.result = { ...(op.data.result || {}), transaction: r.transactionHash, blockNumber: String(r.blockNumber) };
                  save(op, kind === 'gateway-deposit' ? 'deposited' : 'minted');
                } else await finishSend(op, row, to, r, BigInt(op.data.withdrawAmount || 0));
              }
            }
          }
        } catch { /* Insufficient evidence keeps the request blocked, never successful. */ }
        finally {
          if (op.state === 'pending') { op.data.reason = 'interrupted_operation'; save(op, 'unknown'); }
          active.delete(`${walletId}:${requestId}`); busy--;
        }
      }
      // A paid router answer is recoverable with its private Idempotency-Key alone.
      // Never attach a payment header or sign again; a new 402 is not payable here.
      if (kind === 'pay' && url === ROUTER_CHAT_URL && op.state === 'paid' && !op.data.result?.resource) {
        active.add(`${walletId}:${requestId}`); busy++;
        try {
          const response = await merchantFetch(url, { 'Idempotency-Key': op.request }, undefined, requestShape(req));
          if (response.status >= 200 && response.status < 300) {
            op.data.contentDelivered = true;
            op.data.result = { ...op.data.result, httpStatus: response.status, contentDelivered: true, resource: resource(response) };
            save(op);
          }
        } catch { /* Keep the original receipt; the same request can recover later. */ }
        finally { active.delete(`${walletId}:${requestId}`); busy--; }
      }
      return publicOp(op); // Never regenerate or redispatch a payment authorization.
    }
    active.add(`${walletId}:${requestId}`); busy++;
    try {
      if (kind === 'pay') await payFresh(op, row, req, keys);
      else if (kind === 'gateway-deposit') await gatewayDepositFresh(op, row, amountUnits, keys);
      else if (kind === 'gateway-burn') await gatewayBurnFresh(op, row, destinationChainId, amountUnits, keys);
      else if (kind === 'gateway-mint') { if (retryMint) db.prepare("DELETE FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND state='aborted'").run(walletId, requestId); await gatewayMintFresh(op, row, { attestation, operatorSignature, minter }); } // a retried mint clears its never-signed attempt first, like fee and owner sends do (live 2026-09-29: operator_transaction_unknown)
      else await sendFresh(op, row, to, amountUnits, keys);
    } catch (e) {
      op.data.reason = e.runtimeCode || 'runtime_execution_unconfirmed';
      // Private diagnostic only; publicOp/facade never project exception payloads.
      op.data.failure = { name: e.name, message: e.shortMessage || e.message };
      // gateway-burn is off-chain: a deploy tx row is not part of its outcome.
      const dispatched = kind === 'gateway-burn' ? false
        : op.data.external || op.data.signing || op.data.dispatched
        || db.prepare("SELECT 1 FROM agent_kernel_alpha_txs WHERE wallet=? AND request=? AND state NOT IN ('aborted')").get(walletId, requestId);
      save(op, dispatched ? 'unknown' : 'failed');
    } finally { active.delete(`${walletId}:${requestId}`); busy--; }
    return publicOp(op);
  }
  return {
    admit, cancelAdmission, claim, chainId,
    async status(walletId) {
      const row = wallet(walletId, { capped: true }); await chain();
      return { walletId, address: row.address, chainId, asset: usdc, status: row.status, claimed: row.claimed,
        ownerAddress: row.ownerAddress, custody: row.ownershipScope === 'on-chain' ? 'user-owned' : 'guest', ownershipScope: row.ownershipScope,
        balanceUnits: String(await balance(row.address)), maxTransferUnits: row.record.maxTransferUnits,
        operatorGasCommittedWei: db.prepare('SELECT committed FROM agent_kernel_alpha_budget WHERE id=1').get().committed,
        operatorGasBudgetWei: String(budget),
        ownerExitReserveWei: db.prepare('SELECT reserve FROM agent_kernel_alpha_exit WHERE wallet=?').get(walletId)?.reserve || '0',
        minimumOwnerExitReserveWei: String(ownerExitReserve),
        operations: db.prepare('SELECT wallet,request FROM agent_kernel_alpha_ops WHERE wallet=? ORDER BY created,request').all(walletId).map(r => publicOp(getOp(r.wallet,r.request))) };
    },
    pay: args => mutate(args, 'pay'),
    // dry_run: the unpaid request and the offer the Safe would pay. Signs nothing, stores nothing.
    async quote({ walletId, url, method, body, contentType, prefer, maxAmountUnits }) {
      enabled(); const row = wallet(walletId); await chain(); merchantUrl(url);
      const { response, offer } = await challenge({ url, shape: requestShape({ method, body, contentType }), prefer,
        maxAmountUnits: maxAmountUnits === undefined ? undefined : String(units(maxAmountUnits)) });
      if (!offer) return { walletId, status: 'not_required', httpStatus: response.status };
      const balanceUnits = String(await tokenBalance(offer.asset, row.address));
      return { walletId, status: 'quoted', quote: quoteAny(offer), balanceUnits, payable: BigInt(balanceUnits) >= BigInt(offer.amount) };
    }, send: args => mutate(args, 'send'), fee: args => mutate(args, 'fee'),
    gatewayDeposit: a => mutate(a, 'gateway-deposit'), gatewayBurn: a => mutate(a, 'gateway-burn'), gatewayMint: a => mutate(a, 'gateway-mint'),
    async gatewayBalance(walletId) {
      enabled(); const row = wallet(walletId);
      const testnet = gatewayFor(chainId).testnet;
      const chainIds = Object.keys(GATEWAY_DOMAINS).map(Number).filter(id => gatewayFor(id).testnet === testnet);
      return { walletId, balances: await gatewayBalances({ depositor: row.address, chainIds, testnet }) };
    },
    history(walletId) { wallet(walletId); return db.prepare('SELECT wallet,request FROM agent_kernel_alpha_ops WHERE wallet=? ORDER BY created,request').all(walletId).map(r => publicOp(getOp(r.wallet,r.request))); },
    close() { check(busy === 0, 'runtime_busy'); if (!closed) { db.close(); closed = true; } },
  };
}
