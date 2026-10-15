// wallet.fund path (b) — DECISIONS.md D-B + D-D, issue #166.
// Verified user with reserve > 0 → refill the caller's Agent Safe from their
// Wirex smart account. The refill is a UserOp from the smart account, signed
// by the refill key registered on its payment module, calling
// USDC.transfer(safe, amount). The refill key never holds funds and never
// pays merchants (D-B). Sandbox (Base Sepolia 84532) only until the payment
// module is registered on Base mainnet (D-D).
//
// Shape contract (imported by src/mcp-wallet-tool.mjs):
//   fundFromReserve(deps, { walletAddress, amountUnits = null })
//   → { funded:false, from:null, hint }   module not registered on this network
//   → null                                not verified or no reserve (fall through)
//   → { funded:true, from:'reserve', tx } refill landed on-chain
// deps = { accountFlow, chainId, path, wirexBaas, bridge, walletPay,
//          spendPolicy, playground, publicBase, session?, env? }.
// deps.session carries the caller credential from the wallet tool.

import { concatHex, createPublicClient, decodeEventLog, encodeFunctionData, getAddress, http, keccak256, parseAbi, toHex } from 'viem';
import { baseSepolia } from 'viem/chains';
import { privateKeyToAccount, toAccount } from 'viem/accounts';
import { constants, createKernelAccount, createKernelAccountClient, createZeroDevPaymasterClient, getCustomNonceKeyFromString } from '@zerodev/sdk';
import { getEntryPoint, KERNEL_V3_1 } from '@zerodev/sdk/constants';
import { toPermissionValidator } from '@zerodev/permissions';
import { readAaConfig, selfHostPaymaster } from './aa-register.mjs';
import { readPaymentAgentDomain } from './payment-agent-registry.mjs';
import { paymentAgentPolicies, PAYMENT_USDC } from './payment-agent-policy.mjs';
import { scheduledHash, sendRecordedUserOperation } from './payment-agent-operations.mjs';

const SANDBOX_CHAIN_ID = 84532;
const ENTRY_POINT = getEntryPoint('0.7');
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const UNITS = /^(0|[1-9][0-9]*)$/;

const TokenAbi = parseAbi([
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address) view returns (uint256)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]);
const ModuleAbi = parseAbi([
  'function walletConfig(address wallet) view returns ((bool installed, uint40 epoch, uint32 agentCount, bytes32 permissionId, address delayPolicy))',
  'function agentEntry(address wallet, address agent) view returns ((uint8 agentType, bool live, uint32 sigGasCap, uint32 index))',
  'function tokenLimit(address wallet, address agent, address token) view returns ((uint128 cap, uint128 spent, uint128 perTxMax, uint48 windowStart, bool configured))',
  'function windowLength() pure returns (uint256)',
]);

const DelayAbi = parseAbi([
  'function request(address wallet, uint256 nonce, bytes callData) returns (uint48)',
  'function operationsPerAccount(bytes32) view returns (uint8 opType, uint8 status, uint48 validAfter, uint48 validUntil)',
]);

const NOT_AVAILABLE = 'Refill from your bank reserve is not available yet.';
const UNAVAILABLE = () => { const e = new Error('reserve_refill_unavailable'); e.model = 'Refill from your bank reserve could not be sent. Send USDC to your wallet address to start.'; return e; };

function requireAddress(value, code = 'reserve_address_invalid') {
  if (typeof value !== 'string' || !ADDRESS.test(value)) throw new Error(code);
  return getAddress(value);
}

function requireUnits(value, code = 'reserve_amount_invalid') {
  if (typeof value !== 'string' || !UNITS.test(value) || BigInt(value) <= 0n || BigInt(value) >= 2n ** 128n) throw new Error(code);
  return BigInt(value);
}

// Caller binding: verified user = connected session whose account holds a
// smart account (the fiat-side account exists only after verification).
function callerBinding(deps) {
  const session = deps?.session;
  if (typeof session !== 'string' || !session || typeof deps?.accountFlow?.authorized !== 'function') return null;
  let s;
  try { s = deps.accountFlow.authorized(session, { signingGrant: false }); } catch { return null; }
  const owner = s?.result?.signer, kernel = s?.context?.accountReady?.smart_account_address;
  if (!ADDRESS.test(String(owner || '')) || !ADDRESS.test(String(kernel || ''))) return null;
  return { owner: getAddress(owner), kernel: getAddress(kernel) };
}

// Refill key (prototype): a plain server-held key registered on the account's
// payment module as a refill-only agent. TODO(D-B follow-up): source this key
// from the agent wallet store / Privy agent app once the refill-key
// registration flow lands; the Wirex partner question on a recipient-locked
// policy is still open (DECISIONS.md 2026-09-21), so the recipient is
// asserted server-side in the transfer receipt below.
function refillSigner(env) {
  const key = String(env?.WALLET_FUND_REFILL_PRIVATE_KEY || '').trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw UNAVAILABLE();
  const inner = privateKeyToAccount(key);
  return toAccount({
    address: inner.address,
    signMessage: async ({ message }) => {
      const raw = typeof message === 'string' ? message : message?.raw;
      if (typeof raw !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(raw)) throw new Error('reserve_signer_accepts_hash_only');
      return inner.sign({ hash: raw });
    },
    signTypedData: async () => { throw new Error('reserve_typed_signing_not_used'); },
    signTransaction: async () => { throw new Error('reserve_transaction_signing_not_used'); },
  });
}

// Payment-module signer wrapper (same shape the agent rail uses): the module
// contract itself is the signer contract; the signature is the refill key's
// raw signature prefixed by the key address.
function moduleSigner(agent, agentAddresses, moduleAddress) {
  const fail = async () => { throw new Error('reserve_typed_or_transaction_signing_not_used'); };
  return {
    account: toAccount({
      address: agent.address,
      signMessage: async ({ message }) => concatHex([agent.address, await agent.signMessage({ message })]),
      signTypedData: fail,
      signTransaction: fail,
    }),
    signerContractAddress: moduleAddress,
    getSignerData: () => concatHex(agentAddresses.map(address => concatHex([getAddress(address), '0x01']))),
    getDummySignature: () => concatHex([agent.address, constants.DUMMY_ECDSA_SIG]),
  };
}

async function exactTransfer(publicClient, txHash, token, from, to, amount) {
  const receipt = await publicClient.getTransactionReceipt({ hash: txHash });
  if (receipt.status !== 'success') return null;
  for (const log of receipt.logs) {
    if (getAddress(log.address) !== getAddress(token)) continue;
    try {
      const decoded = decodeEventLog({ abi: TokenAbi, data: log.data, topics: log.topics });
      if (decoded.eventName === 'Transfer' && getAddress(decoded.args.from) === getAddress(from)
        && getAddress(decoded.args.to) === getAddress(to) && decoded.args.value === amount) {
        return { from: getAddress(from), to: getAddress(to), value: amount.toString() };
      }
    } catch { /* not the transfer */ }
  }
  return null;
}

export async function fundFromReserve(deps, { walletAddress, amountUnits = null } = {}) {
  // Gate 1 (D-D): the payment module is registered on the sandbox network
  // only; anywhere else this path is not available yet.
  if (deps?.chainId !== SANDBOX_CHAIN_ID) return { funded: false, from: null, hint: NOT_AVAILABLE };

  const safe = requireAddress(walletAddress);
  const requested = amountUnits === null || amountUnits === undefined ? null : requireUnits(String(amountUnits));

  // Gate 2: verified caller with reserve > 0, else fall through to the next
  // funding path.
  const caller = callerBinding(deps);
  if (!caller) return null;

  const env = deps?.env || process.env;
  // No refill key (prod today, D-QUORUM row 13): the lane is not configured — answer its
  // one sentence instead of throwing into "temporarily unavailable" at refillSigner().
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(env.WALLET_FUND_REFILL_PRIVATE_KEY || '').trim())) return { funded: false, from: null, hint: NOT_AVAILABLE };
  const config = readAaConfig(env);
  if (config.chainId !== SANDBOX_CHAIN_ID || !config.bundlerUrl) return null;
  const publicClient = createPublicClient({ chain: baseSepolia, transport: http(config.publicRpcUrl) });

  const domain = await readPaymentAgentDomain({
    publicClient, registry: config.registry, kernel: caller.kernel, owner: caller.owner, partnerId: config.partnerId,
  });

  const reserve = await publicClient.readContract({ address: PAYMENT_USDC, abi: TokenAbi, functionName: 'balanceOf', args: [caller.kernel] });
  if (reserve <= 0n) return null;

  // The refill key must be a live refill-only agent on the account's payment
  // module, with daily cap room and per-payment room for the amount.
  const agent = refillSigner(env);
  const [entry, limit, windowLength] = await Promise.all([
    publicClient.readContract({ address: domain.validator, abi: ModuleAbi, functionName: 'agentEntry', args: [caller.kernel, agent.address] }),
    publicClient.readContract({ address: domain.validator, abi: ModuleAbi, functionName: 'tokenLimit', args: [caller.kernel, agent.address, PAYMENT_USDC] }),
    publicClient.readContract({ address: domain.validator, abi: ModuleAbi, functionName: 'windowLength' }),
  ]);
  if (!entry?.live || entry.agentType !== 1 || !limit?.configured || limit.cap <= 0n || limit.perTxMax <= 0n) return null;
  const now = BigInt(Math.floor(Date.now() / 1000));
  const windowOpen = windowLength > 0n && now < BigInt(limit.windowStart) + windowLength;
  const spent = windowOpen ? limit.spent : 0n;
  const remaining = limit.cap > spent ? limit.cap - spent : 0n;

  let amount = remaining < limit.perTxMax ? remaining : limit.perTxMax;
  if (amount > reserve) amount = reserve;
  if (requested !== null && amount > requested) amount = requested;
  if (amount <= 0n || (requested !== null && amount < requested)) return null;

  // Gate 3: execute the refill — one UserOp from the account, signed by the
  // refill key, calling USDC.transfer(safe, amount). Recipient is always the
  // caller's Agent Safe (D-B).
  const moduleConfig = await publicClient.readContract({ address: domain.validator, abi: ModuleAbi, functionName: 'walletConfig', args: [caller.kernel] });
  if (!moduleConfig?.installed) return null;
  const signer = moduleSigner(agent, [agent.address], domain.validator);
  const permission = await toPermissionValidator(publicClient, {
    entryPoint: ENTRY_POINT,
    kernelVersion: KERNEL_V3_1,
    // walletConfig stores the id left-padded to bytes32; the validator wants the 4-byte id.
    permissionId: `0x${moduleConfig.permissionId.slice(2, 10)}`,
    signer,
    policies: paymentAgentPolicies(domain.delayPolicy, domain.synthetic),
  });
  const account = await createKernelAccount(publicClient, {
    entryPoint: ENTRY_POINT,
    kernelVersion: KERNEL_V3_1,
    address: caller.kernel,
    plugins: { regular: permission },
  });
  const client = createKernelAccountClient({
    account,
    chain: baseSepolia,
    bundlerTransport: http(config.bundlerUrl, { timeout: 120_000 }),
    client: publicClient,
    userOperation: { estimateFeesPerGas: async () => publicClient.estimateFeesPerGas() },
    paymaster: config.paymasterRpcUrl
      ? createZeroDevPaymasterClient({ chain: baseSepolia, transport: http(config.paymasterRpcUrl) })
      : selfHostPaymaster(publicClient, config),
  });

  const callData = await account.encodeCalls([
    { to: PAYMENT_USDC, value: 0n, data: encodeFunctionData({ abi: TokenAbi, functionName: 'transfer', args: [safe, amount] }) },
  ]);
  // The delay policy requires scheduling: request(kernel, nonce, callData),
  // wait for validAfter, then execute with the SAME nonce (proven by
  // scripts/probe-refill-register.mjs; an unscheduled send reverts AA23).
  const nonceKey = getCustomNonceKeyFromString(keccak256(concatHex([toHex('wallet-fund-reserve'), keccak256(callData)])), '0.7');
  const nonce = await account.getNonce({ key: nonceKey });
  const opHash = scheduledHash(caller.kernel, callData, nonce);
  const readSchedule = () => publicClient.readContract({ address: domain.delayPolicy, abi: DelayAbi, functionName: 'operationsPerAccount', args: [opHash] });
  let row = await readSchedule();
  if (Number(row[1]) !== 1) {
    const request = await account.encodeCalls([
      { to: domain.delayPolicy, value: 0n, data: encodeFunctionData({ abi: DelayAbi, functionName: 'request', args: [caller.kernel, nonce, callData] }) },
    ]);
    await sendRecordedUserOperation({ account, client, callData: request, journal: {}, save: async () => {} });
    const deadline = Date.now() + 30_000;
    while (Number(row[1]) !== 1 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      row = await readSchedule();
    }
  }
  for (;;) {
    const now = (await publicClient.getBlock()).timestamp;
    if (Number(row[1]) !== 1) throw UNAVAILABLE();
    if (now > BigInt(row[3])) throw UNAVAILABLE();
    if (now >= BigInt(row[2])) break;
    await new Promise((resolve) => setTimeout(resolve, 3000));
    row = await readSchedule();
  }
  // No durable journal at this layer: the wallet tool's own ledger records the
  // outcome; a lost response is reconciled from the on-chain receipt by tx.
  const sent = await sendRecordedUserOperation({ account, client, callData, nonce, journal: {}, save: async () => {} });

  // Receipt assertion (payment-agent-funding style): exactly one transfer,
  // from the caller's account to their own Safe, for the full amount.
  const transfer = await exactTransfer(publicClient, sent.txHash, PAYMENT_USDC, caller.kernel, safe, amount);
  if (!transfer) throw UNAVAILABLE();

  return { funded: true, from: 'reserve', tx: sent.txHash, amount_units: amount.toString(), user_op_hash: sent.userOpHash };
}
