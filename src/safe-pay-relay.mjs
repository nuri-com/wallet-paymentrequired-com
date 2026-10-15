// D-SAFE-EOA-RELAY: what the Agent Safe does when a verifier only accepts a plain EOA signature.
// The Safe's spender key is the Agent EOA (Privy 2-of-2, src/privy-agent-app-signer.mjs); it can
// sign like any wallet. Three things live here, none of them move money on their own:
//
//   safeSignatureAccepted({ offer, payload, readContract })  does the token accept the Safe's ERC-1271
//        signature? eth_call of transferWithAuthorization(bytes). false = the direct path is dead.
//   relayPay({ offer, required, safe, agent, client, sendSafeCalls })   ONE Safe UserOp moves exactly
//        the quoted amount to the Agent EOA, then the EOA signs the offer -> { headers, payload, relay }.
//   finishRelay({ offer, safe, agent, client, relay, typedData, settlementTx, submit })   proves the
//        settlement, sends any unused remainder back to the Safe (EIP-3009 signed by the EOA, submitted
//        by the operator: the EOA holds no gas) -> receipt with every tx hash.
//   signMessageAs / signInWithX   plain-message signing (x402 sign-in-with-x): Safe via ERC-1271 when
//        the verifier says it checks contract signatures, else the Agent EOA (eip191).
//   registerRelaySchemes(register)   x402 `batch-settlement`: Safe = payer (funds the deposit),
//        Agent EOA = payerAuthorizer (signs every voucher, ecrecover, no RPC for the server).
//
// No import of ./safe-pay.mjs: safe-pay imports this file (registration hook), a cycle would
// hit uninitialised bindings.
import { getAddress, parseAbi, parseEventLogs, encodeFunctionData, keccak256, toHex, parseSignature } from 'viem';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { ExactEvmSchemeV1 } from '@x402/evm/exact/v1/client';
import { authorizationTypes } from '@x402/evm';
import { encodePaymentSignatureHeader } from '@x402/core/http';
import { BatchSettlementEvmScheme, InMemoryClientChannelStorage, processSettleResponse } from '@x402/evm/batch-settlement/client';
import { hopCall } from './safe-pay-mpp.mjs'; // the same exact Safe → Agent EOA hop as MPP and Circle

const fail = code => { throw Object.assign(new Error(code), { runtimeCode: code }); };
const check = (ok, code) => { if (!ok) fail(code); };
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
const uint = v => typeof v === 'string' && /^(0|[1-9][0-9]{0,77})$/.test(v);
const token = parseAbi(['function balanceOf(address) view returns (uint256)', 'function transfer(address,uint256) returns (bool)',
  'function authorizationState(address,bytes32) view returns (bool)', 'event Transfer(address indexed from,address indexed to,uint256 value)',
  'function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,bytes signature)',
  'function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)']);
const moved = (receipt, asset, from, to) => parseEventLogs({ abi: token, eventName: 'Transfer', logs: receipt.logs })
  .filter(e => same(e.address, asset) && same(e.args.from, from) && same(e.args.to, to)).reduce((n, e) => n + e.args.value, 0n);
const envelope = (offer, required, signed) => offer.version === 1 ? signed
  : { ...signed, accepted: offer.raw, resource: required.resource, ...(required.extensions === undefined ? {} : { extensions: { ...required.extensions, ...(signed.extensions || {}) } }) };
const headersOf = (offer, payload) => { const h = encodePaymentSignatureHeader(payload); return offer.version === 1 ? { 'X-PAYMENT': h } : { 'PAYMENT-SIGNATURE': h }; };

// Only EIP-3009 can need the relay: Permit2 verifies ERC-1271 itself, and an EIP-3009 return
// (EOA -> Safe) needs no gas in the EOA.
export const relayable = offer => offer.scheme === 'exact' && offer.method === 'eip3009' && !!(offer.extra?.name && offer.extra?.version);

// The token is the verifier for EIP-3009. A revert here with the Safe's balance in place means the
// Safe's signature can never settle there (dead, so relaying cannot double-pay). A facilitator that
// rejects ERC-1271 while the token accepts it is NOT this case: that Safe authorization stays live
// until validBefore, so the caller must not relay before it expired.
export async function safeSignatureAccepted({ offer, payload, readContract }) {
  if (!relayable(offer)) return true;
  const p = payload.payload, a = p?.authorization;
  check(a && typeof p.signature === 'string', 'invalid_payment_payload');
  try {
    await readContract({ address: offer.asset, abi: token, functionName: 'transferWithAuthorization',
      args: [a.from, a.to, BigInt(a.value), BigInt(a.validAfter), BigInt(a.validBefore), a.nonce, p.signature] });
    return true;
  } catch { return false; }
}

// sendSafeCalls(calls) -> tx hash of the Safe's UserOp (runtime: operation(op, 'relay-fund', agentAccount, calls)).
// The Transfer log, not the outer tx status, is the evidence (an inner UserOp revert still mines).
export async function relayPay({ offer, required, safe, agent, client, sendSafeCalls }) {
  check(relayable(offer), 'relay_unsupported_offer');
  const eoa = getAddress(agent.address), asset = getAddress(offer.asset), amount = BigInt(offer.amount);
  check(!same(eoa, safe) && amount > 0n, 'relay_invalid_terms');
  const before = await client.readContract({ address: asset, abi: token, functionName: 'balanceOf', args: [eoa] });
  const fundTx = await sendSafeCalls([hopCall(asset, eoa, amount)]);
  const r = await client.waitForTransactionReceipt({ hash: fundTx });
  check(r.status === 'success' && moved(r, asset, safe, eoa) === amount, 'relay_funding_unconfirmed');
  let typedData;
  const signer = { address: eoa, readContract: a => client.readContract(a), signTypedData: async td => { typedData = td; return agent.signTypedData(td); } };
  const signed = offer.version === 1 ? await new ExactEvmSchemeV1(signer).createPaymentPayload(1, offer.raw)
    : await new ExactEvmScheme(signer).createPaymentPayload(2, offer.raw);
  const m = typedData?.message;
  check(typedData?.primaryType === 'TransferWithAuthorization' && same(typedData.domain.verifyingContract, asset) && same(m.from, eoa)
    && same(m.to, offer.payTo) && BigInt(m.value) === amount, 'relay_signing_terms');
  const payload = envelope(offer, required, signed);
  return { payload, typedData, headers: headersOf(offer, payload),
    relay: { eoa, asset, fundTx, fundedUnits: String(amount), eoaBalanceBeforeUnits: String(before) } };
}

// submit({ to, data }) -> tx hash, sent by the operator (runtime: send(op, 'relay-return', …)).
// Remainder = funded - settled, never more than the EOA holds. The return nonce derives from the
// funding tx, so a retry can never return twice (the token refuses a used nonce).
export async function finishRelay({ offer, safe, agent, client, relay, typedData, settlementTx, submit }) {
  const eoa = getAddress(relay.eoa), asset = getAddress(relay.asset), funded = BigInt(relay.fundedUnits);
  check(same(agent.address, eoa) && same(typedData.message.from, eoa), 'relay_signer_mismatch');
  const block = await client.getBlock();
  const used = await client.readContract({ address: asset, abi: token, functionName: 'authorizationState', args: [eoa, typedData.message.nonce] });
  let settled = 0n, settleTx = null;
  if (used) {
    check(/^0x[0-9a-fA-F]{64}$/.test(settlementTx ?? ''), 'relay_settlement_tx_required');
    const r = await client.waitForTransactionReceipt({ hash: settlementTx });
    settled = moved(r, asset, eoa, offer.payTo);
    check(r.status === 'success' && settled === BigInt(typedData.message.value), 'relay_settlement_mismatch');
    settleTx = r.transactionHash;
  } else check(BigInt(typedData.message.validBefore) <= block.timestamp, 'relay_authorization_still_live');
  const held = await client.readContract({ address: asset, abi: token, functionName: 'balanceOf', args: [eoa] });
  const remainder = funded - settled < held ? funded - settled : held;
  let returnTx = null;
  if (remainder > 0n) {
    const nonce = keccak256(toHex(`nuri-safe-relay-return:${relay.fundTx}`));
    check(!await client.readContract({ address: asset, abi: token, functionName: 'authorizationState', args: [eoa, nonce] }), 'relay_return_already_submitted');
    const message = { from: eoa, to: getAddress(safe), value: remainder, validAfter: 0n, validBefore: block.timestamp + 3600n, nonce };
    const sig = parseSignature(await agent.signTypedData({ domain: { name: offer.extra.name, version: offer.extra.version, chainId: offer.chainId, verifyingContract: asset },
      types: authorizationTypes, primaryType: 'TransferWithAuthorization', message }));
    returnTx = await submit({ to: asset, data: encodeFunctionData({ abi: token, functionName: 'transferWithAuthorization',
      args: [message.from, message.to, message.value, message.validAfter, message.validBefore, nonce, Number(sig.v ?? 27n + BigInt(sig.yParity)), sig.r, sig.s] }) });
    const r = await client.waitForTransactionReceipt({ hash: returnTx });
    check(r.status === 'success' && moved(r, asset, eoa, safe) === remainder, 'relay_return_unconfirmed');
  }
  return { path: 'eoa_relay', payer: eoa, fundTx: relay.fundTx, settleTx, returnTx,
    fundedUnits: String(funded), settledUnits: String(settled), returnedUnits: String(remainder) };
}

// Plain message (EIP-191 / ERC-1271). safeSignMessage(message) = the Safe's Kernel signMessage
// through the agent permission; agent = the Agent EOA account.
export async function signMessageAs({ message, viaSafe, safe, safeSignMessage, agent }) {
  if (viaSafe) { check(typeof safeSignMessage === 'function', 'safe_signer_required'); return { signer: 'safe', address: getAddress(safe), signature: await safeSignMessage(message) }; }
  return { signer: 'agent_eoa', address: getAddress(agent.address), signature: await agent.signMessage({ message }) };
}

// EIP-4361 text exactly as @x402/extensions formats it (SiweMessage.prepareMessage, v4).
export function siweMessage(info, address) {
  const chain = /^eip155:([0-9]{1,12})$/.exec(info.chainId)?.[1]; check(chain, 'siwx_chain_id');
  const head = `${info.domain} wants you to sign in with your Ethereum account:\n${getAddress(address)}`;
  const body = [`URI: ${info.uri}`, `Version: ${info.version}`, `Chain ID: ${chain}`, `Nonce: ${info.nonce}`, `Issued At: ${info.issuedAt}`,
    ...(info.expirationTime ? [`Expiration Time: ${info.expirationTime}`] : []), ...(info.notBefore ? [`Not Before: ${info.notBefore}`] : []),
    ...(info.requestId !== undefined ? [`Request ID: ${info.requestId}`] : []),
    ...(info.resources ? [['Resources:', ...info.resources.map(r => `- ${r}`)].join('\n')] : [])].join('\n');
  return (info.statement === undefined ? `${head}\n\n` : `${head}\n\n${info.statement}\n`) + '\n' + body;
}

// x402 sign-in-with-x (https://docs.x402.org/extensions/sign-in-with-x). The challenge must be bound
// to the origin that answered 402 (spec: client MUST refuse otherwise). The Safe signs only when the
// server hints eip1271/eip6492 (or the caller knows the verifier checks contracts): default servers
// verify with ecrecover and would reject a contract signature.
export async function signInWithX({ required, requestUrl, chainId, safe, safeSignMessage, agent, verifierSupports1271 }) {
  const ext = required?.extensions?.['sign-in-with-x']; check(ext?.info && Array.isArray(ext.supportedChains), 'siwx_challenge_missing');
  const url = new URL(requestUrl), info = ext.info;
  check(info.domain === url.host && new URL(info.uri).origin === url.origin, 'siwx_origin_mismatch');
  check(info.version === '1' && typeof info.nonce === 'string' && typeof info.issuedAt === 'string', 'siwx_invalid_challenge');
  const entry = ext.supportedChains.find(c => c.chainId === `eip155:${chainId}`); check(entry, 'siwx_chain_not_supported');
  const viaSafe = verifierSupports1271 ?? ['eip1271', 'eip6492'].includes(entry.signatureScheme);
  const full = { ...info, chainId: entry.chainId, type: entry.type };
  const { signer, address, signature } = await signMessageAs({ viaSafe, safe, safeSignMessage, agent, message: siweMessage(full, viaSafe ? safe : agent.address) });
  const payload = Object.fromEntries(Object.entries({ ...full, address, signatureScheme: viaSafe ? entry.signatureScheme ?? 'eip1271' : 'eip191', signature })
    .filter(([, v]) => v !== undefined));
  return { signer, address, payload, headers: { 'SIGN-IN-WITH-X': Buffer.from(JSON.stringify(payload), 'utf8').toString('base64') } };
}

// batch-settlement (https://docs.x402.org/schemes/batch-settlement). Channel state per process,
// recovered from the x402BatchSettlement contract when missing. The resource server's
// PAYMENT-RESPONSE goes through recordBatchSettlement so the next voucher is cumulative.
export const batchChannels = new InMemoryClientChannelStorage();
export const recordBatchSettlement = (settle, storage = batchChannels) => processSettleResponse(storage, settle);
const depositTarget = o => uint(String(o.extra.minDeposit ?? '')) && BigInt(o.extra.minDeposit) >= BigInt(o.amount) ? BigInt(o.extra.minDeposit) : 5n * BigInt(o.amount);
export function registerRelaySchemes(register) {
  register('batch-settlement', {
    supports: o => o.version === 2 && ['eip3009', 'permit2'].includes(o.method) && typeof o.extra.receiverAuthorizer === 'string'
      && Number.isSafeInteger(o.extra.withdrawDelay) && !!(o.method === 'permit2' || (o.extra.name && o.extra.version)),
    rank: () => 3,
    needs: o => o.method === 'permit2' ? { permit2Allowance: depositTarget(o) } : {},
    // signer = the Safe (deposit authorization, ERC-1271); agent = Agent EOA (vouchers). Without the
    // agent nothing is signed: a Safe-only voucher channel would cost the server an RPC per request.
    sign: ({ offer, signer, agent, channels = batchChannels }) => {
      check(agent?.address && typeof agent.signTypedData === 'function' && !same(agent.address, signer.address), 'agent_signer_required');
      return new BatchSettlementEvmScheme(signer, { storage: channels, payerAuthorizer: getAddress(agent.address), voucherSigner: agent,
        depositStrategy: c => { const t = depositTarget(offer), min = BigInt(c.minimumDepositAmount); return String(t > min ? t : min); } })
        .createPaymentPayload(2, offer.raw);
    },
    nonceUsed: ({ typedData, safe, readContract, blockNumber }) => typedData?.primaryType === 'ReceiveWithAuthorization'
      ? readContract({ address: typedData.domain.verifyingContract, abi: token, functionName: 'authorizationState', args: [safe, typedData.message.nonce], blockNumber }) : null,
  });
}
