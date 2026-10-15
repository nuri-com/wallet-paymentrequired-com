// D-SAFE-NO-LIMITS: the one place that turns a 402 challenge into a signed payment from the
// Agent Safe. The runtime (src/agent-kernel-runtime.mjs) keeps durability, gas and the
// merchant HTTP call; this module only parses, picks and signs. Other rails plug in here:
//
//   registerPaymentScheme(name, handler)            add a scheme (sibling PRs: MPP, Circle, …)
//   parseChallenge({ status, headers, bodyText })    402 → { version, required, offers[] }
//   selectOffer(offers, { chainIds, prefer })         pick the offer the Safe can pay
//   quoteOffer(offer)                                 dry_run view: price, rail, chain, token
//   payWithSafe({ offer, required, safe, signTypedData, readContract, agent? })
//        → { headers, payload, typedData, needs: { permit2Allowance?: bigint } }
//
// handler = { name, scheme?, payer?, supports(offer) → bool, rank(offer) → number (lower first),
//   needs(offer) → { permit2Allowance?: bigint }, sign({ offer, required, safe, signTypedData,
//   readContract, agent }) → { payload, typedData }, nonceUsed?({ typedData, safe, readContract, blockNumber }) }
// scheme: the x402 scheme name it serves (default: name). Several handlers may serve one scheme; a
// specialised one (name ≠ scheme, e.g. Circle 'circle-gateway-batched' for 'exact') wins over the
// generic when it supports the offer. payer: 'safe' (default, ERC-1271) or 'agent-eoa' (the Safe's
// Agent EOA signs; the runtime first hops the amount Safe → Agent EOA, src/safe-pay-mpp.mjs hopCall).
// signTypedData(td) must return the Safe's ERC-1271 signature (Kernel validator-wrapped, no
// ERC-6492 wrapper: every token/Permit2 here calls isValidSignature on deployed code).
import { getAddress, parseAbi, maxUint256 } from 'viem';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { UptoEvmScheme } from '@x402/evm/upto/client';
import { ExactEvmSchemeV1 } from '@x402/evm/exact/v1/client';
import { EVM_NETWORK_CHAIN_ID_MAP } from '@x402/evm/v1';
import { PERMIT2_ADDRESS } from '@x402/evm';
import { decodePaymentRequiredHeader, encodePaymentSignatureHeader } from '@x402/core/http';
import { SAFE_CHAINS } from './safe-pay-chains.mjs';
import { registerRelaySchemes } from './safe-pay-relay.mjs';

const fail = code => { throw Object.assign(new Error(code), { runtimeCode: code }); };
const check = (ok, code) => { if (!ok) fail(code); };
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
const uint = v => typeof v === 'string' && /^(0|[1-9][0-9]{0,77})$/.test(v) && BigInt(v) < 2n ** 256n;
const nonceAbi = parseAbi(['function nonceBitmap(address,uint256) view returns(uint256)', 'function authorizationState(address,bytes32) view returns(bool)']);

const schemes = new Map();
export function registerPaymentScheme(name, handler) {
  check(typeof name === 'string' && /^[a-z0-9:_-]{1,64}$/.test(name), 'invalid_scheme_name');
  check(handler && typeof handler.supports === 'function' && typeof handler.sign === 'function', 'invalid_scheme_handler');
  check(handler.payer === undefined || handler.payer === 'safe' || handler.payer === 'agent-eoa', 'invalid_scheme_payer');
  schemes.set(name, { rank: () => 50, needs: () => ({}), payer: 'safe', scheme: name, ...handler, name });
}
export const paymentSchemes = () => [...schemes.keys()];
// The handler that pays this offer: a specialised handler for the offer's scheme first, then the generic.
export function handlerFor(offer) {
  const all = [...schemes.values()].filter(h => h.scheme === offer?.scheme && h.supports(offer));
  return all.find(h => h.name !== h.scheme) || all[0] || null;
}

// v2: PAYMENT-REQUIRED header. v1: JSON body { x402Version: 1, accepts } (answered with X-PAYMENT).
export function parseChallenge({ headers = {}, bodyText = '' }) {
  const h = headers['payment-required'];
  let required;
  if (typeof h === 'string') { check(h.length <= 32768, 'payment_challenge_too_large'); required = decodePaymentRequiredHeader(h); }
  else { try { required = JSON.parse(bodyText); } catch { fail('payment_challenge_missing'); } }
  check(required && (required.x402Version === 1 || required.x402Version === 2) && Array.isArray(required.accepts), 'invalid_x402_envelope');
  const offers = required.accepts.map((raw, i) => normalize(raw, required.x402Version, i)).filter(Boolean);
  return { version: required.x402Version, required, offers };
}
function normalize(raw, version, index) {
  if (!raw || typeof raw !== 'object' || typeof raw.scheme !== 'string') return null;
  const chainId = version === 1 ? EVM_NETWORK_CHAIN_ID_MAP[raw.network]
    : (/^eip155:([0-9]{1,12})$/.exec(String(raw.network)) || [])[1];
  const amount = version === 1 ? raw.maxAmountRequired : raw.amount;
  if (!chainId || !uint(String(amount)) || typeof raw.payTo !== 'string' || typeof raw.asset !== 'string') return null;
  return { index, version, raw, scheme: raw.scheme, chainId: Number(chainId), network: raw.network, asset: raw.asset,
    amount: String(amount), payTo: raw.payTo, maxTimeoutSeconds: raw.maxTimeoutSeconds, extra: raw.extra || {},
    method: raw.extra?.assetTransferMethod ?? (raw.scheme === 'exact' ? 'eip3009' : 'permit2') };
}
export function selectOffer(offers, { chainIds = [...SAFE_CHAINS.keys()], prefer } = {}) {
  const payable = offers.map(o => ({ o, h: handlerFor(o) })).filter(({ o, h }) => chainIds.includes(o.chainId) && h
    && Number.isSafeInteger(o.maxTimeoutSeconds) && o.maxTimeoutSeconds > 0);
  check(payable.length, 'no_payable_offer');
  const pinned = prefer ? payable.filter(({ o, h }) => o.scheme === prefer || h.name === prefer || `${o.scheme}:${o.method}` === prefer) : payable;
  check(pinned.length, 'preferred_scheme_not_offered');
  const best = pinned.sort((a, b) => a.h.rank(a.o) - b.h.rank(b.o) || a.o.index - b.o.index)[0];
  return { ...best.o, handler: best.h.name, payer: best.h.payer };
}
export function quoteOffer(offer) {
  const token = SAFE_CHAINS.get(offer.chainId)?.usdc;
  return { scheme: offer.scheme, rail: offer.method, x402_version: offer.version, chain_id: offer.chainId, network: offer.network,
    token: offer.asset, token_symbol: token && same(token.address, offer.asset) ? 'USDC' : null, decimals: token && same(token.address, offer.asset) ? token.decimals : null,
    amount_units: offer.amount, pay_to: offer.payTo, max_timeout_seconds: offer.maxTimeoutSeconds ?? null,
    ...(offer.extra?.paymentFlow ? { payment_flow: offer.extra.paymentFlow } : {}), ...(offer.handler && offer.handler !== offer.scheme ? { handler: offer.handler } : {}),
    payer: offer.payer ?? 'safe', needs: handlerOf(offer)?.needs(offer) ?? {} };
}
// The handler chosen by selectOffer (offer.handler), else the best one for the offer.
const handlerOf = offer => (offer.handler && schemes.get(offer.handler)) || handlerFor(offer);
// payerAddress: the Agent EOA when the handler's payer is 'agent-eoa' (signTypedData then signs as that EOA).
// agent: the Agent EOA account, only for schemes that need its own signature (batch-settlement vouchers).
export async function payWithSafe({ offer, required, safe, signTypedData, readContract, payerAddress, agent }) {
  const handler = handlerOf(offer); check(handler?.supports(offer), 'no_payable_offer');
  check(handler.payer !== 'agent-eoa' || payerAddress, 'agent_eoa_payer_required');
  let typedData;
  const signer = { address: getAddress(handler.payer === 'agent-eoa' ? payerAddress : safe), readContract,
    signTypedData: async td => { typedData = td; return signTypedData(td); } };
  const signed = await handler.sign({ offer, required, signer, agent });
  const payload = offer.version === 1 ? signed
    : { ...signed, accepted: offer.raw, resource: required.resource, ...(required.extensions === undefined ? {} : { extensions: { ...required.extensions, ...(signed.extensions || {}) } }) };
  const header = encodePaymentSignatureHeader(payload);
  return { payload, typedData, headers: offer.version === 1 ? { 'X-PAYMENT': header } : { 'PAYMENT-SIGNATURE': header }, needs: handler.needs(offer) };
}
export async function nonceUsed({ offer, typedData, safe, readContract, blockNumber }) {
  const h = handlerOf(offer); return h?.nonceUsed ? h.nonceUsed({ offer, typedData, safe, readContract, blockNumber }) : null;
}
const permit2Used = async ({ typedData, safe, readContract, blockNumber }) => {
  const n = BigInt(typedData.message.nonce);
  return ((await readContract({ address: PERMIT2_ADDRESS, abi: nonceAbi, functionName: 'nonceBitmap', args: [safe, n >> 8n], blockNumber })) & (1n << (n & 255n))) !== 0n;
};
const eip3009Used = ({ typedData, safe, readContract, blockNumber }) =>
  readContract({ address: typedData.domain.verifyingContract, abi: nonceAbi, functionName: 'authorizationState', args: [safe, typedData.message.nonce], blockNumber });

// exact: EIP-3009 (default, no approve: USDC v2.2 checks the Safe via ERC-1271) or Permit2.
// No amount cap anywhere (owner decision 2026-09-25): the amount is whatever the offer says.
registerPaymentScheme('exact', {
  supports: o => o.method === 'eip3009' ? !!(o.extra.name && o.extra.version) : o.method === 'permit2',
  rank: o => o.method === 'eip3009' ? 0 : 1,
  needs: o => o.method === 'permit2' ? { permit2Allowance: BigInt(o.amount) } : {},
  sign: ({ offer, signer }) => offer.version === 1
    ? new ExactEvmSchemeV1(signer).createPaymentPayload(1, offer.raw)
    : new ExactEvmScheme(signer).createPaymentPayload(2, offer.raw),
  nonceUsed: args => args.typedData.primaryType === 'TransferWithAuthorization' ? eip3009Used(args) : permit2Used(args),
});
// upto: Permit2 witness for a ceiling; the facilitator settles the metered amount.
registerPaymentScheme('upto', {
  supports: o => o.version === 2 && o.method === 'permit2' && typeof o.extra.facilitatorAddress === 'string',
  rank: () => 2,
  needs: o => ({ permit2Allowance: BigInt(o.amount) }),
  sign: ({ offer, signer }) => new UptoEvmScheme(signer).createPaymentPayload(2, offer.raw),
  nonceUsed: permit2Used,
});
// batch-settlement: Safe funds the deposit, Agent EOA signs vouchers (src/safe-pay-relay.mjs).
registerRelaySchemes(registerPaymentScheme);
export const STANDING_PERMIT2_ALLOWANCE = maxUint256;
