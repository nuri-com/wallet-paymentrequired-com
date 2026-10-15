// D-SAFE-CIRCLE: the Agent Safe on Circle rails — Gateway (unified USDC balance), Arc, and
// Gateway Nanopayments. Pure builders + two thin HTTP calls; no custody, no persistence.
//
// What works for a Kernel Safe (ERC-1271), per Circle docs read 2026-09-25:
// - Gateway deposit: GatewayWallet.depositWithAuthorization(token, from, …, bytes signature)
//   pulls USDC via USDC.receiveWithAuthorization(bytes) (ERC-7598), so the Safe only SIGNS an
//   EIP-3009 ReceiveWithAuthorization (1271) and any relayer submits. The agent's CallPolicy
//   (transfer/approve only, src/agent-kernel-wallet.mjs) cannot call GatewayWallet.deposit()
//   itself, and does not need to.
// - Gateway transfer: burn intent signed by the Safe via ERC-1271, POST /v1/transfer with
//   contractSigner:true (developers.circle.com/gateway/references/erc-1271). Circle's TEE
//   simulates Safe.isValidSignature on the source chain — the Safe must be DEPLOYED there.
//   gatewayMint(attestation, signature) on the destination is permissionless when
//   destinationCaller = 0x0, so any relayer mints to the payee.
// - Nanopayments (x402 scheme "exact" + extra.name "GatewayWalletBatched"): Circle verifies
//   the EIP-3009 authorization with ecrecover, ERC-1271 is NOT supported
//   (developers.circle.com/gateway-nanopayments, note at the top). So the Safe cannot be the
//   nanopayment payer. The payer is the Safe's agent signer EOA with its own Gateway balance,
//   topped up from the Safe (Safe → agent EOA USDC.transfer, which the no-limit spender may
//   do; then the EOA signs depositWithAuthorization). That is the Agent-EOA fallback.
import { randomBytes } from 'node:crypto';
import { encodeFunctionData, getAddress, hashTypedData, hexToNumber, keccak256, maxUint256, pad, parseAbi, parseErc6492Signature, slice, zeroAddress } from 'viem';
import { safeChain } from './safe-pay-chains.mjs';
import { hopCall } from './safe-pay-mpp.mjs';

export const GATEWAY = Object.freeze({
  testnet: Object.freeze({ wallet: '0x0077777d7EBA4688BDeF3E311b846F25870A19B9', minter: '0x0022222ABE238Cc2C7Bb1f21003F0a260052475B', api: 'https://gateway-api-testnet.circle.com' }),
  mainnet: Object.freeze({ wallet: '0x77777777Dcc4d5A8B6E418Fd04D8997ef11000eE', minter: '0x2222222d7164433c4C09B0b0D809a9b52C04C205', api: 'https://gateway-api.circle.com' }),
});
// Gateway/CCTP domain per chainId, only for chains in src/safe-pay-chains.mjs.
// Source: GET https://gateway-api-testnet.circle.com/v1/info (Arc Testnet = 26) + use-gateway skill.
export const GATEWAY_DOMAINS = Object.freeze({ 1: 0, 10: 2, 42161: 3, 8453: 6, 137: 7, 84532: 6, 5042002: 26 });
const TESTNETS = new Set([84532, 5042002]);

export const gatewayFor = (chainId) => {
  const id = Number(chainId);
  if (!(id in GATEWAY_DOMAINS)) throw Object.assign(new Error('gateway_unsupported_chain'), { runtimeCode: 'gateway_unsupported_chain' });
  const net = TESTNETS.has(id) ? GATEWAY.testnet : GATEWAY.mainnet;
  const c = safeChain(id);
  return { ...net, chainId: id, domain: GATEWAY_DOMAINS[id], testnet: TESTNETS.has(id), usdc: c.usdc, chain: c.chain, rpc: c.rpc };
};

export const gatewayWalletAbi = parseAbi([
  'function depositWithAuthorization(address token,address from,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,bytes signature)',
  'function availableBalance(address token,address depositor) view returns (uint256)',
  'function totalBalance(address token,address depositor) view returns (uint256)',
]);
export const gatewayMinterAbi = parseAbi(['function gatewayMint(bytes attestationPayload,bytes signature)',
  'function isTransferSpecHashUsed(bytes32 transferSpecHash) view returns (bool)',
  'error AttestationExpiredAtIndex(uint32 index,uint256 maxBlockHeight,uint256 currentBlock)']);

const units = (v) => { const n = BigInt(v); if (n <= 0n || n > maxUint256) throw new Error('invalid_amount_units'); return n; };
const nonce32 = () => `0x${randomBytes(32).toString('hex')}`;
const b32 = (a) => pad(getAddress(a).toLowerCase(), { size: 32 });
// A Kernel signer returns an ERC-6492 wrapper while the Safe is counterfactual. Gateway and
// USDC call isValidSignature on the deployed Safe, so strip the wrapper (the Safe must exist).
const raw1271 = (sig) => parseErc6492Signature(sig).signature;

// ---- 1. Deposit into Gateway (Safe signs, relayer submits) ----------------------------------
const receiveTypes = { ReceiveWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] };

export function gatewayDepositTypedData({ chainId, from, amountUnits, validSeconds = 3600, now = Math.floor(Date.now() / 1000) }) {
  const gw = gatewayFor(chainId);
  const message = { from: getAddress(from), to: getAddress(gw.wallet), value: units(amountUnits), validAfter: 0n, validBefore: BigInt(now + validSeconds), nonce: nonce32() };
  return { domain: { name: gw.usdc.name, version: gw.usdc.version, chainId: gw.chainId, verifyingContract: gw.usdc.address }, types: receiveTypes, primaryType: 'ReceiveWithAuthorization', message };
}

// signer: the Safe's agent account (Kernel, signs via ERC-1271) or an EOA account.
export async function signGatewayDeposit({ signer, chainId, amountUnits, from = signer.address, ...rest }) {
  const typedData = gatewayDepositTypedData({ chainId, from, amountUnits, ...rest });
  const signature = raw1271(await signer.signTypedData(typedData));
  const gw = gatewayFor(chainId), m = typedData.message;
  return { typedData, signature, digest: hashTypedData(typedData),
    call: { to: gw.wallet, value: 0n, data: encodeFunctionData({ abi: gatewayWalletAbi, functionName: 'depositWithAuthorization',
      args: [gw.usdc.address, m.from, m.value, m.validAfter, m.validBefore, m.nonce, signature] }) } };
}

// ---- 2. Gateway transfer: burn intent signed by the Safe (ERC-1271) -------------------------
// Types copied verbatim from developers.circle.com/gateway/howtos/transfer-with-erc-1271.
const burnTypes = {
  TransferSpec: [
    { name: 'version', type: 'uint32' }, { name: 'sourceDomain', type: 'uint32' }, { name: 'destinationDomain', type: 'uint32' },
    { name: 'sourceContract', type: 'bytes32' }, { name: 'destinationContract', type: 'bytes32' },
    { name: 'sourceToken', type: 'bytes32' }, { name: 'destinationToken', type: 'bytes32' },
    { name: 'sourceDepositor', type: 'bytes32' }, { name: 'destinationRecipient', type: 'bytes32' },
    { name: 'sourceSigner', type: 'bytes32' }, { name: 'destinationCaller', type: 'bytes32' },
    { name: 'value', type: 'uint256' }, { name: 'salt', type: 'bytes32' }, { name: 'hookData', type: 'bytes' }],
  BurnIntent: [{ name: 'maxBlockHeight', type: 'uint256' }, { name: 'maxFee', type: 'uint256' }, { name: 'spec', type: 'TransferSpec' }],
};
export const BURN_INTENT_DOMAIN = Object.freeze({ name: 'GatewayWallet', version: '1' });

// Circle Gateway fees (developers.circle.com/gateway/references/fees): the source chain's gas fee plus 0.005 % of the
// amount; the unified balance must hold amount + maxFee. A flat 2.01 USDC cap refused every small bridge from Base
// (live 2026-09-29). ponytail: gas table for our home chains only; any other source keeps the old 2 USDC cap.
const GATEWAY_GAS_FEE_UNITS = { 8453: 10_000n, 84532: 10_000n };
export const gatewayMaxFeeUnits = (sourceChainId, amountUnits) => (GATEWAY_GAS_FEE_UNITS[Number(sourceChainId)] ?? 2_000_000n) + BigInt(amountUnits) * 5n / 100_000n + 10_000n;
export function burnIntentTypedData({ sourceChainId, destinationChainId, depositor, recipient, amountUnits, maxFeeUnits = gatewayMaxFeeUnits(sourceChainId, amountUnits), maxBlockHeight = maxUint256 }) {
  const src = gatewayFor(sourceChainId), dst = gatewayFor(destinationChainId);
  if (src.testnet !== dst.testnet) throw new Error('gateway_mixed_networks');
  const message = { maxBlockHeight: BigInt(maxBlockHeight), maxFee: BigInt(maxFeeUnits), spec: {
    version: 1, sourceDomain: src.domain, destinationDomain: dst.domain,
    sourceContract: b32(src.wallet), destinationContract: b32(dst.minter),
    sourceToken: b32(src.usdc.address), destinationToken: b32(dst.usdc.address),
    sourceDepositor: b32(depositor), destinationRecipient: b32(recipient),
    sourceSigner: b32(depositor), // ERC-1271: the Safe itself is the signer
    destinationCaller: pad(zeroAddress, { size: 32 }), value: units(amountUnits), salt: nonce32(), hookData: '0x' } };
  return { domain: BURN_INTENT_DOMAIN, types: burnTypes, primaryType: 'BurnIntent', message, api: src.api, minter: dst.minter, destinationChainId: dst.chainId };
}

export async function signSafeBurnIntent({ safeAccount, ...params }) {
  const { api, minter, destinationChainId, ...typedData } = burnIntentTypedData({ depositor: safeAccount.address, ...params });
  const signature = raw1271(await safeAccount.signTypedData(typedData));
  return { typedData, signature, digest: hashTypedData(typedData), api, minter, destinationChainId,
    request: { burnIntent: typedData.message, signature, contractSigner: true } };
}

const json = (v) => JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x));
// POST /v1/transfer → { attestation, signature }. Public endpoint (no API key on testnet).
export async function requestGatewayAttestation({ requests, api, headers = {}, fetchImpl = fetch }) {
  const res = await fetchImpl(`${api}/v1/transfer`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: json(requests) });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.attestation || !body.signature) throw Object.assign(new Error(`gateway_transfer_failed:${res.status} ${String(body.message || body.error || '').slice(0, 200)}`), { status: res.status, body, runtimeCode: 'gateway_transfer_failed' });
  return { attestation: body.attestation, operatorSignature: body.signature };
}
export const gatewayMintCall = ({ minter, attestation, operatorSignature }) =>
  ({ to: minter, value: 0n, data: encodeFunctionData({ abi: gatewayMinterAbi, functionName: 'gatewayMint', args: [attestation, operatorSignature] }) });
// An attestation expires at its own maxBlockHeight (bytes 4..36) against the destination's
// block.number: about 10 min, and on Arbitrum block.number is the L1 block (live 2026-09-29: the
// operator had no Arbitrum gas in that window, every later mint reverted AttestationExpiredAtIndex).
// Dead = the minter itself reverts with that error AND the transfer spec (bytes 40..40+len) was
// never minted. Circle burns nothing for it, so a fresh burn intent cannot bridge twice.
export async function gatewayAttestationDead({ client, minter, attestation, operatorSignature }) {
  if (slice(attestation, 0, 4).toLowerCase() !== '0xff6fb334') return false; // one attestation, not a set
  try { await client.simulateContract({ address: minter, abi: gatewayMinterAbi, functionName: 'gatewayMint', args: [attestation, operatorSignature] }); return false; }
  catch (e) { if (!e?.walk?.(x => x?.data?.errorName === 'AttestationExpiredAtIndex')) return false; }
  const specHash = keccak256(slice(attestation, 40, 40 + hexToNumber(slice(attestation, 36, 40))));
  return !(await client.readContract({ address: minter, abi: gatewayMinterAbi, functionName: 'isTransferSpecHashUsed', args: [specHash] }));
}

export async function gatewayBalances({ depositor, chainIds, testnet = true, fetchImpl = fetch }) {
  const api = testnet ? GATEWAY.testnet.api : GATEWAY.mainnet.api;
  const res = await fetchImpl(`${api}/v1/balances`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: json({ token: 'USDC', sources: chainIds.map((id) => ({ domain: gatewayFor(id).domain, depositor: getAddress(depositor) })) }) });
  if (!res.ok) throw new Error(`gateway_balances_failed:${res.status}`);
  return (await res.json()).balances;
}

// ---- 3. Nanopayments (x402 "exact" / GatewayWalletBatched) — EOA payer only ----------------
export const isGatewayBatched = (accept) => accept?.scheme === 'exact' && accept?.extra?.name === 'GatewayWalletBatched' && accept?.extra?.version === '1' && typeof accept?.extra?.verifyingContract === 'string';
const transferTypes = { TransferWithAuthorization: receiveTypes.ReceiveWithAuthorization };
const MIN_VALIDITY = 7 * 24 * 3600 + 100; // Circle x402-batching GATEWAY_AUTH_VALIDITY_WINDOW_SECONDS

// Same payload @circle-fin/x402-batching BatchEvmScheme builds (v3.5.0, client/index.mjs).
export async function signNanopayment({ eoa, accept, resource, x402Version = 2, now = Math.floor(Date.now() / 1000) }) {
  if (!isGatewayBatched(accept)) throw new Error('not_gateway_batched');
  const m = /^eip155:([0-9]+)$/.exec(accept.network ?? '');
  if (!m) throw new Error('unsupported_network');
  const authorization = { from: getAddress(eoa.address), to: getAddress(accept.payTo), value: String(units(accept.amount)),
    validAfter: String(now - 600), validBefore: String(now + Math.max(Number(accept.maxTimeoutSeconds) || 0, MIN_VALIDITY)), nonce: nonce32() };
  const typedData = { domain: { name: 'GatewayWalletBatched', version: '1', chainId: Number(m[1]), verifyingContract: getAddress(accept.extra.verifyingContract) },
    types: transferTypes, primaryType: 'TransferWithAuthorization',
    message: { ...authorization, value: BigInt(authorization.value), validAfter: BigInt(authorization.validAfter), validBefore: BigInt(authorization.validBefore) } };
  const signature = await eoa.signTypedData(typedData);
  return { typedData, paymentPayload: { x402Version, payload: { authorization, signature }, accepted: accept, ...(resource ? { resource } : {}) } };
}

// Top-up plan for the nanopayment EOA from the Safe: the exact hop of MPP (hopCall, one agent UserOp,
// allowed by the no-limit spender) + one EOA-signed Gateway deposit that any relayer submits.
export async function planNanopayTopUp({ chainId, eoa, amountUnits }) {
  const gw = gatewayFor(chainId), value = units(amountUnits);
  const safeCall = hopCall(gw.usdc.address, eoa.address, value);
  const deposit = await signGatewayDeposit({ signer: eoa, chainId, amountUnits: value });
  return { safeCalls: [safeCall], relayCall: deposit.call, deposit };
}

// ---- Handlers for main's payment-scheme hook (src/safe-pay.mjs registerPaymentScheme) --------
// A specialised handler for x402 scheme 'exact': it wins over the generic 'exact' (EIP-3009 from the
// Safe) when the offer is GatewayWalletBatched. payer 'agent-eoa': the runtime first moves exactly the
// amount Safe → Agent EOA (hopCall, src/safe-pay-mpp.mjs) and into the EOA's Gateway balance, then
// the Agent EOA signs here (ecrecover). signer = { address: Agent EOA, signTypedData } from payWithSafe.
export const CIRCLE_SCHEMES = Object.freeze([
  // rank 3: after exact (0/1) and upto (2) — a merchant that also offers a plain Safe-payable offer gets
  // that one (no hop, no Gateway deposit). prefer: 'circle-gateway-batched' pins it.
  Object.freeze({ name: 'circle-gateway-batched', scheme: 'exact', payer: 'agent-eoa', rank: () => 3,
    supports: (o) => o?.version === 2 && isGatewayBatched(o.raw) && o.chainId in GATEWAY_DOMAINS,
    sign: async ({ offer, signer }) => {
      const { paymentPayload } = await signNanopayment({ eoa: signer, accept: offer.raw, x402Version: 2 });
      return { x402Version: 2, payload: paymentPayload.payload };
    },
    note: 'Circle Nanopayments: ecrecover only, Safe cannot sign; the Agent EOA with its own Gateway balance pays' }),
]);
export function registerCircleSchemes(register) {
  if (typeof register !== 'function') return [];
  return CIRCLE_SCHEMES.map((s) => register(s.name, s));
}
// Balance the Agent EOA can spend through Gateway (after a deposit is final on chain).
export const gatewayAvailable = ({ client, chainId, depositor }) => {
  const gw = gatewayFor(chainId);
  return client.readContract({ address: gw.wallet, abi: gatewayWalletAbi, functionName: 'availableBalance', args: [gw.usdc.address, getAddress(depositor)] });
};
