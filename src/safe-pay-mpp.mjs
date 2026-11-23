// D-SAFE-MPP: MPP (Machine Payments Protocol, https://mpp.dev/protocol) paid from the Agent Safe.
// x402 answers with PAYMENT-REQUIRED / a JSON body; MPP answers 402 with `WWW-Authenticate: Payment …`.
// detectProtocol() tells them apart; src/agent-kernel-runtime.mjs routes MPP here.
//
// One model for every MPP method and intent, the "exact-amount hop": the Safe moves exactly what
// the challenge asks (charge amount, or session deposit) to its own Agent EOA with one agent
// UserOp (`transfer`, which the no-limit CallPolicy allows on any token). The Agent EOA then pays
// with the stock mppx client, so every stock MPP server accepts it:
//   - evm/charge   EIP-3009 authorization signed by the Agent EOA. Stock mppx evm servers verify
//                  with recoverTypedDataAddress (ECDSA only, mppx 0.8.19 and 0.11.0), so a Safe
//                  ERC-1271 signature would be rejected even though USDC itself would accept it.
//   - tempo/charge TIP-20 transferWithMemo (challenge-bound attribution memo). The Safe's
//                  CallPolicy allows transfer/approve only, not transferWithMemo.
//   - tempo/session TIP-1034 escrow: open() makes msg.sender the channel payer and refunds go to
//                  the payer. The Agent EOA opens with the hopped deposit, signs cumulative
//                  vouchers, closes, and sweeps whatever came back to the Safe (sweepToSafe).
// Kernel v3.1 itself runs on Tempo (EntryPoint 0.7 + factory present on 4217 and 42431; a UserOp
// with maxFeePerGas 0 relayed by a fee-token-paying EOA works, scripts/prove-safe-mpp-fork.mjs).
// CallPolicy v0.0.5 is not deployed on Tempo yet; it is a permissionless CREATE2 (0x4e59…) and
// the proof deploys it on the fork. Stripe (method "stripe", SPT) is not a Safe rail: it spends a
// card, not the Safe's stablecoins, so it is never selected here.
import { encodeFunctionData, parseAbi, getAddress, recoverPublicKey, keccak256, toHex } from 'viem';
import { Challenge, Receipt } from 'mppx';
import { PublicKey } from 'ox'; // mppx's own dependency (Tempo keys)
import { Mppx, evm as evmClient, tempo as tempoClient, sessionManager } from 'mppx/client';
import { Account as TempoAccount, Actions as TempoActions } from 'viem/tempo';
import { readContract } from 'viem/actions';

const fail = code => { throw Object.assign(new Error(code), { runtimeCode: code }); };
const check = (ok, code) => { if (!ok) fail(code); };
const erc20 = parseAbi(['function transfer(address,uint256) returns (bool)', 'function balanceOf(address) view returns (uint256)']);
// Tempo chain ids (mainnet 4217, testnet "moderato" 42431). A tempo challenge without chainId means mainnet.
export const TEMPO_CHAIN_IDS = [4217, 42431];

const header = (headers, name) => { const v = headers?.get ? headers.get(name) : headers?.[name] ?? headers?.[name.toLowerCase()]; return Array.isArray(v) ? v.join(', ') : v; };
// 402 → 'x402' | 'mpp' | null. A merchant may send both (the stock mppx evm server does): x402 wins
// (the Safe's native rail, no hop) unless the caller prefers MPP (prefer 'mpp', 'mpp:evm', 'session', …).
export function detectProtocol({ headers, bodyText = '', prefer }) {
  const mpp = /^\s*Payment\s/i.test(header(headers, 'www-authenticate') || '');
  if (mpp && typeof prefer === 'string' && (prefer.startsWith('mpp') || ['charge', 'session'].includes(prefer))) return 'mpp';
  if (typeof header(headers, 'payment-required') === 'string') return 'x402';
  try { const j = JSON.parse(bodyText); if (j && (j.x402Version === 1 || j.x402Version === 2)) return 'x402'; } catch {}
  return mpp ? 'mpp' : null;
}

// WWW-Authenticate → offers the Safe can pay, normalized like src/safe-pay.mjs offers (asset, amount, payTo, chainId).
export function parseMppChallenges({ headers }) {
  const raw = header(headers, 'www-authenticate');
  check(typeof raw === 'string' && raw.length <= 32768, 'payment_challenge_missing');
  let list; try { list = Challenge.deserializeList(raw); } catch { fail('invalid_mpp_challenge'); }
  return list.map((challenge, index) => {
    const r = challenge.request || {}, d = r.methodDetails || {};
    const kind = `${challenge.method}/${challenge.intent}`;
    if (!['evm/charge', 'tempo/charge', 'tempo/session'].includes(kind)) return null;
    const chainId = Number(d.chainId ?? (challenge.method === 'tempo' ? 4217 : NaN));
    if (!Number.isSafeInteger(chainId) || typeof r.currency !== 'string' || typeof r.recipient !== 'string' || !/^[0-9]+$/.test(String(r.amount))) return null;
    if (challenge.method === 'tempo' && !TEMPO_CHAIN_IDS.includes(chainId)) return null;
    if (kind === 'evm/charge' && (d.splits?.length || !(d.credentialTypes ?? ['authorization']).includes('authorization'))) return null;
    // A session reserves a deposit up front (suggestedDeposit, else 100 units of the per-unit price).
    const deposit = kind === 'tempo/session' ? String(r.suggestedDeposit ?? BigInt(r.amount) * 100n) : String(r.amount);
    return { protocol: 'mpp', index, challenge, scheme: `mpp:${challenge.method}:${challenge.intent}`, method: challenge.method, intent: challenge.intent,
      chainId, network: `eip155:${chainId}`, asset: getAddress(r.currency), payTo: getAddress(r.recipient), amount: deposit,
      unitAmount: String(r.amount), decimals: d.decimals ?? r.decimals ?? 6, expires: challenge.expires ?? null, maxTimeoutSeconds: 300 };
  }).filter(Boolean);
}
export function selectMppOffer(offers, { chainIds, prefer } = {}) {
  const payable = offers.filter(o => !chainIds || chainIds.includes(o.chainId));
  check(payable.length, 'no_payable_offer');
  const pinned = prefer ? payable.filter(o => o.scheme === prefer || `mpp:${o.method}` === prefer || o.intent === prefer) : payable;
  check(pinned.length, 'preferred_scheme_not_offered');
  // charge before session (a session keeps a deposit locked), then merchant order.
  return pinned.sort((a, b) => (a.intent === 'charge' ? 0 : 1) - (b.intent === 'charge' ? 0 : 1) || a.index - b.index)[0];
}
export const quoteMppOffer = o => ({ protocol: 'mpp', scheme: o.scheme, rail: o.method, intent: o.intent, chain_id: o.chainId, network: o.network,
  token: o.asset, decimals: o.decimals, amount_units: o.amount, ...(o.intent === 'session' ? { unit_amount_units: o.unitAmount } : {}),
  pay_to: o.payTo, expires: o.expires, needs: { hop: 'safe_to_agent_exact' } });

// The one Safe call: exactly `amount` of `token` to the Agent EOA.
export const hopCall = (token, agent, amount) => ({ to: getAddress(token), value: 0n, data: encodeFunctionData({ abi: erc20, functionName: 'transfer', args: [getAddress(agent), BigInt(amount)] }) });

// A Tempo account from any signer with sign({ hash }) (local key or the Privy 2-of-2 quorum account,
// src/privy-agent-app-signer.mjs:210). The public key is recovered from one signature over a fixed hash.
export async function tempoAccountOf(signer) {
  const hash = keccak256(toHex('nuri-safe-mpp-pubkey'));
  const publicKey = PublicKey.fromHex(signer.publicKey || await recoverPublicKey({ hash, signature: await signer.sign({ hash }) }));
  const account = TempoAccount.from({ keyType: 'secp256k1', publicKey, sign: ({ hash: h }) => signer.sign({ hash: h }) });
  check(getAddress(account.address) === getAddress(signer.address), 'agent_public_key_mismatch');
  return account;
}

// Pay one MPP offer. hop(token, amount) runs the Safe → Agent EOA transfer (a Kernel UserOp in the
// runtime) and resolves after it is mined. fetchPaid(credentialHeaderOrNull) re-sends the merchant
// request. getClient(chainId) → viem client for that chain. Returns { response, receipt, credential }.
// feeReserve: Tempo has no native gas coin; the Agent EOA pays its tx fee in a USD TIP-20, so a Tempo
// hop carries amount + feeReserve and sweepToSafe returns what is left. EVM charges are gasless (0).
export async function payMppCharge({ offer, agent, hop, getClient, fetchPaid, evmAuthorization, feeReserve = 0n }) {
  check(offer.intent === 'charge', 'mpp_intent_mismatch');
  const amountUnits = BigInt(offer.amount);
  if (amountUnits > 0n) {
    await hop(offer.asset, amountUnits + (offer.method === 'tempo' ? BigInt(feeReserve) : 0n));
  }
  const method = offer.method === 'evm'
    ? evmClient.charge({ account: agent, networks: [offer.chainId], ...(evmAuthorization ? { authorization: evmAuthorization } : {}) })
    : tempoClient.charge({ account: await tempoAccountOf(agent), getClient: () => getClient(offer.chainId), expectedChainId: offer.chainId, mode: 'pull' });
  const client = Mppx.create({ polyfill: false, methods: [method] });
  const res402 = new Response(null, { status: 402, headers: { 'www-authenticate': Challenge.serialize(offer.challenge) } });
  const credential = await client.createCredential(res402);
  const response = await fetchPaid(credential);
  let receipt = null; try { receipt = Receipt.fromResponse(response); } catch {}
  return { response, receipt, credential };
}

// Session: hop the deposit, open + vouchers through the stock sessionManager (the Agent EOA is payer
// and voucher signer), close, then sweep the Agent EOA's balance of that token back to the Safe.
export async function openMppSession({ offer, agent, hop, getClient, fetch: fetchImpl, feeReserve = 0n }) {
  check(offer.intent === 'session' && offer.method === 'tempo', 'mpp_intent_mismatch');
  await hop(offer.asset, BigInt(offer.amount) + BigInt(feeReserve));
  const account = await tempoAccountOf(agent);
  const decimals = Number(offer.decimals);
  const maxDeposit = (Number(BigInt(offer.amount)) / 10 ** decimals).toString();
  const manager = sessionManager({ account, getClient: () => getClient(offer.chainId), maxDeposit, ...(fetchImpl ? { fetch: fetchImpl } : {}) });
  return { manager, account, fetch: (url, init) => manager.fetch(url, init), close: () => manager.close() };
}
// After a session closes (or a Tempo charge), return the Agent EOA's leftover of `token` to the Safe.
// Tempo fees are paid in the token itself, so `keep` stays behind to pay for this transfer.
export async function sweepToSafe({ client, account, token, safe, keep = 0n }) {
  const bal = await readContract(client, { address: token, abi: erc20, functionName: 'balanceOf', args: [account.address] });
  if (bal <= BigInt(keep)) return null;
  const { receipt } = await TempoActions.token.transferSync(client, { account, token, to: getAddress(safe), amount: bal - BigInt(keep), feeToken: token });
  return { hash: receipt.transactionHash, amount: bal - BigInt(keep) };
}
