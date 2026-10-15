// D-SAFE-NO-LIMITS: the chains the Agent Safe pays on, one table instead of a hard-coded Base.
// The Kernel v3.1 Safe is counterfactual: factory 0xaac5…E419, ECDSA validator, EntryPoint 0.7,
// Permit2 and both x402 proxies have the same address on every chain below (read on chain
// 2026-09-25 with eth_getCode), so the Safe has the SAME address everywhere and is deployed
// on first use. USDC on each chain is FiatToken v2.2 with the bytes-signature
// transferWithAuthorization (selector cf092995 in the implementation), so a Safe can be the
// EIP-3009 `from` via ERC-1271. RPC per chain: env SAFE_RPC_<chainId>, else viem's default.
import { base, baseSepolia, mainnet, arbitrum, optimism, polygon, celo, arcTestnet, tempo, tempoModerato } from 'viem/chains';

// callPolicy: CallPolicy v0.0.5 has code there (the no-limit spender needs it). Tempo and Celo
// lack it, so the Safe cannot hold the agent permission there yet (see DECISIONS D-SAFE-NO-LIMITS).
// feeCeiling: the operator's max fee per gas (wei) it accepts to sponsor a UserOp there; Base keeps
// its old 0.01 gwei. opStack: receipts carry an L1 data fee the gas accounting must include.
const TABLE = [
  [base, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', 'USD Coin', true, 10000000n, true],
  [baseSepolia, '0x036CbD53842c5426634e7929541eC2318f3dCF7e', 'USDC', true, 10000000n, true],
  [mainnet, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'USD Coin', true, 20000000000n, false],
  [arbitrum, '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', 'USD Coin', true, 100000000n, false],
  [optimism, '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85', 'USD Coin', true, 10000000n, true],
  [polygon, '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', 'USD Coin', true, 500000000000n, false],
  [arcTestnet, '0x3600000000000000000000000000000000000000', 'USDC', true, 500000000000n, false],
  [celo, '0xcebA9300f2b948710d2653dD7B07f33A8B32118C', 'USDC', false, 0n, false],
  [tempo, null, null, false, 0n, false],
  // D-SAFE-MPP: Tempo testnet, for MPP tempo/charge + tempo/session proofs (scripts/prove-safe-mpp-fork.mjs).
  [tempoModerato, null, null, false, 0n, false],
];
export const SAFE_CHAINS = new Map(TABLE.map(([chain, usdc, name, callPolicy, feeCeiling, opStack]) => [chain.id, Object.freeze({
  chain, chainId: chain.id, network: `eip155:${chain.id}`, callPolicy, feeCeiling, opStack,
  usdc: usdc && Object.freeze({ address: usdc, name, version: '2', decimals: 6 }),
})]));
export function safeChain(chainId, env = process.env) {
  const entry = SAFE_CHAINS.get(Number(chainId));
  if (!entry) throw Object.assign(new Error('unsupported_chain'), { runtimeCode: 'unsupported_chain' });
  return { ...entry, rpc: env[`SAFE_RPC_${entry.chainId}`] || entry.chain.rpcUrls.default.http[0],
    feeCeiling: env[`SAFE_MAX_FEE_WEI_${entry.chainId}`] ? BigInt(env[`SAFE_MAX_FEE_WEI_${entry.chainId}`]) : entry.feeCeiling };
}
export const tokenFor = chainId => safeChain(chainId).usdc;
// Chains where the Safe can hold the no-limit spender (and so pay).
export const PAYABLE_CHAIN_IDS = [...SAFE_CHAINS.values()].filter(c => c.callPolicy && c.usdc).map(c => c.chainId);
export const chainOfNetwork = network => {
  const m = /^eip155:([0-9]{1,12})$/.exec(String(network ?? ''));
  return m && SAFE_CHAINS.has(Number(m[1])) ? Number(m[1]) : null;
};
