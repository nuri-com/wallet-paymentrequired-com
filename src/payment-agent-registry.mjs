import { getAddress, keccak256, pad, parseAbi, zeroAddress } from 'viem';
import { KernelV3_1AccountAbi } from '@zerodev/sdk';
import { PAYMENT_CALL_POLICY, PAYMENT_USDC, PAYMENT_WCUSDC } from './payment-agent-policy.mjs';

const IMPLEMENTATION_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const VALIDATOR_IMPLEMENTATION = '0x1433785b3a575fa98e40fd439fc25c64c17fb95c';
const OWNER_SIGNER = '0x6A6F069E2a08c2468e7724Ab3250CdBFBA14D4FF';
const DOMAINS = {
  '0xc801a0f38e20500b5840c4927553b3409890bc3c': {
    Accounts: '0x6A51218b31074879d93b86B93CdD585c7BB31ad3',
    AgenticValidator: '0x79277b8Caa0192eCA259917d3Ccd0B87661A5836',
    ExecutionDelayPolicy: '0x5D8540F1856674632F7B417BBBDBCbFFfdE97bBD',
    TokensRegistry: '0x9E0D9e26192eCD21B47D1D88dc60E20429b0f35c',
    // Wirex rotated the sandbox delay-policy implementation (was
    // 0xd6165c4a5c69320e17590846d56d4a1f78ba1e47); verified live via the
    // proxy's implementation slot on 2026-09-21 (#166 path b unblock).
    implementation: '0x263f8f2756e89eea51dbcdb1914a6338fd983578',
  },
  '0x062afb76614dd594a99e70fd2cfbdf417ccf8797': {
    Accounts: '0x0124FACC85003AaA06ac0a6ca86982e1Ae04b549',
    AgenticValidator: '0xD7Acf149eAD09b61a6546807e5855d0aa4219Ada',
    ExecutionDelayPolicy: '0x5932A1DD516964b2652240e2E127615013869354',
    TokensRegistry: '0x93705FB5333A986d75aA52DD504192ad84714581',
    implementation: '0x6737dda1d03bf991416f07071ab47e143a648c9c',
  },
};
const RegistryAbi = parseAbi(['function contractByName(string) view returns (address)']);
const AddressAbi = parseAbi(['function contractRegistry() view returns (address)', 'function tokensRegistry() view returns (address)', 'function windowLength() pure returns (uint256)']);
const TokenRegistryAbi = parseAbi(['function isSupportedByAddress(address) view returns (bool)', 'function getSyntheticAddress(address) view returns (address)', 'function isSyntheticToken(address) view returns (bool)', 'function getBaseAddress(address) view returns (address)']);
const SyntheticAbi = parseAbi(['function decimals() view returns (uint8)', 'function baseToken() view returns (address)', 'function DECIMALS_CONVERSION() view returns (uint256)']);
const equal = (a, b) => getAddress(a) === getAddress(b);



export async function readPaymentAgentDomain({ publicClient, registry, kernel, owner, partnerId }) {
  if (await publicClient.getChainId() !== 84532) throw new Error('payment_agents_base_sepolia_only');
  const expected = DOMAINS[registry.toLowerCase()];
  if (!expected) throw new Error('payment_agent_registry_unsupported');
  const blockNumber = await publicClient.getBlockNumber();
  const read = (address, abi, functionName, args = []) => publicClient.readContract({ address, abi, functionName, args, blockNumber });
  const resolved = {};
  for (const name of ['Accounts', 'AgenticValidator', 'ExecutionDelayPolicy', 'TokensRegistry']) {
    resolved[name] = await read(registry, RegistryAbi, 'contractByName', [name]);
    if (!equal(resolved[name], expected[name])) throw new Error('payment_agent_registry_changed');
  }
  const { Accounts: accounts, AgenticValidator: validator, ExecutionDelayPolicy: delayPolicy, TokensRegistry: tokensRegistry } = resolved;
  for (const [address, implementation] of [[validator, VALIDATOR_IMPLEMENTATION], [delayPolicy, expected.implementation]]) {
    const word = await publicClient.getStorageAt({ address, slot: IMPLEMENTATION_SLOT, blockNumber });
    if (!word || !equal(`0x${word.slice(-40)}`, implementation)) throw new Error('payment_agent_implementation_mismatch');
  }
  if (!equal(await read(validator, AddressAbi, 'contractRegistry'), registry)
    || !equal(await read(validator, AddressAbi, 'tokensRegistry'), tokensRegistry)) throw new Error('payment_agent_validator_domain_mismatch');
  if (await read(validator, AddressAbi, 'windowLength') !== 86400n) throw new Error('validator_window_mismatch');
  const root = await read(kernel, KernelV3_1AccountAbi, 'rootValidator');
  if (!root.startsWith('0x02')) throw new Error('unsupported_root_type');
  const rootId = `0x${root.slice(4, 12)}`;
  const permission = await read(kernel, KernelV3_1AccountAbi, 'permissionConfig', [rootId]);
  if (!equal(permission.signer, OWNER_SIGNER) || permission.permissionFlag !== '0x0000'
    || permission.policyData.length !== 1 || permission.policyData[0].toLowerCase() !== `0x0000${delayPolicy.slice(2)}`.toLowerCase()) throw new Error('payment_agent_existing_root_mismatch');
  const mappedOwner = await read(OWNER_SIGNER, parseAbi(['function signer(bytes32,address) view returns (address)']), 'signer', [pad(rootId, { size: 32, dir: 'right' }), kernel]);
  if (!equal(mappedOwner, owner)) throw new Error('payment_agent_root_owner_mismatch');
  for (const [address, hash] of [[OWNER_SIGNER, '0x510a0a1ab8b3f256a5c90b5fff51a9fd98656bd1c8a29fbd7857faa70c400ccd'], [PAYMENT_CALL_POLICY, '0x99fc4b02bdbb9a5133728a2bfffb458bf8530b1b068d6d4334f69dcb454ace78']]) {
    const code = await publicClient.getCode({ address, blockNumber });
    if (!code || keccak256(code) !== hash) throw new Error('payment_agent_policy_code_mismatch');
  }
  const parent = await read(delayPolicy, parseAbi(['function accountToParentEntity(address) view returns (bytes16)']), 'accountToParentEntity', [kernel]);
  if (parent.toLowerCase() !== partnerId.toLowerCase()) throw new Error('payment_agent_parent_registration_required');
  if (!await read(tokensRegistry, TokenRegistryAbi, 'isSupportedByAddress', [PAYMENT_USDC])
    || await read(PAYMENT_USDC, SyntheticAbi, 'decimals') !== 6) throw new Error('payment_agent_canonical_usdc_mismatch');
  const synthetic = await read(tokensRegistry, TokenRegistryAbi, 'getSyntheticAddress', [PAYMENT_USDC]);
  let conversion = 1n;
  if (!equal(synthetic, zeroAddress)) {
    if (!equal(synthetic, PAYMENT_WCUSDC)
      || !await read(tokensRegistry, TokenRegistryAbi, 'isSupportedByAddress', [synthetic])
      || !await read(tokensRegistry, TokenRegistryAbi, 'isSyntheticToken', [synthetic])
      || !equal(await read(tokensRegistry, TokenRegistryAbi, 'getBaseAddress', [synthetic]), PAYMENT_USDC)
      || !equal(await read(synthetic, SyntheticAbi, 'baseToken'), PAYMENT_USDC)
      || await read(synthetic, SyntheticAbi, 'decimals') !== 18) throw new Error('payment_agent_synthetic_mismatch');
    conversion = await read(synthetic, SyntheticAbi, 'DECIMALS_CONVERSION');
    if (conversion !== 1_000_000_000_000n) throw new Error('payment_agent_synthetic_conversion_mismatch');
  }
  return { registry: getAddress(registry), accounts, validator, delayPolicy, tokensRegistry, root, asset: PAYMENT_USDC, synthetic, conversion };
}
