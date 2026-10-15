// New wallets only. SDK views/builders; no custody, persistence, funding or broadcast.
import { encodeFunctionData, getAddress, maxUint256, pad, parseAbi, zeroAddress } from 'viem';
import { createKernelAccount, addressToEmptyAccount, toSigner } from '@zerodev/sdk';
import { toKernelPluginManager } from '@zerodev/sdk/accounts';
import { getEntryPoint, KERNEL_V3_1 } from '@zerodev/sdk/constants';
import { getKernelAddressFromECDSA, signerToEcdsaValidator } from '@zerodev/ecdsa-validator';
import { toPermissionValidator } from '@zerodev/permissions';
import { toECDSASigner } from '@zerodev/permissions/signers';
import { toCallPolicy, CallPolicyVersion } from '@zerodev/permissions/policies';
import { SAFE_CHAINS } from './safe-pay-chains.mjs';

const tokenAbi = parseAbi(['function transfer(address to,uint256 value) returns (bool)', 'function approve(address spender,uint256 value) returns (bool)']);
const validatorAbi = parseAbi(['function onUninstall(bytes data)', 'function onInstall(bytes data)']);
const tx = (to, abi, functionName, args) => ({ to, value: 0n, data: encodeFunctionData({ abi, functionName, args }) });
function address(value) {
  const result = getAddress(value);
  if (result === zeroAddress) throw new Error('zero address');
  return result;
}
function units(value, name, allowZero = false) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > maxUint256 || (!allowZero && value === '0')) {
    throw new Error(`invalid ${name}: expected ${allowZero ? 'nonnegative' : 'positive'} uint256 decimal string`);
  }
  return BigInt(value);
}

// D-SAFE-NO-LIMITS: every Safe's spender is the no-limit spender (maxTransferUnits === NO_LIMIT).
// It may call transfer and approve on ANY token contract (CallPolicy v0.0.5 zero-address target)
// with no amount rule, and ERC-1271 signing stays unrestricted (EIP-3009, Permit2 exact/upto, MPP).
// It can call nothing else: no installModule, changeRootValidator or execute on the Safe itself,
// so the owner keeps the Safe. The record is chain-free: same permissionId and Safe address on
// every chain of src/safe-pay-chains.mjs. No capped records exist (D-NO-LEGACY).
export const NO_LIMIT = maxUint256.toString();
const knownChain = (chainId, maxTransferUnits) => maxTransferUnits === NO_LIMIT && SAFE_CHAINS.has(chainId);
export function agentPermissionPolicies({ maxTransferUnits, chainId, policyVersion = CallPolicyVersion.V0_0_5, permit2Enabled = false }) {
  if (!knownChain(chainId, maxTransferUnits)) throw new Error('unsupported/mismatched chainId');
  if (policyVersion !== CallPolicyVersion.V0_0_5 || typeof permit2Enabled !== 'boolean') throw new Error('unsupported policy configuration');
  return [toCallPolicy({ policyVersion, permissions: [
    { target: zeroAddress, abi: tokenAbi, functionName: 'transfer', valueLimit: 0n },
    { target: zeroAddress, abi: tokenAbi, functionName: 'approve', valueLimit: 0n },
  ] })];
}

// pluginEnableSignature: the sudo owner's signature over the permission's enable typed data
// (enableTypedData below), when the owner is a person who tapped it.
export async function createAgentKernelWallet({ client, ownerSigner, agentSigner, record, pluginEnableSignature }) {
  const { chainId, index, initialOwnerAddress, maxTransferUnits, policyVersion = CallPolicyVersion.V0_0_5, permit2Enabled = false } = record;
  if (!Number.isInteger(chainId) || !knownChain(chainId, maxTransferUnits) || client.chain?.id !== chainId || await client.getChainId() !== chainId) throw new Error('unsupported/mismatched chainId');
  if (policyVersion !== CallPolicyVersion.V0_0_5 || typeof permit2Enabled !== 'boolean') throw new Error('unsupported policy configuration');
  const accountIndex = units(index, 'index', true);
  const initialOwner = address(initialOwnerAddress);
  const owner = await toSigner({ signer: ownerSigner }), agent = await toSigner({ signer: agentSigner });
  const ownerAddress = address(owner.address), agentAddress = address(agent.address);
  // Custody v2 guest: one Privy agent EOA is sudo owner AND spender until connect rotates sudo to the user EOA.
  const selfOwned = agentAddress === initialOwner && agentAddress === ownerAddress;
  if (!selfOwned && (agentAddress === initialOwner || agentAddress === ownerAddress)) throw new Error('owner and agent must be independent');
  const config = { entryPoint: getEntryPoint('0.7'), kernelVersion: KERNEL_V3_1 };
  const sudo = await signerToEcdsaValidator(client, { ...config, signer: owner });
  const initialSudo = ownerAddress === initialOwner ? sudo : await signerToEcdsaValidator(client, { ...config, signer: addressToEmptyAccount(initialOwner) });
  // SDK derives the original sudo-only address even after deployment/rotation.
  const walletAddress = await getKernelAddressFromECDSA({ ...config, publicClient: client, eoaAddress: initialOwner, index: accountIndex });
  const creation = { ...config, index: accountIndex, address: walletAddress };
  const initial = await createKernelAccount(client, { ...creation, plugins: { sudo: initialSudo } });
  const validatorInitData = await initial.kernelPluginManager.getValidatorInitData();
  const policies = agentPermissionPolicies({ maxTransferUnits, chainId, policyVersion, permit2Enabled });
  const regular = await toPermissionValidator(client, { ...config, signer: await toECDSASigner({ signer: agent }), policies });
  // Public SDK initialization override, not a patch to plugin-manager internals.
  // A fresh manager per view/invocation avoids stale pluginEnabled after uninstall.
  const view = async (regular) => createKernelAccount(client, { ...creation,
    plugins: await toKernelPluginManager(client, { ...config, sudo, regular, validatorInitData, ...(regular && pluginEnableSignature ? { pluginEnableSignature } : {}) }) });
  const ownerAccount = await view(), agentAccount = await view(regular);
  const derived = { address: walletAddress, factory: initial.factoryAddress, factoryData: await initial.generateInitCode(), agentAddress,
    permissionId: regular.getIdentifier(), validationId: pad(agentAccount.kernelPluginManager.getIdentifier(), { size: 21, dir: 'right' }) };
  for (const [key, value] of Object.entries(derived)) {
    if (Object.hasOwn(record, key) && (typeof record[key] !== 'string' || record[key].toLowerCase() !== value.toLowerCase())) throw new Error(`persisted ${key} mismatch`);
  }
  return {
    record: Object.freeze({ chainId, index, initialOwnerAddress: initialOwner, maxTransferUnits, policyVersion, permit2Enabled, ...derived }),
    ownerAccount, agentAccount,
    // What the sudo owner signs to enable the agent permission (Kernel ENABLE mode). The ECDSA
    // root accepts it raw or as an eth_sign/personal_sign digest, so a one-tap bridge works.
    enableTypedData: () => agentAccount.kernelPluginManager.getPluginsEnableTypedData(walletAddress),
    rotateOwnerCalls(newOwnerAddress) {
      const next = address(newOwnerAddress);
      if (next === agentAddress) throw new Error('owner and agent must be independent');
      // Same-id changeRootValidator is a no-op; execute these together atomically.
      return [tx(sudo.address, validatorAbi, 'onUninstall', ['0x']), tx(sudo.address, validatorAbi, 'onInstall', [next])];
    },
  };
}
