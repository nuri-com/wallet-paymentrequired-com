import { encodeFunctionData, getAddress, parseAbi, toFunctionSelector, zeroAddress } from 'viem';
import { toCallPolicy, toSudoPolicy, CallPolicyVersion } from '@zerodev/permissions/policies';

export const PAYMENT_CALL_POLICY = '0x9a52283276A0ec8740DF50bF01B28A80D880eaf2';
export const PAYMENT_USDC = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
export const PAYMENT_WCUSDC = '0x2BA2c69030F7deefA77bB3b3d64BF46f0fa4528B';




export function paymentAgentPolicies(delayPolicy, synthetic) {
  if (!synthetic) throw new Error('payment_agent_funding_domain_required');
  return [toSudoPolicy({ policyAddress: delayPolicy }), toCallPolicy({
    policyVersion: CallPolicyVersion.V0_0_4,
    permissions: [
      { target: delayPolicy, selector: toFunctionSelector('request(address,uint256,bytes)') },
      ...(getAddress(synthetic) === zeroAddress ? [] : [{ target: synthetic, selector: toFunctionSelector('withdraw(uint256)') }]),
      { target: PAYMENT_USDC, selector: toFunctionSelector('transfer(address,uint256)') },
    ],
  })];
}

const AdminAbi = parseAbi([
  'function setLimit(address,address,uint128,uint128)',
  'function addAgent(address,uint8)',
  'function removeAgent(address)',
]);



export function paymentAgentActivationCalls({ validator, owner, agents, cap, perTxMax }) {
  const addresses = agents.map(address => getAddress(address));
  if (addresses.length !== 3 || new Set(addresses).size !== 3 || addresses.includes(getAddress(owner)) || addresses.includes(zeroAddress)) throw new Error('three_distinct_agents_required');
  if (cap <= 0n || cap >= 2n ** 128n || perTxMax <= 0n || perTxMax > cap) throw new Error('invalid_daily_limits');
  const call = (functionName, args) => ({ to: validator, value: 0n, data: encodeFunctionData({ abi: AdminAbi, functionName, args }) });
  return [
    ...addresses.flatMap(agent => [
      call('setLimit', [agent, PAYMENT_USDC, cap, perTxMax]),
      call('setLimit', [agent, PAYMENT_WCUSDC, 0n, 0n]),
      call('setLimit', [agent, zeroAddress, 0n, 0n]),
    ]),
    ...addresses.map(agent => call('addAgent', [agent, 1])),
    call('removeAgent', [getAddress(owner)]),
  ];
}






export function paymentAgentSetLimitCall({ validator, agent, cap, perTxMax }) {
  if (cap <= 0n || cap >= 2n ** 128n || perTxMax <= 0n || perTxMax > cap) throw new Error('invalid_daily_limits');
  return { to: getAddress(validator), value: 0n, data: encodeFunctionData({ abi: AdminAbi, functionName: 'setLimit', args: [getAddress(agent), PAYMENT_USDC, cap, perTxMax] }) };
}





export function paymentAgentRevokeCall({ validator, agent }) {
  return { to: getAddress(validator), value: 0n, data: encodeFunctionData({ abi: AdminAbi, functionName: 'removeAgent', args: [getAddress(agent)] }) };
}
