import { decodeEventLog, encodeAbiParameters, keccak256, parseAbi, parseAbiParameters } from 'viem';
import { getUserOperationHash, formatUserOperationRequest } from 'viem/account-abstraction';
import { getEntryPoint } from '@zerodev/sdk/constants';

const ENTRY_POINT = getEntryPoint('0.7');
const RECEIPT_ABI = parseAbi(['event UserOperationEvent(bytes32 indexed userOpHash,address indexed sender,address indexed paymaster,uint256 nonce,bool success,uint256 actualGasCost,uint256 actualGasUsed)']);
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
export function scheduledHash(wallet, callData, nonce) {
  return keccak256(encodeAbiParameters(parseAbiParameters('address, bytes, uint256'), [wallet, callData, nonce]));
}



export function assertFundingNotStarted(payment, journal, wallet) {
  const op = payment.operation;
  const hash = scheduledHash(wallet, op.callData, BigInt(op.nonce));
  const checkpoint = payment.fundingAuthorization;
  if (op.hash !== hash || payment.funding || !checkpoint || checkpoint.status !== 'not_started'
    || Object.keys(op).some(key => !['hash', 'nonce', 'callData'].includes(key))
    || checkpoint.operationHash !== hash || Object.keys(checkpoint).length !== 2
    || Object.hasOwn(journal, hash)
    || Object.values(journal).some(record => record?.nonce === op.nonce && record?.callData === op.callData)) {
    throw new Error('funding_authorization_requires_reconciliation');
  }
}



export async function ensureFundingRequest({ payment, journal, account, client, request, createOperation, readSchedule, save, allowRenewal = false }) {
  const op = payment.operation;
  const validRequest = candidate => {
    if (!candidate || candidate.callData !== request || candidate.hash !== scheduledHash(account.address, request, BigInt(candidate.nonce))) throw new Error('funding_request_changed');
    if (BigInt(candidate.nonce) === BigInt(op.nonce)) throw new Error('request_nonce_collision');
  };
  let { row, now } = await readSchedule();
  if (Number(row[1]) === 1 && BigInt(row[3]) >= now) return;
  assertFundingNotStarted(payment, journal, account.address);
  
  
  if (![0, 1].includes(Number(row[1]))) throw new Error('funding_schedule_requires_reconciliation');
  if (!payment.requestOperation) {
    if (Number(row[1]) !== 0) throw new Error('funding_request_evidence_missing');
    const first = await createOperation();
    validRequest(first);
    payment.requestOperation = first;
    await save();
  }
  validRequest(payment.requestOperation);
  const previous = payment.requestOperation;
  const receipt = await sendRecordedUserOperation({ account, client, callData: request, nonce: BigInt(previous.nonce), journal, save });
  ({ row, now } = await readSchedule());
  if (Number(row[1]) === 1 && BigInt(row[3]) >= now) return;
  if (Number(row[1]) !== 1) throw new Error('funding_schedule_requires_reconciliation');
  assertFundingNotStarted(payment, journal, account.address);
  if (!allowRenewal) throw new Error('funding_renewal_route_not_supported');
  
  
  const next = await createOperation();
  validRequest(next);
  const history = payment.requestOperationHistory || [];
  if (!Array.isArray(history) || [previous, ...history.map(entry => entry.operation)].some(entry => BigInt(entry.nonce) === BigInt(next.nonce))) throw new Error('funding_request_nonce_not_fresh');
  payment.requestOperationHistory = [...history, { operation: previous, receipt,
    expiredSchedule: { opType: Number(row[0]), status: Number(row[1]), validAfter: String(row[2]), validUntil: String(row[3]), observedAt: String(now) } }];
  payment.requestOperation = next;
  await save(); 
  await sendRecordedUserOperation({ account, client, callData: request, nonce: BigInt(next.nonce), journal, save });
}

const NUMBER_FIELDS = ['nonce', 'callGasLimit', 'verificationGasLimit', 'preVerificationGas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'paymasterVerificationGasLimit', 'paymasterPostOpGasLimit'];
const hashOperation = userOperation => getUserOperationHash({ userOperation, chainId: 84532, entryPointAddress: ENTRY_POINT.address, entryPointVersion: '0.7' });



export async function sendRecordedUserOperation({ account, client, callData, nonce, journal, save }) {
  if (typeof client.client?.getTransactionReceipt !== 'function') throw new Error('payment_public_receipt_client_required');
  const existing = nonce === undefined
    ? Object.values(journal).find(record => record.callData === callData)
    : journal[scheduledHash(account.address, callData, BigInt(nonce))];
  
  if ((existing || (nonce !== undefined && Object.hasOwn(journal, scheduledHash(account.address, callData, BigInt(nonce))))) && !existing?.userOpHash) throw new Error('recorded_userop_signing_uncertain');
  let userOpHash = existing?.userOpHash;
  let rpcOperation = existing?.rpcOperation;
  let receipt;
  if (existing && (existing.callData !== callData || (nonce !== undefined && existing.nonce !== String(nonce)))) throw new Error('recorded_userop_binding_mismatch');
  if (userOpHash) {
    if (!rpcOperation) {
      
      receipt = await client.waitForUserOperationReceipt({ hash: userOpHash, timeout: 180_000 });
    } else {
      const decoded = { ...rpcOperation };
      for (const key of NUMBER_FIELDS) if (decoded[key] !== undefined) decoded[key] = BigInt(decoded[key]);
      if (rpcOperation.sender?.toLowerCase() !== account.address.toLowerCase() || rpcOperation.callData !== callData || String(decoded.nonce) !== existing.nonce || hashOperation(decoded).toLowerCase() !== userOpHash.toLowerCase()) throw new Error('recorded_userop_payload_mismatch');
      try { receipt = await client.getUserOperationReceipt({ hash: userOpHash }); }
      catch (error) { if (error.name !== 'UserOperationReceiptNotFoundError') throw error; }
    }
  } else {
    const prepared = await client.prepareUserOperation({ callData, nonce });
    if (!same(prepared.sender, account.address) || prepared.callData !== callData || (nonce !== undefined && BigInt(prepared.nonce) !== BigInt(nonce))) throw new Error('prepared_userop_binding_mismatch');
    if (prepared.authorization) throw new Error('payment_userop_7702_not_supported');
    const key = scheduledHash(account.address, callData, prepared.nonce);
    journal[key] = { nonce: prepared.nonce.toString(), callData, status: 'signing' };
    await save(); 
    const signature = await account.signUserOperation(prepared);
    userOpHash = hashOperation({ ...prepared, signature });
    rpcOperation = formatUserOperationRequest({ ...prepared, signature });
    journal[key] = { userOpHash, nonce: prepared.nonce.toString(), callData, rpcOperation };
  }
  if (!receipt) {
    
    await save();
    const submitted = await client.request({ method: 'eth_sendUserOperation', params: [rpcOperation, ENTRY_POINT.address] }, { retryCount: 0 });
    if (submitted.toLowerCase() !== userOpHash.toLowerCase()) throw new Error('submitted_userop_hash_mismatch');
    receipt = await client.waitForUserOperationReceipt({ hash: userOpHash, timeout: 180_000 });
  }
  if (!receipt.success) throw new Error('recorded_userop_failed');
  const expectedNonce = BigInt(rpcOperation?.nonce ?? existing.nonce);
  if (!same(receipt.userOpHash, userOpHash) || !same(receipt.sender, account.address)
    || !['string', 'bigint'].includes(typeof receipt.nonce) || BigInt(receipt.nonce) !== expectedNonce) throw new Error('recorded_userop_receipt_mismatch');
  const txHash = receipt.receipt?.transactionHash;
  if (typeof txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) throw new Error('recorded_userop_receipt_mismatch');
  const mined = await client.client.getTransactionReceipt({ hash: txHash });
  if (mined.status !== 'success' || !same(mined.transactionHash, txHash)) throw new Error('recorded_userop_transaction_failed');
  const confirmed = mined.logs.some(log => {
    if (!same(log.address, ENTRY_POINT.address)) return false;
    try {
      const event = decodeEventLog({ abi: RECEIPT_ABI, data: log.data, topics: log.topics });
      return same(event.args.userOpHash, userOpHash) && same(event.args.sender, account.address)
        && event.args.nonce === expectedNonce && event.args.success;
    } catch { return false; }
  });
  if (!confirmed) throw new Error('recorded_userop_event_mismatch');
  return { userOpHash, txHash, blockNumber: mined.blockNumber.toString() };
}
