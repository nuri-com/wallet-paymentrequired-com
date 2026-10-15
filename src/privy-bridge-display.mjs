const stages = {
  load_request: 'load this approval', select_wallet: 'select your wallet', create_wallet: 'create the payment wallet',
  connect_wallet: 'connect the payment wallet', prepare_signature: 'prepare the approval',
  sign_request: 'approve this request', sign_consent: 'approve the payment limits',
  submit_approval: 'finish the approval', connect_account: 'connect your account',
  authorize_session: 'authorize the connection', approval: 'approve this request',
};
const selectionMessages = {
  privy_selection_pin_missing: 'The wallet for this request is not connected.',
  privy_selection_pin_conflict: 'This request points to different wallets. Approval is blocked.',
  privy_selection_metadata_missing: 'Your wallet details are incomplete.',
  privy_selection_metadata_conflict: 'Your wallet details do not agree. Approval is blocked.',
  privy_selection_not_connected: 'Your wallet is not connected yet.',
  privy_selection_recovery: 'This wallet cannot be recovered here yet.',
  privy_selection_ambiguous: 'Choose the wallet to use.',
  privy_selection_identity_changed: 'The account or request changed. Approval is blocked.',
};
const codes = new Set([
  ...Object.keys(selectionMessages),
  'invalid_data', 'missing_or_invalid_privy_app_id', 'missing_or_invalid_token',
  'must_be_authenticated', 'invalid_credentials', 'missing_or_invalid_mfa',
  'embedded_wallet_already_exists', 'embedded_wallet_not_found', 'embedded_wallet_create_error',
  'unknown_embedded_wallet_error', 'max_accounts_reached', 'client_request_timeout',
  'too_many_requests', 'not_supported', 'unable_to_sign', 'invalid_message',
  'exited_auth_flow', 'exited_update_flow', 'policy_violation',
  'no_valid_user_session_keys', 'user_session_keys_expired',
  'privy_agent_wallet_not_connected', 'privy_agent_wallet_metadata_missing',
  'privy_primary_wallet_unavailable', 'privy_required_wallet_unavailable',
]);

export function approvalFailure(stage, error) {
  const candidates = [error?.privyErrorCode, error?.code, error?.cause?.privyErrorCode, error?.cause?.code];
  const code = candidates.find(value => codes.has(value)) || (candidates.includes(4001) ? 'user_rejected' : 'unknown');
  const status = [error?.status, error?.response?.status].find(value => Number.isInteger(value) && value >= 400 && value <= 599);
  return { stage: Object.hasOwn(stages, stage) ? stage : 'approval', code, ...(status ? { status } : {}) };
}

export function approvalFailureMessage(failure) {
  if (failure?.stage === 'select_wallet' && Object.hasOwn(selectionMessages, failure?.code)) return selectionMessages[failure.code];
  return "This approval hasn't been confirmed.";
}

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => record(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const address = value => typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value) && !/^0x0{40}$/i.test(value);
const uint256 = value => (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && value.length <= 78
  || typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
  && BigInt(value) < (1n << 256n);
const transferFields = [['from', 'address'], ['to', 'address'], ['value', 'uint256'], ['validAfter', 'uint256'], ['validBefore', 'uint256'], ['nonce', 'bytes32']];
const domainFields = [['name', 'string'], ['version', 'string'], ['chainId', 'uint256'], ['verifyingContract', 'address']];
const matchesFields = (actual, expected) => Array.isArray(actual) && actual.length === expected.length
  && expected.every(([name, type], index) => exactKeys(actual[index], ['name', 'type']) && actual[index].name === name && actual[index].type === type);



export function approvalActionLabel(params) {
  if (params?.walletConnection) return 'Connect';
  if (['card_details', 'card_pin', 'read_session'].includes(params?.approvalType)) return 'Show details';
  if (params?.privyAgentSignerId) return 'Create wallet';
  if (params?.approvalType === 'payment_agent_setup') return 'Approve actions';
  const data = params?.signTypedData;
  if (!exactKeys(data, ['domain', 'types', 'primaryType', 'message']) || data.primaryType !== 'TransferWithAuthorization') return 'Approve actions';
  const { domain, types, message } = data;
  if (!exactKeys(domain, ['name', 'version', 'chainId', 'verifyingContract']) || domain.name !== 'USD Coin' || domain.version !== '2'
    || ![8453, '8453'].includes(domain.chainId) || typeof domain.verifyingContract !== 'string'
    || domain.verifyingContract.toLowerCase() !== '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'
    || !(exactKeys(types, ['TransferWithAuthorization']) || exactKeys(types, ['EIP712Domain', 'TransferWithAuthorization']))
    || !matchesFields(types.TransferWithAuthorization, transferFields)
    || (Object.hasOwn(types, 'EIP712Domain') && !matchesFields(types.EIP712Domain, domainFields))
    || !exactKeys(message, transferFields.map(([name]) => name)) || !address(message.from) || !address(message.to)
    || (params.expectedAddress && message.from.toLowerCase() !== params.expectedAddress.toLowerCase())
    || !uint256(message.value) || BigInt(message.value) === 0n || !uint256(message.validAfter) || !uint256(message.validBefore)
    || BigInt(message.validBefore) <= BigInt(message.validAfter) || typeof message.nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(message.nonce)) return 'Approve actions';
  const units = BigInt(message.value);
  const fraction = (units % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '');
  const amount = `${units / 1_000_000n}${fraction ? `.${fraction}` : ''}`;
  if (params.consentText) {
    
    
    const consent = typeof params.consentText === 'string' && params.consentText.match(/^Authorize a ([0-9]+(?:\.[0-9]+)?) USDC payment to (0x[0-9a-fA-F]{40}) on Base \(payment [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\)\. The merchant settles gasless via EIP-3009; this signature cannot move any other amount or payee\.$/);
    if (!consent || consent[1] !== amount || consent[2].toLowerCase() !== message.to.toLowerCase()) return 'Approve actions';
  }
  return `Pay ${amount} USDC`;
}


export function approvalDisplayMessage(message) {
  const spoken = String(message).split('\n').filter((line) => !/^(Origin|Nonce|Expires): /.test(line)).join('\n').trim();
  if (spoken === 'Nuri Wirex CLI PoC\nAction: create user-owned Privy Agent EOA') return 'Create a payment wallet you own.';
  if (spoken === 'Nuri Wirex CLI PoC\nAction: connect Privy owner'
    || spoken === 'Nuri Wirex CLI PoC\nChain: Base Sepolia (84532)\nAction: connect Privy owner') return 'Connect your wallet.';
  return spoken.replace(/^Nuri Wirex:\s*/, '').replace(/ at [0-9]+$/, '');
}
