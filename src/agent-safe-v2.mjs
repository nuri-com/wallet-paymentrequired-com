// 2-of-4 Counterfactual Base Agent Safe (`nuri-agent-safe-v1` on Base 8453).
//
// Owners: [mainEoa, passkeySignerAddress, agentEoa, cosignerEoa], threshold = 2.
// Normal agent payments use [agentEoa + cosignerEoa] via loopback co-signing.
// Recovery works vendor-independently via [mainEoa + passkeySignerAddress] or
// [mainEoa + agentEoa] (re-derived from Passkey PRF).
//
// Lazy counterfactual deployment is relayed on first spend by the operator funder
// key (`AGENT_KERNEL_FUNDER_KEY_FILE` / `/run/agent-kernel-funder.key`) via
// `SafeProxyFactory.createProxyWithNonce(SAFE_L2_SINGLETON, initializer, saltNonce)`.
import { readFileSync } from "node:fs";
import { sha256 } from "@noble/hashes/sha256";
import {
  concatHex,
  createPublicClient,
  createWalletClient,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  hashTypedData,
  http,
  keccak256,
  maxUint256,
  padHex,
  parseAbi,
  toBytes,
  toHex,
} from "viem";
import { base, tempo, tempoModerato } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { sendTransactionSync } from "viem/actions";
import { Account as TempoAccount } from "viem/tempo";

export const AGENT_SAFE_VERSION = "nuri-agent-safe-v1";
export const BASE_CHAIN_ID = 8453;
// Tempo (MPP native chain, no gas coin: fees are paid in the token itself).
// The same Gnosis Safe singleton + proxy factory live at the same addresses on
// both Tempo chains, so the counterfactual Safe keeps its address there too.
export const TEMPO_CHAIN_IDS = [4217, 42431];
export const BASE_USDC_ADDRESS = getAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
export const PERMIT2_ADDRESS = getAddress("0x000000000022D473030F116dDEE9F6B43aC78BA3");

export const SAFE_L2_SINGLETON = getAddress("0xEdd160fEBBD92E350D4D398fb636302fccd67C7e");
export const SAFE_PROXY_FACTORY = getAddress("0x14F2982D601c9458F93bd70B218933A6f8165e7b");
export const SAFE_FALLBACK_HANDLER = getAddress("0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4");
export const MULTISEND_CALL_ONLY = getAddress("0xA83c336B20401Af773B6219BA5027174338D1836");
export const SAFE_WEBAUTHN_SIGNER_FACTORY = getAddress("0x1d31F259eE307358a26dFb23EB365939E8641195");
export const SAFE_WEBAUTHN_SIGNER_SINGLETON = getAddress("0x4e27b51350e6c2083ee19011120f50dafec5ca50");
export const DAIMO_P256_VERIFIER = getAddress("0xc2b78104907F722DABAc4C69f826a522B2754De4");
export const DEFAULT_P256_VERIFIERS = (0x100n << 160n) | BigInt(DAIMO_P256_VERIFIER);

export const SAFE_PROXY_CREATION_CODE =
  "0x608060405234801561001057600080fd5b506040516101b63803806101b68339818101604052602081101561003357600080fd5b8101908080519060200190929190505050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156100ca576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001806101946022913960400191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050607b806101196000396000f3fe608060405260005463a619486e60003560e01c14156024578060601b606c5260206060f35b3660008037600080366000845af43d6000803e806040573d6000fd5b3d6000f3fea2646970667358221220e61834ebd2d8cd909d362bf67c47ef58fd665df38e6dd036ce65611101d072e964736f6c63430007060033496e76616c69642073696e676c65746f6e20616464726573732070726f7669646564";

export const SAFE_WEBAUTHN_PROXY_INIT_CODE =
  "0x610100346100ad57601f6101b538819003918201601f19168301916001600160401b038311848410176100b2578084926080946040528339810103126100ad578051906001600160a01b03821682036100ad5760208101516040820151606090920151926001600160b01b03841684036100ad5760805260a05260c05260e05260405160ec90816100c98239608051816082015260a05181604d015260c051816027015260e0518160010152f35b600080fd5b634e487b7160e01b600052604160045260246000fdfe7f000000000000000000000000000000000000000000000000000000000000000060b63601527f000000000000000000000000000000000000000000000000000000000000000060a03601527f000000000000000000000000000000000000000000000000000000000000000036608001523660006080376000806056360160807f00000000000000000000000000000000000000000000000000000000000000005af43d600060803e60b1573d6080fd5b3d6080f3fea26469706673582212201660515548d15702d720bbc046b457ca85e941a4559ab9f9518488e4c82e5ee964736f6c634300081a0033";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const SPKI_PREFIX_HEX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

const SAFE_SETUP_ABI = parseAbi([
  "function setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)",
]);

const SAFE_FACTORY_ABI = parseAbi([
  "function createProxyWithNonce(address _singleton, bytes initializer, uint256 saltNonce) returns (address proxy)",
]);

const SAFE_EXEC_ABI = parseAbi([
  "function nonce() view returns (uint256)",
  "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool success)",
]);

const ERC20_ABI = parseAbi([
  "function balanceOf(address owner) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);

const SAFE_TX_TYPES = {
  SafeTx: [
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "data", type: "bytes" },
    { name: "operation", type: "uint8" },
    { name: "safeTxGas", type: "uint256" },
    { name: "baseGas", type: "uint256" },
    { name: "gasPrice", type: "uint256" },
    { name: "gasToken", type: "address" },
    { name: "refundReceiver", type: "address" },
    { name: "nonce", type: "uint256" },
  ],
};

const SAFE_MESSAGE_TYPES = {
  SafeMessage: [{ name: "message", type: "bytes" }],
};

function extractUncompressedP256(bytes, depth = 0) {
  if (bytes.length === 65 && bytes[0] === 0x04) return bytes;
  if (bytes.length === 64) return Buffer.concat([Buffer.from([0x04]), bytes]);
  const hex = bytes.toString("hex").toLowerCase();
  if (hex.startsWith(SPKI_PREFIX_HEX)) {
    const offset = SPKI_PREFIX_HEX.length / 2;
    const key = bytes.subarray(offset, offset + 65);
    if (key.length === 65 && key[0] === 0x04) return key;
  }
  for (let i = 0; i <= bytes.length - 68; i += 1) {
    if (bytes[i] === 0x03 && bytes[i + 1] === 0x42 && bytes[i + 2] === 0x00 && bytes[i + 3] === 0x04) {
      return bytes.subarray(i + 3, i + 68);
    }
  }
  let x = null;
  let y = null;
  for (let i = 0; i <= bytes.length - 35; i += 1) {
    const label = bytes[i];
    if ((label === 0x21 || label === 0x22) && bytes[i + 1] === 0x58 && bytes[i + 2] === 0x20) {
      const value = bytes.subarray(i + 3, i + 35);
      if (label === 0x21) x = value;
      else y = value;
      if (x && y) return Buffer.concat([Buffer.from([0x04]), x, y]);
    }
  }
  if (depth < 1) {
    const text = new TextDecoder().decode(bytes).trim();
    if (text.startsWith("{") && text.endsWith("}")) {
      const jwk = JSON.parse(text);
      const jx = Buffer.from(String(jwk?.x || ""), "base64url");
      const jy = Buffer.from(String(jwk?.y || ""), "base64url");
      if (jx.length === 32 && jy.length === 32) return Buffer.concat([Buffer.from([0x04]), jx, jy]);
    }
    if (/^(0x)?[0-9a-fA-F]+$/.test(text)) {
      return extractUncompressedP256(Buffer.from(text.replace(/^0x/, ""), "hex"), depth + 1);
    }
    if (/^[A-Za-z0-9+/_=-]+$/.test(text)) {
      return extractUncompressedP256(Buffer.from(text, "base64url"), depth + 1);
    }
  }
  throw new Error("invalid_credential_pubkey");
}

export function predictPasskeySignerAddress(credPubkeyB64u, verifiers = DEFAULT_P256_VERIFIERS) {
  const bytes = Buffer.from(String(credPubkeyB64u || "").trim(), "base64url");
  const uncompressed = extractUncompressedP256(bytes);
  const x = BigInt(`0x${uncompressed.subarray(1, 33).toString("hex")}`);
  const y = BigInt(`0x${uncompressed.subarray(33, 65).toString("hex")}`);
  const args = encodeAbiParameters(
    [{ type: "address" }, { type: "uint256" }, { type: "uint256" }, { type: "uint176" }],
    [SAFE_WEBAUTHN_SIGNER_SINGLETON, x, y, verifiers],
  );
  const initHash = keccak256(concatHex([SAFE_WEBAUTHN_PROXY_INIT_CODE, args]));
  const digest = keccak256(concatHex(["0xff", SAFE_WEBAUTHN_SIGNER_FACTORY, padHex("0x00", { size: 32 }), initHash]));
  return { address: getAddress(`0x${digest.slice(-40)}`), x, y, verifiers };
}

export function deriveFallbackSecondRecoveryAddress({ mainEoa, credIdB64u }) {
  const digest = sha256(new TextEncoder().encode(`nuri-agent-legacy-owner2:${mainEoa.toLowerCase()}:${credIdB64u}`));
  return getAddress(`0x${Buffer.from(digest).subarray(0, 20).toString("hex")}`);
}

export function computeAgentSafeSaltNonce({ credIdB64u, index = 0 }) {
  return BigInt(keccak256(toBytes(`${AGENT_SAFE_VERSION}:${credIdB64u}:${Number(index)}`)));
}

export function predictAgentSafeAddress({
  mainEoa,
  passkeySignerAddress,
  agentEoa,
  cosignerEoa,
  credIdB64u,
  index = 0,
}) {
  const owners = [
    getAddress(mainEoa),
    getAddress(passkeySignerAddress),
    getAddress(agentEoa),
    getAddress(cosignerEoa),
  ];
  const initializer = encodeFunctionData({
    abi: SAFE_SETUP_ABI,
    functionName: "setup",
    args: [owners, 2n, ZERO_ADDRESS, "0x", SAFE_FALLBACK_HANDLER, ZERO_ADDRESS, 0n, ZERO_ADDRESS],
  });
  const saltNonce = computeAgentSafeSaltNonce({ credIdB64u, index });
  const salt = keccak256(concatHex([keccak256(initializer), padHex(toHex(saltNonce), { size: 32 })]));
  const deploymentData = concatHex([SAFE_PROXY_CREATION_CODE, padHex(SAFE_L2_SINGLETON, { size: 32 })]);
  const digest = keccak256(concatHex(["0xff", SAFE_PROXY_FACTORY, salt, keccak256(deploymentData)]));
  return {
    safeAddress: getAddress(`0x${digest.slice(-40)}`),
    owners,
    threshold: 2,
    initializer,
    saltNonce,
  };
}

export function computeSafeTxHash({ chainId = BASE_CHAIN_ID, safeAddress, transaction }) {
  return hashTypedData({
    domain: { chainId: Number(chainId), verifyingContract: getAddress(safeAddress) },
    types: SAFE_TX_TYPES,
    primaryType: "SafeTx",
    message: {
      to: getAddress(transaction.to),
      value: BigInt(transaction.value ?? 0),
      data: transaction.data || "0x",
      operation: Number(transaction.operation ?? 0),
      safeTxGas: BigInt(transaction.safeTxGas ?? 0),
      baseGas: BigInt(transaction.baseGas ?? 0),
      gasPrice: BigInt(transaction.gasPrice ?? 0),
      gasToken: transaction.gasToken ? getAddress(transaction.gasToken) : ZERO_ADDRESS,
      refundReceiver: transaction.refundReceiver ? getAddress(transaction.refundReceiver) : ZERO_ADDRESS,
      nonce: BigInt(transaction.nonce ?? 0),
    },
  });
}

export function computeSafeMessageHash({ chainId = BASE_CHAIN_ID, safeAddress, innerDigest }) {
  const encodedMessage = encodeAbiParameters([{ type: "bytes32" }], [innerDigest]);
  return hashTypedData({
    domain: { chainId: Number(chainId), verifyingContract: getAddress(safeAddress) },
    types: SAFE_MESSAGE_TYPES,
    primaryType: "SafeMessage",
    message: { message: encodedMessage },
  });
}

function loadRelayerPrivateKey(env = process.env) {
  if (typeof env.AGENT_SAFE_RELAYER_PRIVATE_KEY === "string" && env.AGENT_SAFE_RELAYER_PRIVATE_KEY.trim()) {
    const raw = env.AGENT_SAFE_RELAYER_PRIVATE_KEY.trim();
    return raw.startsWith("0x") ? raw : `0x${raw}`;
  }
  const keyFile = env.AGENT_KERNEL_FUNDER_KEY_FILE || "/run/agent-kernel-funder.key";
  try {
    const raw = readFileSync(keyFile, "utf8").trim();
    if (/^(0x)?[0-9a-fA-F]{64}$/.test(raw)) return raw.startsWith("0x") ? raw : `0x${raw}`;
  } catch {
    // Offline or unset relayer key.
  }
  return null;
}

export function createAgentSafeRuntime({
  env = process.env,
  cosignerClient,
  publicClient = null,
  walletClient = null,
} = {}) {
  const rpcUrl = env.AGENT_KERNEL_RPC_URL || env.AA_PUBLIC_RPC_URL || "https://mainnet.base.org";
  const pub = publicClient || createPublicClient({ chain: base, transport: http(rpcUrl) });

  const TEMPO_CHAINS = new Map([[4217, tempo], [42431, tempoModerato]]);
  const tempoClients = new Map();
  function chainFor(chainId) {
    const id = Number(chainId);
    if (id === BASE_CHAIN_ID) return base;
    const chain = TEMPO_CHAINS.get(id);
    if (!chain) throw new Error("chain_unsupported_by_safe_runtime");
    return chain;
  }
  // Public client for Base or a Tempo chain (reads are free on both).
  function clientForChain(chainId) {
    const id = Number(chainId);
    if (id === BASE_CHAIN_ID) return pub;
    if (!tempoClients.has(id)) {
      const chain = chainFor(id);
      const url = id === 4217
        ? env.TEMPO_RPC_URL || chain.rpcUrls.default.http[0]
        : env.TEMPO_TESTNET_RPC_URL || chain.rpcUrls.default.http[0];
      tempoClients.set(id, createPublicClient({ chain, transport: http(url) }));
    }
    return tempoClients.get(id);
  }
  function isTempoChain(chainId) {
    return TEMPO_CHAIN_IDS.includes(Number(chainId));
  }

  let relayerQueue = Promise.resolve();
  function getRelayerClient() {
    if (walletClient) return walletClient;
    const pk = loadRelayerPrivateKey(env);
    if (!pk) throw Object.assign(new Error("operator_balance_insufficient"), { runtimeCode: "operator_balance_insufficient" });
    const account = privateKeyToAccount(pk);
    return createWalletClient({ account, chain: base, transport: http(rpcUrl) });
  }
  // The same relayer EOA on a Tempo chain: fees are paid in a TIP-20 fee token.
  function getTempoRelayerAccount() {
    const pk = loadRelayerPrivateKey(env);
    if (!pk) throw Object.assign(new Error("operator_balance_insufficient"), { runtimeCode: "operator_balance_insufficient" });
    return TempoAccount.fromSecp256k1(pk.startsWith("0x") ? pk : `0x${pk}`);
  }

  function withRelayerLock(fn) {
    const next = relayerQueue.then(fn, fn);
    relayerQueue = next.catch(() => {});
    return next;
  }

  async function isSafeDeployed(safeAddress, chainId = BASE_CHAIN_ID) {
    const code = await clientForChain(chainId).getCode({ address: getAddress(safeAddress) });
    return Boolean(code && code !== "0x" && code.length > 2);
  }

  async function ensureSafeDeployed(walletRecord, chainId = BASE_CHAIN_ID, feeToken = BASE_USDC_ADDRESS) {
    const safeAddress = getAddress(walletRecord.safe_address);
    if (await isSafeDeployed(safeAddress, chainId)) return { deployed: true, txHash: null };
    const predicted = predictAgentSafeAddress({
      mainEoa: walletRecord.main_eoa,
      passkeySignerAddress: walletRecord.passkey_signer_address,
      agentEoa: walletRecord.agent_eoa,
      cosignerEoa: walletRecord.cosigner_eoa,
      credIdB64u: walletRecord.cred_id_b64u,
      index: walletRecord.slot_index,
    });
    if (predicted.safeAddress !== safeAddress) {
      throw new Error("safe_prediction_mismatch");
    }
    return await withRelayerLock(async () => {
      if (await isSafeDeployed(safeAddress, chainId)) return { deployed: true, txHash: null };
      if (isTempoChain(chainId)) {
        const result = await sendTransactionSync(clientForChain(chainId), {
          account: getTempoRelayerAccount(),
          to: SAFE_PROXY_FACTORY,
          gas: 1_500_000n,
          feeToken: getAddress(feeToken || BASE_USDC_ADDRESS),
          data: encodeFunctionData({
            abi: SAFE_FACTORY_ABI,
            functionName: "createProxyWithNonce",
            args: [SAFE_L2_SINGLETON, predicted.initializer, predicted.saltNonce],
          }),
        });
        if (result.status !== "success") throw new Error("operator_transaction_reverted");
        return { deployed: true, txHash: result.transactionHash || result.hash || null };
      }
      const relayer = getRelayerClient();
      const hash = await relayer.writeContract({
        address: SAFE_PROXY_FACTORY,
        abi: SAFE_FACTORY_ABI,
        functionName: "createProxyWithNonce",
        args: [SAFE_L2_SINGLETON, predicted.initializer, predicted.saltNonce],
      });
      const receipt = await pub.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error("operator_transaction_reverted");
      return { deployed: true, txHash: hash };
    });
  }

  async function readUsdcBalanceUnits(safeAddress) {
    const bal = await pub.readContract({
      address: BASE_USDC_ADDRESS,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [getAddress(safeAddress)],
    });
    return BigInt(bal);
  }

  async function readTokenBalanceUnits(safeAddress, token = BASE_USDC_ADDRESS, chainId = BASE_CHAIN_ID) {
    const bal = await clientForChain(chainId).readContract({
      address: getAddress(token),
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [getAddress(safeAddress)],
    });
    return BigInt(bal);
  }

  async function signSafeTypedData({ walletRecord, agentEthPrivateKeyHex, typedData, opId, signal }) {
    await ensureSafeDeployed(walletRecord);
    const agentAccount = privateKeyToAccount(
      agentEthPrivateKeyHex.startsWith("0x") ? agentEthPrivateKeyHex : `0x${agentEthPrivateKeyHex}`,
    );
    const innerDigest = hashTypedData(typedData);
    const safeMessageHash = computeSafeMessageHash({
      chainId: BASE_CHAIN_ID,
      safeAddress: walletRecord.safe_address,
      innerDigest,
    });
    const agentSignature = await agentAccount.sign({ hash: safeMessageHash });
    const coSigned = await cosignerClient.signTypedData({
      cred_id_b64u: walletRecord.cred_id_b64u,
      index: walletRecord.slot_index,
      safe_address: walletRecord.safe_address,
      typed_data: typedData,
      agent_signature: agentSignature,
      op_id: opId,
    }, { signal });
    return coSigned.combined_signatures;
  }

  async function execSafeTokenCall({
    walletRecord,
    agentEthPrivateKeyHex,
    data,
    opId,
    signal,
    chainId = BASE_CHAIN_ID,
    token = BASE_USDC_ADDRESS,
  }) {
    const id = Number(chainId);
    await ensureSafeDeployed(walletRecord, id, token);
    const safeAddress = getAddress(walletRecord.safe_address);
    const client = clientForChain(id);
    const nonce = await client.readContract({
      address: safeAddress,
      abi: SAFE_EXEC_ABI,
      functionName: "nonce",
    });
    const transaction = {
      to: getAddress(token),
      value: 0n,
      data,
      operation: 0,
      safeTxGas: 0n,
      baseGas: 0n,
      gasPrice: 0n,
      gasToken: ZERO_ADDRESS,
      refundReceiver: ZERO_ADDRESS,
      nonce: BigInt(nonce),
    };
    const safeTxHash = computeSafeTxHash({ chainId: id, safeAddress, transaction });
    const agentAccount = privateKeyToAccount(
      agentEthPrivateKeyHex.startsWith("0x") ? agentEthPrivateKeyHex : `0x${agentEthPrivateKeyHex}`,
    );
    const agentSignature = await agentAccount.sign({ hash: safeTxHash });
    const coSigned = await cosignerClient.signSafeTx({
      cred_id_b64u: walletRecord.cred_id_b64u,
      index: walletRecord.slot_index,
      chain_id: id,
      safe_address: safeAddress,
      transaction,
      agent_signature: agentSignature,
      op_id: opId,
    }, { signal });

    return await withRelayerLock(async () => {
      const execData = encodeFunctionData({
        abi: SAFE_EXEC_ABI,
        functionName: "execTransaction",
        args: [
          getAddress(token),
          0n,
          data,
          0,
          0n,
          0n,
          0n,
          ZERO_ADDRESS,
          ZERO_ADDRESS,
          coSigned.combined_signatures,
        ],
      });
      if (isTempoChain(id)) {
        const result = await sendTransactionSync(client, {
          account: getTempoRelayerAccount(),
          to: safeAddress,
          gas: 300_000n,
          feeToken: getAddress(token),
          data: execData,
        });
        if (result.status !== "success") throw new Error("operator_transaction_reverted");
        return { txHash: result.transactionHash || result.hash || null, safeTxHash };
      }
      const relayer = getRelayerClient();
      const hash = await relayer.writeContract({
        address: safeAddress,
        abi: SAFE_EXEC_ABI,
        functionName: "execTransaction",
        args: [
          getAddress(token),
          0n,
          data,
          0,
          0n,
          0n,
          0n,
          ZERO_ADDRESS,
          ZERO_ADDRESS,
          coSigned.combined_signatures,
        ],
      });
      const receipt = await pub.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error("operator_transaction_reverted");
      return { txHash: hash, safeTxHash };
    });
  }

  async function execSafeUsdcCall({ walletRecord, agentEthPrivateKeyHex, data, opId, signal }) {
    return await execSafeTokenCall({ walletRecord, agentEthPrivateKeyHex, data, opId, signal });
  }

  async function ensurePermit2Allowance({ walletRecord, agentEthPrivateKeyHex, requiredUnits, opId, signal }) {
    const allowance = await pub.readContract({
      address: BASE_USDC_ADDRESS,
      abi: ERC20_ABI,
      functionName: "allowance",
      args: [getAddress(walletRecord.safe_address), PERMIT2_ADDRESS],
    });
    if (BigInt(allowance) >= BigInt(requiredUnits)) return null;
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: "approve",
      args: [PERMIT2_ADDRESS, maxUint256],
    });
    return await execSafeUsdcCall({
      walletRecord,
      agentEthPrivateKeyHex,
      data,
      opId: `${opId}:permit2-approve`,
      signal,
    });
  }

  async function transferToken({ walletRecord, agentEthPrivateKeyHex, to, amountUnits, opId, signal, chainId = BASE_CHAIN_ID, token = BASE_USDC_ADDRESS }) {
    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: "transfer",
      args: [getAddress(to), BigInt(amountUnits)],
    });
    return await execSafeTokenCall({
      walletRecord,
      agentEthPrivateKeyHex,
      data,
      opId,
      signal,
      chainId: Number(chainId),
      token: getAddress(token),
    });
  }

  async function transferUsdc({ walletRecord, agentEthPrivateKeyHex, to, amountUnits, opId, signal }) {
    return await transferToken({ walletRecord, agentEthPrivateKeyHex, to, amountUnits, opId, signal });
  }

  return {
    publicClient: pub,
    isSafeDeployed,
    ensureSafeDeployed,
    readUsdcBalanceUnits,
    readTokenBalanceUnits,
    signSafeTypedData,
    ensurePermit2Allowance,
    transferUsdc,
    transferToken,
    execSafeTokenCall,
    clientForChain,
    chainFor,
    isTempoChain,
  };
}
