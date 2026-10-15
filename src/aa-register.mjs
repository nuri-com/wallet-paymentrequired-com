













import { createPublicClient, http, encodeFunctionData, encodeAbiParameters, concatHex, keccak256, toHex, zeroAddress, pad, parseAbi } from "viem";
import { readFileSync } from "node:fs";
import { base, baseSepolia } from "viem/chains";
import { toAccount, privateKeyToAccount } from "viem/accounts";
import { getUserOperationHash } from "viem/account-abstraction";
import { signerToEcdsaValidator } from "@zerodev/ecdsa-validator";
import { createKernelAccount, createKernelAccountClient, createZeroDevPaymasterClient, KernelV3_1AccountAbi } from "@zerodev/sdk";
import { getEntryPoint, KERNEL_V3_1, VALIDATOR_TYPE } from "@zerodev/sdk/constants";
import { toPermissionValidator } from "@zerodev/permissions";
import { toSudoPolicy } from "@zerodev/permissions/policies";
import { toECDSASigner } from "@zerodev/permissions/signers";


function getValidatorId(validator) {
  return concatHex([VALIDATOR_TYPE[validator.validatorType], pad(validator.getIdentifier(), { size: 20, dir: "right" })]);
}


export const PAYMASTER_VERIFICATION_GAS_LIMIT = 300_000n;
export const PAYMASTER_POST_OP_GAS_LIMIT = 300_000n;






export const PRE_VERIFICATION_GAS_LIMIT = 150_000n;


const PaymasterCapsAbi = parseAbi([
  "function maxCallGasCap() view returns (uint256)",
  "function maxVerificationGasCap() view returns (uint256)",
  "function maxPreVerificationGasCap() view returns (uint256)",
]);
const sponsorCaps = new Map();




const VerifyingPaymasterConfigAbi = parseAbi([
  "function entryPoint() view returns (address)",
  "function verifyingSigner() view returns (address)",
  "function paused() view returns (bool)",
  "function maxFeePerGasCap() view returns (uint256)",
  "function maxVerificationGasCap() view returns (uint256)",
  "function maxCallGasCap() view returns (uint256)",
  "function maxPreVerificationGasCap() view returns (uint256)",
  "function maxPaymasterVerificationGasCap() view returns (uint256)",
  "function maxPostOpGasCap() view returns (uint256)",
  "function maxCostCap() view returns (uint256)",
]);
const sponsorAttestations = new Map();




const MIN_PAYMASTER_SIGNATURE_TTL_SECONDS = 65 * 60;
const MAX_PAYMASTER_SIGNATURE_TTL_SECONDS = 2 * 60 * 60;


const CONTRACT_REGISTRY = "0xC801a0f38E20500B5840c4927553b3409890bc3c";
const PARTNER_ID = "0x00000000000000000000000000000027"; 
const ENTRY_POINT = getEntryPoint("0.7");

const ContractRegistryAbi = [{
  inputs: [{ name: "name", type: "string" }],
  name: "contractByName",
  outputs: [{ name: "proxy", type: "address" }],
  stateMutability: "view",
  type: "function",
}];
const AccountsAbi = [{
  inputs: [{ name: "parentEntity", type: "bytes16" }],
  name: "createUserAccountWithWallet",
  outputs: [],
  stateMutability: "nonpayable",
  type: "function",
}];








export const PAYMASTER_SIGNER_KEY_PATH = "/run/paymaster-signer.key";

export function readPaymasterSignerKey(env = process.env) {
  const path = env.AA_PAYMASTER_SIGNER_KEY_PATH || PAYMASTER_SIGNER_KEY_PATH;
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    return "";
  }
}

export function readAaConfig(env = process.env) {
  
  
  const chainId = Number(env.AA_CHAIN_ID || env.WIREX_CHAIN_ID || 84532);
  return {
    chainId,
    
    publicRpcUrl: env.AA_PUBLIC_RPC_URL || (chainId === 8453 ? "https://mainnet.base.org" : "https://sepolia.base.org"),
    
    bundlerUrl: env.AA_BUNDLER_RPC_URL || "",
    
    paymasterAddress: env.AA_PAYMASTER_ADDRESS || "",
    
    
    paymasterRpcUrl: env.AA_PAYMASTER_RPC_URL || "",
    
    
    
    
    paymasterKind: env.AA_PAYMASTER_KIND || "open",
    
    
    paymasterSignerPrivateKey: readPaymasterSignerKey(env),
    paymasterSignatureTtlSeconds: Number(env.AA_PAYMASTER_SIGNATURE_TTL_SECONDS || MIN_PAYMASTER_SIGNATURE_TTL_SECONDS),
    registry: env.AA_CONTRACT_REGISTRY || CONTRACT_REGISTRY,
    partnerId: env.AA_PARTNER_ID || PARTNER_ID,
    
    
    registrationFromBlock: /^\d+$/.test(String(env.SUPPORT_REGISTRATIONS_FROM_BLOCK || ""))
      ? BigInt(env.SUPPORT_REGISTRATIONS_FROM_BLOCK)
      : 0n,
  };
}

export function assertAaConfigured(config) {
  if (!config.bundlerUrl) throw new Error("aa_bundler_rpc_url_not_configured (set AA_BUNDLER_RPC_URL)");
  
  
  if (!config.paymasterRpcUrl && !/^0x[0-9a-fA-F]{40}$/.test(config.paymasterAddress)) {
    throw new Error("aa_paymaster_not_configured (set AA_PAYMASTER_RPC_URL for a managed paymaster, or AA_PAYMASTER_ADDRESS for a self-host one)");
  }
  
  
  const kind = config.paymasterKind ?? "open";
  if (!["open", "verifying"].includes(kind)) throw new Error("aa_paymaster_kind_invalid");
  
  
  if (kind === "verifying") {
    if (config.paymasterRpcUrl) throw new Error("aa_verifying_paymaster_requires_static_address");
    if (config.paymasterAddress.toLowerCase() === zeroAddress) throw new Error("aa_paymaster_address_invalid");
    if (!/^0x[0-9a-fA-F]{64}$/.test(config.paymasterSignerPrivateKey)) throw new Error("aa_paymaster_signer_private_key_invalid");
    try {
      privateKeyToAccount(config.paymasterSignerPrivateKey);
    } catch {
      throw new Error("aa_paymaster_signer_private_key_invalid");
    }
    if (!Number.isInteger(config.paymasterSignatureTtlSeconds)
      || config.paymasterSignatureTtlSeconds < MIN_PAYMASTER_SIGNATURE_TTL_SECONDS
      || config.paymasterSignatureTtlSeconds > MAX_PAYMASTER_SIGNATURE_TTL_SECONDS) {
      throw new Error("aa_paymaster_signature_ttl_invalid");
    }
  }
}



function deferredSigner(address) {
  const fail = async () => { throw new Error("deferred_signer_no_inline_signing"); };
  return toAccount({ address, signMessage: fail, signTransaction: fail, signTypedData: fail });
}

async function buildAccount(eoaAddress, config) {
  const chain = config.chainId === 8453 ? base : baseSepolia;
  const publicClient = createPublicClient({ chain, transport: http(config.publicRpcUrl) });
  const validator = await signerToEcdsaValidator(publicClient, {
    signer: deferredSigner(eoaAddress),
    entryPoint: ENTRY_POINT,
    kernelVersion: KERNEL_V3_1,
  });
  const account = await createKernelAccount(publicClient, {
    entryPoint: ENTRY_POINT,
    kernelVersion: KERNEL_V3_1,
    plugins: { sudo: validator },
  });
  return { chain, publicClient, account };
}




function readSponsorCaps(publicClient, sponsor) {
  if (!sponsorCaps.has(sponsor)) {
    sponsorCaps.set(sponsor, (async () => {
      try {
        const [callGasLimit, verificationGasLimit, preVerificationGas] = await Promise.all([
          publicClient.readContract({ address: sponsor, abi: PaymasterCapsAbi, functionName: "maxCallGasCap" }),
          publicClient.readContract({ address: sponsor, abi: PaymasterCapsAbi, functionName: "maxVerificationGasCap" }),
          preVerificationGasCap(publicClient, sponsor),
        ]);
        return {
          callGasLimit: BigInt(callGasLimit),
          verificationGasLimit: BigInt(verificationGasLimit),
          preVerificationGas: BigInt(preVerificationGas),
        };
      } catch {
        return null;
      }
    })());
  }
  return sponsorCaps.get(sponsor);
}



async function preVerificationGasCap(publicClient, sponsor) {
  try {
    const cap = BigInt(await publicClient.readContract({ address: sponsor, abi: PaymasterCapsAbi, functionName: "maxPreVerificationGasCap" }));
    return cap < PRE_VERIFICATION_GAS_LIMIT ? cap : PRE_VERIFICATION_GAS_LIMIT;
  } catch {
    return PRE_VERIFICATION_GAS_LIMIT;
  }
}





function attestVerifyingPaymaster(publicClient, config) {
  const signerAddress = privateKeyToAccount(config.paymasterSignerPrivateKey).address;
  const cacheKey = `${config.paymasterAddress.toLowerCase()}:${signerAddress.toLowerCase()}`;
  if (!sponsorAttestations.has(cacheKey)) {
    const attestation = (async () => {
      const read = (functionName) => publicClient.readContract({
        address: config.paymasterAddress,
        abi: VerifyingPaymasterConfigAbi,
        functionName,
      });
      let values;
      try {
        values = await Promise.all([
          read("entryPoint"),
          read("verifyingSigner"),
          read("paused"),
          read("maxFeePerGasCap"),
          read("maxVerificationGasCap"),
          read("maxCallGasCap"),
          read("maxPreVerificationGasCap"),
          read("maxPaymasterVerificationGasCap"),
          read("maxPostOpGasCap"),
          read("maxCostCap"),
        ]);
      } catch {
        throw new Error("aa_verifying_paymaster_contract_unreadable");
      }
      const [entryPoint, signer, paused, feeCap, verificationCap, callCap, preVerificationCap, paymasterVerificationCap, postOpCap, costCap] = values;
      if (String(entryPoint).toLowerCase() !== ENTRY_POINT.address.toLowerCase()
        || String(signer).toLowerCase() !== signerAddress.toLowerCase()
        || BigInt(feeCap) <= 0n
        || BigInt(verificationCap) <= 0n
        || BigInt(callCap) <= 0n
        || BigInt(preVerificationCap) <= 0n
        || BigInt(paymasterVerificationCap) < PAYMASTER_VERIFICATION_GAS_LIMIT
        || BigInt(postOpCap) < PAYMASTER_POST_OP_GAS_LIMIT
        || BigInt(costCap) <= 0n) {
        throw new Error("aa_verifying_paymaster_contract_mismatch");
      }
      if (paused === true) throw new Error("aa_verifying_paymaster_paused");
      return {
        gas: {
          verificationGasLimit: BigInt(verificationCap),
          callGasLimit: BigInt(callCap),
          preVerificationGas: BigInt(preVerificationCap),
        },
        feeCap: BigInt(feeCap),
        costCap: BigInt(costCap),
      };
    })();
    
    
    attestation.catch(() => sponsorAttestations.delete(cacheKey));
    sponsorAttestations.set(cacheKey, attestation);
  }
  return sponsorAttestations.get(cacheKey);
}

function pack128(high, low) {
  const h = BigInt(high ?? 0n);
  const l = BigInt(low ?? 0n);
  if (h < 0n || h >= 1n << 128n || l < 0n || l >= 1n << 128n) throw new Error("aa_paymaster_gas_value_out_of_range");
  return toHex((h << 128n) | l, { size: 32 });
}








export function getAaPaymasterHash(parameters, config, validUntil, validAfter) {
  const initCode = parameters.factory ? concatHex([parameters.factory, parameters.factoryData || "0x"]) : "0x";
  const accountGasLimits = pack128(parameters.verificationGasLimit, parameters.callGasLimit);
  const paymasterGasLimits = pack128(PAYMASTER_VERIFICATION_GAS_LIMIT, PAYMASTER_POST_OP_GAS_LIMIT);
  const gasFees = pack128(parameters.maxPriorityFeePerGas, parameters.maxFeePerGas);
  return keccak256(encodeAbiParameters(
    [
      { type: "address" }, { type: "uint256" }, { type: "bytes32" }, { type: "bytes32" },
      { type: "bytes32" }, { type: "uint256" }, { type: "uint256" }, { type: "bytes32" },
      { type: "uint256" }, { type: "address" }, { type: "uint48" }, { type: "uint48" },
    ],
    [
      parameters.sender, BigInt(parameters.nonce), keccak256(initCode), keccak256(parameters.callData),
      accountGasLimits, BigInt(paymasterGasLimits), BigInt(parameters.preVerificationGas ?? 0n), gasFees,
      BigInt(config.chainId), config.paymasterAddress, validUntil, validAfter,
    ],
  ));
}





async function signedPaymasterData(parameters, config) {
  if (parameters.chainId !== config.chainId || parameters.entryPointAddress?.toLowerCase() !== ENTRY_POINT.address.toLowerCase()) {
    throw new Error("aa_paymaster_domain_mismatch");
  }
  const now = Math.floor(Date.now() / 1000);
  const validAfter = BigInt(Math.max(0, now - 5));
  const validUntil = BigInt(now + config.paymasterSignatureTtlSeconds);
  const hash = getAaPaymasterHash(parameters, config, validUntil, validAfter);
  const signature = await privateKeyToAccount(config.paymasterSignerPrivateKey).signMessage({ message: { raw: hash } });
  return concatHex([
    encodeAbiParameters([{ type: "uint48" }, { type: "uint48" }], [validUntil, validAfter]),
    signature,
  ]);
}




function fillAccountGas(parameters, limits) {
  return Object.fromEntries(Object.entries(limits).map(([name, cap]) => [name, BigInt(parameters[name] ?? 0n) || cap]));
}















export function selfHostPaymaster(publicClient, config) {
  const verifying = config.paymasterKind === "verifying";
  const sponsorLimits = async () => (verifying ? (await attestVerifyingPaymaster(publicClient, config)).gas : readSponsorCaps(publicClient, config.paymasterAddress));
  const data = async (parameters) => {
    if (verifying) {
      const { gas, feeCap, costCap } = await attestVerifyingPaymaster(publicClient, config);
      let requiredGas = PAYMASTER_VERIFICATION_GAS_LIMIT + PAYMASTER_POST_OP_GAS_LIMIT;
      for (const [name, cap] of Object.entries(gas)) {
        const value = BigInt(parameters[name] ?? 0n);
        if (value < 0n || value > cap) throw new Error(`aa_paymaster_gas_cap_exceeded:${name}`);
        requiredGas += value;
      }
      const maxFee = BigInt(parameters.maxFeePerGas ?? 0n);
      const priorityFee = BigInt(parameters.maxPriorityFeePerGas ?? 0n);
      if (maxFee < 0n || priorityFee < 0n || maxFee > feeCap || priorityFee > feeCap) {
        throw new Error("aa_paymaster_fee_cap_exceeded");
      }
      
      
      
      if (requiredGas * maxFee > costCap) throw new Error("aa_paymaster_cost_cap_exceeded");
    }
    return {
      paymaster: config.paymasterAddress,
      paymasterData: verifying ? await signedPaymasterData(parameters, config) : "0x",
      paymasterVerificationGasLimit: PAYMASTER_VERIFICATION_GAS_LIMIT,
      paymasterPostOpGasLimit: PAYMASTER_POST_OP_GAS_LIMIT,
    };
  };
  return {
    getPaymasterStubData: async (parameters) => {
      const limits = await sponsorLimits();
      if (!limits) return data(parameters);
      
      const gas = fillAccountGas(parameters, limits);
      return { ...gas, ...await data({ ...parameters, ...gas }) };
    },
    getPaymasterData: data,
  };
}




function kernelClient(account, chain, publicClient, config) {
  
  
  const paymaster = config.paymasterRpcUrl
    ? createZeroDevPaymasterClient({ chain, transport: http(config.paymasterRpcUrl) })
    : selfHostPaymaster(publicClient, config);
  return createKernelAccountClient({
    account,
    chain,
    bundlerTransport: http(config.bundlerUrl),
    client: publicClient,
    userOperation: {
      estimateFeesPerGas: async () => {
        const { maxFeePerGas, maxPriorityFeePerGas } = await publicClient.estimateFeesPerGas();
        return { maxFeePerGas, maxPriorityFeePerGas };
      },
    },
    paymaster,
  });
}


export async function deriveKernelAddress(eoaAddress, config = readAaConfig()) {
  const { account } = await buildAccount(eoaAddress, config);
  return account.address;
}


export async function readAccountRegistration(eoaAddress, config = readAaConfig()) {
  const { publicClient, account } = await buildAccount(eoaAddress, config);
  const accounts = await publicClient.readContract({ address: config.registry, abi: ContractRegistryAbi, functionName: "contractByName", args: ["Accounts"] });
  const [wallet, code] = await Promise.all([
    publicClient.readContract({
      address: accounts,
      abi: parseAbi(["function getWallet(bytes16 parentEntity, address wallet) view returns ((uint8 confirmationStatus, address owner))"]),
      functionName: "getWallet", args: [config.partnerId, account.address],
    }),
    publicClient.getCode({ address: account.address }),
  ]);
  if (wallet.confirmationStatus === 0 && wallet.owner === zeroAddress) return { registered: false, kernelAddress: account.address };
  
  
  if (wallet.confirmationStatus !== 1 || wallet.owner.toLowerCase() !== eoaAddress.toLowerCase() || !code || code === "0x") throw new Error("account_registration_not_confirmed");
  return { registered: true, kernelAddress: account.address };
}



async function applyDeploymentState(account, publicClient) {
  const code = await publicClient.getCode({ address: account.address });
  const deployed = Boolean(code && code !== "0x");
  if (deployed) account.getFactoryArgs = async () => ({ factory: undefined, factoryData: undefined });
  return deployed;
}



















export async function prepareRegistration(eoaAddress, config = readAaConfig()) {
  assertAaConfigured(config);
  const { chain, publicClient, account } = await buildAccount(eoaAddress, config);
  const deployed = await applyDeploymentState(account, publicClient);
  const accountsAddress = await publicClient.readContract({ address: config.registry, abi: ContractRegistryAbi, functionName: "contractByName", args: ["Accounts"] });
  const registerData = encodeFunctionData({ abi: AccountsAbi, functionName: "createUserAccountWithWallet", args: [config.partnerId] });

  let calls;
  if (deployed) {
    
    calls = [{ to: accountsAddress, value: 0n, data: registerData }];
  } else {
    
    
    
    const [fundsManagementAddress, executionDelayPolicyAddress] = await Promise.all([
      publicClient.readContract({ address: config.registry, abi: ContractRegistryAbi, functionName: "contractByName", args: ["FundsManagement"] }),
      publicClient.readContract({ address: config.registry, abi: ContractRegistryAbi, functionName: "contractByName", args: ["ExecutionDelayPolicy"] }),
    ]);
    const installExecutorData = encodeFunctionData({
      abi: KernelV3_1AccountAbi, functionName: "installModule",
      args: [2n, fundsManagementAddress, concatHex([zeroAddress, "0x0000000000000000000000000000000000000000000000000000000000000000"])],
    });
    const rootPolicy = toSudoPolicy({ policyAddress: executionDelayPolicyAddress });
    const executionDelaySigner = await toECDSASigner({ signer: deferredSigner(eoaAddress) });
    const executionDelayValidator = await toPermissionValidator(publicClient, {
      entryPoint: ENTRY_POINT, signer: executionDelaySigner, kernelVersion: KERNEL_V3_1, policies: [rootPolicy],
    });
    const setRootDelayData = encodeFunctionData({
      abi: KernelV3_1AccountAbi, functionName: "changeRootValidator",
      args: [getValidatorId(executionDelayValidator), zeroAddress, await executionDelayValidator.getEnableData(account.address), "0x"],
    });
    calls = [
      { to: account.address, value: 0n, data: installExecutorData },
      { to: account.address, value: 0n, data: setRootDelayData },
      { to: accountsAddress, value: 0n, data: registerData },
    ];
  }

  const callData = await account.encodeCalls(calls);
  const client = kernelClient(account, chain, publicClient, config);
  const userOp = await client.prepareUserOperation({ callData });
  const userOpHash = getUserOperationHash({
    chainId: chain.id, entryPointAddress: ENTRY_POINT.address, entryPointVersion: "0.7", userOperation: userOp,
  });
  return { kernelAddress: account.address, userOpHash, userOp, alreadyDeployed: deployed };
}


export async function submitRegistration({ eoaAddress, userOp, signature }, config = readAaConfig()) {
  const { chain, publicClient, account } = await buildAccount(eoaAddress, config);
  await applyDeploymentState(account, publicClient); 
  const client = kernelClient(account, chain, publicClient, config);
  const signed = { ...userOp, signature };
  
  const userOpHash = await client.sendUserOperation(signed);
  const receipt = await client.waitForUserOperationReceipt({ hash: userOpHash, timeout: 150_000 });
  return {
    user_op_hash: userOpHash,
    tx_hash: receipt?.receipt?.transactionHash || null,
    success: receipt?.success === true,
    kernel_address: account.address,
  };
}



export async function readRegistrationReceipt(userOpHash, config = readAaConfig(), fetchImpl = fetch) {
  assertAaConfigured(config);
  const hash = String(userOpHash || "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error("user_op_hash_invalid");
  const response = await fetchImpl(config.bundlerUrl, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getUserOperationReceipt", params: [hash] }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`aa_bundler_receipt_http_${response.status}`);
  const payload = await response.json();
  if (payload?.error) throw new Error(`aa_bundler_receipt_error:${payload.error.code ?? "unknown"}`);
  if (payload?.result === null) return { status: "pending", user_op_hash: hash, tx_hash: null };
  if (typeof payload?.result?.success !== "boolean") throw new Error("aa_bundler_receipt_invalid");
  if (String(payload.result.userOpHash || "").toLowerCase() !== hash) throw new Error("aa_bundler_receipt_hash_mismatch");
  const txHash = payload.result.receipt?.transactionHash || null;
  if (txHash !== null && !/^0x[0-9a-fA-F]{64}$/.test(txHash)) throw new Error("aa_bundler_receipt_invalid");
  return {
    status: payload.result.success ? "succeeded" : "failed",
    user_op_hash: hash,
    tx_hash: txHash?.toLowerCase() || null,
  };
}
