// Offline end-to-end integration & security check for Nuri Passkey PRF v2
// Dual-Rail Agent Wallets (2-of-4 Base Safe USDC + 2-of-2 Arkade/Lightning)
// and the 4-action MCP `wallet` tool (`balance`, `receive`, `pay`, `history`).
//
// Zero network access. Uses frozen cross-repo test vectors, an in-process mock
// `nuri-agent-cosigner` implementing exact ECDSA Safe + MuSig2 Tapscript PSBT
// co-signing & spend caps, plus synthetic Arkade operator/indexer/RFQ solver
// and synthetic HTTP 402 (`x402`, `EVM MPP`, `L402`, `Lightning MPP`) servers.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { base64, bech32, hex } from "@scure/base";
import { SigHash, Transaction } from "@scure/btc-signer";
import * as musig2 from "@scure/btc-signer/musig2.js";
import {
  ArkAddress,
  CSVMultisigTapscript,
  MultisigTapscript,
  SingleKey,
  VtxoScript,
  networkFromOperatorInfo,
  resolveEmulatorPubkey,
  toXOnly,
} from "@arkade-os/sdk";
import { decodeBolt11 } from "@arkade-os/swap/advanced";
import { lightningReceiveContract, lightningSendContract, unilateralClaimDelay } from "@arkade-os/swap/protocol";
import { Challenge, Credential, Receipt } from "mppx";
import { encodePaymentResponseHeader } from "@x402/core/http";
import {
  concatHex,
  encodeFunctionData,
  getAddress,
  hashTypedData,
  keccak256,
  parseAbi,
  recoverAddress,
  toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  AGENT_DERIVATION_VERSION,
  AGENT_GRANT_REPLY_FORMAT,
  AGENT_REPLY_SALT_DOMAIN,
  agentGrantProofMessage,
  createConnectGrantClient,
  decryptAgentGrantReply,
  deriveAgentWallet,
  verifyAgentGrantProof,
} from "../src/agent-grant-crypto.mjs";
import { createAgentCosignerClient } from "../src/agent-cosigner-client.mjs";
import {
  BASE_CHAIN_ID,
  BASE_USDC_ADDRESS,
  PERMIT2_ADDRESS,
  TEMPO_CHAIN_IDS,
  computeSafeMessageHash,
  computeSafeTxHash,
  createAgentSafeRuntime,
  deriveFallbackSecondRecoveryAddress,
  predictAgentSafeAddress,
  predictPasskeySignerAddress,
} from "../src/agent-safe-v2.mjs";
import { parseMppChallenges, payMppCharge, selectMppOffer } from "../src/safe-pay-mpp.mjs";
import {
  DEFAULT_ARKADE_SOLVER_PUBKEY,
  NuriAgentVtxoScript,
  createAgentArkadeRuntime,
  deriveLightningReceiveSecrets,
} from "../src/agent-arkade-v2.mjs";
import {
  classifyHttp402Response,
  createPrfHttp402Payer,
  parseL402Challenge,
  parseLightningMppChallenges,
} from "../src/agent-lightning-pay.mjs";
import {
  PRF_WALLET_KEY_RE,
  isPrfWalletKey,
  openPrfAgentWalletStore,
} from "../src/prf-agent-wallet-store.mjs";
import { WALLET_TOOL, createMcpWalletTool } from "../src/mcp-wallet-tool.mjs";

const vector = JSON.parse(
  readFileSync(new URL("../test/fixtures/agent-grant-vector.json", import.meta.url), "utf8"),
);

// Block accidental external internet fetches during offline test run.
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  if (url.startsWith("http://127.0.0.1:")) {
    return await realFetch(input, init);
  }
  throw new Error(`Unexpected external fetch in check-prf-arkade-v2: ${url}`);
};

function intToWordsBE(num, len) {
  const out = new Array(len).fill(0);
  let n = BigInt(num);
  for (let i = len - 1; i >= 0; i -= 1) {
    out[i] = Number(n & 31n);
    n >>= 5n;
  }
  return out;
}

function makeSyntheticBolt11({ amountSats, paymentHashHex, timestamp, expiry = 3600 }) {
  const hrp = `lnbc${BigInt(amountSats) * 10n}n`;
  const tsWords = intToWordsBE(timestamp, 7);
  const phWords = bech32.toWords(hex.decode(paymentHashHex));
  const expWords = intToWordsBE(expiry, 2);
  const sigWords = bech32.toWords(new Uint8Array(65).fill(0x42));
  const words = [
    ...tsWords,
    1,
    ...intToWordsBE(phWords.length, 2),
    ...phWords,
    6,
    ...intToWordsBE(expWords.length, 2),
    ...expWords,
    ...sigWords,
  ];
  return bech32.encode(hrp, words, 2000);
}

function encryptGrantForTest({ prfBytes, sessionId, replyPubkey, index = 0, policy }) {
  const derived = deriveAgentWallet(prfBytes, index);
  const ephSk = new Uint8Array(32).fill(0x19);
  const ephPubXonly = hex.encode(schnorr.getPublicKey(ephSk));
  const shared = secp256k1.getSharedSecret(ephSk, `02${replyPubkey.toLowerCase()}`, true).slice(1);
  const key = hkdf(
    sha256,
    shared,
    new TextEncoder().encode(AGENT_REPLY_SALT_DOMAIN),
    new TextEncoder().encode(sessionId),
    32,
  );
  const nonce = new Uint8Array(24).fill(0x27);
  const aad = new TextEncoder().encode(
    JSON.stringify({
      format: AGENT_GRANT_REPLY_FORMAT,
      session_id: sessionId,
      index: derived.public.index,
      agent_eth_eoa: getAddress(derived.public.agent_eth_eoa),
      agent_btc_public_key_33_hex: derived.public.agent_btc_public_key_33_hex,
      policy,
    }),
  );
  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      format: AGENT_GRANT_REPLY_FORMAT,
      derivation_version: AGENT_DERIVATION_VERSION,
      index: derived.public.index,
      agent_eth_private_key_hex: hex.encode(derived.secrets.agent_eth_private_key),
      agent_btc_private_key_hex: hex.encode(derived.secrets.agent_btc_private_key),
      public: derived.public,
      policy,
    }),
  );
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return {
    ephemeral_pubkey: ephPubXonly,
    nonce_b64u: Buffer.from(nonce).toString("base64url"),
    ciphertext_b64u: Buffer.from(ciphertext).toString("base64url"),
    agent_public: derived.public,
    policy,
  };
}

// ---------------------------------------------------------------------------
// 1. Frozen Cross-Repo Vector Parity & 4-Action Tool Schema Verification
// ---------------------------------------------------------------------------
{
  assert.deepEqual(WALLET_TOOL.inputSchema.properties.action.enum, [
    "balance",
    "receive",
    "pay",
    "history",
    "lnurl",
  ]);
  assert.equal(DEFAULT_ARKADE_SOLVER_PUBKEY.length, 64);

  const prfBytes = hex.decode(vector.prf_hex);
  const slot0 = deriveAgentWallet(prfBytes, 0);
  const slot1 = deriveAgentWallet(prfBytes, 1);

  assert.deepEqual(slot0.public, vector.slot0.public);
  assert.equal(hex.encode(slot0.secrets.agent_eth_private_key), vector.slot0.eth_sk_hex);
  assert.equal(hex.encode(slot0.secrets.agent_btc_private_key), vector.slot0.btc_sk_hex);

  assert.deepEqual(slot1.public, vector.slot1.public);
  assert.equal(hex.encode(slot1.secrets.agent_eth_private_key), vector.slot1.eth_sk_hex);
  assert.equal(hex.encode(slot1.secrets.agent_btc_private_key), vector.slot1.btc_sk_hex);

  assert.equal(
    agentGrantProofMessage({
      sessionId: vector.session_id,
      replyPubkey: vector.reply_pubkey,
      reply: vector.encrypted,
    }),
    vector.proof_message,
  );

  const decrypted = decryptAgentGrantReply({
    replySkHex: vector.reply_sk_hex,
    sessionId: vector.session_id,
    reply: vector.encrypted,
  });
  assert.equal(decrypted.agent_eth_private_key_hex, vector.slot0.eth_sk_hex);
  assert.equal(decrypted.agent_btc_private_key_hex, vector.slot0.btc_sk_hex);
  assert.deepEqual(decrypted.public, vector.slot0.public);
}

// ---------------------------------------------------------------------------
// 2. Spin up local mock `nuri-agent-cosigner` + `connect.nuri.com` + Arkade
// ---------------------------------------------------------------------------
const COSIGNER_SECRET = "test-cosigner-rpc-secret-32-chars-minimum-ok";
const COSIGNER_EVM_ACCOUNT = privateKeyToAccount(
  "0x4444444444444444444444444444444444444444444444444444444444444444",
);
const COSIGNER_BTC_PRIV = new Uint8Array(32).fill(0x45);
const COSIGNER_BTC_PUB33 = secp256k1.getPublicKey(COSIGNER_BTC_PRIV, true);

const MAIN_WALLET_ACCOUNT = privateKeyToAccount(
  "0x3333333333333333333333333333333333333333333333333333333333333333",
);
const TEST_CRED_ID = "dGVzdC1wYXNza2V5LWNyZWQtaWQtbnVyaS12Mg";

// Synthetic Arkade operator & solver keys
const ARK_SERVER_KEY = SingleKey.fromPrivateKey(new Uint8Array(32).fill(0x51));
const ARK_SERVER_PUB33_HEX = hex.encode(await ARK_SERVER_KEY.compressedPublicKey());
const ARK_SERVER_XONLY = await ARK_SERVER_KEY.xOnlyPublicKey();
const ARK_FORFEIT_KEY = SingleKey.fromPrivateKey(new Uint8Array(32).fill(0x52));
const ARK_FORFEIT_PUB33_HEX = hex.encode(await ARK_FORFEIT_KEY.compressedPublicKey());
const ARK_FORFEIT_XONLY = await ARK_FORFEIT_KEY.xOnlyPublicKey();
const ARK_CHECKPOINT_SCRIPT_HEX = hex.encode(
  CSVMultisigTapscript.encode({
    timelock: { type: "seconds", value: 605184n },
    pubkeys: [ARK_FORFEIT_XONLY],
  }).script,
);
const SOLVER_KEY = SingleKey.fromPrivateKey(new Uint8Array(32).fill(0x53));
const SOLVER_XONLY_HEX = hex.encode(await SOLVER_KEY.xOnlyPublicKey());

const ARK_INFO = {
  version: "v0.9.26",
  signerPubkey: ARK_SERVER_PUB33_HEX,
  forfeitPubkey: ARK_FORFEIT_PUB33_HEX,
  checkpointTapscript: ARK_CHECKPOINT_SCRIPT_HEX,
  network: "bitcoin",
  unilateralExitDelay: "605184",
  boardingExitDelay: "7776256",
  dust: "330",
  deprecatedSigners: [],
};

const grantsByKey = new Map();
const connectSessions = new Map();
const cosignerSpendOps = new Map();

function packSortedSafeSigs(sigA, signerA, sigB, signerB) {
  const pair = [
    { signer: getAddress(signerA), sig: sigA.slice(2) },
    { signer: getAddress(signerB), sig: sigB.slice(2) },
  ].sort((x, y) => (BigInt(x.signer) < BigInt(y.signer) ? -1 : 1));
  return `0x${pair[0].sig}${pair[1].sig}`;
}

const mockHttpServer = createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
  const send = (code, payload) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  };

  // Mock connect.nuri.com `/mcp`
  if (req.method === "POST" && req.url === "/mcp") {
    const { id, params } = body;
    const { name, arguments: args } = params;
    if (name === "wallet_sign_start") {
      assert.equal(args.operation, "agent_grant");
      assert.equal(args.timeout_ms, 24 * 60 * 60_000);
      const sessionId = createHash("sha256")
        .update(`sess:${connectSessions.size}:${args.payload.reply_pubkey}`)
        .digest("hex");
      const record = {
        status: "pending",
        session_id: sessionId,
        kind: "sign",
        approval_url: `https://connect.nuri.com/approve?session_id=${sessionId}`,
        expires_at: args.timeout_ms === 0 ? 0 : Date.now() + args.timeout_ms,
        payload: args.payload,
      };
      connectSessions.set(sessionId, record);
      return send(200, {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(record) }],
        },
      });
    }
    if (name === "wallet_sign_result") {
      const rec = connectSessions.get(args.session_id);
      return send(200, {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(rec || { status: "expired" }) }],
        },
      });
    }
  }

  // Mock nuri-agent-cosigner endpoints
  if (req.headers.authorization !== `Bearer ${COSIGNER_SECRET}`) {
    return send(401, { ok: false, error: "unauthorized", code: "unauthorized" });
  }

  if (req.method === "POST" && req.url === "/v1/agent/grants/register") {
    await verifyAgentGrantProof({
      mainEoa: body.main_eoa,
      sessionId: body.session_id,
      replyPubkey: body.reply_pubkey,
      grantResult: body.grant_result,
    });
    const slotIndex = Number(body.grant_result.agent_public.index);
    const agentEthEoa = getAddress(body.grant_result.agent_public.agent_eth_eoa);
    const agentBtcPk33 = body.grant_result.agent_public.agent_btc_public_key_33_hex.toLowerCase();
    const passkeySignerAddress = body.credential_pubkey_b64u
      ? predictPasskeySignerAddress(body.credential_pubkey_b64u).address
      : deriveFallbackSecondRecoveryAddress({
          mainEoa: body.main_eoa,
          credIdB64u: body.cred_id_b64u,
        });
    const safe = predictAgentSafeAddress({
      mainEoa: body.main_eoa,
      passkeySignerAddress,
      agentEoa: agentEthEoa,
      cosignerEoa: COSIGNER_EVM_ACCOUNT.address,
      credIdB64u: body.cred_id_b64u,
      index: slotIndex,
    });
    const sortedBtcKeys = musig2.sortKeys([COSIGNER_BTC_PUB33, hex.decode(agentBtcPk33)]);
    const aggXonlyHex = hex.encode(musig2.keyAggExport(musig2.keyAggregate(sortedBtcKeys)));

    const grant = {
      cred_id_b64u: body.cred_id_b64u,
      slot_index: slotIndex,
      index: slotIndex,
      main_eoa: getAddress(body.main_eoa),
      passkey_signer_address: passkeySignerAddress,
      agent_eoa: agentEthEoa,
      cosigner_eoa: COSIGNER_EVM_ACCOUNT.address,
      safe_address: safe.safeAddress,
      agent_btc_pk33: agentBtcPk33,
      cosigner_btc_pk33: hex.encode(COSIGNER_BTC_PUB33),
      aggregated_btc_xonly: aggXonlyHex,
    };
    grantsByKey.set(`${body.cred_id_b64u}:${slotIndex}`, grant);
    return send(200, { ok: true, grant, nuri_server_csv: 7776256 });
  }

  if (req.method === "POST" && req.url === "/v1/evm/sign-typed-data") {
    const grant = grantsByKey.get(`${body.cred_id_b64u}:${Number(body.index || 0)}`);
    assert.ok(grant, "grant must exist");
    const innerDigest = hashTypedData(body.typed_data);
    const safeMsgHash = computeSafeMessageHash({
      chainId: BASE_CHAIN_ID,
      safeAddress: body.safe_address,
      innerDigest,
    });
    const recAgent = await recoverAddress({ hash: safeMsgHash, signature: body.agent_signature });
    assert.equal(getAddress(recAgent), grant.agent_eoa);
    const cosig = await COSIGNER_EVM_ACCOUNT.sign({ hash: safeMsgHash });
    cosignerSpendOps.set(body.op_id, { kind: "typed_data", typedData: body.typed_data });
    return send(200, {
      ok: true,
      combined_signatures: packSortedSafeSigs(
        body.agent_signature,
        grant.agent_eoa,
        cosig,
        COSIGNER_EVM_ACCOUNT.address,
      ),
    });
  }

  if (req.method === "POST" && req.url === "/v1/evm/sign-safe-tx") {
    const grant = grantsByKey.get(`${body.cred_id_b64u}:${Number(body.index || 0)}`);
    assert.ok(grant, "grant must exist");
    const safeTxHash = computeSafeTxHash({
      chainId: body.chain_id,
      safeAddress: body.safe_address,
      transaction: body.transaction,
    });
    const recAgent = await recoverAddress({ hash: safeTxHash, signature: body.agent_signature });
    assert.equal(getAddress(recAgent), grant.agent_eoa);
    const cosig = await COSIGNER_EVM_ACCOUNT.sign({ hash: safeTxHash });
    cosignerSpendOps.set(body.op_id, { kind: "safe_tx", tx: body.transaction });
    return send(200, {
      ok: true,
      combined_signatures: packSortedSafeSigs(
        body.agent_signature,
        grant.agent_eoa,
        cosig,
        COSIGNER_EVM_ACCOUNT.address,
      ),
    });
  }

  if (req.method === "POST" && req.url === "/v1/arkade/sign-psbt") {
    const grant = grantsByKey.get(`${body.cred_id_b64u}:${Number(body.index || 0)}`);
    assert.ok(grant, "grant must exist");
    const tx = Transaction.fromPSBT(Buffer.from(body.psbt_b64, "base64"), {
      allowUnknown: true,
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
    });
    const prevScripts = [];
    const prevAmounts = [];
    for (let i = 0; i < tx.inputsLength; i += 1) {
      const inp = tx.getInput(i);
      prevScripts.push(inp.witnessUtxo.script);
      prevAmounts.push(inp.witnessUtxo.amount);
    }
    if (body.intent?.lockup_script_hex) {
      let matchedIntent = false;
      for (let o = 0; o < tx.outputsLength; o += 1) {
        const out = tx.getOutput(o);
        if (
          hex.encode(out.script) === body.intent.lockup_script_hex &&
          out.amount === BigInt(body.intent.funding_amount_sats)
        ) {
          matchedIntent = true;
        }
      }
      assert.equal(matchedIntent, true, "PSBT must match declared Arkade Intents lockup output");
    }

    const signatures = [];
    let jobIdx = 0;
    for (let i = 0; i < tx.inputsLength; i += 1) {
      const inp = tx.getInput(i);
      const leaf = inp.tapLeafScript?.[0];
      if (!leaf) continue;
      const scriptWithVer = leaf[1];
      const leafScript = scriptWithVer.subarray(0, -1);
      const leafVer = scriptWithVer[scriptWithVer.length - 1];
      const msg32 = tx.preimageWitnessV1(
        i,
        prevScripts,
        inp.sighashType || SigHash.DEFAULT,
        prevAmounts,
        undefined,
        leafScript,
        leafVer,
      );
      const clientNonceHex = body.nonces[jobIdx].client_pub_nonce;
      const clientPub = hex.decode(grant.agent_btc_pk33);
      const clientNonce = hex.decode(clientNonceHex);
      const sortedKeys = musig2.sortKeys([COSIGNER_BTC_PUB33, clientPub]);
      const aggXonly = musig2.keyAggExport(musig2.keyAggregate(sortedKeys));
      const srvNonce = musig2.nonceGen(COSIGNER_BTC_PUB33, COSIGNER_BTC_PRIV, aggXonly, msg32);
      const orderedNonces = sortedKeys.map((pk) =>
        Buffer.compare(Buffer.from(pk), Buffer.from(COSIGNER_BTC_PUB33)) === 0
          ? srvNonce.public
          : clientNonce,
      );
      const session = new musig2.Session(musig2.nonceAggregate(orderedNonces), sortedKeys, msg32);
      const partial = session.sign(srvNonce.secret, COSIGNER_BTC_PRIV);
      signatures.push({
        input_index: i,
        path: "script",
        msg32: hex.encode(msg32),
        tweak32: null,
        server_pubkey: hex.encode(COSIGNER_BTC_PUB33),
        server_pub_nonce66: hex.encode(srvNonce.public),
        server_partial32: hex.encode(partial),
      });
      jobIdx += 1;
    }
    cosignerSpendOps.set(body.op_id, { kind: "arkade_psbt", intent: body.intent || null });
    return send(200, { ok: true, op_id: body.op_id, signatures });
  }

  return send(404, { ok: false, error: "not_found" });
});

await new Promise((resolve) => mockHttpServer.listen(0, "127.0.0.1", resolve));
const mockPort = mockHttpServer.address().port;
const mockOrigin = `http://127.0.0.1:${mockPort}`;

// ---------------------------------------------------------------------------
// 3. Synthetic Base Safe RPC + Arkade Operator/Indexer/Solver + HTTP 402
// ---------------------------------------------------------------------------
const chainState = {
  safeDeployed: false,
  safeNonce: 0n,
  permit2Allowance: 0n,
  balances: new Map(),
  txs: [],
};

const fakePublicClient = {
  getChainId: async () => BASE_CHAIN_ID,
  getCode: async ({ address }) => (chainState.safeDeployed && address ? "0x60806040" : "0x"),
  readContract: async ({ address, functionName, args }) => {
    if (functionName === "balanceOf") {
      return chainState.balances.get(getAddress(args[0])) ?? 0n;
    }
    if (functionName === "nonce") {
      return chainState.safeNonce;
    }
    if (functionName === "allowance") {
      return chainState.permit2Allowance;
    }
    if (functionName === "name") return "USD Coin";
    if (functionName === "version") return "2";
    throw new Error(`unexpected readContract: ${address}.${functionName}`);
  },
  waitForTransactionReceipt: async ({ hash }) => ({ status: "success", transactionHash: hash }),
};

const ERC20_ABI = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);

const fakeWalletClient = {
  writeContract: async ({ address, functionName, args }) => {
    const txHash = `0x${createHash("sha256")
      .update(`${functionName}:${chainState.txs.length}:${Date.now()}`)
      .digest("hex")}`;
    if (functionName === "createProxyWithNonce") {
      chainState.safeDeployed = true;
    } else if (functionName === "execTransaction") {
      const safeAddr = getAddress(address);
      const data = args[2];
      // Selector 0xa9059cbb = transfer(address,uint256), 0x095ea7b3 = approve(address,uint256)
      if (data.startsWith("0xa9059cbb")) {
        const to = getAddress(`0x${data.slice(34, 74)}`);
        const amount = BigInt(`0x${data.slice(74, 138)}`);
        const cur = chainState.balances.get(safeAddr) ?? 0n;
        assert.ok(cur >= amount, "Safe balance must cover transfer");
        chainState.balances.set(safeAddr, cur - amount);
        chainState.balances.set(to, (chainState.balances.get(to) ?? 0n) + amount);
      } else if (data.startsWith("0x095ea7b3")) {
        chainState.permit2Allowance = BigInt(`0x${data.slice(74, 138)}`);
      }
      chainState.safeNonce += 1n;
    }
    chainState.txs.push({ txHash, address, functionName });
    return txHash;
  },
};

// In-memory Arkade ledger: tracks VTXOs by script hex + virtual txs for `readLockupFate`
const arkState = {
  vtxosByScript: new Map(), // scriptHex -> array of vtxo objects
  virtualTxs: new Map(), // txid -> base64 PSBT
  submittedArkTxs: [],
  finalizedArkTxs: [],
  lnSendPreimage: hex.decode("11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"),
};

function addArkVtxo(scriptHex, vtxo) {
  const arr = arkState.vtxosByScript.get(scriptHex) || [];
  arr.push(vtxo);
  arkState.vtxosByScript.set(scriptHex, arr);
}

const fakeOperator = {
  getInfo: async () => ARK_INFO,
  submitTx: async (signedArkTxB64, checkpointTxsB64) => {
    const userArkTx = Transaction.fromPSBT(base64.decode(signedArkTxB64), {
      allowUnknown: true,
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
    });
    // Co-sign every input leaf with ARK_SERVER_KEY so SDK's `verifyServerSignatures` passes!
    const serverSignedArk = await ARK_SERVER_KEY.sign(userArkTx.clone());
    const signedCheckpoints = [];
    for (const cpB64 of checkpointTxsB64) {
      const cp = Transaction.fromPSBT(base64.decode(cpB64), {
        allowUnknown: true,
        allowUnknownInputs: true,
        allowUnknownOutputs: true,
      });
      const srvCp = await ARK_SERVER_KEY.sign(cp.clone());
      signedCheckpoints.push(base64.encode(srvCp.toPSBT()));
    }
    arkState.submittedArkTxs.push(serverSignedArk.id);
    return {
      arkTxid: serverSignedArk.id,
      finalArkTx: base64.encode(serverSignedArk.toPSBT()),
      signedCheckpointTxs: signedCheckpoints,
    };
  },
  finalizeTx: async (arkTxid, finalCheckpoints) => {
    arkState.finalizedArkTxs.push({ arkTxid, count: finalCheckpoints.length });
    // Inspect the submitted arkTx outputs: credit any new outputs in our in-memory indexer,
    // and if an output funds a Lightning send VHTLC, simulate the solver claiming it with the preimage!
    // Also mark spent VTXOs as spent.
    for (const [, list] of arkState.vtxosByScript) {
      for (const v of list) {
        if (!v.isSpent && v.markSpentNext) {
          v.isSpent = true;
        }
      }
    }
  },
};

const fakeIndexer = {
  getVtxos: async ({ scripts }) => {
    const out = [];
    for (const s of scripts) {
      for (const v of arkState.vtxosByScript.get(s) || []) {
        out.push({ ...v });
      }
    }
    return { vtxos: out };
  },
  getVirtualTxs: async (txids) => ({
    txs: txids.map((id) => arkState.virtualTxs.get(id)).filter(Boolean),
  }),
};

const network = networkFromOperatorInfo(ARK_INFO);
const emulatorPubkey = toXOnly(hex.decode(resolveEmulatorPubkey(network)), "emulator");
const claimDelay = unilateralClaimDelay(Number(ARK_INFO.unilateralExitDelay));
const solverReceiverPkScript = new VtxoScript([
  MultisigTapscript.encode({ pubkeys: [hex.decode(SOLVER_XONLY_HEX), ARK_SERVER_XONLY] }).script,
]).pkScript;

// Wrap submitTx so outputs created by `sendArkade` / `pushClaim` update `arkState`!
const baseSubmitTx = fakeOperator.submitTx;
fakeOperator.submitTx = async (signedArkTxB64, checkpointTxsB64) => {
  const res = await baseSubmitTx(signedArkTxB64, checkpointTxsB64);
  const tx = Transaction.fromPSBT(base64.decode(res.finalArkTx), {
    allowUnknown: true,
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
  });
  // Verify that every input on `arkTx` carries a valid Schnorr signature for the leaf pubkeys!
  const prevScripts = [];
  const prevAmounts = [];
  for (let i = 0; i < tx.inputsLength; i += 1) {
    const inp = tx.getInput(i);
    prevScripts.push(inp.witnessUtxo.script);
    prevAmounts.push(inp.witnessUtxo.amount);
  }
  for (let i = 0; i < tx.inputsLength; i += 1) {
    const inp = tx.getInput(i);
    const leaf = inp.tapLeafScript?.[0];
    if (leaf && inp.tapScriptSig?.length) {
      const scriptWithVer = leaf[1];
      const leafScript = scriptWithVer.subarray(0, -1);
      const leafVer = scriptWithVer[scriptWithVer.length - 1];
      const msg32 = tx.preimageWitnessV1(
        i,
        prevScripts,
        inp.sighashType || SigHash.DEFAULT,
        prevAmounts,
        undefined,
        leafScript,
        leafVer,
      );
      for (const [{ pubKey }, sig] of inp.tapScriptSig) {
        assert.equal(
          schnorr.verify(sig.subarray(0, 64), msg32, pubKey),
          true,
          "Tapscript Schnorr signature must be cryptographically valid",
        );
      }
    }
  }

  // Mark spent inputs by checkpoint input outpoint
  for (const cpB64 of checkpointTxsB64) {
    const cp = Transaction.fromPSBT(base64.decode(cpB64), {
      allowUnknown: true,
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
    });
    const spent = cp.getInput(0);
    const spentTxid = hex.encode(spent.txid);
    for (const [, list] of arkState.vtxosByScript) {
      for (const v of list) {
        if (v.txid === spentTxid && v.vout === spent.index) {
          v.isSpent = true;
          v.spentBy = cp.id;
          v.arkTxId = tx.id;
        }
      }
    }
  }

  // Credit created outputs (skipping P2A fee anchor)
  for (let o = 0; o < tx.outputsLength; o += 1) {
    const out = tx.getOutput(o);
    const scriptHex = hex.encode(out.script);
    if (!scriptHex.startsWith("5120") || out.amount <= 0n) continue;
    if (arkState.pendingSendLockups?.has(scriptHex)) {
      const meta = arkState.pendingSendLockups.get(scriptHex);
      // Simulate solver immediately claiming the VHTLC lockup and revealing the preimage in witness!
      const claimCpTx = new Transaction({ allowUnknownInputs: true, allowUnknownOutputs: true });
      claimCpTx.addInput({
        txid: hex.decode(tx.id),
        index: o,
        witnessUtxo: { script: out.script, amount: out.amount },
      });
      claimCpTx.addOutput({ script: solverReceiverPkScript, amount: out.amount });
      claimCpTx.updateInput(0, {
        finalScriptWitness: [meta.preimage, new Uint8Array([0x01])],
      });
      const claimCpB64 = base64.encode(claimCpTx.toPSBT());
      arkState.virtualTxs.set(claimCpTx.id, claimCpB64);
      addArkVtxo(scriptHex, {
        txid: tx.id,
        vout: o,
        value: Number(out.amount),
        isSpent: true,
        isUnrolled: false,
        isSwept: false,
        spentBy: claimCpTx.id,
        arkTxId: claimCpTx.id,
      });
    } else {
      addArkVtxo(scriptHex, {
        txid: tx.id,
        vout: o,
        value: Number(out.amount),
        isSpent: false,
        isUnrolled: false,
        isSwept: false,
      });
    }
  }
  return res;
};
arkState.pendingSendLockups = new Map();

const fakeRfqTransportFactory = async () => ({
  requestQuote: async (req) => {
    const now = Math.floor(Date.now() / 1000);
    // Outgoing Lightning Send RFQ (`invoice` in profile)
    if (req.profile?.invoice) {
      const facts = decodeBolt11(req.profile.invoice);
      const feeSats = 15;
      const refundLocktime = now + 7200;
      const refundWithoutReceiverDelay = Math.ceil((7200 + claimDelay) / 512) * 512;
      const refundPkScript = ArkAddress.decode(req.profile.refund_address).pkScript;
      const script = lightningSendContract({
        solverPubkey: hex.decode(SOLVER_XONLY_HEX),
        refundLocktime,
        operatorPubkey: ARK_SERVER_XONLY,
        paymentHash: facts.paymentHash,
        claimDelay,
        refundWithoutReceiverDelay,
        emulatorPubkey,
        senderPubkey: hex.decode(req.profile.client_refund_pubkey || req.profile.sender_pubkey),
        receiverPkScript: solverReceiverPkScript,
        refundPkScript,
      });
      const lockupAddr = new ArkAddress(ARK_SERVER_XONLY, script.tweakedPublicKey, network.hrp).encode();
      arkState.pendingSendLockups.set(hex.encode(script.pkScript), {
        preimage: metaPreimageFor(facts.paymentHash),
      });
      return {
        rfq_id: req.rfq_id,
        pair: req.pair,
        solver_pubkey: SOLVER_XONLY_HEX,
        from_amount: facts.amountSats + feeSats,
        to_amount: facts.amountSats,
        valid_until: now + 600,
        refund_locktime: refundLocktime,
        profile: {
          lockup_address: lockupAddr,
          receiver_pk_script: hex.encode(solverReceiverPkScript),
          refund_without_receiver_delay: refundWithoutReceiverDelay,
        },
      };
    }

    // Incoming Lightning Receive RFQ (`payment_hash` + `payout_address` in profile)
    const payAmount = Number(req.amount);
    const feeSats = 10;
    const toAmount = payAmount - feeSats;
    const refundLocktime = now + 10800;
    const payoutPkScript = ArkAddress.decode(req.profile.payout_address).pkScript;
    const script = lightningReceiveContract({
      solverPubkey: hex.decode(SOLVER_XONLY_HEX),
      refundLocktime,
      operatorPubkey: ARK_SERVER_XONLY,
      paymentHash: req.profile.payment_hash,
      claimDelay,
      emulatorPubkey,
      solverRefundPkScript: solverReceiverPkScript,
      payoutPubkey: hex.decode(req.profile.payout_pubkey),
      payoutPkScript,
    });
    const lockupAddr = new ArkAddress(ARK_SERVER_XONLY, script.tweakedPublicKey, network.hrp).encode();
    const invoice = makeSyntheticBolt11({
      amountSats: payAmount,
      paymentHashHex: req.profile.payment_hash,
      timestamp: now,
      expiry: 1800,
    });

    // Save lockup script so test can simulate payer paying the invoice (solver funding the VHTLC)
    arkState.lastReceiveLockup = {
      paymentHash: req.profile.payment_hash,
      swapPkScriptHex: hex.encode(script.pkScript),
      toAmount,
    };

    return {
      rfq_id: req.rfq_id,
      pair: req.pair,
      solver_pubkey: SOLVER_XONLY_HEX,
      from_amount: payAmount,
      to_amount: toAmount,
      valid_until: now + 1800,
      refund_locktime: refundLocktime,
      profile: {
        lockup_address: lockupAddr,
        invoice,
        solver_refund_pk_script: hex.encode(solverReceiverPkScript),
      },
    };
  },
  close: async () => {},
});

const knownPreimages = new Map();
function registerPreimage(preimageBytes) {
  const hashHex = hex.encode(sha256(preimageBytes));
  knownPreimages.set(hashHex, preimageBytes);
  return { preimageBytes, preimageHex: hex.encode(preimageBytes), paymentHashHex: hashHex };
}
function metaPreimageFor(paymentHashHex) {
  const p = knownPreimages.get(paymentHashHex);
  assert.ok(p, `missing test preimage for ${paymentHashHex}`);
  return p;
}

const l402Secret = registerPreimage(new Uint8Array(32).fill(0x71));
const mppLnSecret = registerPreimage(new Uint8Array(32).fill(0x72));
const directBoltSecret = registerPreimage(new Uint8Array(32).fill(0x73));
const lnAddrSecret = registerPreimage(new Uint8Array(32).fill(0x74));

const nowSec = Math.floor(Date.now() / 1000);
const l402Invoice = makeSyntheticBolt11({
  amountSats: 800,
  paymentHashHex: l402Secret.paymentHashHex,
  timestamp: nowSec,
});
const mppLnInvoice = makeSyntheticBolt11({
  amountSats: 600,
  paymentHashHex: mppLnSecret.paymentHashHex,
  timestamp: nowSec,
});
const directBoltInvoice = makeSyntheticBolt11({
  amountSats: 500,
  paymentHashHex: directBoltSecret.paymentHashHex,
  timestamp: nowSec,
});
const lnAddrInvoice = makeSyntheticBolt11({
  amountSats: 450,
  paymentHashHex: lnAddrSecret.paymentHashHex,
  timestamp: nowSec,
});

const mppLnChallenge = Challenge.from({
  id: "chal-ln-1",
  realm: "ln.example.com",
  method: "lightning",
  intent: "charge",
  request: {
    invoice: mppLnInvoice,
    amount: "600",
    currency: "SAT",
    paymentHash: mppLnSecret.paymentHashHex,
  },
});

const mppEvmChallenge = Challenge.from({
  id: "chal-evm-1",
  realm: "evm.example.com",
  method: "evm",
  intent: "charge",
  request: {
    amount: "150000", // 0.15 USDC
    currency: BASE_USDC_ADDRESS,
    recipient: "0x7777777777777777777777777777777777777777",
    methodDetails: {
      chainId: BASE_CHAIN_ID,
      decimals: 6,
      credentialTypes: ["authorization"],
    },
  },
});

const PATHUSD_ADDRESS = "0x20c0000000000000000000000000000000000000";
const mppTempoChallenge = Challenge.from({
  id: "chal-tempo-1",
  realm: "tempo.example.com",
  method: "tempo",
  intent: "charge",
  request: {
    amount: "500000", // 0.50 PATHUSD
    currency: PATHUSD_ADDRESS,
    recipient: "0x7777777777777777777777777777777777777777",
    methodDetails: {
      chainId: 4217,
      decimals: 6,
    },
  },
});

// Synthetic HTTPS merchant dispatcher (zero network)
async function syntheticMerchantFetch(url, { headers = {}, shape } = {}) {
  const auth = headers.Authorization || headers.authorization || "";
  const paySig = headers["PAYMENT-SIGNATURE"] || headers["payment-signature"] || "";

  if (url === "https://l402.example.com/secret") {
    if (!auth) {
      return {
        status: 402,
        headers: {
          "www-authenticate": `L402 macaroon="bWFjYXJvb24tMTIz", invoice="${l402Invoice}"`,
          "content-type": "application/json",
        },
        bytes: Buffer.from(JSON.stringify({ error: "payment_required" })),
      };
    }
    assert.equal(auth, `L402 bWFjYXJvb24tMTIz:${l402Secret.preimageHex}`);
    return {
      status: 200,
      headers: { "content-type": "application/json" },
      bytes: Buffer.from(JSON.stringify({ data: "l402-unlocked" })),
    };
  }

  if (url === "https://mpp-ln.example.com/data") {
    if (!auth) {
      return {
        status: 402,
        headers: {
          "www-authenticate": Challenge.serialize(mppLnChallenge),
          "content-type": "application/json",
        },
        bytes: Buffer.from(JSON.stringify({ error: "payment_required" })),
      };
    }
    const cred = Credential.deserialize(auth);
    assert.equal(cred.payload.preimage, mppLnSecret.preimageHex);
    return {
      status: 200,
      headers: { "content-type": "application/json" },
      bytes: Buffer.from(JSON.stringify({ data: "mpp-lightning-unlocked" })),
    };
  }

  if (url === "https://x402.example.com/report") {
    if (!paySig) {
      const required = {
        x402Version: 2,
        resource: { url, description: "Paid report", mimeType: "application/json" },
        accepts: [
          {
            scheme: "exact",
            network: "eip155:8453",
            amount: "250000", // 0.25 USDC
            asset: BASE_USDC_ADDRESS,
            payTo: "0x8888888888888888888888888888888888888888",
            maxTimeoutSeconds: 300,
            extra: { name: "USD Coin", version: "2" },
          },
        ],
      };
      return {
        status: 402,
        headers: {
          "payment-required": Buffer.from(JSON.stringify(required)).toString("base64"),
          "content-type": "application/json",
        },
        bytes: Buffer.from("{}"),
      };
    }
    const parsed = JSON.parse(Buffer.from(paySig, "base64").toString("utf8"));
    assert.equal(parsed.accepted.amount, "250000");
    assert.equal(parsed.payload.signature.length, 2 + 260);
    const receiptHeader = encodePaymentResponseHeader({
      success: true,
      transaction: `0x${"ab".repeat(32)}`,
      network: "eip155:8453",
      payer: parsed.payload.authorization.from,
    });
    return {
      status: 200,
      headers: {
        "content-type": "application/json",
        "payment-response": receiptHeader,
      },
      bytes: Buffer.from(JSON.stringify({ report: "x402-paid-ok" })),
    };
  }

  if (url === "https://mpp-evm.example.com/compute") {
    if (!auth) {
      return {
        status: 402,
        headers: {
          "www-authenticate": Challenge.serialize(mppEvmChallenge),
          "content-type": "application/json",
        },
        bytes: Buffer.from(JSON.stringify({ error: "payment_required" })),
      };
    }
    const cred = Credential.deserialize(auth);
    assert.equal(cred.challenge.method, "evm");
    const receiptHeader = Receipt.serialize(
      Receipt.from({
        method: "evm",
        status: "success",
        timestamp: new Date().toISOString(),
        reference: `0x${"cd".repeat(32)}`,
      }),
    );
    return {
      status: 200,
      headers: {
        "content-type": "application/json",
        "payment-receipt": receiptHeader,
      },
      bytes: Buffer.from(JSON.stringify({ compute: "mpp-evm-paid-ok" })),
    };
  }

  if (url === "https://dual.example.com/both") {
    const x402Req = {
      x402Version: 2,
      resource: { url, description: "Dual rail", mimeType: "application/json" },
      accepts: [
        {
          scheme: "exact",
          network: "eip155:8453",
          amount: "100000",
          asset: BASE_USDC_ADDRESS,
          payTo: "0x8888888888888888888888888888888888888888",
          maxTimeoutSeconds: 300,
          extra: { name: "USD Coin", version: "2" },
        },
      ],
    };
    return {
      status: 402,
      headers: {
        "www-authenticate": `L402 macaroon="bWFjLWR1YWw=", invoice="${l402Invoice}"`,
        "payment-required": Buffer.from(JSON.stringify(x402Req)).toString("base64"),
      },
      bytes: Buffer.from("{}"),
    };
  }

  throw new Error(`Unhandled synthetic merchant URL: ${url} (${shape?.method})`);
}

// Custom fetch for LNURL-pay + loopback HTTP
async function testFetch(input, init) {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  if (url === "https://pay.walletofsatoshi.com/.well-known/lnurlp/alice") {
    return new Response(
      JSON.stringify({
        callback: "https://pay.walletofsatoshi.com/lnurlp/alice/cb",
        minSendable: 1000,
        maxSendable: 100_000_000,
        tag: "payRequest",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }
  if (url.startsWith("https://pay.walletofsatoshi.com/lnurlp/alice/cb?")) {
    const u = new URL(url);
    assert.equal(u.searchParams.get("amount"), "450000");
    return new Response(JSON.stringify({ pr: lnAddrInvoice, routes: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  return await realFetch(input, init);
}

// ---------------------------------------------------------------------------
// 4. End-to-End Test of `createMcpWalletTool` (v2 PRF + Legacy v1 Coexistence)
// ---------------------------------------------------------------------------
const tmpDir = mkdtempSync(join(tmpdir(), "prf-wallet-v2-test-"));
const dbPath = join(tmpDir, "wallet.sqlite");

const savedEnv = { ...process.env };
process.env.AGENT_KERNEL_ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.AGENT_COSIGNER_URL = mockOrigin;
process.env.AGENT_COSIGNER_RPC_SECRET = COSIGNER_SECRET;
process.env.CONNECT_NURI_URL = mockOrigin;

try {
  const connectClient = createConnectGrantClient({ baseUrl: mockOrigin, fetchImpl: testFetch });
  const cosignerClient = createAgentCosignerClient({
    baseUrl: mockOrigin,
    secret: COSIGNER_SECRET,
    fetchImpl: testFetch,
  });
  const safeRuntime = createAgentSafeRuntime({
    env: process.env,
    cosignerClient,
    publicClient: fakePublicClient,
    walletClient: fakeWalletClient,
  });
  const arkadeRuntime = createAgentArkadeRuntime({
    env: process.env,
    cosignerClient,
    operatorProvider: fakeOperator,
    indexerProvider: fakeIndexer,
    rfqTransportFactory: fakeRfqTransportFactory,
    fetchImpl: testFetch,
  });
  const http402Payer = createPrfHttp402Payer({
    safeRuntime,
    arkadeRuntime,
    merchantFetch: syntheticMerchantFetch,
  });

  // Also verify legacy v1 Privy `wallet_key` routing stays 100% intact!
  const legacyWalletKey = "L".repeat(44);
  let legacyCalls = 0;
  const fakeLegacyAgentWalletFactory = () => ({
    call: async (req) => {
      legacyCalls += 1;
      if (req.action === "create") {
        return {
          ok: true,
          wallet_key: legacyWalletKey,
          wallet: {
            wallet_id: "legacy-w1",
            address: "0x9999999999999999999999999999999999999999",
            claimed: true,
            owner_address: MAIN_WALLET_ACCOUNT.address,
          },
        };
      }
      if (req.action === "status" || req.action === "balance") {
        return { ok: true, available_units: "4200000", operation: { balance_units: "4200000" } };
      }
      if (req.action === "history") {
        return {
          ok: true,
          history: [
            {
              request_id: "leg-1",
              action: "pay",
              status: "paid",
              amount_units: "100000",
              to: "0x2222222222222222222222222222222222222222",
              transaction_hash: `0x${"ee".repeat(32)}`,
            },
          ],
        };
      }
      return { ok: true };
    },
    close: () => {},
  });

  const walletTool = createMcpWalletTool({
    accountFlow: { authorized: async () => null },
    chainId: BASE_CHAIN_ID,
    path: dbPath,
    consolidate: false,
    agentWalletFactory: fakeLegacyAgentWalletFactory,
    prfOptions: {
      connectClient,
      cosignerClient,
      safeRuntime,
      arkadeRuntime,
      http402Payer,
      fetchImpl: testFetch,
    },
  });

  // Step A: Onboarding start (`wallet balance` with no wallet_key) — returns ONLY `approval_url`, NO `create_url`!
  const startRes = await walletTool.call({ action: "balance", request_id: "onboard-1" });
  assert.equal(startRes.ok, true);
  assert.equal(startRes.status, "connect_required");
  assert.equal(startRes.request_id, "onboard-1");
  assert.match(startRes.approval_url, /^https:\/\/connect\.nuri\.com\/approve\?session_id=/);
  assert.equal(startRes.create_url, undefined);
  assert.equal("create_url" in startRes, false);

  // Poll while still pending -> returns same `connect_required` and still NO `create_url`
  const pendingRes = await walletTool.call({ action: "balance", request_id: "onboard-1" });
  assert.equal(pendingRes.status, "connect_required");
  assert.equal(pendingRes.approval_url, startRes.approval_url);
  assert.equal(pendingRes.create_url, undefined);
  assert.equal("create_url" in pendingRes, false);

  // Simulate user approving on connect.nuri.com with their Nuri Passkey PRF (`vector.prf_hex`)
  const connectSessionId = new URL(startRes.approval_url).searchParams.get("session_id");
  const sessRec = connectSessions.get(connectSessionId);
  const encryptedReply = encryptGrantForTest({
    prfBytes: hex.decode(vector.prf_hex),
    sessionId: connectSessionId,
    replyPubkey: sessRec.payload.reply_pubkey,
    index: sessRec.payload.index,
    policy: sessRec.payload.policy,
  });
  const proofMsg = agentGrantProofMessage({
    sessionId: connectSessionId,
    replyPubkey: sessRec.payload.reply_pubkey,
    reply: encryptedReply,
  });
  const proofSig = await MAIN_WALLET_ACCOUNT.signMessage({ message: proofMsg });
  sessRec.status = "approved";
  sessRec.wallet = {
    eth_user_eoa: MAIN_WALLET_ACCOUNT.address,
    cred_id_b64u: TEST_CRED_ID,
  };
  sessRec.result = {
    ...encryptedReply,
    address: MAIN_WALLET_ACCOUNT.address,
    signature: proofSig,
  };

  // Step B: Poll `wallet balance` with same `request_id` -> issues `npw1_...` wallet_key!
  const finRes = await walletTool.call({ action: "balance", request_id: "onboard-1" });
  assert.equal(finRes.ok, true);
  assert.equal(finRes.status, "done");
  assert.match(finRes.wallet_key, PRF_WALLET_KEY_RE);
  assert.equal(isPrfWalletKey(finRes.wallet_key), true);
  assert.equal(finRes.owner_address, MAIN_WALLET_ACCOUNT.address);
  assert.match(finRes.arkade_address, /^ark1/);

  const walletKey = finRes.wallet_key;
  const safeAddress = finRes.address;
  const arkadeAddress = finRes.arkade_address;

  // Capture original persisted wallet_id to prove reconnect preserves exact wallet row
  const inspectStore1 = openPrfAgentWalletStore({
    path: dbPath,
    encryptionKey: process.env.AGENT_KERNEL_ENCRYPTION_KEY,
  });
  const walletBeforeReconnect = inspectStore1.getWalletByKey(walletKey);
  assert.ok(walletBeforeReconnect?.walletId);
  inspectStore1.close();

  // Repeating `onboard-1` while session is unexpired MUST safely retry and still return `wallet_key`!
  const repeatOnboard = await walletTool.call({ action: "balance", request_id: "onboard-1" });
  assert.equal(repeatOnboard.ok, true);
  assert.equal(repeatOnboard.status, "done");
  assert.equal(repeatOnboard.wallet_key, walletKey);
  assert.equal(repeatOnboard.address, safeAddress);
  assert.equal(repeatOnboard.arkade_address, arkadeAddress);

  // Reconnecting with the SAME Passkey PRF (new session `onboard-reconnect`) MUST deterministically
  // return the EXACT SAME `wallet_id`, `npw1_...` wallet_key, Safe address, and Arkade address,
  // and MUST NOT return `create_url`!
  const reconStart = await walletTool.call({ action: "balance", new: true, request_id: "onboard-reconnect" });
  assert.equal(reconStart.status, "connect_required");
  assert.equal(reconStart.create_url, undefined);
  assert.equal("create_url" in reconStart, false);
  const reconSessionId = new URL(reconStart.approval_url).searchParams.get("session_id");
  const reconSessRec = connectSessions.get(reconSessionId);
  const reconReply = encryptGrantForTest({
    prfBytes: hex.decode(vector.prf_hex),
    sessionId: reconSessionId,
    replyPubkey: reconSessRec.payload.reply_pubkey,
    index: reconSessRec.payload.index,
    policy: reconSessRec.payload.policy,
  });
  const reconSig = await MAIN_WALLET_ACCOUNT.signMessage({
    message: agentGrantProofMessage({
      sessionId: reconSessionId,
      replyPubkey: reconSessRec.payload.reply_pubkey,
      reply: reconReply,
    }),
  });
  reconSessRec.status = "approved";
  reconSessRec.wallet = {
    cred_id_b64u: TEST_CRED_ID,
    eth_user_eoa: MAIN_WALLET_ACCOUNT.address,
  };
  reconSessRec.result = { ...reconReply, address: MAIN_WALLET_ACCOUNT.address, signature: reconSig };
  const reconFin = await walletTool.call({ action: "balance", request_id: "onboard-reconnect" });
  assert.equal(reconFin.ok, true);
  assert.equal(reconFin.wallet_key, walletKey);
  assert.equal(reconFin.address, safeAddress);
  assert.equal(reconFin.arkade_address, arkadeAddress);

  const inspectStore2 = openPrfAgentWalletStore({
    path: dbPath,
    encryptionKey: process.env.AGENT_KERNEL_ENCRYPTION_KEY,
  });
  const walletAfterReconnect = inspectStore2.getWalletByKey(walletKey);
  assert.equal(walletAfterReconnect.walletId, walletBeforeReconnect.walletId);
  inspectStore2.close();

  // Seed initial Base Safe USDC (5.00 USDC) and 2-of-2 Arkade VTXO (10,000 sats)
  chainState.balances.set(getAddress(safeAddress), 5_000_000n);
  const walletArkDecoded = ArkAddress.decode(arkadeAddress);
  addArkVtxo(hex.encode(walletArkDecoded.pkScript), {
    txid: "ab".repeat(32),
    vout: 0,
    value: 10_000,
    isSpent: false,
    isUnrolled: false,
    isSwept: false,
  });

  // Step C: `wallet balance` with `wallet_key` shows both Base USDC & Bitcoin/Arkade sats!
  const bal1 = await walletTool.call({ action: "balance", wallet_key: walletKey });
  assert.equal(bal1.ok, true);
  assert.equal(bal1.available, "5");
  assert.equal(bal1.sats, 10_000);
  assert.equal(bal1.btc, "0.0001");
  assert.equal(bal1.address, safeAddress);
  assert.equal(bal1.arkade_address, arkadeAddress);

  // Step D: `wallet receive` across all 3 rails (`usdc`, `arkade`, `lightning` + pushClaim sweep)
  const recvUsdc = await walletTool.call({
    action: "receive",
    wallet_key: walletKey,
    rail: "usdc",
  });
  assert.equal(recvUsdc.ok, true);
  assert.equal(recvUsdc.rail, "usdc");
  assert.equal(recvUsdc.address, safeAddress);

  const recvArk = await walletTool.call({
    action: "receive",
    wallet_key: walletKey,
    rail: "arkade",
  });
  assert.equal(recvArk.ok, true);
  assert.equal(recvArk.rail, "arkade");
  assert.equal(recvArk.arkade_address, arkadeAddress);

  const recvLn = await walletTool.call({
    action: "receive",
    wallet_key: walletKey,
    rail: "lightning",
    amount_sats: 2000,
    request_id: "ln-in-1",
  });
  assert.equal(recvLn.ok, true, JSON.stringify(recvLn));
  assert.equal(recvLn.rail, "lightning");
  assert.equal(recvLn.amount_sats, 2000);
  assert.equal(recvLn.expected_sats, 1990);
  assert.match(recvLn.invoice, /^lnbc/);

  // Simulate solver locking 1,990 sats in the VHTLC after external Lightning payer pays the invoice!
  addArkVtxo(arkState.lastReceiveLockup.swapPkScriptHex, {
    txid: "cd".repeat(32),
    vout: 0,
    value: arkState.lastReceiveLockup.toAmount,
    isSpent: false,
    isUnrolled: false,
    isSwept: false,
  });

  // Calling `wallet balance` automatically sweeps the funded Lightning VHTLC into 2-of-2 Arkade custody!
  const balAfterRecv = await walletTool.call({ action: "balance", wallet_key: walletKey });
  assert.equal(balAfterRecv.sats, 11_990); // 10,000 + 1,990 claimed!

  // Step D2: Reconnect immediate balance sweep — a paid-but-unclaimed Lightning receive MUST sweep
  // and appear immediately on Passkey reconnect (`startOrPollOnboarding` finalization)!
  const recvLnReconnect = await walletTool.call({
    action: "receive",
    wallet_key: walletKey,
    rail: "lightning",
    amount_sats: 1500,
    request_id: "ln-in-reconnect",
  });
  assert.equal(recvLnReconnect.ok, true, JSON.stringify(recvLnReconnect));
  assert.equal(recvLnReconnect.expected_sats, 1490);
  addArkVtxo(arkState.lastReceiveLockup.swapPkScriptHex, {
    txid: "ce".repeat(32),
    vout: 0,
    value: arkState.lastReceiveLockup.toAmount,
    isSpent: false,
    isUnrolled: false,
    isSwept: false,
  });

  const reconSweepStart = await walletTool.call({
    action: "balance",
    new: true,
    request_id: "onboard-reconnect-sweep",
  });
  assert.equal(reconSweepStart.status, "connect_required");
  assert.equal(reconSweepStart.create_url, undefined);
  const reconSweepSid = new URL(reconSweepStart.approval_url).searchParams.get("session_id");
  const reconSweepRec = connectSessions.get(reconSweepSid);
  const reconSweepReply = encryptGrantForTest({
    prfBytes: hex.decode(vector.prf_hex),
    sessionId: reconSweepSid,
    replyPubkey: reconSweepRec.payload.reply_pubkey,
    index: reconSweepRec.payload.index,
    policy: reconSweepRec.payload.policy,
  });
  const reconSweepSig = await MAIN_WALLET_ACCOUNT.signMessage({
    message: agentGrantProofMessage({
      sessionId: reconSweepSid,
      replyPubkey: reconSweepRec.payload.reply_pubkey,
      reply: reconSweepReply,
    }),
  });
  reconSweepRec.status = "approved";
  reconSweepRec.wallet = {
    cred_id_b64u: TEST_CRED_ID,
    eth_user_eoa: MAIN_WALLET_ACCOUNT.address,
  };
  reconSweepRec.result = {
    ...reconSweepReply,
    address: MAIN_WALLET_ACCOUNT.address,
    signature: reconSweepSig,
  };
  const preSweepCheck = openPrfAgentWalletStore({
    path: dbPath,
    encryptionKey: process.env.AGENT_KERNEL_ENCRYPTION_KEY,
  });
  assert.equal(preSweepCheck.listPendingLightningReceives(walletBeforeReconnect.walletId).length, 1);
  preSweepCheck.close();

  const reconSweepFin = await walletTool.call({
    action: "balance",
    request_id: "onboard-reconnect-sweep",
  });
  assert.equal(reconSweepFin.ok, true);
  assert.equal(reconSweepFin.status, "done");
  assert.equal(reconSweepFin.wallet_key, walletKey);
  assert.equal(reconSweepFin.sats, 13_480); // 11,990 + 1,490 swept immediately on reconnect!

  const postSweepCheck = openPrfAgentWalletStore({
    path: dbPath,
    encryptionKey: process.env.AGENT_KERNEL_ENCRYPTION_KEY,
  });
  assert.equal(postSweepCheck.listPendingLightningReceives(walletBeforeReconnect.walletId).length, 0);
  postSweepCheck.close();

  // Step E: Dry-run dual-rail HTTP 402 (`prefer: "lightning"` vs `prefer: "usdc"`)
  const dryLn = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    url: "https://dual.example.com/both",
    dry_run: true,
    prefer: "lightning",
  });
  assert.equal(dryLn.ok, true);
  assert.equal(dryLn.protocol, "l402");
  assert.equal(dryLn.rail, "lightning");
  assert.equal(dryLn.payable, true);

  const dryUsdc = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    url: "https://dual.example.com/both",
    dry_run: true,
    prefer: "usdc",
  });
  assert.equal(dryUsdc.ok, true);
  assert.equal(dryUsdc.protocol, "x402");
  assert.equal(dryUsdc.rail, "usdc");
  assert.equal(dryUsdc.payable, true);

  // Step F: Pay HTTP 402 via L402 (`WWW-Authenticate: L402`)
  const paidL402 = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    url: "https://l402.example.com/secret",
    max_sats: 1000,
    request_id: "pay-l402-1",
  });
  assert.equal(paidL402.ok, true, JSON.stringify(paidL402));
  assert.equal(paidL402.status, "done");
  assert.equal(paidL402.protocol, "l402");
  assert.equal(paidL402.rail, "lightning");
  assert.equal(paidL402.preimage, l402Secret.preimageHex);
  assert.equal(JSON.parse(paidL402.resource.body).data, "l402-unlocked");

  // Idempotent replay with same `request_id` does not pay a second time
  const arkTxCountBeforeReplay = arkState.submittedArkTxs.length;
  const replayL402 = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    url: "https://l402.example.com/secret",
    max_sats: 1000,
    request_id: "pay-l402-1",
  });
  assert.deepEqual(replayL402, paidL402);
  assert.equal(arkState.submittedArkTxs.length, arkTxCountBeforeReplay);

  // Step G: Pay HTTP 402 via Lightning MPP (`WWW-Authenticate: Payment` method="lightning")
  const paidMppLn = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    url: "https://mpp-ln.example.com/data",
    max_sats: 800,
    request_id: "pay-mppln-1",
  });
  assert.equal(paidMppLn.ok, true);
  assert.equal(paidMppLn.protocol, "mpp-lightning");
  assert.equal(paidMppLn.rail, "lightning");
  assert.equal(paidMppLn.preimage, mppLnSecret.preimageHex);
  assert.equal(JSON.parse(paidMppLn.resource.body).data, "mpp-lightning-unlocked");

  // Step H: Pay HTTP 402 via x402 (`PAYMENT-REQUIRED` ERC-1271 2-of-4 Safe EIP-3009)
  const paidX402 = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    url: "https://x402.example.com/report",
    max_amount: "0.50",
    request_id: "pay-x402-1",
  });
  assert.equal(paidX402.ok, true);
  assert.equal(paidX402.protocol, "x402");
  assert.equal(paidX402.rail, "usdc");
  assert.equal(JSON.parse(paidX402.resource.body).report, "x402-paid-ok");
  assert.equal(chainState.safeDeployed, true);

  // Over-cap check (`max_amount` < invoice) refuses cleanly with NEW request_id instruction
  const overCap = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    url: "https://x402.example.com/report",
    max_amount: "0.05",
    request_id: "pay-overcap-1",
  });
  assert.equal(overCap.ok, false);
  assert.match(overCap.error, /NEW request_id and a higher max_amount/);

  // Tempo MPP offers (chain 4217/42431) must be selectable by the PRF payer
  {
    const tempoHeaders = new Headers({ "www-authenticate": Challenge.serialize(mppTempoChallenge) });
    const tempoOffers = parseMppChallenges({ headers: tempoHeaders });
    assert.equal(tempoOffers.length, 1);
    assert.equal(tempoOffers[0].method, "tempo");
    assert.equal(Number(tempoOffers[0].chainId), 4217);
    const picked = selectMppOffer(tempoOffers, { chainIds: [BASE_CHAIN_ID, ...TEMPO_CHAIN_IDS] });
    assert.equal(picked.method, "tempo");
    assert.equal(Number(picked.chainId), 4217);
    assert.equal(String(picked.asset).toLowerCase(), PATHUSD_ADDRESS.toLowerCase());
    const dual = parseMppChallenges({
      headers: new Headers({
        "www-authenticate": `${Challenge.serialize(mppEvmChallenge)}, ${Challenge.serialize(mppTempoChallenge)}`,
      }),
    });
    const dualPick = selectMppOffer(dual, { chainIds: [BASE_CHAIN_ID, ...TEMPO_CHAIN_IDS] });
    assert.equal(dualPick.method, "evm"); // charge intent + lowest index first

    // Zero-amount Tempo credit-proof challenge (e.g. treg.to) must sign EIP-712 proof without hopping
    const mppTempoProofChallenge = Challenge.from({
      id: "chal-tempo-proof-0",
      realm: "treg.to",
      method: "tempo",
      intent: "charge",
      request: {
        amount: "0",
        currency: PATHUSD_ADDRESS,
        recipient: "0x7777777777777777777777777777777777777777",
        methodDetails: { chainId: 4217, decimals: 6 },
      },
    });
    const mppTempoPaidChallenge = Challenge.from({
      id: "chal-tempo-paid-1",
      realm: "treg.to",
      method: "tempo",
      intent: "charge",
      request: {
        amount: "110000",
        currency: PATHUSD_ADDRESS,
        recipient: "0x7777777777777777777777777777777777777777",
        methodDetails: { chainId: 4217, decimals: 6 },
      },
    });
    const proofOffers = parseMppChallenges({
      headers: new Headers({ "www-authenticate": Challenge.serialize(mppTempoProofChallenge) }),
    });
    const testTempoAgentPriv = "11".repeat(32);
    const testTempoAgent = privateKeyToAccount(`0x${testTempoAgentPriv}`);
    let zeroHopCalls = 0;
    let capturedAuth = null;
    const proofRes = await payMppCharge({
      offer: proofOffers[0],
      agent: testTempoAgent,
      feeReserve: 2_000_000n,
      hop: async () => { zeroHopCalls += 1; },
      getClient: () => ({ chain: { id: 4217 } }),
      fetchPaid: async (auth) => {
        capturedAuth = auth;
        return new Response(JSON.stringify({ ok: true, credit: true }), { status: 200 });
      },
    });
    assert.equal(zeroHopCalls, 0, "zero-amount MPP credit proof must not hop on-chain");
    assert.match(String(capturedAuth || ""), /^Payment /);
    assert.equal(proofRes.response.status, 200);

    // Two-step Tempo credit-proof -> 402 credit_insufficient -> paid challenge flow
    let tregStep = 0;
    const tregPayer = createPrfHttp402Payer({
      safeRuntime: {
        publicClient: { readContract: async () => 0n },
        clientForChain: () => ({ chain: { id: 4217 } }),
        readUsdcBalanceUnits: async () => 5_000_000n, // funded on Base, NOT Tempo
        readTokenBalanceUnits: async () => 0n,       // 0 on Tempo
        transferToken: async () => { throw new Error("must_not_hop_when_unfunded"); },
      },
      merchantFetch: async (_url, { headers }) => {
        tregStep += 1;
        if (!headers.Authorization) {
          return {
            status: 402,
            headers: {
              "www-authenticate": `${Challenge.serialize(mppTempoProofChallenge)}, ${Challenge.serialize(mppTempoPaidChallenge)}`,
            },
            bytes: Buffer.from('{"detail":{"error":"payment_required"}}'),
          };
        }
        return {
          status: 402,
          headers: { "www-authenticate": Challenge.serialize(mppTempoPaidChallenge) },
          bytes: Buffer.from('{"detail":{"error":"credit_insufficient"}}'),
        };
      },
    });
    const fakeWalletRec = {
      credIdB64u: "cred-tempo-1",
      slotIndex: 0,
      mainEoa: MAIN_WALLET_ACCOUNT.address,
      passkeySignerAddress: "0x1111111111111111111111111111111111111111",
      agentEthEoa: testTempoAgent.address,
      cosignerEoa: "0x3333333333333333333333333333333333333333",
      safeAddress: "0x4444444444444444444444444444444444444444",
    };
    const tregDry = await tregPayer.payHttpResource({
      walletRecord: fakeWalletRec,
      secrets: { agentEthPrivHex: testTempoAgentPriv },
      url: "https://treg.example.com/call/test",
      maxAmountUnits: 200_000n,
      dryRun: true,
      opId: "treg-dry",
    });
    assert.equal(tregDry.amount_units, "110000");
    assert.equal(tregDry.available_units, "0");
    assert.equal(tregDry.payable, false);

    // Real pay: tries free amount=0 proof first, then enforces cap on follow-up 402
    tregStep = 0;
    await assert.rejects(
      () => tregPayer.payHttpResource({
        walletRecord: fakeWalletRec,
        secrets: { agentEthPrivHex: testTempoAgentPriv },
        url: "https://treg.example.com/call/test",
        maxAmountUnits: 50_000n,
        opId: "treg-cap",
      }),
      (err) => err.code === "over_max_amount" && err.invoiceUnits === "110000",
    );
    assert.equal(tregStep, 2, "must submit free amount=0 proof before receiving paid 402");

    // Within cap, 0 Tempo balance without bridge fails cleanly with insufficient_tempo_balance before any hop
    await assert.rejects(
      () => tregPayer.payHttpResource({
        walletRecord: fakeWalletRec,
        secrets: { agentEthPrivHex: testTempoAgentPriv },
        url: "https://treg.example.com/call/test",
        maxAmountUnits: 200_000n,
        opId: "treg-bal",
      }),
      (err) => err.code === "insufficient_tempo_balance",
    );

    // With ensureRailFunded (Base USDC -> Tempo Relay bridge), dry_run reports cross_rail payable
    let relayBridgeCalls = [];
    const tregBridgedPayer = createPrfHttp402Payer({
      safeRuntime: {
        publicClient: { readContract: async () => 0n },
        clientForChain: () => ({ chain: { id: 4217 } }),
        readUsdcBalanceUnits: async () => 560_000n, // funded on Base
        readTokenBalanceUnits: async () => 0n,      // 0 on Tempo
        transferToken: async () => { throw new Error("must_not_hop_when_relay_bridges_to_eoa"); },
      },
      ensureRailFunded: async (req) => {
        relayBridgeCalls.push(req);
        return { from: "base_usdc", to: "tempo", provider: "relay", sent_usdc: "0.18", received_tempo_units: String(req.neededTotalUnits) };
      },
      merchantFetch: async (_url, { headers }) => {
        if (!headers.Authorization) {
          return {
            status: 402,
            headers: {
              "www-authenticate": `${Challenge.serialize(mppTempoProofChallenge)}, ${Challenge.serialize(mppTempoPaidChallenge)}`,
            },
            bytes: Buffer.from('{"detail":{"error":"payment_required"}}'),
          };
        }
        return {
          status: 402,
          headers: { "www-authenticate": Challenge.serialize(mppTempoPaidChallenge) },
          bytes: Buffer.from('{"detail":{"error":"credit_insufficient"}}'),
        };
      },
    });
    const tregDryBridged = await tregBridgedPayer.payHttpResource({
      walletRecord: fakeWalletRec,
      secrets: { agentEthPrivHex: testTempoAgentPriv },
      url: "https://treg.example.com/call/test",
      maxAmountUnits: 200_000n,
      dryRun: true,
      opId: "treg-dry-bridge",
    });
    assert.equal(tregDryBridged.amount_units, "110000");
    assert.equal(tregDryBridged.cross_rail, true);
    assert.equal(tregDryBridged.funded_from, "base_usdc");
    assert.equal(tregDryBridged.payable, true);
  }
  // Step I: Pay HTTP 402 via EVM MPP (Safe -> Agent EOA hop + stock `mppx`)
  const paidMppEvm = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    url: "https://mpp-evm.example.com/compute",
    max_amount: "0.25",
    request_id: "pay-mppevm-1",
  });

  assert.equal(paidMppEvm.ok, true);
  assert.equal(paidMppEvm.rail, "usdc");
  assert.equal(JSON.parse(paidMppEvm.resource.body).compute, "mpp-evm-paid-ok");

  // Step I2: LNURL handle on nuriwallet.com — register, public serve, callback invoice
  {
    const registered = await walletTool.call({
      action: "receive",
      wallet_key: walletKey,
      lnurl_username: "nuri-agents-rock",
    });
    assert.equal(registered.ok, true);
    assert.equal(registered.rail, "lnurl");
    assert.equal(registered.lnurl, "nuri-agents-rock@nuriwallet.com");

    // Second wallet cannot take the same username; same wallet re-registers fine.
    const taken = await walletTool.call({ action: "receive", wallet_key: walletKey, lnurl_username: "nuri-agents-rock" });
    assert.equal(taken.ok, true);

    const served = await walletTool.call({ action: "lnurl", lnurl_username: "nuri-agents-rock" });
    assert.equal(served.ok, true);
    assert.equal(served.payRequest.status, "OK");
    assert.equal(served.payRequest.tag, "payRequest");
    assert.equal(served.payRequest.callback, "https://nuriwallet.com/lnurl/callback/nuri-agents-rock");
    assert.equal(served.payRequest.minSendable, 340000);
    assert.match(served.payRequest.metadata, /nuri-agents-rock@nuriwallet\.com/);

    const cb = await walletTool.call({ action: "lnurl", lnurl_username: "nuri-agents-rock", lnurl_op: "callback", amount_msat: 500000 });
    assert.equal(cb.ok, true);
    assert.ok(cb.pr.startsWith("lnbc"), `callback returned a BOLT11 invoice: ${String(cb.pr).slice(0, 24)}…`);
    assert.equal(cb.amount_sats, 500);
    assert.match(cb.request_id, /^lnurlp:nuri-agents-rock:/);

    const unknown = await walletTool.call({ action: "lnurl", lnurl_username: "nobody" });
    assert.equal(unknown.ok, false);
    assert.equal(unknown.status, 404);

    // Bad amounts rejected cleanly
    const bad = await walletTool.call({ action: "lnurl", lnurl_username: "nuri-agents-rock", lnurl_op: "callback", amount_msat: 500 });
    assert.equal(bad.ok, false);
    assert.match(bad.error, /millisatoshis/);
  }


  const paidBolt = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    invoice: directBoltInvoice,
    max_sats: 600,
    request_id: "pay-bolt-1",
  });
  assert.equal(paidBolt.ok, true);
  assert.equal(paidBolt.rail, "lightning");
  assert.equal(paidBolt.preimage, directBoltSecret.preimageHex);

  const paidLnAddr = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: "alice@pay.walletofsatoshi.com",
    amount_sats: 450,
    request_id: "pay-lnaddr-1",
  });
  assert.equal(paidLnAddr.ok, true);
  assert.equal(paidLnAddr.rail, "lightning");
  assert.equal(paidLnAddr.preimage, lnAddrSecret.preimageHex);

  const destArk = new ArkAddress(
    ARK_SERVER_XONLY,
    new VtxoScript([MultisigTapscript.encode({ pubkeys: [ARK_SERVER_XONLY] }).script]).tweakedPublicKey,
    network.hrp,
  ).encode();
  const paidArk = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: destArk,
    amount_sats: 700,
    request_id: "pay-ark-1",
  });
  assert.equal(paidArk.ok, true);
  assert.equal(paidArk.rail, "arkade");
  assert.equal(paidArk.amount_sats, 700);

  const recipient0x = "0x5555555555555555555555555555555555555555";
  const paidUsdcSend = await walletTool.call({
    action: "pay",
    wallet_key: walletKey,
    to: recipient0x,
    amount: "1.25",
    request_id: "pay-usdc-1",
  });
  assert.equal(paidUsdcSend.ok, true);
  assert.equal(paidUsdcSend.rail, "usdc");
  assert.equal(paidUsdcSend.receipt.amount, "1.25");
  assert.equal(chainState.balances.get(getAddress(recipient0x)), 1_250_000n);

  // Verify `payFee` helper for v2 PRF wallet_key
  const feePaid = await walletTool.payFee({
    who: { wallet_key: walletKey },
    amountUnits: "50000",
    payTo: "0x6666666666666666666666666666666666666666",
    reference: "tool-call-1",
  });
  assert.equal(feePaid.status, "paid");
  assert.equal(feePaid.payer, safeAddress);

  // Step K: `wallet history` returns dual-rail items
  const hist = await walletTool.call({ action: "history", wallet_key: walletKey });
  assert.equal(hist.ok, true);
  assert.ok(hist.history.length >= 8, `expected >= 8 history entries, got ${hist.history.length}`);
  const railsSeen = new Set(hist.history.map((h) => h.rail));
  assert.equal(railsSeen.has("lightning"), true);
  assert.equal(railsSeen.has("arkade"), true);
  assert.equal(railsSeen.has("usdc"), true);

  // Step L: Legacy v1 Privy `wallet_key` coexistence
  const legBal = await walletTool.call({ action: "balance", wallet_key: legacyWalletKey });
  assert.equal(legBal.ok, true);
  assert.equal(legBal.available, "4.2");
  assert.equal(legBal.address, "0x9999999999999999999999999999999999999999");

  const legHist = await walletTool.call({ action: "history", wallet_key: legacyWalletKey });
  assert.equal(legHist.ok, true);
  assert.equal(legHist.history.length, 1);
  assert.ok(legacyCalls > 0);

  // Step M: Verify NuriAgentVtxoScript 3-leaf structure & Lightning Receive HKDF determinism
  const s1 = deriveLightningReceiveSecrets(vector.slot0.btc_sk_hex, "rfq-deterministic-check");
  const s2 = deriveLightningReceiveSecrets(vector.slot0.btc_sk_hex, "rfq-deterministic-check");
  assert.equal(s1.paymentHash, s2.paymentHash);
  assert.equal(hex.encode(s1.claimXonly), hex.encode(s2.claimXonly));

  const vtxoScript = new NuriAgentVtxoScript({
    aggregatedXonly: "11".repeat(32),
    agentClientXonly: "22".repeat(32),
    serverXonly: ARK_SERVER_XONLY,
    exitTimelock: 605184n,
  });
  assert.equal(vtxoScript.leaves.length, 3);

  // Step N: Store immutability (`wallet_custody_mismatch`) + retryable/expiring `popIssuedGrantWalletKey`
  {
    const memStore = openPrfAgentWalletStore({
      path: ":memory:",
      encryptionKey: process.env.AGENT_KERNEL_ENCRYPTION_KEY,
    });
    try {
      const baseNow = 1_800_000_000_000;
      const baseSession = memStore.createGrantSession({
        requestId: "req-retry-key",
        connectSessionId: "conn-retry-key",
        slotIndex: 0,
        replyPubkey: "aa".repeat(32),
        replySkHex: "bb".repeat(32),
        policy: { max_usdc_per_tx: "5" },
        approvalUrl: "https://connect.nuri.com/approve?session_id=conn-retry-key",
        expiresAt: new Date(baseNow + 60_000).toISOString(),
        nowMs: baseNow,
      });
      assert.equal(baseSession.status, "pending");

      const baseWalletArgs = {
        requestId: "req-retry-key",
        credIdB64u: "cred-immutable-1",
        slotIndex: 0,
        mainEoa: MAIN_WALLET_ACCOUNT.address,
        passkeySignerAddress: "0x1111111111111111111111111111111111111111",
        agentEthEoa: "0x2222222222222222222222222222222222222222",
        cosignerEoa: "0x3333333333333333333333333333333333333333",
        safeAddress: "0x4444444444444444444444444444444444444444",
        agentBtcPub33Hex: `02${"11".repeat(32)}`,
        cosignerBtcPub33Hex: `03${"22".repeat(32)}`,
        aggregatedBtcXonlyHex: "33".repeat(32),
        arkadeAddress: "ark1originaladdress00000000000000000000000000000000000000000",
        policy: { max_usdc_per_tx: "5" },
        agentEthPrivHex: "44".repeat(32),
        agentBtcPrivHex: "55".repeat(32),
        nowMs: baseNow,
      };
      const orig = memStore.finalizeGrantWallet(baseWalletArgs);

      // Repeated polls of the same approved request_id before expires_at MUST keep returning wallet_key
      assert.equal(memStore.getGrantSession("req-retry-key", baseNow).hasIssuedWalletKey, true);
      assert.equal(memStore.popIssuedGrantWalletKey("req-retry-key", { nowMs: baseNow + 1_000 }), orig.walletKey);
      assert.equal(memStore.popIssuedGrantWalletKey("req-retry-key", { nowMs: baseNow + 30_000 }), orig.walletKey);
      assert.equal(memStore.getGrantSession("req-retry-key", baseNow + 30_000).hasIssuedWalletKey, true);

      // After expires_at, popIssuedGrantWalletKey wipes issued_wallet_key_sealed and returns null
      assert.equal(memStore.getGrantSession("req-retry-key", baseNow + 60_001).hasIssuedWalletKey, false);
      assert.equal(memStore.popIssuedGrantWalletKey("req-retry-key", { nowMs: baseNow + 60_001 }), null);
      assert.equal(memStore.getGrantSession("req-retry-key", baseNow).hasIssuedWalletKey, false);

      // connect.nuri.com no-deadline sentinel (expires_at: 0) must not parse as expired (Jan 1, 2000)
      const noDeadline = memStore.createGrantSession({
        requestId: "req-no-deadline",
        connectSessionId: "conn-no-deadline",
        slotIndex: 0,
        replyPubkey: "aa".repeat(32),
        replySkHex: "bb".repeat(32),
        policy: { max_usdc_per_tx: "5" },
        approvalUrl: "https://connect.nuri.com/signature/conn-no-deadline",
        expiresAt: 0,
        nowMs: baseNow,
      });
      assert.equal(noDeadline.expiresAtMs, Number.POSITIVE_INFINITY);

      // Finalizing the same (cred_id_b64u, slot_index) with identical custody fields preserves wallet_id
      const sameCustody = memStore.finalizeGrantWallet({
        ...baseWalletArgs,
        requestId: null,
        policy: { max_usdc_per_tx: "10" },
        nowMs: baseNow + 2_000,
      });
      assert.equal(sameCustody.wallet.walletId, orig.wallet.walletId);
      assert.equal(sameCustody.walletKey, orig.walletKey);

      // Attempting to finalize existing (cred_id_b64u, slot_index) with mismatched safe_address MUST throw
      // `wallet_custody_mismatch` and MUST NOT overwrite the DB row!
      assert.throws(
        () =>
          memStore.finalizeGrantWallet({
            ...baseWalletArgs,
            requestId: null,
            safeAddress: "0x9999999999999999999999999999999999999999",
            nowMs: baseNow + 3_000,
          }),
        (err) => err?.code === "wallet_custody_mismatch" && /wallet_custody_mismatch.*safe_address/.test(err.message),
      );
      assert.throws(
        () =>
          memStore.finalizeGrantWallet({
            ...baseWalletArgs,
            requestId: null,
            arkadeAddress: "ark1differentaddress0000000000000000000000000000000000000000",
            nowMs: baseNow + 3_000,
          }),
        (err) => err?.code === "wallet_custody_mismatch" && /wallet_custody_mismatch.*arkade_address/.test(err.message),
      );

      // Verify persisted row and sealed secrets remain 100% untouched
      const unchanged = memStore.getWalletById(orig.wallet.walletId);
      assert.equal(unchanged.safeAddress, baseWalletArgs.safeAddress);
      assert.equal(unchanged.arkadeAddress, baseWalletArgs.arkadeAddress);
      assert.equal(unchanged.mainEoa, baseWalletArgs.mainEoa);
      const unlocked = memStore.unlockWalletSecrets(orig.walletKey);
      assert.equal(unlocked.wallet.walletId, orig.wallet.walletId);
      assert.equal(unlocked.secrets.agentEthPrivHex, baseWalletArgs.agentEthPrivHex);
    } finally {
      memStore.close();
    }
  }

  // Step O: Arkade ASP signer rotation — `listSpendableVtxos` scans `info.deprecatedSigners` scripts too!
  {
    const depSignerPriv = hex.decode("88".repeat(32));
    const depSignerPub33Hex = hex.encode(secp256k1.getPublicKey(depSignerPriv, true));
    const depSignerXonly = toXOnly(hex.decode(depSignerPub33Hex));
    const walletRec = {
      aggregatedBtcXonlyHex: "11".repeat(32),
      agentBtcPub33Hex: `02${"22".repeat(32)}`,
    };
    const activeScript = new NuriAgentVtxoScript({
      aggregatedXonly: walletRec.aggregatedBtcXonlyHex,
      agentClientXonly: "22".repeat(32),
      serverXonly: ARK_SERVER_XONLY,
      exitTimelock: 605184n,
    });
    const depScript = new NuriAgentVtxoScript({
      aggregatedXonly: walletRec.aggregatedBtcXonlyHex,
      agentClientXonly: "22".repeat(32),
      serverXonly: depSignerXonly,
      exitTimelock: 605184n,
    });
    const activePkHex = hex.encode(activeScript.pkScript);
    const depPkHex = hex.encode(depScript.pkScript);
    assert.notEqual(activePkHex, depPkHex);

    const seenScripts = [];
    const rotatedRuntime = createAgentArkadeRuntime({
      env: process.env,
      operatorProvider: {
        getInfo: async () => ({
          ...(await fakeOperator.getInfo()),
          deprecatedSigners: [{ pubkey: depSignerPub33Hex, cutoffDate: 0n }],
        }),
      },
      indexerProvider: {
        getVtxos: async ({ scripts }) => {
          seenScripts.push(...scripts);
          const vtxos = [];
          if (scripts.includes(activePkHex)) {
            vtxos.push({ txid: "a1".repeat(32), vout: 0, value: 1_000, isSpent: false, script: activePkHex });
          }
          if (scripts.includes(depPkHex)) {
            vtxos.push({ txid: "d2".repeat(32), vout: 1, value: 2_500, isSpent: false, script: depPkHex });
          }
          return { vtxos };
        },
      },
    });
    const listed = await rotatedRuntime.listSpendableVtxos(walletRec);
    assert.equal(seenScripts.includes(activePkHex), true);
    assert.equal(seenScripts.includes(depPkHex), true);
    assert.equal(listed.totalSats, 3_500n);
    assert.equal(listed.coins.length, 2);
    const depCoin = listed.coins.find((c) => c.txid === "d2".repeat(32));
    assert.ok(depCoin);
    assert.equal(hex.encode(depCoin.tapTree), hex.encode(depScript.encode()));
    assert.notEqual(hex.encode(depCoin.tapTree), hex.encode(activeScript.encode()));
  }

  // Verify L402 & Lightning MPP header parsers directly
  const parsedL402 = parseL402Challenge({
    "www-authenticate": `LSAT macaroon="abc123==", invoice="${l402Invoice}"`,
  });
  assert.equal(parsedL402.scheme, "LSAT");
  assert.equal(parsedL402.macaroon, "abc123==");
  const parsedMppLn = parseLightningMppChallenges({
    "www-authenticate": Challenge.serialize(mppLnChallenge),
  });
  assert.equal(parsedMppLn.length, 1);
  assert.equal(parsedMppLn[0].invoice, mppLnInvoice);
  assert.equal(
    classifyHttp402Response({
      headers: { "www-authenticate": Challenge.serialize(mppLnChallenge) },
      bodyText: "",
      decodeBolt11,
    })?.kind,
    "mpp-lightning",
  );

  walletTool.close();
  console.log(
    "prf arkade v2 check ok: frozen vectors, connect agent_grant, 2-of-4 Safe (x402 + MPP + 0x + payFee + Tempo MPP selection), 2-of-2 MuSig2 Arkade + Lightning Intents (L402 + Lightning MPP + BOLT11 + LNURL + pushClaim), nuriwallet.com LNURL handles, and legacy v1 coexistence verified",
  );
} finally {
  Object.keys(process.env).forEach((k) => {
    if (!(k in savedEnv)) delete process.env[k];
  });
  Object.assign(process.env, savedEnv);
  globalThis.fetch = realFetch;
  await new Promise((resolve) => mockHttpServer.close(resolve));
  rmSync(tmpDir, { recursive: true, force: true });
}
