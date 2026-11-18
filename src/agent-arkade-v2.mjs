// 2-of-2 MuSig2 Arkade + Arkade Intents (Nostr RFQ, zero Boltz) runtime for
// Nuri Passkey PRF Agent Wallets (`nuri-agent-arkade-v1`).
//
// Script policy (3-leaf Nuri server-decay VtxoScript):
//   Leaf 0 (forfeit): MultisigTapscript([aggregatedXonly, arkadeServerXonly])
//   Leaf 1 (exit):    CSVMultisigTapscript(arkadeExitTimelock, [aggregatedXonly])
//   Leaf 2 (decay):   CSVMultisigTapscript(combinedDecayTimelock, [agentClientXonly])
//
// Normal agent collaborative spends use Leaf 0, co-signed over loopback HTTP by
// `nuri-agent-cosigner` (`/v1/arkade/sign-psbt`). Incoming Lightning receives
// derive a deterministic per-RFQ claim SingleKey via HKDF from `agentBtcPrivHex`
// and sweep solver-funded VHTLCs directly into the 2-of-2 `NuriAgentVtxoScript`
// via `pushClaim` (never consuming cosigner spend limits).
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { schnorr } from "@noble/curves/secp256k1";
import { Script, SigHash } from "@scure/btc-signer";
import * as musig2 from "@scure/btc-signer/musig2.js";
import {
  ArkAddress,
  CSVMultisigTapscript,
  MultisigTapscript,
  RestIndexerProvider,
  RestOperatorProvider,
  SingleKey,
  VtxoScript,
  assertValidServerUnrollScript,
  networkFromOperatorInfo,
  resolveEmulatorPubkey,
  selectVirtualCoins,
  signAndSubmitOffchainTx,
  toXOnly,
} from "@arkade-os/sdk";
import { decodeBolt11 } from "@arkade-os/swap/advanced";
import { nostrRfqTransport } from "@arkade-os/swap/nostr";
import {
  deriveLightningReceive,
  lightningReceiveRequest,
  lightningSendContract,
  lightningSendRequest,
  pushClaim,
  readLockupFate,
  unilateralClaimDelay,
  verifyLockupAddress,
  verifyReceiveInvoice,
} from "@arkade-os/swap/protocol";
import WebSocketImpl from "ws";

if (typeof globalThis.WebSocket === "undefined") {
  globalThis.WebSocket = WebSocketImpl;
}

export const DEFAULT_ARKADE_SERVER_URL = "https://arkade.computer";
export const DEFAULT_ARKADE_NOSTR_RELAYS = ["wss://nostr.arkade.sh"];
export const DEFAULT_ARKADE_SOLVER_PUBKEY =
  "66422c952f8dcb96e4d0c3f049cd1e265b8461b916d9913c65c2494b64b4e3ce";
export const DEFAULT_SERVER_DECAY_OFFSET_SECONDS = 7776256n; // ~90 days (512s-aligned)
export const SEQUENCE_GRANULARITY_SECONDS = 512;

const TAP_LEAF_TAG = sha256(new TextEncoder().encode("TapLeaf"));
const LN_CLAIM_SALT = sha256(new TextEncoder().encode("app:nuri.com|arkade-ln-claim|v1"));

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex").toLowerCase();
}

function hexToBytes(hex) {
  const clean = String(hex || "").trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid_hex");
  }
  return new Uint8Array(Buffer.from(clean, "hex"));
}

export function toArkadeTimelock(rawDelay) {
  const value = BigInt(rawDelay);
  if (value >= 512n) {
    const aligned = value - (value % 512n);
    return { type: "seconds", value: aligned > 0n ? aligned : 512n };
  }
  return { type: "blocks", value: value > 0n ? value : 144n };
}

export function computeTapLeafHash(leafScript, leafVersion = 0xc0) {
  const len = leafScript.length;
  const varint =
    len < 0xfd
      ? [len]
      : len <= 0xffff
        ? [0xfd, len & 0xff, (len >> 8) & 0xff]
        : [0xfe, len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff];
  return sha256(
    Buffer.concat([
      Buffer.from(TAP_LEAF_TAG),
      Buffer.from(TAP_LEAF_TAG),
      Buffer.from([leafVersion, ...varint]),
      Buffer.from(leafScript),
    ]),
  );
}

/**
 * 3-leaf Nuri server-decay 2-of-2 Arkade VtxoScript.
 */
export class NuriAgentVtxoScript extends VtxoScript {
  constructor({
    aggregatedXonly,
    agentClientXonly,
    serverXonly,
    exitTimelock,
    decayOffsetSeconds = DEFAULT_SERVER_DECAY_OFFSET_SECONDS,
  }) {
    const aggPub = toXOnly(
      aggregatedXonly instanceof Uint8Array ? aggregatedXonly : hexToBytes(aggregatedXonly),
      "aggregatedXonly",
    );
    const clientPub = toXOnly(
      agentClientXonly instanceof Uint8Array ? agentClientXonly : hexToBytes(agentClientXonly),
      "agentClientXonly",
    );
    const srvPub = toXOnly(
      serverXonly instanceof Uint8Array ? serverXonly : hexToBytes(serverXonly),
      "serverXonly",
    );
    const exitTl =
      typeof exitTimelock === "object" && exitTimelock !== null
        ? exitTimelock
        : toArkadeTimelock(exitTimelock ?? 605184n);

    const decayTl =
      exitTl.type === "seconds"
        ? {
            type: "seconds",
            value: exitTl.value + (BigInt(decayOffsetSeconds) - (BigInt(decayOffsetSeconds) % 512n)),
          }
        : {
            type: "blocks",
            value: exitTl.value + 12960n,
          };

    const forfeitScript = MultisigTapscript.encode({
      pubkeys: [aggPub, srvPub],
    }).script;
    const exitScript = CSVMultisigTapscript.encode({
      timelock: exitTl,
      pubkeys: [aggPub],
    }).script;
    const decayScript = CSVMultisigTapscript.encode({
      timelock: decayTl,
      pubkeys: [clientPub],
    }).script;

    super([forfeitScript, exitScript, decayScript]);
    this.aggregatedXonly = aggPub;
    this.agentClientXonly = clientPub;
    this.serverXonly = srvPub;
    this.exitTimelock = exitTl;
    this.decayTimelock = decayTl;
    this.forfeitScriptHex = bytesToHex(forfeitScript);
    this.exitScriptHex = bytesToHex(exitScript);
    this.decayScriptHex = bytesToHex(decayScript);
  }

  forfeit() {
    return this.findLeaf(this.forfeitScriptHex);
  }

  exit() {
    return this.findLeaf(this.exitScriptHex);
  }

  decay() {
    return this.findLeaf(this.decayScriptHex);
  }

  address(hrp = "ark") {
    return new ArkAddress(this.serverXonly, this.tweakedPublicKey, hrp).encode();
  }
}

/**
 * Deterministic HKDF derivation for incoming Lightning receive claim secrets.
 * Recoverable solely from `agent_btc_private_key_hex` + `rfqId`.
 */
export function deriveLightningReceiveSecrets(agentBtcPrivHex, rfqId) {
  const privBytes = hexToBytes(agentBtcPrivHex);
  const cleanId = String(rfqId || "").trim();
  if (!cleanId) throw new Error("rfq_id_required");
  try {
    const claimKeyBytes = hkdf(
      sha256,
      privBytes,
      LN_CLAIM_SALT,
      new TextEncoder().encode(`claim-key:${cleanId}`),
      32,
    );
    const preimage = hkdf(
      sha256,
      privBytes,
      LN_CLAIM_SALT,
      new TextEncoder().encode(`preimage:${cleanId}`),
      32,
    );
    const paymentHash = bytesToHex(sha256(preimage));
    const singleKey = SingleKey.fromPrivateKey(claimKeyBytes);
    const claimXonly = schnorr.getPublicKey(claimKeyBytes);
    return {
      rfqId: cleanId,
      preimage,
      preimageHex: bytesToHex(preimage),
      paymentHash,
      claimSingleKey: singleKey,
      claimXonly,
      claimXonlyHex: bytesToHex(claimXonly),
    };
  } finally {
    privBytes.fill(0);
  }
}

function scriptContainsXonly(decodedScript, xonlyHex) {
  if (!Array.isArray(decodedScript)) return false;
  return decodedScript.some((item) => {
    if (!(item instanceof Uint8Array)) return false;
    if (item.length === 32 && bytesToHex(item) === xonlyHex) return true;
    if (item.length === 33 && bytesToHex(item.subarray(1)) === xonlyHex) return true;
    return false;
  });
}

/**
 * `@arkade-os/sdk` Identity backed by 2-of-2 MuSig2 co-signing with `nuri-agent-cosigner`.
 */
export function createCoSignedArkadeIdentity({
  agentBtcPrivHex,
  agentBtcPub33Hex,
  aggregatedBtcXonlyHex,
  credIdB64u,
  index = 0,
  cosignerClient,
  opIdPrefix,
  intent = null,
}) {
  const clientPriv = hexToBytes(agentBtcPrivHex);
  const clientPub33 = hexToBytes(agentBtcPub33Hex);
  const aggXonly = hexToBytes(aggregatedBtcXonlyHex);
  const aggXonlyHex = bytesToHex(aggXonly);
  let signCallSeq = 0;

  async function sign(tx, inputIndexes) {
    const txCpy = tx.clone();
    const prevScripts = [];
    const prevAmounts = [];
    for (let i = 0; i < txCpy.inputsLength; i += 1) {
      const inp = txCpy.getInput(i);
      if (!inp?.witnessUtxo) {
        throw new Error(`arkade_input_missing_witness_utxo:${i}`);
      }
      prevScripts.push(inp.witnessUtxo.script);
      prevAmounts.push(inp.witnessUtxo.amount);
    }

    const allowedIndexes = inputIndexes ? new Set(inputIndexes) : null;
    const jobs = [];
    for (let i = 0; i < txCpy.inputsLength; i += 1) {
      const inp = txCpy.getInput(i);
      const sighashType = inp.sighashType || SigHash.DEFAULT;
      const leaves = Array.isArray(inp.tapLeafScript) ? inp.tapLeafScript : [];
      for (const leaf of leaves) {
        if (!Array.isArray(leaf) || leaf.length < 2) continue;
        const scriptWithVer = leaf[1];
        if (!(scriptWithVer instanceof Uint8Array) || scriptWithVer.length < 2) continue;
        const leafScript = scriptWithVer.subarray(0, -1);
        const leafVersion = scriptWithVer[scriptWithVer.length - 1];
        let decoded;
        try {
          decoded = Script.decode(leafScript);
        } catch {
          continue;
        }
        if (!scriptContainsXonly(decoded, aggXonlyHex)) continue;
        const msg32 = txCpy.preimageWitnessV1(
          i,
          prevScripts,
          sighashType,
          prevAmounts,
          undefined,
          leafScript,
          leafVersion,
        );
        const nonce = musig2.nonceGen(
          clientPub33,
          clientPriv,
          aggXonly,
          msg32,
          randomBytes(32),
        );
        jobs.push({
          inputIndex: i,
          sighashType,
          leafHash: computeTapLeafHash(leafScript, leafVersion),
          msg32,
          secretNonce: nonce.secret,
          publicNonceHex: bytesToHex(nonce.public),
          publicNonce: nonce.public,
          shouldAttach: !allowedIndexes || allowedIndexes.has(i),
        });
      }
    }

    if (jobs.length === 0) return txCpy;

    signCallSeq += 1;
    const psbtB64 = Buffer.from(txCpy.toPSBT()).toString("base64");
    const txDigest = createHash("sha256").update(psbtB64).digest("hex").slice(0, 16);
    const opId = `${opIdPrefix || randomUUID()}:s${signCallSeq}:${txDigest}`;

      const cosigned = await cosignerClient.signArkadePsbt({
        cred_id_b64u: credIdB64u,
        index,
        psbt_b64: psbtB64,
        nonces: jobs.map((j) => ({
          input_index: j.inputIndex,
          client_pub_nonce: j.publicNonceHex,
        })),
        ...(intent && signCallSeq === 1 ? { intent } : {}),
        op_id: opId,
      });

    const sigs = cosigned?.signatures || [];
    if (sigs.length !== jobs.length) {
      throw new Error(`cosigner_signature_count_mismatch:${sigs.length}:${jobs.length}`);
    }

    for (let k = 0; k < jobs.length; k += 1) {
      const job = jobs[k];
      const srv = sigs[k];
      const serverPub33 = hexToBytes(srv.server_pubkey);
      const serverNonce = hexToBytes(srv.server_pub_nonce66);
      const serverPartial = hexToBytes(srv.server_partial32);

      const sortedKeys = musig2.sortKeys([serverPub33, clientPub33]);
      const orderedNonces = sortedKeys.map((pk) =>
        Buffer.compare(Buffer.from(pk), Buffer.from(serverPub33)) === 0
          ? serverNonce
          : job.publicNonce,
      );
      const aggNonce = musig2.nonceAggregate(orderedNonces);
      const session = new musig2.Session(aggNonce, sortedKeys, job.msg32);
      const serverIdx = sortedKeys.findIndex(
        (pk) => Buffer.compare(Buffer.from(pk), Buffer.from(serverPub33)) === 0,
      );
      if (!session.partialSigVerify(serverPartial, orderedNonces, serverIdx)) {
        throw new Error(`cosigner_partial_sig_invalid:${job.inputIndex}`);
      }
      const clientPartial = session.sign(job.secretNonce, clientPriv);
      const orderedPartials = sortedKeys.map((pk) =>
        Buffer.compare(Buffer.from(pk), Buffer.from(serverPub33)) === 0
          ? serverPartial
          : clientPartial,
      );
      const schnorrSig64 = session.partialSigAgg(orderedPartials);
      if (!schnorr.verify(schnorrSig64, job.msg32, aggXonly)) {
        throw new Error(`musig2_combined_sig_invalid:${job.inputIndex}`);
      }
      if (!job.shouldAttach) continue;

      const finalSig =
        job.sighashType && job.sighashType !== SigHash.DEFAULT
          ? new Uint8Array([...schnorrSig64, job.sighashType])
          : schnorrSig64;
      const existing = txCpy.getInput(job.inputIndex).tapScriptSig || [];
      txCpy.updateInput(job.inputIndex, {
        tapScriptSig: [
          ...existing,
          [{ pubKey: aggXonly, leafHash: job.leafHash }, finalSig],
        ],
      });
    }

    return txCpy;
  }

  return {
    sign,
    xOnlyPublicKey: async () => aggXonly,
    compressedPublicKey: async () => new Uint8Array([0x02, ...aggXonly]),
  };
}

function deriveLightningSendLockup({
  quote,
  paymentHash,
  senderPubkey,
  refundPkScript,
  operatorPubkey,
  emulatorPubkey,
  claimDelay,
  hrp,
  now,
}) {
  if (quote.refund_locktime === undefined) {
    throw new Error("lightning_send_quote_missing_refund_locktime");
  }
  const refundWithoutReceiverDelay = quote.profile?.refund_without_receiver_delay;
  if (
    !Number.isSafeInteger(refundWithoutReceiverDelay) ||
    refundWithoutReceiverDelay < claimDelay ||
    refundWithoutReceiverDelay % SEQUENCE_GRANULARITY_SECONDS !== 0
  ) {
    throw new Error("lightning_send_quote_invalid_refund_delay");
  }
  if (refundWithoutReceiverDelay < quote.refund_locktime - now) {
    throw new Error("lightning_send_quote_refund_before_locktime");
  }
  const receiverPkScriptHex = quote.profile?.receiver_pk_script;
  if (!receiverPkScriptHex) {
    throw new Error("lightning_send_quote_missing_receiver_pk_script");
  }
  const contractParams = {
    solverPubkey: toXOnly(hexToBytes(quote.solver_pubkey), "solver key"),
    refundLocktime: quote.refund_locktime,
    operatorPubkey,
    paymentHash,
    claimDelay,
    refundWithoutReceiverDelay,
    emulatorPubkey,
    senderPubkey,
    receiverPkScript: hexToBytes(receiverPkScriptHex),
    refundPkScript,
  };
  const candidates = [undefined, "preTimelockedRefund"].map((legacy) => {
    const script = lightningSendContract({
      ...contractParams,
      ...(legacy !== undefined ? { legacy } : {}),
    });
    const address = new ArkAddress(operatorPubkey, script.tweakedPublicKey, hrp).encode();
    return { script, address, legacy };
  });
  const matchedAddress = verifyLockupAddress(
    quote,
    candidates.map((c) => c.address),
  );
  const matched = candidates.find((c) => c.address === matchedAddress);
  if (!matched) throw new Error("lightning_send_lockup_address_mismatch");
  return {
    address: matched.address,
    swapPkScript: matched.script.pkScript,
    script: matched.script,
    refundLocktime: quote.refund_locktime,
  };
}

/**
 * Resolve a Lightning Address (`alice@domain.com`) via LNURL-pay to a BOLT11 invoice.
 */
export async function resolveLightningAddressInvoice({
  lightningAddress,
  amountSats,
  comment,
  fetchImpl = fetch,
}) {
  const raw = String(lightningAddress || "").trim().replace(/^lightning:/i, "");
  const match = /^([a-z0-9._+-]+)@([a-z0-9.-]+\.[a-z]{2,})$/i.exec(raw);
  if (!match) throw new Error("invalid_lightning_address");
  const [, user, domain] = match;
  const sats = Number(amountSats);
  if (!Number.isSafeInteger(sats) || sats <= 0) {
    throw new Error("lightning_address_requires_positive_amount_sats");
  }
  const metaUrl = `https://${domain}/.well-known/lnurlp/${encodeURIComponent(user)}`;
  const metaRes = await fetchImpl(metaUrl, { headers: { accept: "application/json" } });
  if (!metaRes.ok) throw new Error(`lnurlp_lookup_failed:${metaRes.status}`);
  const meta = await metaRes.json();
  if (meta?.status === "ERROR") throw new Error(`lnurlp_error:${meta.reason || "unknown"}`);
  if (!meta?.callback) throw new Error("lnurlp_missing_callback");
  const amountMsat = BigInt(sats) * 1000n;
  if (meta.minSendable && amountMsat < BigInt(meta.minSendable)) {
    throw new Error(`amount_below_lnurl_min:${Math.ceil(Number(meta.minSendable) / 1000)}`);
  }
  if (meta.maxSendable && amountMsat > BigInt(meta.maxSendable)) {
    throw new Error(`amount_above_lnurl_max:${Math.floor(Number(meta.maxSendable) / 1000)}`);
  }
  const cbUrl = new URL(meta.callback);
  cbUrl.searchParams.set("amount", amountMsat.toString());
  if (comment && meta.commentAllowed && Number(meta.commentAllowed) > 0) {
    cbUrl.searchParams.set("comment", String(comment).slice(0, Number(meta.commentAllowed)));
  }
  const invRes = await fetchImpl(cbUrl.toString(), { headers: { accept: "application/json" } });
  if (!invRes.ok) throw new Error(`lnurlp_callback_failed:${invRes.status}`);
  const invData = await invRes.json();
  if (invData?.status === "ERROR" || !invData?.pr) {
    throw new Error(`lnurlp_invoice_failed:${invData?.reason || "missing_pr"}`);
  }
  return String(invData.pr).trim();
}

export function createAgentArkadeRuntime({
  env = process.env,
  cosignerClient,
  operatorProvider,
  indexerProvider,
  rfqTransportFactory,
  fetchImpl = fetch,
} = {}) {
  const serverUrl = String(env.ARKADE_SERVER_URL || DEFAULT_ARKADE_SERVER_URL).replace(/\/+$/, "");
  const relays = String(env.ARKADE_NOSTR_RELAYS || DEFAULT_ARKADE_NOSTR_RELAYS.join(","))
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const configuredSolverPubkey = String(env.ARKADE_SOLVER_PUBKEY || "").trim() || null;
  const decayOffsetSeconds = BigInt(
    env.ARKADE_DECAY_OFFSET_SECONDS || DEFAULT_SERVER_DECAY_OFFSET_SECONDS,
  );

  const operator = operatorProvider || new RestOperatorProvider(serverUrl);
  const indexer = indexerProvider || new RestIndexerProvider(serverUrl);

  let cachedInfo = null;
  let cachedInfoAt = 0;

  async function getOperatorInfo({ force = false } = {}) {
    if (!force && cachedInfo && Date.now() - cachedInfoAt < 60_000) {
      return cachedInfo;
    }
    cachedInfo = await operator.getInfo();
    cachedInfoAt = Date.now();
    return cachedInfo;
  }

  async function resolveSolverRendezvous(info) {
    if (configuredSolverPubkey) {
      return { relays, solverPubkey: configuredSolverPubkey };
    }
    const network = networkFromOperatorInfo(info);
    const registryName =
      network.hrp === "ark" ? "bitcoin" : info.network === "mutinynet" ? "mutinynet" : "signet";
    try {
      const res = await fetchImpl(
        `https://arkade-os.github.io/solver-registry/${registryName}.json`,
        { headers: { accept: "application/json" } },
      );
      if (res.ok) {
        const reg = await res.json();
        const market = (reg?.markets || []).find(
          (m) =>
            (m.quote_corridor === "lightning" || m.base_corridor === "lightning") &&
            typeof m.discovery_pubkey === "string" &&
            m.discovery_pubkey.length === 64,
        );
        if (market) {
          const marketRelays = market.transports?.nostr?.relays;
          return {
            relays: Array.isArray(marketRelays) && marketRelays.length > 0 ? marketRelays : relays,
            solverPubkey: market.discovery_pubkey,
          };
        }
      }
    } catch {
      // Fall back to default solver pubkey if registry fetch fails.
    }
    return { relays, solverPubkey: DEFAULT_ARKADE_SOLVER_PUBKEY };
  }

  async function withRfqTransport(info, fn) {
    if (rfqTransportFactory) {
      const transport = await rfqTransportFactory(info);
      try {
        return await fn(transport);
      } finally {
        await transport?.close?.();
      }
    }
    const rendezvous = await resolveSolverRendezvous(info);
    const transport = nostrRfqTransport({
      relays: rendezvous.relays,
      solverPubkey: rendezvous.solverPubkey,
    });
    try {
      return await fn(transport);
    } finally {
      await transport?.close?.();
    }
  }

  async function deriveWalletScript(walletRecord) {
    const info = await getOperatorInfo();
    const network = networkFromOperatorInfo(info);
    const serverXonly = toXOnly(hexToBytes(info.signerPubkey), "ark signer key");
    const agentClientXonly = hexToBytes(walletRecord.agentBtcPub33Hex).subarray(1);
    const vtxoScript = new NuriAgentVtxoScript({
      aggregatedXonly: walletRecord.aggregatedBtcXonlyHex,
      agentClientXonly,
      serverXonly,
      exitTimelock: info.unilateralExitDelay,
      decayOffsetSeconds,
    });
    return {
      info,
      network,
      serverXonly,
      vtxoScript,
      address: vtxoScript.address(network.hrp),
      pkScript: vtxoScript.pkScript,
      pkScriptHex: bytesToHex(vtxoScript.pkScript),
    };
  }

  async function listSpendableVtxos(walletRecord) {
    const derived = await deriveWalletScript(walletRecord);
    const { vtxos = [] } = await indexer.getVtxos({
      scripts: [derived.pkScriptHex],
      spendableOnly: true,
    });
    const tapLeafScript = derived.vtxoScript.forfeit();
    const tapTree = derived.vtxoScript.encode();
    const coins = vtxos
      .filter((v) => !v.isSpent && Number(v.value) > 0)
      .map((v) => ({
        ...v,
        value: Number(v.value),
        tapLeafScript,
        tapTree,
      }));
    const totalSats = coins.reduce((sum, v) => sum + BigInt(v.value), 0n);
    return {
      ...derived,
      coins,
      totalSats,
    };
  }

  async function readBalance(walletRecord) {
    const state = await listSpendableVtxos(walletRecord);
    return {
      address: state.address,
      pkScriptHex: state.pkScriptHex,
      sats: state.totalSats,
      vtxoCount: state.coins.length,
    };
  }

  async function sendArkade({
    walletRecord,
    agentBtcPrivHex,
    toArkAddress,
    amountSats,
    opId,
    intent = null,
  }) {
    if (!cosignerClient) throw new Error("cosigner_client_required");
    const amount = Number(amountSats);
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      throw new Error("invalid_amount_sats");
    }
    const state = await listSpendableVtxos(walletRecord);
    const decodedDest = ArkAddress.decode(toArkAddress);
    const dust = Number(state.info.dust || 330n);
    if (amount < dust) {
      throw new Error(`amount_below_dust:${dust}`);
    }
    const selection = selectVirtualCoins(state.coins, amount);
    const outputs = [{ script: decodedDest.pkScript, amount: BigInt(amount) }];
    if (selection.changeAmount > 0n) {
      if (selection.changeAmount >= BigInt(dust)) {
        outputs.push({ script: state.pkScript, amount: selection.changeAmount });
      }
    }

    const serverUnrollScript = assertValidServerUnrollScript(
      state.info.checkpointTapscript,
      state.network,
      toXOnly(hexToBytes(state.info.forfeitPubkey), "forfeit key"),
    );

    const identity = createCoSignedArkadeIdentity({
      agentBtcPrivHex,
      agentBtcPub33Hex: walletRecord.agentBtcPub33Hex,
      aggregatedBtcXonlyHex: walletRecord.aggregatedBtcXonlyHex,
      credIdB64u: walletRecord.credIdB64u,
      index: walletRecord.slotIndex,
      cosignerClient,
      opIdPrefix: opId,
      intent,
    });

    const arkTxid = await signAndSubmitOffchainTx({
      provider: operator,
      inputs: selection.inputs,
      outputs,
      serverUnrollScript,
      identity,
      verifyServerSignatures: {
        serverPubkey: hexToBytes(state.info.signerPubkey),
        deprecatedServerPubkeys: (state.info.deprecatedSigners || []).map((s) => hexToBytes(s.pubkey)),
      },
      // Checkpoint signing happens afterarkTx submission only if needed, avoiding
      // double spend-limit accounting unless checkpoint signing is invoked.
      oneShot: false,
    });

    return {
      arkTxid,
      amountSats: BigInt(amount),
      to: toArkAddress,
      from: state.address,
    };
  }

  async function createLightningReceive({
    walletRecord,
    agentBtcPrivHex,
    amountSats,
    rfqId = randomBytes(16).toString("hex"),
  }) {
    const sats = Number(amountSats);
    if (!Number.isSafeInteger(sats) || sats <= 0) {
      throw new Error("lightning_receive_requires_positive_amount_sats");
    }
    const derivedWallet = await deriveWalletScript(walletRecord);
    const secrets = deriveLightningReceiveSecrets(agentBtcPrivHex, rfqId);
    const operatorPubkey = derivedWallet.serverXonly;
    const emulatorPubkey = toXOnly(
      hexToBytes(resolveEmulatorPubkey(derivedWallet.network, env.ARKADE_EMULATOR_PUBKEY)),
      "emulator signer key",
    );
    const claimDelay = unilateralClaimDelay(Number(derivedWallet.info.unilateralExitDelay));

    const quote = await withRfqTransport(derivedWallet.info, (transport) =>
      transport.requestQuote(
        lightningReceiveRequest({
          rfqId: secrets.rfqId,
          paymentHash: secrets.paymentHash,
          payoutAddress: derivedWallet.address,
          payoutPubkey: secrets.claimXonly,
          amount: sats,
          amountSide: "from",
        }),
      ),
    );

    const derived = deriveLightningReceive({
      quote,
      paymentHash: secrets.paymentHash,
      payoutPubkey: secrets.claimXonly,
      payoutAddress: derivedWallet.address,
      operatorPubkey,
      emulatorPubkey,
      claimDelay,
      hrp: derivedWallet.network.hrp,
    });

    const { payDeadline } = verifyReceiveInvoice({
      invoice: derived.invoice,
      decode: decodeBolt11,
      paymentHash: secrets.paymentHash,
      quote,
    });

    const expectedAmountSats = Number(quote.to_amount);
    const payAmountSats = Number(quote.from_amount);
    if (!Number.isSafeInteger(expectedAmountSats) || expectedAmountSats <= 0) {
      throw new Error("invalid_lightning_receive_quote_amount");
    }

    return {
      rfqId: secrets.rfqId,
      invoice: derived.invoice,
      paymentHash: secrets.paymentHash,
      payAmountSats,
      expectedAmountSats,
      feeSats: Math.max(0, payAmountSats - expectedAmountSats),
      expiresAt: payDeadline,
      lockupAddress: derived.address,
      swapPkScriptHex: bytesToHex(derived.swapPkScript),
      payoutAddress: derivedWallet.address,
      payoutPkScriptHex: derivedWallet.pkScriptHex,
      quoteJson: JSON.stringify(quote),
    };
  }

  async function claimLightningReceive({
    walletRecord,
    agentBtcPrivHex,
    receiveRecord,
  }) {
    const derivedWallet = await deriveWalletScript(walletRecord);
    const secrets = deriveLightningReceiveSecrets(agentBtcPrivHex, receiveRecord.rfqId);
    const quote =
      typeof receiveRecord.quoteJson === "string"
        ? JSON.parse(receiveRecord.quoteJson)
        : receiveRecord.quote;
    const emulatorPubkey = toXOnly(
      hexToBytes(resolveEmulatorPubkey(derivedWallet.network, env.ARKADE_EMULATOR_PUBKEY)),
      "emulator signer key",
    );
    const claimDelay = unilateralClaimDelay(Number(derivedWallet.info.unilateralExitDelay));
    const derived = deriveLightningReceive({
      quote,
      paymentHash: secrets.paymentHash,
      payoutPubkey: secrets.claimXonly,
      payoutAddress: derivedWallet.address,
      operatorPubkey: derivedWallet.serverXonly,
      emulatorPubkey,
      claimDelay,
      hrp: derivedWallet.network.hrp,
    });

    const swapPkScriptHex = bytesToHex(derived.swapPkScript);
    const { vtxos = [] } = await indexer.getVtxos({
      scripts: [swapPkScriptHex],
      spendableOnly: true,
    });
    const live = vtxos
      .filter((v) => !v.isSpent && Number(v.value) > 0)
      .map((v) => ({ ...v, value: Number(v.value), recoverable: Boolean(v.isRecoverable) }));
    if (live.length === 0) {
      const fate = await readLockupFate(indexer, {
        swapPkScript: derived.swapPkScript,
        paymentHash: secrets.paymentHash,
      });
      if (fate.fate === "claimed") {
        return { status: "claimed", alreadyClaimed: true };
      }
      return { status: "pending" };
    }

    const claimRes = await pushClaim(operator, {
      vtxos: live,
      contract: derived.script,
      receiver: secrets.claimSingleKey,
      preimage: secrets.preimage,
      expectedAmount: Number(receiveRecord.expectedAmountSats || quote.to_amount),
      destinationPkScript: derivedWallet.pkScript,
      network: derivedWallet.network,
    });

    return {
      status: "claimed",
      claimTxid: typeof claimRes === "string" ? claimRes : claimRes?.txid || claimRes?.arkTxid || null,
      claimedSats: live.reduce((sum, v) => sum + v.value, 0),
    };
  }

  async function payBolt11Invoice({
    walletRecord,
    agentBtcPrivHex,
    bolt11,
    maxSats,
    opId,
    pollTimeoutMs = 45_000,
    pollIntervalMs = 1_000,
  }) {
    const cleanInvoice = String(bolt11 || "").trim().replace(/^lightning:/i, "");
    const facts = decodeBolt11(cleanInvoice);
    if (!facts.amountSats || facts.amountSats <= 0) {
      throw new Error("amountless_bolt11_not_supported");
    }
    const now = Math.floor(Date.now() / 1000);
    if (facts.expiresAt && now >= facts.expiresAt) {
      throw new Error("bolt11_invoice_expired");
    }
    if (maxSats !== undefined && maxSats !== null && BigInt(facts.amountSats) > BigInt(maxSats)) {
      const err = new Error("invoice_exceeds_max_sats");
      err.code = "over_max_amount";
      err.invoiceSats = facts.amountSats;
      err.maxSats = Number(maxSats);
      throw err;
    }

    const derivedWallet = await deriveWalletScript(walletRecord);
    const rfqId = randomBytes(16).toString("hex");
    const senderPubkey = hexToBytes(walletRecord.aggregatedBtcXonlyHex);

    const quote = await withRfqTransport(derivedWallet.info, (transport) =>
      transport.requestQuote(
        lightningSendRequest({
          rfqId,
          invoice: facts.raw,
          refundAddress: derivedWallet.address,
          senderPubkey,
        }),
      ),
    );

    const fundAmountSats = Number(quote.from_amount);
    const invoiceAmountSats = Number(quote.to_amount);
    if (invoiceAmountSats !== facts.amountSats) {
      throw new Error(`solver_quote_amount_mismatch:${invoiceAmountSats}:${facts.amountSats}`);
    }
    if (fundAmountSats < invoiceAmountSats) {
      throw new Error("solver_quote_negative_fee");
    }
    if (maxSats !== undefined && maxSats !== null && BigInt(fundAmountSats) > BigInt(maxSats)) {
      const err = new Error("total_with_fee_exceeds_max_sats");
      err.code = "over_max_amount";
      err.invoiceSats = fundAmountSats;
      err.maxSats = Number(maxSats);
      throw err;
    }

    const emulatorPubkey = toXOnly(
      hexToBytes(resolveEmulatorPubkey(derivedWallet.network, env.ARKADE_EMULATOR_PUBKEY)),
      "emulator signer key",
    );
    const claimDelay = unilateralClaimDelay(Number(derivedWallet.info.unilateralExitDelay));
    const lockup = deriveLightningSendLockup({
      quote,
      paymentHash: facts.paymentHash,
      senderPubkey,
      refundPkScript: derivedWallet.pkScript,
      operatorPubkey: derivedWallet.serverXonly,
      emulatorPubkey,
      claimDelay,
      hrp: derivedWallet.network.hrp,
      now: Math.floor(Date.now() / 1000),
    });

    const swapPkScriptHex = bytesToHex(lockup.swapPkScript);
    const funded = await sendArkade({
      walletRecord,
      agentBtcPrivHex,
      toArkAddress: lockup.address,
      amountSats: fundAmountSats,
      opId,
      intent: {
        kind: "arkade_lightning_send",
        rfq_id: rfqId,
        payment_hash: facts.paymentHash,
        lockup_script_hex: swapPkScriptHex,
        funding_amount_sats: fundAmountSats,
      },
    });

    const deadline = Date.now() + pollTimeoutMs;
    while (Date.now() <= deadline) {
      const fate = await readLockupFate(indexer, {
        swapPkScript: lockup.swapPkScript,
        paymentHash: facts.paymentHash,
      });
      if (fate.preimage) {
        return {
          status: "done",
          rfqId,
          paymentHash: facts.paymentHash,
          preimageHex: bytesToHex(fate.preimage),
          amountSats: invoiceAmountSats,
          feeSats: fundAmountSats - invoiceAmountSats,
          totalSats: fundAmountSats,
          arkTxid: funded.arkTxid,
          lockupAddress: lockup.address,
        };
      }
      if (fate.fate === "refunded") {
        throw new Error("lightning_send_refunded");
      }
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }

    return {
      status: "pending",
      rfqId,
      paymentHash: facts.paymentHash,
      preimageHex: null,
      amountSats: invoiceAmountSats,
      feeSats: fundAmountSats - invoiceAmountSats,
      totalSats: fundAmountSats,
      arkTxid: funded.arkTxid,
      lockupAddress: lockup.address,
    };
  }

  return {
    serverUrl,
    operator,
    indexer,
    getOperatorInfo,
    deriveWalletScript,
    listSpendableVtxos,
    readBalance,
    sendArkade,
    createLightningReceive,
    claimLightningReceive,
    payBolt11Invoice,
    decodeBolt11,
    resolveLightningAddressInvoice: (opts) =>
      resolveLightningAddressInvoice({ fetchImpl, ...opts }),
  };
}
