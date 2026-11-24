// Offline E2E proof for Muun-model Pure-L1 2-of-2 MuSig2+CSV Agent Wallet +
// Server-Only Arkade 0-Conf Lightning Fronter (with LEND, COLLECT, FulfillFullDebt,
// hold-broadcast anti-RBF, trusted 0-conf chaining, micro-receive auto-sweep, and direct L1 send).
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { bech32, hex } from "@scure/base";
import { NETWORK, SigHash, Transaction, p2tr } from "@scure/btc-signer";
import * as musig2 from "@scure/btc-signer/musig2.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import {
  DEFAULT_L1_CSV,
  createAgentL1FronterRuntime,
  deriveAgentL1Wallet,
  estimateP2trVbytes,
} from "../src/agent-l1-fronter-v2.mjs";
import { createPrfWalletCoordinator } from "../src/mcp-wallet-prf-v2.mjs";
import { openPrfAgentWalletStore } from "../src/prf-agent-wallet-store.mjs";

function bytesToHex(b) {
  return Buffer.from(b).toString("hex").toLowerCase();
}
function hexToBytes(h) {
  return new Uint8Array(Buffer.from(String(h).replace(/^0x/, ""), "hex"));
}
function intToWordsBE(num, len) {
  const out = new Array(len).fill(0);
  let n = BigInt(num);
  for (let i = len - 1; i >= 0; i -= 1) {
    out[i] = Number(n & 31n);
    n >>= 5n;
  }
  return out;
}
function makeBolt11({ amountSats, preimageHex, expiry = 3600 }) {
  const preimage = hexToBytes(preimageHex);
  const paymentHashHex = bytesToHex(sha256(preimage));
  const hrp = `lnbc${BigInt(amountSats) * 10n}n`;
  const tsWords = intToWordsBE(Math.floor(Date.now() / 1000), 7);
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
  return {
    bolt11: bech32.encode(hrp, words, 1024),
    paymentHashHex,
    preimageHex,
  };
}

const TAP_TWEAK_TAG = sha256(new TextEncoder().encode("TapTweak"));
function computeTapTweak(aggXonly, merkleRoot) {
  return sha256(Buffer.concat([TAP_TWEAK_TAG, TAP_TWEAK_TAG, aggXonly, merkleRoot]));
}

async function main() {
  // 1. Keypair setup: user/agent key + cosigner key -> canonical L1 tr(MuSig2(u,s), pk(u)+CSV)
  const agentPriv = hexToBytes("51".repeat(32));
  const agentPub33 = secp256k1.getPublicKey(agentPriv, true);
  const cosignerPriv = hexToBytes("61".repeat(32));
  const cosignerPub33 = secp256k1.getPublicKey(cosignerPriv, true);
  const sorted = musig2.sortKeys([agentPub33, cosignerPub33]);
  const aggXonly = musig2.keyAggExport(musig2.keyAggregate(sorted));

  const l1Wallet = deriveAgentL1Wallet({
    aggregatedBtcXonlyHex: bytesToHex(aggXonly),
    agentBtcPub33Hex: bytesToHex(agentPub33),
    nuriServerCsv: DEFAULT_L1_CSV,
    network: "bitcoin",
  });
  assert.match(l1Wallet.address, /^bc1p/);
  assert.equal(l1Wallet.scriptPubKeyHex.length, 68);

  // Server single L1 hot wallet (for receiving L1 replenishment + sending instant 0-conf L1 payouts)
  const poolL1Priv = hexToBytes("71".repeat(32));
  const poolL1P2tr = p2tr(schnorr.getPublicKey(poolL1Priv), undefined, NETWORK);
  const poolL1ScriptHex = bytesToHex(poolL1P2tr.script);

  // 2. Simulated Bitcoin L1 mempool + Esplora (tracks real finalized L1 transactions & UTXOs)
  const utxosByAddress = new Map([
    [l1Wallet.address, []],
    [poolL1P2tr.address, [{ txid: "99".repeat(32), vout: 0, value: 500_000, confirmed: true }]],
  ]);
  const broadcasts = [];
  const esplora = {
    async listUtxos(addr) {
      return [...(utxosByAddress.get(addr) || [])];
    },
    async estimateFeeRate() {
      return 2; // 2 sat/vB
    },
    async broadcastTx(rawHex) {
      const tx = Transaction.fromRaw(hexToBytes(rawHex), { allowUnknownOutputs: true });
      const txid = tx.id.toLowerCase();
      broadcasts.push({ txid, rawHex, tx });
      // Remove spent inputs from mock UTXO set
      const spentSet = new Set();
      for (let i = 0; i < tx.inputsLength; i += 1) {
        const inp = tx.getInput(i);
        spentSet.add(`${bytesToHex(inp.txid)}:${inp.index}`);
      }
      for (const [addr, list] of utxosByAddress.entries()) {
        utxosByAddress.set(
          addr,
          list.filter((u) => !spentSet.has(`${u.txid}:${u.vout}`)),
        );
      }
      // Credit outputs matching known addresses
      for (let vout = 0; vout < tx.outputsLength; vout += 1) {
        const out = tx.getOutput(vout);
        const sHex = bytesToHex(out.script);
        if (sHex === l1Wallet.scriptPubKeyHex) {
          utxosByAddress.get(l1Wallet.address).push({ txid, vout, value: Number(out.amount), confirmed: false });
        } else if (sHex === poolL1ScriptHex) {
          utxosByAddress.get(poolL1P2tr.address).push({ txid, vout, value: Number(out.amount), confirmed: false });
        }
      }
      return txid;
    },
  };

  // Seed user wallet with 1 confirmed L1 UTXO (100,000 sats)
  const seedTxid = "11".repeat(32);
  utxosByAddress.get(l1Wallet.address).push({
    txid: seedTxid,
    vout: 0,
    value: 100_000,
    confirmed: true,
  });

  // 3. In-process anti-RBF MuSig2 cosigner mock matching nuri-agent-cosigner `/v1/l1/*` contract
  const lockedOutpoints = new Map(); // outpoint -> { op_id, spending_txid, status }
  const trustedOutpoints = new Set();
  const cosignerClient = {
    configured: true,
    origin: "http://127.0.0.1:8794",
    async signL1Psbt({ psbt_b64, nonces, op_id }) {
      const tx = Transaction.fromPSBT(Buffer.from(psbt_b64, "base64"));
      const spendingTxid = tx.id.toLowerCase();
      const prevScripts = [];
      const prevAmounts = [];
      const outpoints = [];
      for (let i = 0; i < tx.inputsLength; i += 1) {
        const inp = tx.getInput(i);
        assert.equal(bytesToHex(inp.witnessUtxo.script), l1Wallet.scriptPubKeyHex);
        assert.ok((inp.sequence ?? 0xffffffff) >= 0xfffffffe, "must be non-RBF sequence");
        const outpoint = `${bytesToHex(inp.txid)}:${inp.index}`;
        const existingLock = lockedOutpoints.get(outpoint);
        if (existingLock && (existingLock.op_id !== op_id || existingLock.spending_txid !== spendingTxid)) {
          const err = new Error(`outpoint ${outpoint} already signed (RBF prevented)`);
          err.status = 409;
          err.code = "outpoint_already_signed";
          throw err;
        }
        // Check confirmed or trusted 0-conf
        const allUserUtxos = utxosByAddress.get(l1Wallet.address) || [];
        const match = allUserUtxos.find((u) => `${u.txid}:${u.vout}` === outpoint);
        if (match && !match.confirmed && !trustedOutpoints.has(outpoint)) {
          const err = new Error("unconfirmed external input rejected");
          err.status = 403;
          err.code = "unconfirmed_external_input";
          throw err;
        }
        outpoints.push(outpoint);
        prevScripts.push(inp.witnessUtxo.script);
        prevAmounts.push(inp.witnessUtxo.amount);
      }
      for (const op of outpoints) {
        lockedOutpoints.set(op, { op_id, spending_txid: spendingTxid, status: "locked" });
      }
      const tweak32 = computeTapTweak(aggXonly, l1Wallet.tapMerkleRoot);
      const signatures = outpoints.map((op, i) => {
        const msg32 = tx.preimageWitnessV1(i, prevScripts, SigHash.DEFAULT, prevAmounts);
        const det = musig2.deterministicSign(
          cosignerPriv,
          hexToBytes(nonces[i].client_pub_nonce),
          sorted,
          msg32,
          [tweak32],
          [true],
        );
        return {
          input_index: i,
          outpoint: op,
          path: "key",
          msg32: bytesToHex(msg32),
          tweak32: bytesToHex(tweak32),
          server_pub_nonce66: bytesToHex(det.publicNonce),
          server_partial32: bytesToHex(det.partialSig),
          server_pubkey: bytesToHex(cosignerPub33),
        };
      });
      const changeOutpoints = [];
      for (let i = 0; i < tx.outputsLength; i += 1) {
        const out = tx.getOutput(i);
        if (bytesToHex(out.script) === l1Wallet.scriptPubKeyHex) {
          changeOutpoints.push({ outpoint: `${spendingTxid}:${i}`, amount_sats: out.amount.toString() });
        }
      }
      return { ok: true, op_id, spending_txid: spendingTxid, outpoints, change_outpoints: changeOutpoints, signatures };
    },
    async markL1Broadcast({ op_id, spending_txid, change_outpoints = [] }) {
      for (const [op, lock] of lockedOutpoints.entries()) {
        if (lock.op_id === op_id && lock.spending_txid === spending_txid) {
          lock.status = "broadcast";
        }
      }
      for (const ch of change_outpoints) trustedOutpoints.add(ch.outpoint);
      return { ok: true };
    },
    async releaseL1Outpoints({ op_id, spending_txid }) {
      for (const [op, lock] of [...lockedOutpoints.entries()]) {
        if (lock.op_id === op_id && lock.spending_txid === spending_txid) {
          if (lock.status === "broadcast") throw new Error("already_broadcast");
          lockedOutpoints.delete(op);
        }
      }
      return { ok: true };
    },
    async registerTrustedL1Outpoint({ outpoint }) {
      trustedOutpoints.add(outpoint);
      return { ok: true };
    },
  };

  // 4. Single Server-Side Arkade Liquidity Pool mock (real preimage checks + real L1 payout tx signing!)
  const invoicePreimages = new Map();
  let failNextLightningSend = false;
  const incomingPaidMap = new Map();
  const serverPool = {
    configured: true,
    l1DepositAddress: poolL1P2tr.address,
    l1DepositScriptHex: poolL1ScriptHex,
    async quoteLightningSend({ bolt11 }) {
      const preimageHex = invoicePreimages.get(bolt11);
      assert.ok(preimageHex, "test invoice registered");
      // Parse sats via lnbc<n*10>n
      const m = /^lnbc(\d+)n/.exec(bolt11);
      const invoiceAmountSats = Number(BigInt(m[1]) / 10n);
      const lnFeeSats = invoiceAmountSats >= 100 ? 10 : 0;
      const serviceFeeSats = invoiceAmountSats >= 100 ? 5 : 0;
      return {
        rfqId: randomBytes(16).toString("hex"),
        invoiceAmountSats,
        lnFeeSats,
        serviceFeeSats,
        totalCostSats: invoiceAmountSats + lnFeeSats + serviceFeeSats,
      };
    },
    async payLightningInvoice({ bolt11, quoteContext }) {
      if (failNextLightningSend) {
        failNextLightningSend = false;
        throw new Error("lightning_route_failed");
      }
      return {
        status: "done",
        preimageHex: invoicePreimages.get(bolt11),
        amountSats: quoteContext.invoiceAmountSats,
        lnFeeSats: quoteContext.lnFeeSats,
        serviceFeeSats: quoteContext.serviceFeeSats,
      };
    },
    async createLightningReceive({ amountSats, rfqId }) {
      const preimageHex = randomBytes(32).toString("hex");
      const inv = makeBolt11({ amountSats, preimageHex });
      const feeSats = amountSats >= 1000 ? 10 : 0;
      return {
        rfqId,
        invoice: inv.bolt11,
        paymentHash: inv.paymentHashHex,
        payAmountSats: amountSats,
        expectedAmountSats: amountSats - feeSats,
        feeSats,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        lockupAddress: "ark1mockpool",
        swapPkScriptHex: "5120" + "ab".repeat(32),
        quoteJson: JSON.stringify({ from_amount: amountSats, to_amount: amountSats - feeSats }),
      };
    },
    async claimLightningReceive({ receiveRecord }) {
      const paidSats = incomingPaidMap.get(receiveRecord.rfqId);
      if (!paidSats) return { status: "pending" };
      return { status: "claimed", claimedSats: paidSats };
    },
    async sendL1Payout({ toScriptHex, amountSats }) {
      const poolUtxos = await esplora.listUtxos(poolL1P2tr.address);
      const u = poolUtxos[0];
      assert.ok(u, "pool has L1 UTXO");
      const feeSats = estimateP2trVbytes(1, 2) * 2;
      const payoutSats = amountSats - feeSats;
      const tx = new Transaction({ version: 2 });
      tx.addInput({
        txid: u.txid,
        index: u.vout,
        sequence: 0xfffffffe,
        witnessUtxo: { script: poolL1P2tr.script, amount: BigInt(u.value) },
        tapInternalKey: poolL1P2tr.tapInternalKey,
      });
      tx.addOutput({ script: hexToBytes(toScriptHex), amount: BigInt(payoutSats) });
      const change = BigInt(u.value) - BigInt(payoutSats) - BigInt(feeSats);
      if (change >= 330n) tx.addOutput({ script: poolL1P2tr.script, amount: change });
      tx.sign(poolL1Priv);
      tx.finalize();
      const rawHex = bytesToHex(tx.extract());
      const txid = await esplora.broadcastTx(rawHex);
      return { txid, vout: 0, payoutSats, feeSats, rawHex };
    },
  };

  // 5. Wire `createAgentL1FronterRuntime` directly into `createPrfWalletCoordinator`!
  const l1Runtime = createAgentL1FronterRuntime({
    cosignerClient,
    ledgerPath: ":memory:",
    esploraClient: esplora,
    serverPool,
    network: "bitcoin",
    lendMaxSats: 5_000,
    maxDebtSats: 10_000,
    l1SettleFloorSats: 5_000,
  });

  const encKey = randomBytes(32).toString("hex");
  const coordinator = createPrfWalletCoordinator({
    path: ":memory:",
    env: { AGENT_KERNEL_ENCRYPTION_KEY: encKey, AGENT_BTC_CUSTODY_MODE: "l1_0conf" },
    cosignerClient,
    arkadeRuntime: l1Runtime,
    safeRuntime: {
      readUsdcBalanceUnits: async () => 0n,
    },
  });

  // Seed one PRF wallet row in coordinator's internal store via a helper walletRecord
  const walletRecord = {
    walletId: "w-l1-test-1",
    credIdB64u: "cred_l1_test_1",
    slotIndex: 0,
    agentBtcPub33Hex: bytesToHex(agentPub33),
    cosignerBtcPub33Hex: bytesToHex(cosignerPub33),
    aggregatedBtcXonlyHex: bytesToHex(aggXonly),
  };

  try {
    // TEST 1: Initial pure-L1 balance (100,000 sats on bc1p..., 0 debt, 0 Arkade VTXOs!)
    const b0 = await l1Runtime.readBalance(walletRecord);
    assert.equal(b0.custodyMode, "l1_0conf");
    assert.equal(b0.btcAddress, l1Wallet.address);
    assert.equal(b0.sats, 100_000n);
    assert.equal(b0.debtSats, 0);
    assert.equal(broadcasts.length, 0);

    // TEST 2: Muun `LEND` — 1-sat + 500-sat outgoing LN payments with ZERO L1 transactions!
    const inv1Sat = makeBolt11({ amountSats: 1, preimageHex: "01".repeat(32) });
    invoicePreimages.set(inv1Sat.bolt11, inv1Sat.preimageHex);
    const pay1 = await l1Runtime.payBolt11Invoice({
      walletRecord,
      agentBtcPrivHex: bytesToHex(agentPriv),
      bolt11: inv1Sat.bolt11,
      opId: "op-1sat-lend",
    });
    assert.equal(pay1.status, "done");
    assert.equal(pay1.settlementMode, "lend");
    assert.equal(pay1.preimageHex, inv1Sat.preimageHex);
    assert.equal(pay1.l1Txid, null);
    assert.equal(broadcasts.length, 0, "1-sat LN send uses Muun LEND -> ZERO L1 tx!");

    const inv500 = makeBolt11({ amountSats: 500, preimageHex: "02".repeat(32) });
    invoicePreimages.set(inv500.bolt11, inv500.preimageHex);
    const pay500 = await l1Runtime.payBolt11Invoice({
      walletRecord,
      agentBtcPrivHex: bytesToHex(agentPriv),
      bolt11: inv500.bolt11,
      opId: "op-500sat-lend",
    });
    assert.equal(pay500.settlementMode, "lend");
    assert.equal(broadcasts.length, 0);
    const bAfterLend = await l1Runtime.readBalance(walletRecord);
    assert.equal(bAfterLend.debtSats, 516); // 1 + (500 + 10 ln + 5 svc)
    assert.equal(bAfterLend.sats, 100_000n - 516n);

    // TEST 3: Muun `FulfillFullDebt` — incoming 200-sat LN cancels debt with ZERO L1 tx!
    const inDebt = await l1Runtime.createLightningReceive({ walletRecord, amountSats: 200, rfqId: "rfq-debt-1" });
    incomingPaidMap.set("rfq-debt-1", 200);
    const claimDebt = await l1Runtime.claimLightningReceive({
      walletRecord,
      receiveRecord: { rfqId: "rfq-debt-1", expectedAmountSats: 200, paymentHash: inDebt.paymentHash },
    });
    assert.equal(claimDebt.status, "claimed");
    assert.equal(claimDebt.settlementMode, "full_debt");
    assert.equal(claimDebt.debtCanceledSats, 200);
    assert.equal(claimDebt.claimTxid, null);
    assert.equal(broadcasts.length, 0, "FulfillFullDebt cancels debt with ZERO L1 tx!");
    assert.equal((await l1Runtime.readBalance(walletRecord)).debtSats, 316);

    // TEST 4: Hold-broadcast on LN failure — 0 L1 tx broadcast, UTXO unlocked, 0 fee lost!
    failNextLightningSend = true;
    const invFail = makeBolt11({ amountSats: 15_000, preimageHex: "03".repeat(32) });
    invoicePreimages.set(invFail.bolt11, invFail.preimageHex);
    await assert.rejects(
      () =>
        l1Runtime.payBolt11Invoice({
          walletRecord,
          agentBtcPrivHex: bytesToHex(agentPriv),
          bolt11: invFail.bolt11,
          opId: "op-ln-fail-hold",
        }),
      /lightning_route_failed/,
    );
    assert.equal(broadcasts.length, 0, "Hold-broadcast: failed LN MUST NOT broadcast L1 tx!");
    assert.equal(lockedOutpoints.size, 0, "Failed LN MUST release cosigner outpoint lock!");

    // TEST 5: Outgoing 0-conf L1 -> LN + Muun `COLLECT` (reuses unlocked UTXO, collects 316 debt!)
    const inv15k = makeBolt11({ amountSats: 15_000, preimageHex: "04".repeat(32) });
    invoicePreimages.set(inv15k.bolt11, inv15k.preimageHex);
    const pay15k = await l1Runtime.payBolt11Invoice({
      walletRecord,
      agentBtcPrivHex: bytesToHex(agentPriv),
      bolt11: inv15k.bolt11,
      opId: "op-15k-collect",
    });
    assert.equal(pay15k.status, "done");
    assert.equal(pay15k.settlementMode, "l1_0conf_collect");
    assert.equal(pay15k.debtCollectedSats, 316);
    assert.equal(pay15k.preimageHex, inv15k.preimageHex);
    assert.equal(broadcasts.length, 1, "Signed L1 tx broadcast ONLY after LN preimage!");
    assert.equal(broadcasts[0].txid, pay15k.l1Txid);
    assert.equal((await l1Runtime.readBalance(walletRecord)).debtSats, 0);

    // Verify idempotent replay returns cached preimage without re-paying or re-broadcasting
    const pay15kReplay = await l1Runtime.payBolt11Invoice({
      walletRecord,
      agentBtcPrivHex: bytesToHex(agentPriv),
      bolt11: inv15k.bolt11,
      opId: "op-15k-collect",
    });
    assert.equal(pay15kReplay.replay, true);
    assert.equal(broadcasts.length, 1);

    // TEST 6: Chained 0-conf spend immediately from unconfirmed cosigned self-change output!
    const inv10k = makeBolt11({ amountSats: 10_000, preimageHex: "05".repeat(32) });
    invoicePreimages.set(inv10k.bolt11, inv10k.preimageHex);
    const pay10k = await l1Runtime.payBolt11Invoice({
      walletRecord,
      agentBtcPrivHex: bytesToHex(agentPriv),
      bolt11: inv10k.bolt11,
      opId: "op-10k-chained-0conf",
    });
    assert.equal(pay10k.status, "done");
    assert.equal(pay10k.settlementMode, "l1_0conf");
    assert.equal(broadcasts.length, 2, "Trusted 0-conf self-change chains immediately!");

    // TEST 7: Incoming LN >= 5,000 sats -> instant 0-conf L1 payout to user bc1p... (spendable immediately!)
    const in12k = await l1Runtime.createLightningReceive({ walletRecord, amountSats: 12_000, rfqId: "rfq-in-12k" });
    incomingPaidMap.set("rfq-in-12k", 11_990);
    const claim12k = await l1Runtime.claimLightningReceive({
      walletRecord,
      receiveRecord: { rfqId: "rfq-in-12k", expectedAmountSats: 11_990, paymentHash: in12k.paymentHash },
    });
    assert.equal(claim12k.status, "claimed");
    assert.equal(claim12k.settlementMode, "l1_0conf_settle");
    assert.ok(claim12k.claimTxid);
    assert.equal(broadcasts.length, 3, "Server L1 hot wallet broadcast instant 0-conf payout to bc1p...");
    assert.ok(trustedOutpoints.has(`${claim12k.claimTxid}:0`), "Incoming L1 payout registered trusted 0-conf!");

    // TEST 8: Tiny incoming LN (< 5,000 sats, 0 debt) -> micro-credit -> auto-sweeps to L1 once >= 5,000!
    const in1k = await l1Runtime.createLightningReceive({ walletRecord, amountSats: 1_000, rfqId: "rfq-micro-1" });
    incomingPaidMap.set("rfq-micro-1", 1_000);
    const c1k = await l1Runtime.claimLightningReceive({
      walletRecord,
      receiveRecord: { rfqId: "rfq-micro-1", expectedAmountSats: 1_000, paymentHash: in1k.paymentHash },
    });
    assert.equal(c1k.settlementMode, "micro_credit");
    assert.equal(c1k.pendingReceiveSats, 1_000);
    assert.equal(broadcasts.length, 3, "Below settle floor -> no L1 tx yet");

    const in4500 = await l1Runtime.createLightningReceive({ walletRecord, amountSats: 4_500, rfqId: "rfq-micro-2" });
    incomingPaidMap.set("rfq-micro-2", 4_500);
    const c4500 = await l1Runtime.claimLightningReceive({
      walletRecord,
      receiveRecord: { rfqId: "rfq-micro-2", expectedAmountSats: 4_500, paymentHash: in4500.paymentHash },
    });
    assert.equal(c4500.settlementMode, "l1_0conf_settle");
    assert.equal(broadcasts.length, 4, "Accumulated 5,500 >= 5,000 floor -> auto-swept to user L1 bc1p...!");
    assert.equal((await l1Runtime.readBalance(walletRecord)).pendingReceiveSats, 0);

    // TEST 9: Direct native on-chain Bitcoin send (1-tx L1 MuSig2, zero SwapKit hop!)
    const extDest = p2tr(schnorr.getPublicKey(hexToBytes("88".repeat(32))), undefined, NETWORK).address;
    const directSend = await l1Runtime.sendOnchainBtc({
      walletRecord,
      agentBtcPrivHex: bytesToHex(agentPriv),
      toBtcAddress: extDest,
      amountSats: 20_000,
      opId: "op-direct-l1-send",
    });
    assert.ok(directSend.txid);
    assert.equal(directSend.to, extDest);
    assert.equal(broadcasts.length, 5);

    // Verify every single broadcast transaction is valid raw Bitcoin serialization with witness!
    for (const b of broadcasts) {
      assert.ok(b.rawHex.length > 100);
      assert.equal(b.tx.id.toLowerCase(), b.txid);
    }

    console.log(
      "l1 0-conf fronter check ok: pure L1 MuSig2+CSV wallet, Muun LEND (1-sat & 500-sat zero-L1-tx), FulfillFullDebt, hold-broadcast abort (0 fee), L1 0-conf + COLLECT, trusted 0-conf change chaining, instant LN->L1 0-conf payout, micro-receive auto-sweep, and direct L1 send verified",
    );
  } finally {
    coordinator.close();
    l1Runtime.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
