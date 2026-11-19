// v2 Nuri Passkey PRF + Dual-Rail (2-of-4 Base Safe USDC + 2-of-2 Arkade/Lightning)
// coordinator for the 4-action MCP `wallet` tool (`balance`, `receive`, `pay`, `history`).
import { randomUUID } from "node:crypto";
import { getAddress } from "viem";
import { isValidArkAddress } from "@arkade-os/sdk";
import { createAgentArkadeRuntime } from "./agent-arkade-v2.mjs";
import { createAgentCosignerClient } from "./agent-cosigner-client.mjs";
import {
  createConnectGrantClient,
  decryptAgentGrantReply,
  generateGrantReplyKeypair,
  verifyAgentGrantProof,
} from "./agent-grant-crypto.mjs";
import { createPrfHttp402Payer } from "./agent-lightning-pay.mjs";
import {
  BASE_USDC_ADDRESS,
  createAgentSafeRuntime,
  deriveFallbackSecondRecoveryAddress,
  predictAgentSafeAddress,
  predictPasskeySignerAddress,
} from "./agent-safe-v2.mjs";
import {
  PRF_WALLET_KEY_RE,
  isPrfWalletKey,
  openPrfAgentWalletStore,
} from "./prf-agent-wallet-store.mjs";
import { decimalToUnits, unitsToDecimal } from "./wallet-units.mjs";

const ETH_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const BOLT11_RE = /^(?:lightning:)?ln(?:bc|tb|bcrt|tbs)[0-9a-z]+$/i;
const LN_ADDRESS_RE = /^(?:lightning:)?[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;
const DECIMAL_AMOUNT_RE = /^(0|[1-9][0-9]{0,71})(\.[0-9]{1,6})?$/;

export const DEFAULT_GRANT_POLICY = Object.freeze({
  max_per_tx_usdc: "25",
  daily_limit_usdc: "100",
  max_per_tx_sats: 100000,
  daily_limit_sats: 500000,
});

function formatSatsAsBtc(sats) {
  const s = BigInt(sats);
  const whole = s / 100_000_000n;
  const frac = (s % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}

function parsePositiveSats(value, label = "amount_sats") {
  if (value === undefined || value === null) return undefined;
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new Error(`${label} must be a positive whole number of satoshis.`);
  }
  return n;
}

function parseUsdcUnits(value, label = "amount") {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || !DECIMAL_AMOUNT_RE.test(value.trim())) {
    throw new Error(`${label} must be written like 0.25 or 10.`);
  }
  return decimalToUnits(value.trim(), 6);
}

export function isPrfCustodyConfigured(env = process.env) {
  return Boolean(
    typeof env.AGENT_COSIGNER_URL === "string" &&
      env.AGENT_COSIGNER_URL.trim() &&
      typeof env.AGENT_COSIGNER_RPC_SECRET === "string" &&
      env.AGENT_COSIGNER_RPC_SECRET.trim() &&
      typeof env.AGENT_KERNEL_ENCRYPTION_KEY === "string" &&
      env.AGENT_KERNEL_ENCRYPTION_KEY.trim(),
  );
}

export function createPrfWalletCoordinator({
  path,
  env = process.env,
  connectClient,
  cosignerClient,
  safeRuntime,
  arkadeRuntime,
  http402Payer,
  merchantFetch,
  fetchImpl = fetch,
} = {}) {
  const configured = isPrfCustodyConfigured(env) || Boolean(cosignerClient);
  let store = null;
  let connect = connectClient || null;
  let cosigner = cosignerClient || null;
  let safe = safeRuntime || null;
  let arkade = arkadeRuntime || null;
  let payer = http402Payer || null;

  function ensureStore() {
    if (!store) {
      store = openPrfAgentWalletStore({
        path,
        encryptionKey: env.AGENT_KERNEL_ENCRYPTION_KEY,
      });
    }
    return store;
  }

  function ensureConnect() {
    if (!connect) {
      connect = createConnectGrantClient({
        baseUrl: env.CONNECT_NURI_URL || "https://connect.nuri.com",
        fetchImpl,
      });
    }
    return connect;
  }

  function ensureCosigner() {
    if (!cosigner) {
      cosigner = createAgentCosignerClient({
        baseUrl: env.AGENT_COSIGNER_URL,
        secret: env.AGENT_COSIGNER_RPC_SECRET,
        fetchImpl,
      });
    }
    return cosigner;
  }

  function ensureSafe() {
    if (!safe) {
      safe = createAgentSafeRuntime({
        env,
        cosignerClient: ensureCosigner(),
      });
    }
    return safe;
  }

  function ensureArkade() {
    if (!arkade) {
      arkade = createAgentArkadeRuntime({
        env,
        cosignerClient: ensureCosigner(),
        fetchImpl,
      });
    }
    return arkade;
  }

  function ensurePayer() {
    if (!payer) {
      payer = createPrfHttp402Payer({
        safeRuntime: ensureSafe(),
        arkadeRuntime: ensureArkade(),
        ...(merchantFetch ? { merchantFetch } : {}),
      });
    }
    return payer;
  }

  async function sweepPendingReceives(walletRecord, agentBtcPrivHex) {
    const db = ensureStore();
    const pending = db.listPendingLightningReceives(walletRecord.walletId);
    if (!pending.length) return [];
    const claimed = [];
    for (const rec of pending) {
      try {
        const res = await ensureArkade().claimLightningReceive({
          walletRecord,
          agentBtcPrivHex,
          receiveRecord: rec,
        });
        if (res.status === "claimed") {
          db.markLightningReceiveClaimed(rec.rfqId, {
            claimTxid: res.claimTxid || null,
            claimedSats: res.claimedSats ?? rec.expectedAmountSats,
          });
          if (!res.alreadyClaimed) {
            db.recordOperation({
              walletId: walletRecord.walletId,
              requestId: rec.requestId || `ln-recv-${rec.rfqId.slice(0, 16)}`,
              action: "receive",
              rail: "lightning",
              status: "done",
              amountDisplay: `${res.claimedSats ?? rec.expectedAmountSats} sats`,
              summary: {
                kind: "receive",
                rail: "lightning",
                amount_sats: res.claimedSats ?? rec.expectedAmountSats,
                tx: res.claimTxid || null,
              },
              result: res,
            });
          }
          claimed.push(rec.rfqId);
        }
      } catch {
        // Non-fatal: pending invoice may still be unpaid or operator unreachable.
      }
    }
    return claimed;
  }

  async function readDualBalances(walletRecord, secrets = null) {
    if (secrets?.agentBtcPrivHex) {
      await sweepPendingReceives(walletRecord, secrets.agentBtcPrivHex);
    }
    const [usdcResult, arkResult] = await Promise.allSettled([
      ensureSafe().readUsdcBalanceUnits(walletRecord.safeAddress),
      ensureArkade().readBalance(walletRecord),
    ]);

    const usdcUnits = usdcResult.status === "fulfilled" ? usdcResult.value : 0n;
    const arkadeState =
      arkResult.status === "fulfilled"
        ? arkResult.value
        : {
            address: walletRecord.arkadeAddress || null,
            sats: 0n,
          };

    if (arkadeState.address && arkadeState.address !== walletRecord.arkadeAddress) {
      ensureStore().updateWalletArkadeAddress(walletRecord.walletId, arkadeState.address);
      walletRecord.arkadeAddress = arkadeState.address;
    }

    return {
      available: unitsToDecimal(String(usdcUnits), 6),
      address: walletRecord.safeAddress,
      owner_address: walletRecord.mainEoa,
      sats: Number(arkadeState.sats),
      btc: formatSatsAsBtc(arkadeState.sats),
      ...(arkadeState.address ? { arkade_address: arkadeState.address } : {}),
    };
  }

  async function startOrPollOnboarding({ requestId, slotIndex = 0, policy = DEFAULT_GRANT_POLICY } = {}) {
    const db = ensureStore();
    if (requestId) {
      const existing = db.getGrantSession(requestId);
      if (existing) {
        if (existing.status === "approved" && existing.walletId) {
          const wallet = db.getWalletById(existing.walletId);
          const issuedKey = db.popIssuedGrantWalletKey(requestId);
          const balances = await readDualBalances(wallet);
          return {
            ok: true,
            status: "done",
            ...(issuedKey ? { wallet_key: issuedKey } : {}),
            ...balances,
            next: issuedKey
              ? "Save wallet_key and send it on every wallet call."
              : "Wallet already connected; use the wallet_key returned earlier.",
          };
        }
        if (existing.status === "expired") {
          return {
            ok: false,
            status: "failed",
            error: "That connect link expired. Call wallet balance with new:true to get a fresh link.",
          };
        }

        const polled = await ensureConnect().readAgentGrantResult({
          sessionId: existing.connectSessionId,
        });
        if (polled?.status === "pending") {
          return {
            ok: true,
            status: "connect_required",
            request_id: existing.requestId,
            approval_url: existing.approvalUrl,
            next: "Open approval_url, approve with your Nuri Passkey, then repeat wallet balance with the same request_id.",
          };
        }
        if (polled?.status !== "approved" || !polled?.result || !polled?.wallet) {
          db.markGrantSessionExpired(existing.requestId);
          return {
            ok: false,
            status: "failed",
            error: "That connect link expired before approval. Call wallet balance with new:true for a fresh link.",
          };
        }

        const replySkHex = db.readGrantSessionReplySk(existing.requestId);
        if (!replySkHex) {
          throw new Error("grant_session_reply_key_missing");
        }
        const mainEoa = getAddress(polled.wallet.eth_user_eoa || polled.result.address);
        const validProof = await verifyAgentGrantProof({
          mainEoa,
          sessionId: existing.connectSessionId,
          replyPubkey: existing.replyPubkey,
          grantResult: polled.result,
        });
        if (!validProof) {
          throw new Error("agent_grant_proof_signature_invalid");
        }

        const decrypted = decryptAgentGrantReply({
          replySkHex,
          sessionId: existing.connectSessionId,
          reply: polled.result,
        });

        const credIdB64u = polled.wallet.cred_id_b64u;
        const credPubkeyB64u = polled.wallet.credential_pubkey_b64u;
        if (!credIdB64u) throw new Error("connect_wallet_missing_cred_id");

        const registered = await ensureCosigner().registerGrant({
          cred_id_b64u: credIdB64u,
          ...(credPubkeyB64u ? { credential_pubkey_b64u: credPubkeyB64u } : {}),
          main_eoa: mainEoa,
          session_id: existing.connectSessionId,
          reply_pubkey: existing.replyPubkey,
          grant_result: polled.result,
        });

        const grant = registered.grant;
        const passkeySignerAddress = grant.passkey_signer_address
          ? getAddress(grant.passkey_signer_address)
          : credPubkeyB64u
            ? predictPasskeySignerAddress(credPubkeyB64u).address
            : deriveFallbackSecondRecoveryAddress({ mainEoa, credIdB64u });

        const agentEthEoa = getAddress(decrypted.public.agent_eth_eoa);
        const agentBtcPub33Hex = String(decrypted.public.agent_btc_public_key_33_hex).toLowerCase();
        const cosignerEoa = getAddress(grant.cosigner_eoa);

        const safePrediction = predictAgentSafeAddress({
          mainEoa,
          passkeySignerAddress,
          agentEoa: agentEthEoa,
          cosignerEoa,
          credIdB64u,
          index: decrypted.index,
        });

        let arkadeAddress = null;
        try {
          const derivedArk = await ensureArkade().deriveWalletScript({
            aggregatedBtcXonlyHex: grant.aggregated_btc_xonly,
            agentBtcPub33Hex,
          });
          arkadeAddress = derivedArk.address;
        } catch {
          arkadeAddress = null;
        }

        const finalized = db.finalizeGrantWallet({
          requestId: existing.requestId,
          credIdB64u,
          slotIndex: decrypted.index,
          mainEoa,
          passkeySignerAddress,
          agentEthEoa,
          cosignerEoa,
          safeAddress: grant.safe_address ? getAddress(grant.safe_address) : safePrediction.safeAddress,
          agentBtcPub33Hex,
          cosignerBtcPub33Hex: grant.cosigner_btc_pk33,
          aggregatedBtcXonlyHex: grant.aggregated_btc_xonly,
          arkadeAddress,
          policy: decrypted.policy || existing.policy || DEFAULT_GRANT_POLICY,
          agentEthPrivHex: decrypted.agent_eth_private_key_hex,
          agentBtcPrivHex: decrypted.agent_btc_private_key_hex,
        });

        const issuedKey = db.popIssuedGrantWalletKey(requestId) || finalized.walletKey;
        const balances = await readDualBalances(finalized.wallet);
        return {
          ok: true,
          status: "done",
          wallet_key: issuedKey,
          ...balances,
          next: "Save wallet_key and send it on every later wallet call.",
        };
      }
    }

    // Start fresh `agent_grant` session on connect.nuri.com
    const reqId = requestId && typeof requestId === "string" ? requestId.trim() : randomUUID();
    const replyKp = generateGrantReplyKeypair();
    const started = await ensureConnect().startAgentGrant({
      replyPubkey: replyKp.replyPubkey,
      index: slotIndex,
      policy,
    });
    const saved = db.createGrantSession({
      requestId: reqId,
      connectSessionId: started.session_id || started.sessionId,
      slotIndex,
      replyPubkey: replyKp.replyPubkey,
      replySkHex: replyKp.replySkHex,
      policy,
      approvalUrl: started.approval_url || started.approvalUrl,
      expiresAt: started.expires_at ?? started.expiresAt,
    });
    const createUrl = `${ensureConnect().origin}/`;
    return {
      ok: true,
      status: "connect_required",
      request_id: saved.requestId,
      approval_url: saved.approvalUrl,
      create_url: createUrl,
      next: `Show approval_url to connect an existing Nuri Passkey (or if the person has no Nuri Passkey yet, open ${createUrl} to create one first, then approve approval_url). After approval, repeat wallet balance with the same request_id.`,
    };
  }

  async function handleBalance(args) {
    if (isPrfWalletKey(args?.wallet_key) && !args?.new) {
      const { wallet, secrets } = ensureStore().unlockWalletSecrets(args.wallet_key);
      const balances = await readDualBalances(wallet, secrets);
      return {
        ok: true,
        status: "done",
        ...balances,
        next: "Holdings shown.",
      };
    }
    return await startOrPollOnboarding({
      requestId: args?.request_id,
      slotIndex: Number.isSafeInteger(args?.index) ? args.index : 0,
    });
  }

  async function handleReceive(args) {
    const db = ensureStore();
    const { wallet, secrets } = db.unlockWalletSecrets(args.wallet_key);
    await sweepPendingReceives(wallet, secrets.agentBtcPrivHex);

    const requestedRail = String(
      args.rail || (args.amount_sats !== undefined ? "lightning" : "usdc"),
    )
      .trim()
      .toLowerCase();

    if (requestedRail === "usdc") {
      const usdcUnits = await ensureSafe()
        .readUsdcBalanceUnits(wallet.safeAddress)
        .catch(() => 0n);
      return {
        ok: true,
        status: "done",
        rail: "usdc",
        address: wallet.safeAddress,
        available: unitsToDecimal(String(usdcUnits), 6),
        next: `Send Base USDC to ${wallet.safeAddress}, then call wallet balance.`,
      };
    }

    if (requestedRail === "arkade" || requestedRail === "btc") {
      const ark = await ensureArkade().readBalance(wallet);
      if (ark.address && ark.address !== wallet.arkadeAddress) {
        db.updateWalletArkadeAddress(wallet.walletId, ark.address);
      }
      return {
        ok: true,
        status: "done",
        rail: "arkade",
        arkade_address: ark.address,
        sats: Number(ark.sats),
        btc: formatSatsAsBtc(ark.sats),
        next: `Send Arkade sats to ${ark.address}, then call wallet balance.`,
      };
    }

    if (requestedRail === "lightning" || requestedRail === "bolt11") {
      if (args.request_id) {
        const existing = db.getLightningReceiveByRequest(wallet.walletId, args.request_id);
        if (existing) {
          if (existing.status === "claimed") {
            const ark = await ensureArkade().readBalance(wallet);
            return {
              ok: true,
              status: "done",
              rail: "lightning",
              invoice: existing.invoice,
              payment_hash: existing.paymentHash,
              amount_sats: existing.claimedSats ?? existing.expectedAmountSats,
              sats: Number(ark.sats),
              arkade_address: ark.address,
              next: "Lightning payment received and claimed into 2-of-2 Arkade custody.",
            };
          }
          return {
            ok: true,
            status: "pending",
            rail: "lightning",
            request_id: args.request_id,
            invoice: existing.invoice,
            payment_hash: existing.paymentHash,
            amount_sats: existing.payAmountSats,
            expected_sats: existing.expectedAmountSats,
            fee_sats: existing.feeSats,
            expires_at: existing.expiresAt,
            next: "Pay the BOLT11 invoice, then call wallet balance or repeat wallet receive with the same request_id.",
          };
        }
      }

      const amountSats = parsePositiveSats(args.amount_sats, "amount_sats");
      if (!amountSats) {
        return {
          ok: false,
          status: "failed",
          error: "Lightning receive needs amount_sats (for example 1000). Pass amount_sats and try again.",
        };
      }
      const created = await ensureArkade().createLightningReceive({
        walletRecord: wallet,
        agentBtcPrivHex: secrets.agentBtcPrivHex,
        amountSats,
      });
      db.saveLightningReceive({
        rfqId: created.rfqId,
        walletId: wallet.walletId,
        requestId: args.request_id || null,
        paymentHash: created.paymentHash,
        invoice: created.invoice,
        payAmountSats: created.payAmountSats,
        expectedAmountSats: created.expectedAmountSats,
        feeSats: created.feeSats,
        expiresAt: created.expiresAt,
        lockupAddress: created.lockupAddress,
        swapPkScriptHex: created.swapPkScriptHex,
        payoutAddress: created.payoutAddress,
        quoteJson: created.quoteJson,
      });
      return {
        ok: true,
        status: "done",
        rail: "lightning",
        ...(args.request_id ? { request_id: args.request_id } : {}),
        invoice: created.invoice,
        payment_hash: created.paymentHash,
        amount_sats: created.payAmountSats,
        expected_sats: created.expectedAmountSats,
        fee_sats: created.feeSats,
        expires_at: created.expiresAt,
        arkade_address: created.payoutAddress,
        next: "Pay invoice over Lightning; call wallet balance once paid to claim into 2-of-2 Arkade custody.",
      };
    }

    return {
      ok: false,
      status: "failed",
      error: "rail must be usdc, lightning, or arkade.",
    };
  }

  async function handlePay(args) {
    const db = ensureStore();
    const { wallet, secrets } = db.unlockWalletSecrets(args.wallet_key);
    const reqId =
      typeof args.request_id === "string" && args.request_id.trim()
        ? args.request_id.trim()
        : randomUUID();

    const prior = db.getOperation(wallet.walletId, reqId);
    if (prior && prior.status === "done" && !args.dry_run) {
      return prior.result;
    }

    const opId = `${wallet.walletId}:${reqId}`;
    const maxAmountUnits =
      args.max_amount !== undefined ? parseUsdcUnits(args.max_amount, "max_amount") : undefined;
    const maxSats =
      args.max_sats !== undefined ? parsePositiveSats(args.max_sats, "max_sats") : undefined;

    try {
      // Case 1: HTTP 402 URL (`x402`, `EVM MPP`, `L402`, `Lightning MPP`)
      if (typeof args.url === "string" && args.url.trim()) {
        const res = await ensurePayer().payHttpResource({
          walletRecord: wallet,
          secrets,
          url: args.url.trim(),
          method: args.method || "GET",
          body: args.body,
          prefer: args.prefer,
          maxAmountUnits,
          maxSats,
          dryRun: Boolean(args.dry_run),
          opId,
        });

        const out = {
          ok: res.status !== "failed",
          status: res.status,
          request_id: reqId,
          ...(res.protocol ? { protocol: res.protocol } : {}),
          ...(res.rail ? { rail: res.rail } : {}),
          ...(res.dry_run ? { quote: res.quote, payable: res.payable } : {}),
          ...(res.resource ? { resource: res.resource } : {}),
          ...(res.preimage ? { preimage: res.preimage } : {}),
          ...(res.payment_hash ? { payment_hash: res.payment_hash } : {}),
          ...(res.amount_sats !== undefined ? { amount_sats: res.amount_sats } : {}),
          ...(res.fee_sats !== undefined ? { fee_sats: res.fee_sats } : {}),
          ...(res.tx_hash || res.ark_txid
            ? {
                receipt: {
                  tx: res.tx_hash || res.ark_txid,
                  amount:
                    res.amount_units !== undefined
                      ? `${unitsToDecimal(String(res.amount_units), 6)} USDC`
                      : `${res.amount_sats} sats`,
                  to: args.url.trim(),
                },
              }
            : {}),
        };

        if (!args.dry_run && out.status === "done") {
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: res.rail || "usdc",
            status: "done",
            amountDisplay:
              res.amount_units !== undefined
                ? unitsToDecimal(String(res.amount_units), 6)
                : res.amount_sats !== undefined
                  ? `${res.amount_sats} sats`
                  : null,
            summary: {
              kind: "pay",
              protocol: res.protocol || null,
              to: args.url.trim(),
              tx: res.tx_hash || res.ark_txid || null,
            },
            result: out,
          });
        }
        return out;
      }

      const target = String(args.invoice || args.to || "").trim();
      if (!target) {
        return {
          ok: false,
          status: "failed",
          error:
            "Provide url (paid HTTPS API), invoice (BOLT11 lnbc...), or to (0x Base address, ark1... Arkade address, or user@domain Lightning Address).",
        };
      }

      // Case 2: Direct BOLT11 invoice
      if (BOLT11_RE.test(target)) {
        const paid = await ensureArkade().payBolt11Invoice({
          walletRecord: wallet,
          agentBtcPrivHex: secrets.agentBtcPrivHex,
          bolt11: target,
          maxSats,
          opId,
        });
        const out = {
          ok: true,
          status: paid.status,
          request_id: reqId,
          rail: "lightning",
          amount_sats: paid.amountSats,
          fee_sats: paid.feeSats,
          payment_hash: paid.paymentHash,
          ...(paid.preimageHex ? { preimage: paid.preimageHex } : {}),
          receipt: {
            tx: paid.arkTxid,
            amount: `${paid.amountSats} sats`,
            to: paid.paymentHash,
          },
        };
        if (paid.status === "done") {
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: "lightning",
            status: "done",
            amountDisplay: `${paid.amountSats} sats`,
            summary: { kind: "pay", to: paid.paymentHash, tx: paid.arkTxid },
            result: out,
          });
        }
        return out;
      }

      // Case 3: Lightning Address (`alice@domain.com`)
      if (LN_ADDRESS_RE.test(target)) {
        const sats = parsePositiveSats(args.amount_sats, "amount_sats");
        if (!sats) {
          return {
            ok: false,
            status: "failed",
            error: "Paying a Lightning Address needs amount_sats (for example 500).",
          };
        }
        const bolt11 = await ensureArkade().resolveLightningAddressInvoice({
          lightningAddress: target,
          amountSats: sats,
        });
        const paid = await ensureArkade().payBolt11Invoice({
          walletRecord: wallet,
          agentBtcPrivHex: secrets.agentBtcPrivHex,
          bolt11,
          maxSats: maxSats ?? sats + Math.max(50, Math.ceil(sats * 0.03)),
          opId,
        });
        const out = {
          ok: true,
          status: paid.status,
          request_id: reqId,
          rail: "lightning",
          to: target,
          amount_sats: paid.amountSats,
          fee_sats: paid.feeSats,
          payment_hash: paid.paymentHash,
          ...(paid.preimageHex ? { preimage: paid.preimageHex } : {}),
          receipt: {
            tx: paid.arkTxid,
            amount: `${paid.amountSats} sats`,
            to: target,
          },
        };
        if (paid.status === "done") {
          db.recordOperation({
            walletId: wallet.walletId,
            requestId: reqId,
            action: "pay",
            rail: "lightning",
            status: "done",
            amountDisplay: `${paid.amountSats} sats`,
            summary: { kind: "pay", to: target, tx: paid.arkTxid },
            result: out,
          });
        }
        return out;
      }

      // Case 4: Arkade native off-chain send (`ark1...` / `tark1...`)
      if (isValidArkAddress(target)) {
        const sats = parsePositiveSats(args.amount_sats, "amount_sats");
        if (!sats) {
          return {
            ok: false,
            status: "failed",
            error: "Sending to an Arkade address needs amount_sats (for example 1000).",
          };
        }
        const sent = await ensureArkade().sendArkade({
          walletRecord: wallet,
          agentBtcPrivHex: secrets.agentBtcPrivHex,
          toArkAddress: target,
          amountSats: sats,
          opId,
        });
        const out = {
          ok: true,
          status: "done",
          request_id: reqId,
          rail: "arkade",
          to: target,
          amount_sats: sats,
          receipt: {
            tx: sent.arkTxid,
            amount: `${sats} sats`,
            to: target,
          },
        };
        db.recordOperation({
          walletId: wallet.walletId,
          requestId: reqId,
          action: "pay",
          rail: "arkade",
          status: "done",
          amountDisplay: `${sats} sats`,
          summary: { kind: "send", to: target, tx: sent.arkTxid },
          result: out,
        });
        return out;
      }

      // Case 5: Base USDC transfer to `0x...`
      if (ETH_ADDRESS_RE.test(target)) {
        const units = parseUsdcUnits(args.amount, "amount");
        if (!units || units <= 0n) {
          return {
            ok: false,
            status: "failed",
            error: "Sending Base USDC to a 0x address needs a positive amount like 1.50.",
          };
        }
        const toAddr = getAddress(target);
        const safeWalletRow = {
          cred_id_b64u: wallet.credIdB64u,
          slot_index: wallet.slotIndex,
          main_eoa: wallet.mainEoa,
          passkey_signer_address: wallet.passkeySignerAddress,
          agent_eoa: wallet.agentEthEoa,
          cosigner_eoa: wallet.cosignerEoa,
          safe_address: wallet.safeAddress,
        };
        const sent = await ensureSafe().transferUsdc({
          walletRecord: safeWalletRow,
          agentEthPrivateKeyHex: secrets.agentEthPrivHex,
          to: toAddr,
          amountUnits: units,
          opId,
        });
        const dec = unitsToDecimal(String(units), 6);
        const out = {
          ok: true,
          status: "done",
          request_id: reqId,
          rail: "usdc",
          to: toAddr,
          receipt: {
            tx: sent.txHash,
            amount: dec,
            to: toAddr,
          },
        };
        db.recordOperation({
          walletId: wallet.walletId,
          requestId: reqId,
          action: "pay",
          rail: "usdc",
          status: "done",
          amountDisplay: dec,
          summary: { kind: "send", to: toAddr, tx: sent.txHash },
          result: out,
        });
        return out;
      }

      return {
        ok: false,
        status: "failed",
        error: "Unrecognized destination. Use an https:// URL, BOLT11 lnbc... invoice, user@domain, ark1... address, or 0x... Base address.",
      };
    } catch (err) {
      if (err?.code === "over_max_amount") {
        return {
          ok: false,
          status: "failed",
          error:
            "The invoice exceeds max_amount. Nothing was paid; send again with a NEW request_id and a higher max_amount.",
        };
      }
      const msg = String(err?.message || err);
      db.recordOperation({
        walletId: wallet.walletId,
        requestId: reqId,
        action: "pay",
        rail: args.invoice || args.amount_sats ? "lightning" : "usdc",
        status: "failed",
        summary: { kind: "pay", reason: msg.slice(0, 120) },
        result: { ok: false, status: "failed", error: msg },
      });
      return {
        ok: false,
        status: "failed",
        error: `Payment failed (${msg}).`,
      };
    }
  }

  async function handleHistory(args) {
    const db = ensureStore();
    const { wallet, secrets } = db.unlockWalletSecrets(args.wallet_key);
    await sweepPendingReceives(wallet, secrets.agentBtcPrivHex);
    const items = db.listOperations(wallet.walletId, { limit: args.limit || 25 });
    return {
      ok: true,
      status: "done",
      history: items.reverse().map((op) => ({
        request_id: op.request_id,
        kind: op.kind || op.action,
        ...(op.rail ? { rail: op.rail } : {}),
        status: op.status === "done" ? "done" : op.status === "failed" ? "failed" : "pending",
        amount: op.amount ?? null,
        to: op.to ?? null,
        tx: op.tx ?? null,
        ...(op.reason ? { reason: op.reason } : {}),
      })),
      next: "History shown.",
    };
  }

  async function payFeeWithPrfWallet({ walletKey, amountUnits, payTo, reference }) {
    const db = ensureStore();
    const { wallet, secrets } = db.unlockWalletSecrets(walletKey);
    const bal = await ensureSafe().readUsdcBalanceUnits(wallet.safeAddress);
    if (bal < BigInt(amountUnits)) {
      return { status: "insufficient", address: wallet.safeAddress };
    }
    const safeWalletRow = {
      cred_id_b64u: wallet.credIdB64u,
      slot_index: wallet.slotIndex,
      main_eoa: wallet.mainEoa,
      passkey_signer_address: wallet.passkeySignerAddress,
      agent_eoa: wallet.agentEthEoa,
      cosigner_eoa: wallet.cosignerEoa,
      safe_address: wallet.safeAddress,
    };
    const sent = await ensureSafe().transferUsdc({
      walletRecord: safeWalletRow,
      agentEthPrivateKeyHex: secrets.agentEthPrivHex,
      to: getAddress(payTo),
      amountUnits: BigInt(amountUnits),
      opId: `fee:${wallet.walletId}:${reference}`,
    });
    return {
      status: "paid",
      tx: sent.txHash,
      payer: wallet.safeAddress,
      asset: BASE_USDC_ADDRESS,
    };
  }

  function hasPendingGrantSession(requestId) {
    if (!configured || !requestId || typeof requestId !== "string") return false;
    try {
      return Boolean(ensureStore().getGrantSession(requestId.trim()));
    } catch {
      return false;
    }
  }

  function close() {
    store?.close?.();
    store = null;
  }

  return {
    configured,
    walletKeyPattern: PRF_WALLET_KEY_RE,
    hasPendingGrantSession,
    handleBalance,
    handleReceive,
    handlePay,
    handleHistory,
    payFeeWithPrfWallet,
    findLatestWalletByMainEoa: (owner) =>
      configured ? ensureStore().findLatestWalletByMainEoa(owner) : null,
    close,
  };
}
