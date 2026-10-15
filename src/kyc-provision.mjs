import { prepareRegistration, readRegistrationReceipt, submitRegistration } from "./aa-register.mjs";
import { oncePerSession } from "./approval-once.mjs";
import { normalizeKycUsername } from "./kyc-capability.mjs";

const USER_SYNC_RETRIES = 8;
const USER_SYNC_DELAY_MS = 1_500;
export const ISO_COUNTRY_CODES = new Set("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(" "));

export function createKycProvisioner({
  bridge,
  proxy,
  wirexBaas,
  aaConfig,
  registrationIndex,
  registration = {},
  stateStore,
  publicBase,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  const activeByAddress = new Map();
  const prepare = registration.prepare || ((address) => prepareRegistration(address, aaConfig));
  const submit = registration.submit || ((input) => submitRegistration(input, aaConfig));
  const reconcile = registration.reconcile || ((hash) => readRegistrationReceipt(hash, aaConfig));
  const base = String(publicBase || "").replace(/\/+$/, "");
  if (![stateStore?.get, stateStore?.put, stateStore?.remove].every((method) => typeof method === "function")) {
    throw new Error("kyc_provision_state_store_required");
  }

  return {
    async start(rawInput) {
      const input = normalizeInput(rawInput);
      const key = input.address;
      const active = activeByAddress.get(key);
      if (active) {
        if (active.promise) {
          if (!sameInput(active.input, input)) throw new Error("kyc_provisioning_already_active");
          return await active.promise;
        }
        let status;
        try {
          status = await bridge.readStatus(active.start.session_id);
        } catch (error) {
          if (error?.message !== "session_not_found") throw error;
        }
        if (status?.status === "pending") {
          if (!sameInput(active.input, input)) throw new Error("kyc_provisioning_already_active");
          return active.start;
        }
        if (status?.status === "approved") throw new Error("kyc_provisioning_in_progress");
        activeByAddress.delete(key);
      }

      const promise = prepareStart(input).catch((error) => {
        activeByAddress.delete(key);
        throw error;
      });
      activeByAddress.set(key, { input, promise, start: null });
      const start = await promise;
      activeByAddress.set(key, { input, promise: null, start });
      return start;
    },

    
    
    
    
    async complete(sessionId) {
      return await oncePerSession(sessionId, () => completeSession(sessionId));
    },
  };

  async function completeSession(sessionId) {
      const cached = bridge.getExtra(sessionId);
      if (cached) return await cached;
      const status = await bridge.readStatus(sessionId);
      if (status.status !== "approved") return status;
      const approved = await bridge.approved(sessionId);
      if (approved?.context?.kind !== "kyc_provision") throw new Error("not_a_kyc_provision_session");

      const inFlight = completeOnce(approved)
        .catch(() => ({
          ok: false,
          status: "retry_required",
          error: "kyc_provision_failed",
          redirect: `${base}/kyc/${approved.context.username}`,
        }))
        .then((result) => {
          bridge.setExtra(sessionId, result);
          const active = activeByAddress.get(approved.context.eoa);
          if (active?.start?.session_id === sessionId) activeByAddress.delete(approved.context.eoa);
          return result;
        });
      bridge.setExtra(sessionId, inFlight);
      return await inFlight;
  }

  async function prepareStart(input) {
    const lifecycle = await stateStore.get(input.address);
    let registrations = null;
    if (lifecycle) {
      registrations = (await registrationIndex.list())?.registrations;
      if (!Array.isArray(registrations)) throw new Error("kyc_registration_index_invalid");
      if (hasRegistration(registrations, input.address, lifecycle.kernel_address)) {
        await stateStore.remove(input.address);
        return await createStartSession(input, lifecycle.kernel_address, null, null);
      }
      if (lifecycle.status === "confirmed") {
        return await createStartSession(input, lifecycle.kernel_address, null, null);
      }
      const receipt = await reconcile(lifecycle.user_op_hash);
      if (receipt?.status === "succeeded") {
        await stateStore.put({ ...lifecycle, status: "confirmed", tx_hash: receipt.tx_hash });
        return await createStartSession(input, lifecycle.kernel_address, null, null);
      }
      if (receipt?.status !== "failed") throw new Error("kyc_registration_pending");
      await stateStore.remove(input.address);
    }

    const prepared = await prepare(input.address);
    assertPreparedRegistration(prepared);
    registrations ||= (await registrationIndex.list())?.registrations;
    if (!Array.isArray(registrations)) throw new Error("kyc_registration_index_invalid");
    const registered = hasRegistration(registrations, input.address, prepared.kernelAddress);
    const userOpHash = registered ? null : prepared.userOpHash;
    return await createStartSession(input, prepared.kernelAddress, userOpHash, registered ? null : prepared.userOp);
  }

  async function createStartSession(input, kernelAddress, userOpHash, userOp) {
    const consentText = kycProvisionConsentMessage({ ...input, userOpHash });
    const context = {
      kind: "kyc_provision",
      username: input.username,
      email: input.email,
      country: input.country,
      eoa: input.address,
      kernelAddress,
      userOp,
      userOpHash: userOpHash || "already_registered",
    };
    return await bridge.createSession({
      intent: "auth",
      ...(userOpHash ? { signHash: userOpHash, consentText } : { signText: consentText }),
      expectedAddress: input.address,
      context,
      bridgeOptions: {
        userName: input.username,
        autoStart: true,
      },
    });
  }

  async function completeOnce({ result, context }) {
    if (context.userOp && result.consent_signature_matches_address !== true) {
      throw new Error("kyc_provision_consent_signature_missing");
    }

    let reconciledRegistration = false;
    if (context.userOp) {
      const lifecycle = {
        eoa: context.eoa,
        kernel_address: context.kernelAddress,
        user_op_hash: context.userOpHash,
        status: "submitting",
        tx_hash: null,
      };
      await stateStore.put(lifecycle);
      try {
        const submitted = await submit({
          eoaAddress: context.eoa,
          userOp: context.userOp,
          signature: result.signature,
        });
        if (String(submitted?.user_op_hash || "").toLowerCase() !== context.userOpHash.toLowerCase()) {
          await stateStore.put({ ...lifecycle, status: "unknown" });
          throw new Error("kyc_registration_userop_hash_mismatch");
        }
        if (submitted.success !== true) {
          await stateStore.remove(context.eoa);
          throw new Error("kyc_registration_userop_failed");
        }
        await stateStore.put({ ...lifecycle, status: "confirmed", tx_hash: submitted.tx_hash || null });
      } catch (error) {
        const registrations = (await registrationIndex.list())?.registrations;
        if (!Array.isArray(registrations)) throw error;
        if (hasRegistration(registrations, context.eoa, context.kernelAddress)) {
          await stateStore.put({ ...lifecycle, status: "confirmed" });
          reconciledRegistration = true;
        } else if (error?.message !== "kyc_registration_userop_failed") {
          let receipt = null;
          try {
            receipt = await reconcile(context.userOpHash);
          } catch {
            
          }
          if (receipt?.status === "succeeded") {
            await stateStore.put({ ...lifecycle, status: "confirmed", tx_hash: receipt.tx_hash });
            reconciledRegistration = true;
          } else if (receipt?.status === "failed") {
            await stateStore.remove(context.eoa);
            throw error;
          } else {
            await stateStore.put({ ...lifecycle, status: "unknown" });
            throw error;
          }
        } else {
          throw error;
        }
      }
    }

    const user = await syncWirexUser(context);
    return {
      ok: user !== null,
      status: user ? "provisioned" : "pending",
      redirect: `${base}/kyc/${context.username}`,
      reconciled_registration: reconciledRegistration,
    };
  }

  async function syncWirexUser(context) {
    for (let attempt = 0; attempt < USER_SYNC_RETRIES; attempt += 1) {
      await proxy.onboarding({
        walletAddress: context.eoa,
        email: context.email,
        country: context.country,
      });
      try {
        const response = await wirexBaas.getUser(context.eoa);
        if (response?.ok !== false) return response;
        if (response?.status !== 404) throw new Error("kyc_wirex_user_read_failed");
      } catch (error) {
        if (!isWirexUserNotFound(error)) throw error;
      }
      if (attempt + 1 < USER_SYNC_RETRIES) await sleep(USER_SYNC_DELAY_MS);
    }
    return null;
  }
}

export function isWirexUserNotFound(error) {
  const body = error?.body;
  return error?.status === 400
    && body?.error_reason === "ErrorNotFound"
    && body?.error_description === "Requested user was not found";
}

export function kycProvisionConsentMessage({ username, email, country, address, userOpHash }) {
  return "Set up your account with these details. Tap once to agree.";
}

function normalizeInput({ username, address, email, country } = {}) {
  const name = normalizeKycUsername(username);
  const owner = String(address || "").trim().toLowerCase();
  const mail = String(email || "").trim().toLowerCase();
  const nation = String(country || "").trim().toUpperCase();
  if (!name) throw new Error("kyc_username_invalid");
  if (!/^0x[0-9a-f]{40}$/.test(owner)) throw new Error("kyc_owner_invalid");
  if (mail.length > 254 || !/^[^\s@;=\r\n]+@[^\s@;=\r\n]+\.[^\s@;=\r\n]+$/.test(mail)) throw new Error("kyc_email_invalid");
  if (!ISO_COUNTRY_CODES.has(nation)) throw new Error("kyc_country_invalid");
  return { username: name, address: owner, email: mail, country: nation };
}

function sameInput(a, b) {
  return a.username === b.username
    && a.address === b.address
    && a.email === b.email
    && a.country === b.country;
}

function assertPreparedRegistration(prepared) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(prepared?.kernelAddress || "")
    || !/^0x[0-9a-fA-F]{64}$/.test(prepared?.userOpHash || "")
    || !prepared?.userOp) throw new Error("kyc_registration_prepare_invalid");
}

function hasRegistration(registrations, address, kernelAddress) {
  const owner = address.toLowerCase();
  const kernel = kernelAddress.toLowerCase();
  return registrations.some((row) => String(row?.owner_eoa || "").toLowerCase() === owner
    || String(row?.kernel_address || "").toLowerCase() === kernel);
}
