import { getAddress, recoverAddress } from "viem";
import { toAccount } from "viem/accounts";

import { assertNuriPrivyAppEnv, createNuriPrivyAppClient } from "./privy-agent-app.mjs";
import { openAgentWalletStore } from "./agent-wallet-store.mjs";
import {
  AGENT_QUORUM_THRESHOLD,
  assertAgentQuorum,
  publicKeyOfAuthorizationPrivateKey,
  assertAuthorizationPublicKey,
  assertQuorumId,
  joinAuthorizationSignatures,
  quorumAuthorizationInput,
  signQuorumAuthorization,
} from "./privy-agent-quorum.mjs";



















export const NURI_PRIVY_APP_AGENT_LABELS = ["agent-1", "agent-2", "agent-3"];
export const NURI_PRIVY_APP_2OF2_MODEL = "nuri-privy-app-2of2";

function labelId(ownerAddress, label) {
  return `nuri-privy-app-${getAddress(ownerAddress).toLowerCase()}-${label}`;
}




export function signServerQuorumAuthorization({ input, serverPrivateKey }) {
  if (typeof serverPrivateKey !== "string" || !serverPrivateKey) throw new Error("privy_agent_server_authorization_key_required");
  return signQuorumAuthorization(input, serverPrivateKey);
}

export function assertNuriPrivyAppQuorumEnv(env = process.env) {
  const { appId, appSecret } = assertNuriPrivyAppEnv(env);
  const serverPrivateKey = String(env.PRIVY_AGENT_AUTHORIZATION_PRIVATE_KEY || "").trim();
  if (!serverPrivateKey) throw new Error("privy_agent_server_authorization_key_required");
  return { appId, appSecret, serverPrivateKey };
}




export async function createAgentQuorum({ client, displayName, serverPublicKey, runtimePublicKey }) {
  if (!client || typeof client.createQuorum !== "function") throw new Error("privy_agent_quorum_client_required");
  const server = assertAuthorizationPublicKey(serverPublicKey);
  const runtime = assertAuthorizationPublicKey(runtimePublicKey);
  if (server.replace(/\s/g, "") === runtime.replace(/\s/g, "")) throw new Error("agent_quorum_keys_must_differ");
  const name = String(displayName || "Nuri agent 2-of-2").trim().slice(0, 120);
  if (!name) throw new Error("agent_quorum_display_name_required");
  const quorum = await client.createQuorum({
    display_name: name,
    authorization_threshold: AGENT_QUORUM_THRESHOLD,
    public_keys: [server, runtime],
  });
  return assertAgentQuorum({ quorum, serverPublicKey: server, runtimePublicKey: runtime });
}















export function registerAgentRuntimePublicKey({ store, ownerAddress, label, runtimePublicKey }) {
  const owner = getAddress(ownerAddress);
  if (!NURI_PRIVY_APP_AGENT_LABELS.includes(label)) throw new Error("payment_agent_id_invalid");
  const runtime = assertAuthorizationPublicKey(runtimePublicKey).replace(/\s/g, "");
  const walletStore = store || openAgentWalletStore({ databasePath: process.env.AGENT_STORE_PATH });
  const existing = walletStore.getAgent(labelId(owner, label));
  if (existing) {
    if (existing.model !== NURI_PRIVY_APP_2OF2_MODEL) throw new Error("agent_custody_model_mismatch");
    if (existing.runtimePublicKey !== runtime) throw new Error("agent_runtime_key_mismatch");
    return existing;
  }
  return { id: labelId(owner, label), model: NURI_PRIVY_APP_2OF2_MODEL, ownerAddress: owner, runtimePublicKey: runtime, status: "registering" };
}



















export async function loadNuriPrivyAppAgents({ ownerAddress, store, client, model = NURI_PRIVY_APP_2OF2_MODEL, appId, quorumSignatures } = {}) {
  if (model !== NURI_PRIVY_APP_2OF2_MODEL) throw new Error("agent_custody_model_unsupported");
  const owner = getAddress(ownerAddress);
  const app = client || createNuriPrivyAppClient(assertNuriPrivyAppEnv());
  
  
  
  const configuredAppId = typeof appId === "string" && appId ? appId
    : typeof app?.appId === "string" && app.appId ? app.appId
    : process.env.PRIVY_AGENT_APP_ID;
  const walletStore = store || openAgentWalletStore({ databasePath: process.env.AGENT_STORE_PATH });
  const accounts = [];
  for (const label of NURI_PRIVY_APP_AGENT_LABELS) {
    const id = labelId(owner, label);
    const row = walletStore.getAgent(id);
    if (row && (row.model !== model || row.ownerAddress !== owner)) {
      throw new Error("agent_custody_model_mismatch");
    }
    if (row) {
      const live = await app.getWallet(row.providerWalletId);
      if (getAddress(live.address) !== getAddress(row.address)) throw new Error("agent_wallet_state_mismatch");
      if (!row.providerSignerId) throw new Error("agent_quorum_binding_missing");
      const quorum = typeof app.getQuorum === "function" ? await app.getQuorum(row.providerSignerId) : null;
      assertAgentQuorum({ quorum, serverPublicKey: row.serverPublicKey, runtimePublicKey: row.runtimePublicKey });
      if (live.ownerId !== row.providerSignerId) throw new Error("agent_wallet_owner_mismatch");
      if (typeof quorumSignatures === "function") {
        accounts.push({ label, account: createNuriPrivyAppAccount({ app: app, walletId: row.providerWalletId, address: row.address, appId: configuredAppId, quorumSignatures }) });
        continue;
      }
      accounts.push({ label, account: createNuriPrivyAppAccount({ app: app, walletId: row.providerWalletId, address: row.address, appId: configuredAppId }) });
      continue;
    }
    throw new Error("agent_quorum_provisioning_requires_runtime_public_key");
  }
  return accounts;
}













export function createNuriPrivyAppAccount({ app, walletId, address, quorumSignatures, serverPrivateKey, appId, pinnedRequestExpiry = null }) {
  const accountAddress = getAddress(address);
  const configuredAppId = typeof appId === "string" && appId ? appId
    : typeof app?.appId === "string" && app.appId ? app.appId
    : process.env.PRIVY_AGENT_APP_ID;
  async function quorum(input) {
    if (typeof quorumSignatures !== "function") return undefined;
    const runtimeSignature = await quorumSignatures(input);
    if (typeof runtimeSignature !== "string" || !runtimeSignature) throw new Error("agent_runtime_signature_missing");
    const serverKey = typeof serverPrivateKey === "string" && serverPrivateKey
      ? serverPrivateKey
      : process.env.PRIVY_AGENT_AUTHORIZATION_PRIVATE_KEY;
    if (typeof serverKey !== "string" || !serverKey) throw new Error("privy_agent_server_authorization_key_required");
    const serverSignature = signQuorumAuthorization(input, serverKey);
    return {
      signatures: joinAuthorizationSignatures([serverSignature, runtimeSignature]),
      requestExpiry: input.headers["privy-request-expiry"],
    };
  }
  
  
  
  
  async function authorizedInput({ method, body }) {
    if (pinnedRequestExpiry !== null) {
      const frozen = Number(pinnedRequestExpiry);
      if (!Number.isSafeInteger(frozen) || frozen <= Date.now()) throw new Error('agent_quorum_handle_expired');
    }
    const input = quorumAuthorizationInput({
      appId: configuredAppId,
      method,
      url: `https://api.privy.io/v1/wallets/${walletId}/rpc`,
      body,
      requestExpiry: pinnedRequestExpiry !== null ? Number(pinnedRequestExpiry) : Date.now() + 60_000,
    });
    return { input, auth: await quorum(input) };
  }
  return toAccount({
    address: accountAddress,
    async sign({ hash }) {
      const { input, auth } = await authorizedInput({ method: "POST", body: { method: "secp256k1_sign", params: { hash } } });
      void input;
      const signature = await app.signHash(walletId, hash, auth);
      if (await recoverAddress({ hash, signature }) !== accountAddress) throw new Error("privy_agent_signature_mismatch");
      return signature;
    },
    async signMessage({ message }) {
      const raw = typeof message === "string" ? message : message?.raw;
      if (typeof raw !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(raw)) throw new Error("privy_agent_signer_accepts_userop_hash_only");
      const { input, auth } = await authorizedInput({ method: "POST", body: { method: "secp256k1_sign", params: { hash: raw } } });
      void input;
      const signature = await app.signHash(walletId, raw, auth);
      if (await recoverAddress({ hash: raw, signature }) !== accountAddress) throw new Error("privy_agent_signature_mismatch");
      return signature;
    },
    async signTypedData(typedData) {
      const { domain, message, types, primaryType, primary_type } = typedData || {};
      const normalized = JSON.parse(JSON.stringify({ domain, message, primary_type: primaryType || primary_type, types },
        (_key, value) => typeof value === "bigint" ? value.toString() : value));
      const { input, auth } = await authorizedInput({ method: "POST", body: { method: "eth_signTypedData_v4", params: { typed_data: normalized } } });
      void input;
      return app.signTypedData(walletId, typedData, auth);
    },
    async signTransaction() {
      throw new Error("privy_agent_transaction_signing_not_used");
    },
  });
}


// D-QUORUM package B: a claimed Safe whose on-chain spender is the owner's 2-of-2 agent key pays through Privy.
// null = guest path. The user half is NOT held by the server (owner 2026-09-25, D-CUSTODY-V2): the LLM
// sends it with every call inside its connected wallet_key, exactly like a guest; missing = agent_key_required.
const keyRequired = () => Object.assign(new Error("agent_key_required"), { code: "agent_key_required", runtimeCode: "agent_key_required" });
export async function connectedSafeAgentSigner({ row, store, userPrivateKey, app, env = process.env }) {
  if (!row?.claimed) return null;
  const agent = store.listAgents(row.ownerAddress).find((a) => a.model === NURI_PRIVY_APP_2OF2_MODEL && a.status === "active"
    && getAddress(a.address) === getAddress(row.record.agentAddress));
  if (!agent) return null;
  if (typeof userPrivateKey !== "string" || !userPrivateKey) throw keyRequired();
  if (publicKeyOfAuthorizationPrivateKey(userPrivateKey) !== agent.runtimePublicKey) throw Object.assign(new Error("wallet_key_mismatch"), { code: "wallet_key_mismatch", runtimeCode: "wallet_key_mismatch" });
  const serverPrivateKey = String(env.PRIVY_AGENT_AUTHORIZATION_PRIVATE_KEY || "").trim();
  if (!serverPrivateKey) throw new Error("privy_agent_server_authorization_key_required");
  const client = app || createNuriPrivyAppClient(assertNuriPrivyAppEnv(env));
  return createNuriPrivyAppAccount({ app: client, walletId: agent.providerWalletId, address: agent.address, appId: client.appId || env.PRIVY_AGENT_APP_ID,
    serverPrivateKey, quorumSignatures: (input) => signQuorumAuthorization(input, userPrivateKey) });
}

// Custody v2 guest Safe (issue #285, owner 2026-09-25): the Safe's sudo owner AND its spender are one
// Privy agent EOA owned by a 2-of-2 quorum (server key + MODEL key). The model key is random, handed to
// the agent once inside wallet_key and never stored (only its public key is). No raw EVM key exists.
export const GUEST_AGENT_PREFIX = "nuri-guest-";
const guestAgentId = (walletId) => `${GUEST_AGENT_PREFIX}${walletId}`;
const quorumKeys = (quorum) => (Array.isArray(quorum?.authorization_keys) ? quorum.authorization_keys : []).map((k) => String(k?.public_key || "").replace(/\s/g, "")).sort();
function serverKeyOf(env) {
  const key = String(env.PRIVY_AGENT_AUTHORIZATION_PRIVATE_KEY || "").trim();
  if (!key) throw new Error("privy_agent_server_authorization_key_required");
  return key;
}
function quorumAccount({ client, agent, env, userKey }) {
  return createNuriPrivyAppAccount({ app: client, walletId: agent.providerWalletId, address: agent.address, appId: client.appId || env.PRIVY_AGENT_APP_ID,
    serverPrivateKey: serverKeyOf(env), quorumSignatures: (input) => signQuorumAuthorization(input, userKey()) });
}

// At wallet creation: quorum(server, model) -> Privy wallet. Returns the viem account and the model key (once).
export async function provisionGuestAgent({ walletId, store, app, env = process.env, modelKeypair }) {
  const serverPrivateKey = serverKeyOf(env);
  const client = app || createNuriPrivyAppClient(assertNuriPrivyAppEnv(env));
  const serverPublicKey = publicKeyOfAuthorizationPrivateKey(serverPrivateKey);
  const quorumId = await createAgentQuorum({ client, displayName: `Nuri guest safe ${String(walletId).slice(0, 8)}`, serverPublicKey, runtimePublicKey: modelKeypair.publicKey });
  const created = await client.createWallet({ ownerQuorumId: quorumId });
  const agent = store.putNuriPrivyApp2of2Wallet({ id: guestAgentId(walletId), ownerAddress: created.address, address: created.address,
    providerWalletId: created.walletId, quorumId, serverPublicKey, runtimePublicKey: modelKeypair.publicKey });
  return { agent, account: quorumAccount({ client, agent, env, userKey: () => modelKeypair.privateKey }) };
}

// Every guest call: wallet_key's model key + the server key sign through Privy. Same account shape as connected pay.
export function guestSafeAgentSigner({ walletId, store, modelPrivateKey, app, env = process.env }) {
  const agent = store.getAgent(guestAgentId(walletId));
  if (!agent || agent.model !== NURI_PRIVY_APP_2OF2_MODEL) throw new Error("guest_agent_missing");
  if (publicKeyOfAuthorizationPrivateKey(modelPrivateKey) !== agent.runtimePublicKey) throw Object.assign(new Error("wallet_key_mismatch"), { code: "wallet_key_mismatch" });
  const client = app || createNuriPrivyAppClient(assertNuriPrivyAppEnv(env));
  return quorumAccount({ client, agent, env, userKey: () => modelPrivateKey });
}

// Connect: swap the quorum's model key (random) for the key derived from the EOA's 'Nuri agent signer v1'
// signature. The derived key reaches here only inside this call (opened from the box sealed to the old
// model key, src/mcp-agent-wallet.mjs claimTapped); it is never stored. Privy PATCH /v1/key_quorums/{id};
// the docs do not name the required signers, so BOTH current members sign (server + old model key).
// Idempotent: an already swapped quorum is left alone, then the store row is rebound to the EOA.
export async function swapGuestQuorum({ walletId, ownerAddress, store, modelPrivateKey, derivedPrivateKey, app, env = process.env }) {
  const owner = getAddress(ownerAddress);
  if (typeof derivedPrivateKey !== "string" || !derivedPrivateKey) throw keyRequired();
  const derived = publicKeyOfAuthorizationPrivateKey(derivedPrivateKey);
  const agent = store.getAgent(guestAgentId(walletId));
  if (!agent || agent.model !== NURI_PRIVY_APP_2OF2_MODEL) throw new Error("guest_agent_missing");
  const client = app || createNuriPrivyAppClient(assertNuriPrivyAppEnv(env));
  const serverPrivateKey = serverKeyOf(env);
  const target = [agent.serverPublicKey, derived].sort();
  const live = quorumKeys(await client.getQuorum(agent.quorumId));
  if (live.join() !== target.join()) {
    if (typeof modelPrivateKey !== "string" || !modelPrivateKey) throw Object.assign(new Error("wallet_key_required"), { code: "wallet_key_required" });
    const current = [agent.serverPublicKey, publicKeyOfAuthorizationPrivateKey(modelPrivateKey)].sort();
    if (live.join() !== current.join()) throw new Error("agent_quorum_key_mismatch");
    const body = { public_keys: [agent.serverPublicKey, derived], authorization_threshold: AGENT_QUORUM_THRESHOLD };
    const input = quorumAuthorizationInput({ appId: client.appId || env.PRIVY_AGENT_APP_ID, method: "PATCH",
      url: `https://api.privy.io/v1/key_quorums/${assertQuorumId(agent.quorumId)}`, body, requestExpiry: Date.now() + 60_000 });
    const signatures = joinAuthorizationSignatures([signQuorumAuthorization(input, serverPrivateKey), signQuorumAuthorization(input, modelPrivateKey)]);
    const updated = await client.updateQuorum(agent.quorumId, body, { signatures, requestExpiry: input.headers["privy-request-expiry"] });
    assertAgentQuorum({ quorum: updated, serverPublicKey: agent.serverPublicKey, runtimePublicKey: derived });
  }
  const bound = store.rebindAgent({ id: agent.id, ownerAddress: owner, runtimePublicKey: derived });
  return quorumAccount({ client, agent: bound, env, userKey: () => derivedPrivateKey });
}

export { quorumAuthorizationInput, signQuorumAuthorization, assertQuorumId };
