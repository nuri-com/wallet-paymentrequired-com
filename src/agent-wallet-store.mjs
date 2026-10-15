import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { getAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { assertAuthorizationPublicKey } from "./privy-agent-quorum.mjs";

const MODELS = new Set(["nuri-custody", "privy-user-wallets", "nuri-privy-app", "nuri-privy-app-2of2"]);

function requiredText(value, name, max = 256) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`${name}_invalid`);
  return value;
}

function parseEncryptionKey(value) {
  requiredText(value, "agent_key_encryption_key", 128);
  const key = /^[0-9a-f]{64}$/i.test(value) ? Buffer.from(value, "hex") : Buffer.from(value, "base64url");
  if (key.length !== 32) throw new Error("agent_key_encryption_key_must_be_32_bytes");
  return key;
}

function aad(row) {
  return Buffer.from(`v1\0${row.id}\0${row.model}\0${row.owner_address}\0${row.address}`);
}

function encryptPrivateKey(privateKey, key, row, authenticatedData = aad(row)) {
  if (!/^0x[0-9a-f]{64}$/i.test(privateKey)) throw new Error("agent_private_key_invalid");
  const plaintext = Buffer.from(privateKey.slice(2), "hex");
  const iv = randomBytes(12);
  try {
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(authenticatedData);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return `v1.${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${ciphertext.toString("base64url")}`;
  } finally {
    plaintext.fill(0);
  }
}

function decryptPrivateKey(blob, key, row, authenticatedData = aad(row)) {
  try {
    const [version, iv, tag, ciphertext] = requiredText(blob, "agent_key_ciphertext", 512).split(".");
    if (version !== "v1" || !iv || !tag || !ciphertext) throw new Error("invalid_ciphertext");
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
    decipher.setAAD(authenticatedData);
    decipher.setAuthTag(Buffer.from(tag, "base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64url")), decipher.final()]);
    try {
      if (plaintext.length !== 32) throw new Error("invalid_plaintext");
      return `0x${plaintext.toString("hex")}`;
    } finally {
      plaintext.fill(0);
    }
  } catch {
    throw new Error("agent_private_key_decryption_failed");
  }
}

function publicRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    model: row.model,
    ownerAddress: row.owner_address,
    address: row.address,
    providerUserId: row.provider_user_id,
    providerWalletId: row.provider_wallet_id,
    providerSignerId: row.provider_signer_id,
    status: row.status,
    
    
    
    
    ...(row.model === "nuri-privy-app-2of2"
      ? { quorumId: row.provider_signer_id, serverPublicKey: row.server_public_key, runtimePublicKey: row.runtime_public_key }
      : {}),
  };
}



function kernelRecord(record) {
  const fields = ["chainId", "index", "initialOwnerAddress", "maxTransferUnits", "policyVersion",
    "permit2Enabled", "address", "factory", "factoryData", "agentAddress", "permissionId", "validationId"];
  if (!record || Object.getPrototypeOf(record) !== Object.prototype ||
      Object.keys(record).length !== fields.length || fields.some(field => !Object.hasOwn(record, field))) {
    throw new Error("kernel_record_invalid");
  }
  const result = Object.fromEntries(fields.map(field => [field, record[field]]));
  if (![8453, 84532, 5042002].includes(result.chainId) || result.policyVersion !== "0.0.5" ||
      typeof result.permit2Enabled !== "boolean") throw new Error("kernel_configuration_unsupported");
  for (const field of ["index", "maxTransferUnits"]) {
    const value = result[field];
    if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(value) ||
        BigInt(value) >= 2n ** 256n || (field === "maxTransferUnits" && BigInt(value) === 0n)) {
      throw new Error(`kernel_${field}_invalid`);
    }
  }
  for (const field of ["initialOwnerAddress", "agentAddress", "address", "factory"]) {
    if (typeof result[field] !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(result[field])) throw new Error(`kernel_${field}_invalid`);
    result[field] = getAddress(result[field]);
    if (BigInt(result[field]) === 0n) throw new Error(`kernel_${field}_invalid`);
  }
  // Custody v2 guest: owner and spender may be the same Privy agent EOA; the Safe itself never is.
  if (result.address === result.initialOwnerAddress || result.address === result.agentAddress) {
    throw new Error("kernel_key_roles_must_differ");
  }
  for (const [field, pattern] of [["factoryData", /^0x(?:[0-9a-fA-F]{2}){4,16384}$/],
    ["permissionId", /^0x[0-9a-fA-F]{8}$/], ["validationId", /^0x[0-9a-fA-F]{42}$/]]) {
    if (typeof result[field] !== "string" || !pattern.test(result[field])) throw new Error(`kernel_${field}_invalid`);
    result[field] = result[field].toLowerCase();
  }
  
  if (result.validationId !== `0x02${result.permissionId.slice(2)}${"0".repeat(32)}`) {
    throw new Error("kernel_validation_id_mismatch");
  }
  return result;
}

function publicKernelRow(row) {
  if (!row) return null;
  return {
    id: row.id, address: row.address, record: JSON.parse(row.record_json),
    ownerAddress: row.owner_address, claimed: row.claimed === 1,
    ownershipScope: row.claimed === 1 ? "on-chain" : "local-only",
  };
}

export function openAgentWalletStore({ databasePath, encryptionKey }) {
  requiredText(databasePath, "agent_store_path", 4096);
  const key = encryptionKey ? parseEncryptionKey(encryptionKey) : null;
  const directory = dirname(databasePath);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);

  const database = new DatabaseSync(databasePath);
  chmodSync(databasePath, 0o600);
  database.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA trusted_schema = OFF;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS agent_wallets (
      id TEXT PRIMARY KEY,
      model TEXT NOT NULL CHECK (model IN ('nuri-custody', 'privy-user-wallets', 'nuri-privy-app', 'nuri-privy-app-2of2')),
      owner_address TEXT NOT NULL,
      address TEXT NOT NULL UNIQUE,
      provider_user_id TEXT,
      provider_wallet_id TEXT UNIQUE,
      provider_signer_id TEXT,
      key_ciphertext TEXT,
      server_public_key TEXT,
      runtime_public_key TEXT,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
      created_at TEXT NOT NULL,
      CHECK (
        (model = 'nuri-custody' AND key_ciphertext IS NOT NULL AND provider_wallet_id IS NULL)
        OR
        (model = 'privy-user-wallets' AND key_ciphertext IS NULL AND provider_wallet_id IS NOT NULL)
        OR
        (model = 'nuri-privy-app' AND key_ciphertext IS NULL AND provider_wallet_id IS NOT NULL AND provider_user_id IS NULL)
        OR
        (model = 'nuri-privy-app-2of2' AND key_ciphertext IS NULL AND provider_wallet_id IS NOT NULL AND provider_user_id IS NULL AND provider_signer_id IS NOT NULL AND server_public_key IS NOT NULL AND runtime_public_key IS NOT NULL)
      )
    ) STRICT;
    PRAGMA user_version = 2;
  `);

  const insert = database.prepare(`
    INSERT INTO agent_wallets (
      id, model, owner_address, address, provider_user_id, provider_wallet_id, provider_signer_id, key_ciphertext, server_public_key, runtime_public_key, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const byId = database.prepare("SELECT * FROM agent_wallets WHERE id = ?");
  const byOwner = database.prepare("SELECT * FROM agent_wallets WHERE owner_address = ? ORDER BY created_at, id");

  
  database.exec(`
    CREATE TABLE IF NOT EXISTS agent_kernel_wallets (
      id TEXT PRIMARY KEY,
      initial_owner_address TEXT NOT NULL,
      owner_address TEXT NOT NULL,
      address TEXT NOT NULL,
      chain_id INTEGER NOT NULL,
      record_json TEXT NOT NULL,
      owner_key_ciphertext TEXT NOT NULL,
      agent_key_ciphertext TEXT NOT NULL,
      claim_hash BLOB NOT NULL CHECK (length(claim_hash) = 32),
      claimed INTEGER NOT NULL DEFAULT 0 CHECK (claimed IN (0, 1)),
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'stopped')),
      created_at TEXT NOT NULL,
      UNIQUE (chain_id, address)
    ) STRICT;
  `);
  const kernelById = database.prepare("SELECT * FROM agent_kernel_wallets WHERE id = ?");
  const insertKernel = database.prepare(`INSERT INTO agent_kernel_wallets
    (id,initial_owner_address,owner_address,address,chain_id,record_json,owner_key_ciphertext,agent_key_ciphertext,claim_hash,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`);

  // Guest row: the server keeps no key; the model key lives only in the chat's wallet_key. The
  // owner_key_ciphertext/agent_key_ciphertext/claim_hash/status columns stay in the table shape
  // (existing files open unchanged) but are never read.
  function putGuestKernelWallet({ id, record }) {
    const config = kernelRecord(record);
    const row = { id: requiredText(id, "agent_id", 128), record_json: JSON.stringify(config) };
    try {
      insertKernel.run(row.id, config.initialOwnerAddress, config.initialOwnerAddress, config.address, config.chainId, row.record_json,
        "", "", randomBytes(32), new Date().toISOString());
    } catch (error) {
      if (error.code === "ERR_SQLITE_ERROR" && [1555, 2067].includes(error.errcode)) throw new Error("kernel_wallet_state_mismatch");
      throw error;
    }
    const existing = kernelById.get(row.id);
    if (existing.record_json !== row.record_json || existing.owner_key_ciphertext !== "") throw new Error("kernel_wallet_state_mismatch");
    return publicKernelRow(existing);
  }

  function getKernelWallet(id) {
    return publicKernelRow(kernelById.get(requiredText(id, "agent_id", 128)));
  }

  // The tap landed on chain (sudo = owner EOA, spender = the new agent in `record`): record it. Only once.
  function claimKernelWalletOnChain({ id, ownerAddress, record }) {
    const owner = getAddress(ownerAddress);
    const config = kernelRecord(record);
    const changed = database.prepare(`UPDATE agent_kernel_wallets SET owner_address=?,claimed=1,record_json=?,owner_key_ciphertext='',agent_key_ciphertext=''
      WHERE id=? AND claimed=0 AND address=?`).run(owner, JSON.stringify(config), requiredText(id, "agent_id", 128), config.address).changes;
    if (changed !== 1) throw new Error("kernel_claim_rejected");
    return getKernelWallet(id);
  }

  database.exec(`
    CREATE TABLE IF NOT EXISTS agent_provision_intents (
      id TEXT PRIMARY KEY,
      phase TEXT NOT NULL CHECK (phase IN ('quorum-pending', 'wallet-pending', 'store-pending')),
      worker TEXT NOT NULL, updated_at INTEGER NOT NULL,
      quorum_id TEXT, provider_wallet_id TEXT, address TEXT,
      owner_address TEXT, label TEXT, model TEXT, server_public_key TEXT, runtime_public_key TEXT, display_name TEXT,
      quorum_dispatched INTEGER NOT NULL DEFAULT 1, wallet_dispatched INTEGER NOT NULL DEFAULT 1
    ) STRICT;
  `);
  const getIntent = database.prepare("SELECT * FROM agent_provision_intents WHERE id = ?");
  function intentRow(intent) {
    if (!intent) return null;
    return {
      id: intent.id, phase: intent.phase, worker: intent.worker, updatedAt: intent.updated_at,
      quorumId: intent.quorum_id, providerWalletId: intent.provider_wallet_id, address: intent.address,
      ownerAddress: intent.owner_address, label: intent.label, model: intent.model,
      serverPublicKey: intent.server_public_key, runtimePublicKey: intent.runtime_public_key,
      displayName: intent.display_name, quorumDispatched: intent.quorum_dispatched, walletDispatched: intent.wallet_dispatched,
    };
  }

  function putNuriCustodiedAgent({ id = randomUUID(), ownerAddress, address, privateKey }) {
    if (!key) throw new Error("AGENT_KEY_ENCRYPTION_KEY_required");
    const row = {
      id: requiredText(id, "agent_id", 128),
      model: "nuri-custody",
      owner_address: getAddress(ownerAddress),
      address: getAddress(address),
    };
    const derivedAddress = privateKeyToAccount(privateKey).address;
    if (derivedAddress !== row.address) throw new Error("agent_private_key_address_mismatch");
    insert.run(row.id, row.model, row.owner_address, row.address, null, null, null, encryptPrivateKey(privateKey, key, row), null, null, new Date().toISOString());
    return publicRow(byId.get(row.id));
  }

  function createNuriCustodiedAgent({ id = randomUUID(), ownerAddress }) {
    const privateKey = generatePrivateKey();
    return putNuriCustodiedAgent({ id, ownerAddress, address: privateKeyToAccount(privateKey).address, privateKey });
  }

  function putNuriPrivyAppWallet({ id = randomUUID(), ownerAddress, address, providerWalletId }) {
    const model = "nuri-privy-app";
    if (!MODELS.has(model)) throw new Error("agent_model_invalid");
    const row = {
      id: requiredText(id, "agent_id", 128),
      model,
      owner_address: getAddress(ownerAddress),
      address: getAddress(address),
      provider_user_id: null,
      provider_wallet_id: requiredText(providerWalletId, "privy_wallet_id"),
      provider_signer_id: null,
      key_ciphertext: null,
      status: "active",
    };
    try {
      insert.run(row.id, row.model, row.owner_address, row.address, row.provider_user_id, row.provider_wallet_id, row.provider_signer_id, null, null, null, new Date().toISOString());
    } catch (error) {
      if (error.code !== "ERR_SQLITE_ERROR" || ![1555, 2067].includes(error.errcode)) throw error;
      
      
      const existing = byId.get(row.id);
      if (!existing || Object.entries(row).some(([field, value]) => existing[field] !== value)) throw new Error("agent_wallet_state_mismatch");
      return publicRow(existing);
    }
    return publicRow(byId.get(row.id));
  }

  
  
  
  
  
  function putNuriPrivyApp2of2Wallet({ id = randomUUID(), ownerAddress, address, providerWalletId, quorumId, serverPublicKey, runtimePublicKey }) {
    const model = "nuri-privy-app-2of2";
    if (!MODELS.has(model)) throw new Error("agent_model_invalid");
    
    
    const server = assertAuthorizationPublicKey(serverPublicKey);
    const runtime = assertAuthorizationPublicKey(runtimePublicKey);
    if (server.replace(/\s/g, "") === runtime.replace(/\s/g, "")) {
      throw new Error("agent_quorum_keys_must_differ");
    }
    if (typeof quorumId !== "string" || !/^[a-z0-9]{20,64}$/.test(quorumId)) throw new Error("agent_quorum_id_invalid");
    const row = {
      id: requiredText(id, "agent_id", 128),
      model,
      owner_address: getAddress(ownerAddress),
      address: getAddress(address),
      provider_user_id: null,
      provider_wallet_id: requiredText(providerWalletId, "privy_wallet_id"),
      provider_signer_id: quorumId,
      key_ciphertext: null,
      server_public_key: String(serverPublicKey).replace(/\s/g, ""),
      runtime_public_key: String(runtimePublicKey).replace(/\s/g, ""),
      status: "active",
    };
    try {
      insert.run(row.id, row.model, row.owner_address, row.address, row.provider_user_id, row.provider_wallet_id, row.provider_signer_id, null, row.server_public_key, row.runtime_public_key, new Date().toISOString());
    } catch (error) {
      if (error.code !== "ERR_SQLITE_ERROR" || ![1555, 2067].includes(error.errcode)) throw error;
      const existing = byId.get(row.id);
      if (!existing || Object.entries(row).some(([field, value]) => existing[field] !== value)) throw new Error("agent_wallet_state_mismatch");
      return publicRow(existing);
    }
    return publicRow(byId.get(row.id));
  }

  function putPrivyUserWallet({ id = randomUUID(), ownerAddress, address, providerUserId, providerWalletId, providerSignerId }) {
    const model = "privy-user-wallets";
    if (!MODELS.has(model)) throw new Error("agent_model_invalid");
    const row = {
      id: requiredText(id, "agent_id", 128),
      model,
      owner_address: getAddress(ownerAddress),
      address: getAddress(address),
      provider_user_id: requiredText(providerUserId, "privy_user_id"),
      provider_wallet_id: requiredText(providerWalletId, "privy_wallet_id"),
      provider_signer_id: requiredText(providerSignerId, "privy_signer_id"),
      key_ciphertext: null,
      status: "active",
    };
    try {
      insert.run(row.id, row.model, row.owner_address, row.address, row.provider_user_id, row.provider_wallet_id, row.provider_signer_id, null, null, null, new Date().toISOString());
    } catch (error) {
      if (error.code !== "ERR_SQLITE_ERROR" || ![1555, 2067].includes(error.errcode)) throw error;
      
      
      const existing = byId.get(row.id);
      if (!existing || Object.entries(row).some(([field, value]) => existing[field] !== value)) throw new Error("privy_agent_wallet_store_binding_mismatch");
      return publicRow(existing);
    }
    return publicRow(byId.get(row.id));
  }

  return {
    putGuestKernelWallet,
    claimKernelWalletOnChain,
    getKernelWallet,
    createNuriCustodiedAgent,
    putNuriCustodiedAgent,
    putPrivyUserWallet,
    putNuriPrivyAppWallet,
    putNuriPrivyApp2of2Wallet,
    getProvisionIntent(id) {
      return intentRow(getIntent.get(requiredText(id, "agent_id", 128)));
    },
    insertProvisionIntent({ id, worker, ownerAddress, label, model, serverPublicKey, runtimePublicKey, displayName }) {
      return database.prepare(`INSERT INTO agent_provision_intents
        (id,phase,worker,updated_at,owner_address,label,model,server_public_key,runtime_public_key,display_name,quorum_dispatched,wallet_dispatched)
        VALUES (?,'quorum-pending',?,?,?,?,?,?,?,?,0,0) ON CONFLICT(id) DO NOTHING`).run(
        requiredText(id, "agent_id", 128), requiredText(worker, "agent_provision_worker", 128), Date.now(),
        getAddress(ownerAddress), requiredText(label, "payment_agent_id"), requiredText(model, "agent_model"),
        assertAuthorizationPublicKey(serverPublicKey), assertAuthorizationPublicKey(runtimePublicKey),
        requiredText(displayName, "agent_quorum_display_name", 120)).changes === 1;
    },
    
    
    putProvisionIntent({ id, worker, phase, quorumId = null, providerWalletId = null, address = null,
      quorumDispatched = 0, walletDispatched = 0 }) {
      const changed = database.prepare(`UPDATE agent_provision_intents SET phase=?,updated_at=?,
        quorum_id=COALESCE(quorum_id,?),provider_wallet_id=COALESCE(provider_wallet_id,?),address=COALESCE(address,?),
        quorum_dispatched=MAX(quorum_dispatched,?),wallet_dispatched=MAX(wallet_dispatched,?)
        WHERE id=? AND worker=? AND (quorum_id IS NULL OR ? IS NULL OR quorum_id=?)
        AND (provider_wallet_id IS NULL OR ? IS NULL OR provider_wallet_id=?)
        AND (address IS NULL OR ? IS NULL OR address=?)`).run(
        phase, Date.now(), quorumId, providerWalletId, address, quorumDispatched, walletDispatched,
        requiredText(id, "agent_id", 128), requiredText(worker, "agent_provision_worker", 128),
        quorumId, quorumId, providerWalletId, providerWalletId, address, address).changes;
      if (changed !== 1) throw new Error("agent_wallet_provision_ownership_lost");
    },
    takeProvisionIntent({ id, expectedWorker, worker }) {
      
      if (expectedWorker !== "") return false;
      return database.prepare("UPDATE agent_provision_intents SET worker=?,updated_at=? WHERE id=? AND worker=?")
        .run(requiredText(worker, "agent_provision_worker", 128), Date.now(), requiredText(id, "agent_id", 128), expectedWorker).changes === 1;
    },
    releaseProvisionIntent({ id, worker }) {
      return database.prepare("UPDATE agent_provision_intents SET worker='' WHERE id=? AND worker=?")
        .run(requiredText(id, "agent_id", 128), requiredText(worker, "agent_provision_worker", 128)).changes === 1;
    },
    deleteProvisionIntent({ id, worker }) {
      return database.prepare("DELETE FROM agent_provision_intents WHERE id=? AND worker=?")
        .run(requiredText(id, "agent_id", 128), requiredText(worker, "agent_provision_worker", 128)).changes === 1;
    },
    // Custody v2 connect: the guest agent's quorum now holds the EOA-derived key; the row follows it.
    rebindAgent({ id, ownerAddress, runtimePublicKey }) {
      const runtime = assertAuthorizationPublicKey(runtimePublicKey).replace(/\s/g, "");
      database.prepare("UPDATE agent_wallets SET owner_address=?,runtime_public_key=? WHERE id=? AND model='nuri-privy-app-2of2'")
        .run(getAddress(ownerAddress), runtime, requiredText(id, "agent_id", 128));
      const row = publicRow(byId.get(id));
      if (!row || row.runtimePublicKey !== runtime) throw new Error("agent_wallet_state_mismatch");
      return row;
    },
    getAgent(id) {
      return publicRow(byId.get(requiredText(id, "agent_id", 128)));
    },
    listAgents(ownerAddress) {
      return byOwner.all(getAddress(ownerAddress)).map(publicRow);
    },
    getNuriAccount(id) {
      if (!key) throw new Error("AGENT_KEY_ENCRYPTION_KEY_required");
      const row = byId.get(requiredText(id, "agent_id", 128));
      if (!row || row.model !== "nuri-custody" || !row.key_ciphertext) throw new Error("agent_private_key_not_available");
      return privateKeyToAccount(decryptPrivateKey(row.key_ciphertext, key, row));
    },
    close() {
      database.close();
      key?.fill(0);
    },
  };
}
