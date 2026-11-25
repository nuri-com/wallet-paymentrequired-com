# Nuri Agent Wallet Cryptographic Derivation & Protocol Specification (`nuri-agent-wallet-v1`)

Status: **FROZEN** across `connect-nuri-com`, `nuri-agent-cosigner`, and `wallet-paymentrequired-com`.
Any byte-level change to the domain strings, BIP32 paths, Safe initializer encoding, or Tapscript leaf ordering below breaks deterministic address prediction and sovereign recovery.

---

## 1. WebAuthn Passkey PRF Creation-Time Safety Rule ("The Sinan Lesson")

On iOS / macOS iCloud Keychain and Chromium authenticators, **whether a passkey supports the WebAuthn `prf` extension is fixed at `navigator.credentials.create()` time**:

1. During registration (`navigator.credentials.create`), `publicKey.extensions` **MUST** include `prf: { eval: { first } }` so the authenticator initializes an HMAC-secret / PRF key for that credential.
2. **Immediate PRF Verification Gate**: `createPasskeyWithPrf()` in `connect.nuri.com` checks whether the creation ceremony already returned `clientExtensionResults.prf.results.first` (32 bytes). If the platform only returned `prf: { enabled: true }` (or omitted `results.first` on `create`), `connect.nuri.com` immediately executes a follow-up `navigator.credentials.get()` PRF probe before accepting the passkey.
3. If `results.first` is missing, non-32-byte, or all-zero (`0x00 * 32`), passkey registration **hard-aborts immediately** with a clear user-facing error and never persists a non-PRF credential ID. This prevents "Sinan-class" silent failures where a passkey appears registered but can never derive deterministic keys later.

---

## 2. Frozen PRF Input & Domain Separation

### 2.1 WebAuthn PRF Salt (Shared With `connect.nuri.com` Sign-In Ceremony)
```text
prf_salt = SHA-256(UTF8("nuri-passkey-wallet-v1"))
         = 32 bytes evaluated via extensions.prf.eval.first
```
Evaluating the exact same WebAuthn `first` salt lets a single FaceID / TouchID tap on `connect.nuri.com` authenticate the user's Nuri Passkey and derive the isolated agent sub-tree in browser memory without a second biometric prompt.

### 2.2 Main Wallet vs Agent Sub-Wallet Isolation (`src/agent-grant-crypto.mjs`)
- **Main Nuri Wallet Root** (inside `connect.nuri.com` only, **never** transmitted):
  - `HKDF-SHA256(ikm = prf_output_32b, salt = UTF8("nuri-hkdf-salt-v1"), info = UTF8("master-seed"), len = 64)`
- **Agent Sub-Wallet Domain-Separated Salt & Entropies**:
  ```text
  AGENT_WALLET_SALT = SHA-256(UTF8("app:nuri.com|agent-wallet|v1"))

  eth_entropy_32b = HKDF-SHA256(
    ikm  = prf_output_32b,                      // 32 non-zero bytes
    salt = AGENT_WALLET_SALT,
    info = UTF8("app:nuri.com|agent-wallet|v1|chain=ethereum|fmt=secp256k1|index=" + String(index)),
    len  = 32
  )
  btc_entropy_32b = HKDF-SHA256(
    ikm  = prf_output_32b,                      // 32 non-zero bytes
    salt = AGENT_WALLET_SALT,
    info = UTF8("app:nuri.com|agent-wallet|v1|chain=bitcoin|fmt=taproot|index=" + String(index)),
    len  = 32
  )
  ```
- **Child Key Paths** (`@scure/bip32` `HDKey.fromMasterSeed(...)`):
  - **Agent EVM Key**: `HDKey.fromMasterSeed(eth_entropy_32b).derive("m/44'/60'/0'/0/0")` -> 32-byte secp256k1 private key -> `agent_eth_eoa` (EIP-55 checksummed).
  - **Agent Bitcoin / Arkade Key**: `HDKey.fromMasterSeed(btc_entropy_32b).derive("m/86'/0'/0'/0/0")` -> 32-byte secp256k1 private key -> 33-byte compressed pubkey `agent_btc_pk33` and 32-byte x-only pubkey `agent_btc_xonly`.
- **Slot Rotation (`index = 0, 1, 2, ...`)**: Incrementing `index` derives a brand-new, deterministic `(Agent EVM, Agent BTC)` pair from the same Nuri Passkey without rotating the passkey itself.

---

## 3. End-to-End Encrypted `agent_grant` Transport (`connect.nuri.com` -> `wallet.paymentrequired.com`)

`connect.nuri.com` acts as a zero-knowledge relay (`wallet_sign_start` / `wallet_sign_result` with `operation: "agent_grant"`):

1. `wallet.paymentrequired.com` generates a per-session ephemeral **secp256k1** keypair `(reply_sk, reply_pk_xonly = schnorr.getPublicKey(reply_sk))` and calls `wallet_sign_start` with `{ operation: "agent_grant", reply_pubkey: hex(reply_pk_xonly), index, policy }`.
2. Inside the user's browser on `connect.nuri.com/approve`:
   - Evaluates Passkey PRF (`prf_output_32b`), derives slot `index` child keys (`agent_eth_sk`, `agent_btc_sk`), and extracts the passkey's uncompressed P-256 public key `(qx, qy)` (`credential_pubkey_b64u`) if newly created or stored.
   - Generates ephemeral sender secp256k1 `(eph_sk, eph_pk_xonly)` and seals the JSON plaintext with **secp256k1 ECDH + XChaCha20-Poly1305** (`src/agent-grant-crypto.mjs`):
     ```text
     shared_32b = secp256k1.getSharedSecret(eph_sk, 0x02 || reply_pk_xonly, true).slice(1)
     aead_key   = HKDF-SHA256(
       ikm  = shared_32b,
       salt = UTF8("nuri-agent-grant-reply-v1"),
       info = UTF8(String(session_id)),
       len  = 32
     )
     aad        = UTF8(JSON.stringify({ format: "nuri-agent-grant-reply-v1", session_id, index, agent_eth_eoa, agent_btc_public_key_33_hex, policy }))
     ciphertext = XChaCha20-Poly1305.seal(key = aead_key, nonce = random(24), plaintext, aad)
     ```
   - Signs an EIP-191 ownership proof with the user's `main_eth_eoa` binding `session_id`, `reply_pubkey`, `ephemeral_pubkey`, canonical `policy`, and `SHA-256(UTF8(ciphertext_b64u))`.
3. `wallet.paymentrequired.com` verifies the EIP-191 signature against `wallet.eth_user_eoa`, decrypts the grant, wipes `sealed_reply_sk` from SQLite, seals `(agent_eth_sk, agent_btc_sk)` under `HKDF-SHA256(AGENT_KERNEL_ENCRYPTION_KEY, wallet_key, "nuri-prf-agent-store-v1:" + wallet_id)`, and returns `wallet_key = "npw1_<43-char-base64url>"` **once**.

---

## 4. Deterministic Cosigner Shares (`nuri-agent-cosigner`)

`nuri-agent-cosigner` (`127.0.0.1:8794`) derives its BTC and EVM co-signing scalars deterministically from two separate 32-byte root seeds (`AGENT_BTC_COSIGNER_SEED_HEX` and `AGENT_EVM_COSIGNER_SEED_HEX`; `rust/src/derive.rs`, `rust/src/evm_derive.rs`).

### 4.1 Bitcoin Cosigner Key — Canonical Non-Hardened BIP32 (`nuri-btc-cosigner-v4`)

All **new** wallets and grant slots derive the BTC cosigner key via **non-hardened BIP32** (`nuri-btc-cosigner-v4`), maintaining byte-for-byte parity with `arkade.nuri.com` / `nuri-signing`:

```text
# 1. Cosigner account extended key from 32-byte AGENT_BTC_COSIGNER_SEED_HEX
I                   = HMAC-SHA512(key = UTF8("nuri:btc-cosigner-v4:account"), data = seed_bytes)
d_acc               = (uint256_be(I[0..32]) mod (n - 1)) + 1     // secp256k1 curve order n
account_public_key  = d_acc * G                                  // 33-byte compressed pubkey
account_chain_code  = I[32..64]                                  // 32-byte BIP32 chain code
account_fingerprint = hex(SHA-256(account_public_key || account_chain_code))[0..16]

# 2. Deterministic 4-level non-hardened BIP32 child path from lowercase client_pk33_hex
wallet_id           = SHA-256(UTF8("nuri-btc-cosigner-v4|" + client_pk33_hex))
i0                  = uint32_be(wallet_id[0..4])   & 0x7fffffff
i1                  = uint32_be(wallet_id[4..8])   & 0x7fffffff
i2                  = uint32_be(wallet_id[8..12])  & 0x7fffffff
i3                  = uint32_be(wallet_id[12..16]) & 0x7fffffff
path                = m/i0/i1/i2/i3                              // 4 non-hardened BIP32 hops

# 3. Standard BIP32 CKDpriv (server) / CKDpub (offline client recovery)
btc_sk              = CKDpriv((d_acc, account_chain_code), m/i0/i1/i2/i3)
cosigner_btc_pk33   = CKDpub((account_public_key, account_chain_code), m/i0/i1/i2/i3)
```

`nuri-agent-cosigner` publishes `(account_public_key, account_chain_code, account_fingerprint)` openly on both `GET /healthz` and `GET /v1/btc/account`. Because this is public xpub material (never secret signing material), recovery tooling and public mirrors can archive it safely.

#### Why Non-Hardened BIP32 Is Intentional (Single-Passkey Self-Custody)

In a Taproot 2-of-2 + CSV output (`tr(MuSig2(client_pk, server_pk), pk(client_pk) + older(nuriServerCsv))` or the 3-leaf Arkade VTXO tree), spending the unilateral CSV decay leaf **still requires the Taproot Control Block**, which commits to `internal_key = MuSig2(client_pk, server_pk)`:

- With **non-hardened BIP32 (`nuri-btc-cosigner-v4`)**, a user who has **only their Nuri Passkey** (and the publicly archived `(account_public_key, account_chain_code)`) can deterministically reconstruct `client_pk` -> `m/i0/i1/i2/i3` -> `server_pk` -> `internal_key` -> Taproot CSV Control Block **100% offline** if Nuri disappears — with zero extra per-wallet backup.
- With **hardened HMAC derivation** (`nuri-agent-btc-cosigner-v1`), `server_pk` cannot be derived from public account data alone; every user would need to preserve a separate out-of-band 32-byte `server_pk` / output-descriptor backup just to execute unilateral CSV recovery if the server vanished.
- Tradeoff & roadmap: non-hardened BIP32 requires keeping all derived child private keys strictly inside the isolated `nuri-agent-cosigner` boundary (leaking a child private key alongside `account_chain_code` would expose `d_acc`). This tradeoff is deliberate for zero-backup single-passkey 2-of-2+CSV custody; a future 2-of-3 architecture with a dedicated hardware wallet can revisit hardened derivation.

### 4.2 Legacy Bitcoin Cosigner Key — Backward-Compatible Pinned Grants (`nuri-agent-btc-cosigner-v1`)

Pre-existing grants pinned to `nuri-agent-btc-cosigner-v1` retain automatic **read/sign backward compatibility** so zero existing wallets lose access or change addresses. Legacy grants derive their BTC scalar via hardened **HMAC-SHA512** (iterating `counter = 0..255` until valid non-zero scalar `< n`):

```text
btc_sk_legacy = HMAC-SHA512(
  AGENT_BTC_COSIGNER_SEED_HEX,
  UTF8("nuri-agent-btc-cosigner-v1|" + cred_id_b64u + "|" + index + "|" + client_pk33_hex + "|" + counter)
)[0..32]
```

New wallets and grant slots **never** use `nuri-agent-btc-cosigner-v1`.

### 4.3 EVM Safe Cosigner Key — Hardened HMAC-SHA512 (`nuri-agent-evm-cosigner-v1`)

EVM Safe co-signing keys remain derived via **hardened HMAC-SHA512** (taking the first 32 bytes, iterating `counter = 0..255` until valid non-zero scalar `< n`; `rust/src/evm_derive.rs`), because Base 2-of-4 Safe recovery uses `[main_eoa, passkey_signer_address]` directly on-chain and does not require offline reconstruction of `cosigner_eoa`:

```text
evm_sk = HMAC-SHA512(AGENT_EVM_COSIGNER_SEED_HEX, UTF8("nuri-agent-evm-cosigner-v1|" + cred_id_b64u + "|" + index + "|" + counter))[0..32]
```

---

## 5. Base USDC Rail: Canonical 2-of-4 Safe v1.5.0 L2 (`chainId = 8453`)

Predicted **100% offline** via `CREATE2` (`src/agent-safe-v2.mjs` & `nuri-agent-cosigner/rust/src/evm_derive.rs`) and deployed lazily on first outbound Base transaction:

- **Singleton (SafeL2 v1.5.0)**: `0xEdd160fEBBD92E350D4D398fb636302fccd67C7e`
- **ProxyFactory v1.5.0**: `0x14F2982D601c9458F93bd70B218933A6f8165e7b`
- **CompatibilityFallbackHandler v1.5.0**: `0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4`
- **SafeWebAuthnSignerFactory**: `0x1d31F259eE307358a26dFb23EB365939E8641195`, **SafeWebAuthnSignerSingleton**: `0x4e27b51350e6c2083ee19011120f50dafec5ca50`, **Daimo P-256 Verifier**: `0xc2b78104907F722DABAc4C69f826a522B2754De4` (`DEFAULT_P256_VERIFIERS = (0x100n << 160n) | BigInt(DAIMO_P256_VERIFIER)`) -> `passkey_signer_address`
- **4 Owners (strictly preserve order)** & **Threshold = 2**:
  1. `main_eoa` (User's PasskeyPRF-derived main EOA)
  2. `passkey_signer_address` (User's WebAuthn P-256 hardware passkey contract signer; if P-256 pubkey is unavailable, deterministic fallback `sha256(UTF8("nuri-agent-legacy-owner2:" + main_eoa.toLowerCase() + ":" + cred_id_b64u))[0..20]`)
  3. `agent_eth_eoa` (`wallet.paymentrequired.com` Agent child EOA)
  4. `cosigner_eoa` (`nuri-agent-cosigner` grant EOA)
- **Salt Nonce**:
  ```text
  salt_nonce = BigInt(keccak256(UTF8("nuri-agent-safe-v1:" + cred_id_b64u + ":" + String(index))))
  ```
- **Lazy Deployment**: When the Safe holds USDC and executes its first `x402` Permit2 approval, EVM `MPP` hop, or direct `0x` USDC transfer, the server relayer (`AGENT_KERNEL_FUNDER_KEY_FILE`) deploys the Safe proxy first if `getCode(safeAddress)` is empty, then broadcasts `Safe.execTransaction` signed by sorted `[agent_eth_eoa, cosigner_eoa]`.

---

## 6. Bitcoin / Arkade / Lightning Rail: 3-Leaf Server-Decay `NuriAgentVtxoScript`

### 6.1 BIP-327 MuSig2 Key Aggregation
`keyAggExport([agent_btc_pk33, cosigner_btc_pk33])` (`sortKeys: true` per BIP-327, implemented identically in `nuri-agent-cosigner` and `@arkade-os/sdk` MuSig2):
- Produces 32-byte x-only `aggregated_btc_xonly`.

### 6.2 3-Leaf Taproot VTXO Script (`src/agent-arkade-v2.mjs`)
Constructed over BIP-341 unspendable NUMS internal key (`VtxoScript` in `@arkade-os/sdk`):

1. **Leaf 0 — Collaborative Off-Chain Forfeit / Spend**:
   `MultisigTapscript([aggregated_btc_xonly, ark_operator_xonly])`
   Used on every instant off-chain Arkade transfer and Lightning VHTLC funding transaction (`MuSig2(Agent, Cosigner)` + Arkade Operator Schnorr signature).
2. **Leaf 1 — Standard Unilateral Exit**:
   `CSVMultisigTapscript(unilateralExitDelay, [aggregated_btc_xonly])`
   Allows `Agent + Cosigner` to exit unilaterally on Bitcoin L1 if the Arkade operator goes offline.
3. **Leaf 2 — Sovereign Cosigner-Decay Recovery (`+7,776,256s` / ~90 days default)**:
   `CSVMultisigTapscript(unilateralExitDelay + 7_776_256, [agent_btc_xonly])` (or `+12,960` blocks when block-based; configurable via `ARKADE_DECAY_OFFSET_SECONDS`; in `AGENT_BTC_CUSTODY_MODE=l1_0conf`, L1 outputs use `tr(MuSig2(agent, cosigner), pk(agent) + older(nuriServerCsv))`).
   After the decay timelock (encoded in 512-second BIP-68 time units or blocks), `nuri-agent-cosigner` decays completely: the user re-derives `agent_btc_sk` from their Nuri Passkey PRF and sweeps unilaterally on Bitcoin L1 with zero server involvement.

### 6.3 Trustless Lightning Swaps via Arkade Intents (`@arkade-os/swap`, Zero Boltz)
- **Operator**: `https://arkade.computer` (`arkd` mainnet, `hrp = "ark"`).
- **Solver Discovery**: Nostr RFQ over `wss://nostr.arkade.sh` (default mainnet solver `66422c952f8dcb96e4d0c3f049cd1e265b8461b916d9913c65c2494b64b4e3ce` / registry `https://arkade-os.github.io/solver-registry/bitcoin.json`).
- **Outgoing Lightning (`L402`, `MPP` Lightning, `BOLT11`, `LNURL-pay`)**:
  1. Decodes BOLT11 (`payment_hash`, `amount_sats`, `expires_at`) and requests RFQ quote on `arkade:bitcoin/slip44:0 -> bolt11:bitcoin/slip44:0`.
  2. Re-derives `lightningSendContract` locally and verifies `quote.profile.lockup_address` byte-for-byte (`AddressMismatch` aborts before signing).
  3. Co-signs `arkTx` + `checkpointTxs` via 2-of-2 MuSig2 (`nuri-agent-cosigner` independently rebuilds the VHTLC script from `intent` and enforces satoshi policy limits) — or in `l1_0conf` mode submits from the server's Arkade liquidity pool against a hold-broadcast L1 MuSig2 spend.
  4. `readLockupFate(indexer, ...)` extracts the revealed 32-byte `preimage` directly from the solver's claim checkpoint witness and verifies `SHA-256(preimage) === payment_hash`.
- **Incoming Lightning (`wallet receive` `rail: "lightning"`)**:
  1. Deterministically derives secrets using `LN_CLAIM_SALT = SHA-256(UTF8("app:nuri.com|arkade-ln-claim|v1"))` via `deriveLightningReceiveSecrets(keyHex, rfqId)` (`preimage` + `claim_sk`).
  2. Requests `bolt11 -> arkade` RFQ quote with `payout_address = 2-of-2 Arkade address` (or Pool Arkade address in `l1_0conf` mode), verifies `lightningReceiveContract` + BOLT11 `payment_hash` & amount, and returns the BOLT11 invoice.
  3. `pushClaim` reveals `preimage` and sweeps the solver's VHTLC directly into the Arkade `DefaultVtxo` script (and settles L1 in `l1_0conf` mode when above `FRONTER_L1_SETTLE_FLOOR_SATS`).

---

## 7. Frozen Cross-Repo Test Vector (`test/fixtures/agent-grant-vector.json`)

Verified on every CI run across `connect-nuri-com`, `nuri-agent-cosigner`, and `wallet-paymentrequired-com` (`npm run check:prf`):

```json
{
  "prf_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "slot0": {
    "index": 0,
    "eth_sk_hex": "a84be43865a72d3d9e171556853f6d305ba26ab1b36417645111d1a76399daaf",
    "agent_eth_eoa": "0xFDD0eD97c09575a78cfEBcfb1C33c2fed757951c",
    "btc_sk_hex": "118b77752f5b00ca5e46a5d2a92f788a156f2acd802ca49bbe2e20667dcff4dd",
    "agent_btc_public_key_33_hex": "02b680afa5e2d1624f6d205a9f1cfd728709e28491a8c866d538eede9bba383dbf",
    "agent_btc_taproot_address": "bc1pq7ysmft44p20zhetv78cgukhhzvp798g0mfpxej9fumlnlljsu3sxvhqw8"
  },
  "slot1": {
    "index": 1,
    "eth_sk_hex": "cfe6fdd1d63c107a71a95311a385205d618dd75a56e6106cc1a1ff1d783c0622",
    "agent_eth_eoa": "0xBB814a337bEED15edb56882F31f4772aB066A1f1",
    "btc_sk_hex": "6c04e29b43abb32dcd91efcff525f0e3eaee62d1dfa539b311c4144b19e8e618",
    "agent_btc_public_key_33_hex": "02b6931ca220319870c751d8b6a6b3cb928f35cfeb0188081eb18cbd2eeec42937",
    "agent_btc_taproot_address": "bc1pafr6heu8a0gdw7q5twwek2twffrk2wv33v7fsd9fuz85emnjsk0qwtkjrc"
  }
}
```
