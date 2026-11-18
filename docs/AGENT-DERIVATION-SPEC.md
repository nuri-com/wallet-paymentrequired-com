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

### 2.2 Main Wallet vs Agent Sub-Wallet Isolation
- **Main Nuri Wallet Root** (inside `connect.nuri.com` only, **never** transmitted):
  - `HKDF-SHA256(ikm = prf_output_32b, salt = UTF8("nuri-hkdf-salt-v1"), info = UTF8("master-seed"), len = 64)`
- **Agent Sub-Wallet Master Seed** (domain-separated; cryptographically independent of `"master-seed"`):
  ```text
  agent_seed_64b = HKDF-SHA256(
    ikm  = prf_output_32b,                      // 32 non-zero bytes
    salt = UTF8("nuri-agent-wallet-v1"),
    info = UTF8("nuri-agent-master-seed:" + String(index)), // index = non-negative integer slot (default 0)
    len  = 64
  )
  ```
- **Child Key Paths** (`@scure/bip32` `HDKey.fromMasterSeed(agent_seed_64b)`):
  - **Agent EVM Key**: `m/44'/60'/0'/0/0` -> 32-byte secp256k1 private key -> `agent_eth_eoa` (EIP-55 checksummed).
  - **Agent Bitcoin / Arkade Key**: `m/86'/0'/0'/0/0` -> 32-byte secp256k1 private key -> 33-byte compressed pubkey `agent_btc_pk33` and 32-byte x-only pubkey `agent_btc_xonly`.
- **Slot Rotation (`index = 0, 1, 2, ...`)**: Incrementing `index` derives a brand-new, deterministic `(Agent EVM, Agent BTC)` pair from the same Nuri Passkey without rotating the passkey itself.

---

## 3. End-to-End Encrypted `agent_grant` Transport (`connect.nuri.com` -> `wallet.paymentrequired.com`)

`connect.nuri.com` acts as a zero-knowledge relay (`wallet_sign_start` / `wallet_sign_result` with `operation: "agent_grant"`):

1. `wallet.paymentrequired.com` generates a per-session ephemeral X25519 keypair `(reply_sk, reply_pk)` and calls `wallet_sign_start` with `{ operation: "agent_grant", reply_pubkey: hex(reply_pk), index, policy }`.
2. Inside the user's browser on `connect.nuri.com/approve`:
   - Evaluates Passkey PRF (`prf_output_32b`), derives slot `index` child keys (`agent_eth_sk`, `agent_btc_sk`), and extracts the passkey's uncompressed P-256 public key `(qx, qy)` (`credential_pubkey_b64u`, `0x04 || x32 || y32`) if newly created or stored.
   - Generates ephemeral sender X25519 `(eph_sk, eph_pk)` and seals the JSON plaintext with **XChaCha20-Poly1305**:
     ```text
     shared_32b = X25519(eph_sk, reply_pk)
     aead_key   = HKDF-SHA256(
       ikm  = shared_32b,
       salt = UTF8("nuri-agent-grant-reply-v1"),
       info = UTF8("nuri-agent-grant-reply-v1:" + session_id),
       len  = 32
     )
     aad        = UTF8("nuri-agent-grant-reply-v1:" + session_id + ":" + reply_pubkey_hex)
     ciphertext = XChaCha20-Poly1305.seal(key = aead_key, nonce = random(24), plaintext, aad)
     ```
   - Signs an EIP-191 ownership proof with the user's `main_eth_eoa` binding `session_id`, `reply_pubkey`, `ephemeral_pubkey`, `nonce`, and `SHA-256(ciphertext_bytes)`.
3. `wallet.paymentrequired.com` verifies the EIP-191 signature against `wallet.eth_user_eoa`, decrypts the grant, wipes `sealed_reply_sk` from SQLite, seals `(agent_eth_sk, agent_btc_sk)` under `HKDF-SHA256(AGENT_KERNEL_ENCRYPTION_KEY, wallet_key, "nuri-prf-agent-store-v1:" + wallet_id)`, and returns `wallet_key = "npw1_<43-char-base64url>"` **once**.

---

## 4.Deterministic Cosigner Shares (`nuri-agent-cosigner`)

For each `(cred_id_b64u, index)` grant, `nuri-agent-cosigner` (`127.0.0.1:8794`) deterministically derives its EVM and BTC co-signing shares from `COSIGNER_MASTER_SEED`:

```text
evm_sk = HKDF-SHA256(COSIGNER_MASTER_SEED, UTF8("nuri-agent-cosigner-evm-v1"), UTF8(cred_id_b64u + ":" + index), 32)
btc_sk = HKDF-SHA256(COSIGNER_MASTER_SEED, UTF8("nuri-agent-cosigner-btc-v1"), UTF8(cred_id_b64u + ":" + index), 32)
```
*(Reduced mod secp256k1 curve order `n` with counter fallback if out of `[1, n-1]`.)*

---

## 5. Base USDC Rail: Canonical 2-of-4 Safe v1.4.1 L2 (`chainId = 8453`)

Predicted **100% offline** via `CREATE2` (`src/agent-safe-v2.mjs`) and deployed lazily on first outbound Base transaction:

- **Singleton (SafeL2 v1.4.1)**: `0x29fcB43b46531BcA003ddC8FCB67FFE91900C762`
- **ProxyFactory v1.4.1**: `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67`
- **CompatibilityFallbackHandler v1.4.1**: `0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99`
- **Daimo P-256 Passkey Signer Factory**: `0x100000000000fd0821329A2A41697A10D2B22B35` + FCL Verifier `0xc2b78104907F722DABAc4C69f826a522B2754De4` -> `passkey_signer_address`
- **4 Owners (strictly preserve order)** & **Threshold = 2**:
  1. `main_eoa` (User's PasskeyPRF-derived main EOA)
  2. `passkey_signer_address` (User's WebAuthn P-256 hardware passkey contract signer; if P-256 pubkey is unavailable, deterministic fallback `keccak256("nuri-passkey-backup-owner-v1:" + cred_id_b64u)` address distinct from other owners)
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
3. **Leaf 2 — Sovereign Cosigner-Decay Recovery (`+14 days`)**:
   `CSVMultisigTapscript(unilateralExitDelay + 1_209_600, [agent_btc_xonly])`
   After `unilateralExitDelay + 14 days` (`1,209,600` seconds, encoded in 512-second BIP-68 time blocks), `nuri-agent-cosigner` decays completely: the user re-derives `agent_btc_sk` from their Nuri Passkey PRF and sweeps unilaterally on Bitcoin L1 with zero server involvement.

### 6.3 Trustless Lightning Swaps via Arkade Intents (`@arkade-os/swap`, Zero Boltz)
- **Operator**: `https://arkade.computer` (`arkd` mainnet, `hrp = "ark"`).
- **Solver Discovery**: Nostr RFQ over `wss://nostr.arkade.sh` (default mainnet solver `66422c952f8dcb96e4d0c3f049cd1e265b8461b916d9913c65c2494b64b4e3ce` / registry `https://arkade-os.github.io/solver-registry/bitcoin.json`).
- **Outgoing Lightning (`L402`, `MPP` Lightning, `BOLT11`, `LNURL-pay`)**:
  1. Decodes BOLT11 (`payment_hash`, `amount_sats`, `expires_at`) and requests RFQ quote on `arkade:bitcoin/slip44:0 -> bolt11:bitcoin/slip44:0`.
  2. Re-derives `lightningSendContract` locally and verifies `quote.profile.lockup_address` byte-for-byte (`AddressMismatch` aborts before signing).
  3. Co-signs `arkTx` + `checkpointTxs` via 2-of-2 MuSig2 (`nuri-agent-cosigner` independently rebuilds the VHTLC script from `intent` and enforces satoshi policy limits).
  4. `awaitSwapped` extracts the revealed 32-byte `preimage` directly from the solver's claim checkpoint witness and verifies `SHA-256(preimage) === payment_hash`.
- **Incoming Lightning (`wallet receive` `rail: "lightning"`)**:
  1. Deterministically derives `preimage = HKDF-SHA256(agent_btc_sk, "nuri-agent-ln-recv-v1", "preimage:" + rfq_id, 32)` and `claim_sk = HKDF-SHA256(agent_btc_sk, "nuri-agent-ln-recv-v1", "claim-key:" + rfq_id, 32)`.
  2. Requests `bolt11 -> arkade` RFQ quote with `payout_address = 2-of-2 Arkade address`, verifies `lightningReceiveContract` + BOLT11 `payment_hash` & amount, and returns the BOLT11 invoice.
  3. On subsequent `wallet balance` or `wallet receive` poll, `pushClaim` reveals `preimage` and sweeps the solver's VHTLC directly into the wallet's 2-of-2 `NuriAgentVtxoScript`.

---

## 7. Frozen Cross-Repo Test Vector (`test/vectors/agent-derivation-v1.json`)

Verified on every CI run across `connect-nuri-com`, `nuri-agent-cosigner`, and `wallet-paymentrequired-com` (`npm run check:prf`):

```json
{
  "prf_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "prf_salt_hex": "2760f8f82d8c709e169918dc800bd4d623ab14180bb21a701e8405600a3f9268",
  "slot0": {
    "index": 0,
    "eth_sk_hex": "31e75c96045238b3413d1c90057a1a8a21d08a400a2bf1ef971029a707e1f793",
    "eth_eoa": "0x246537b23697DE2ad29713D652b222B5dd0a9b97",
    "btc_sk_hex": "019dd64587119070468482cd53c07d2df3605b46da2bf072acdd7010b6352f42",
    "btc_pk33_hex": "0224733ba2444780fa5523b3b9d74b7c08e811484208ed9587a52dc3d7a3db362c",
    "btc_xonly_hex": "24733ba2444780fa5523b3b9d74b7c08e811484208ed9587a52dc3d7a3db362c"
  },
  "slot1": {
    "index": 1,
    "eth_eoa": "0x49bB62B87F430C7b6f0E36bFe566fB58d7aE5e26",
    "btc_pk33_hex": "027fb1782231438011fb7fd770a70f64a852ef1c85fb2e94420e61c764e6f2cf00"
  }
}
```
