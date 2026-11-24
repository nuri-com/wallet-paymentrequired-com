# Pure-L1 2-of-2 MuSig2+CSV + Server-Only Arkade 0-Conf Lightning Fronter

Implemented in [`src/agent-l1-fronter-v2.mjs`](../src/agent-l1-fronter-v2.mjs), wired into [`src/mcp-wallet-prf-v2.mjs`](../src/mcp-wallet-prf-v2.mjs) and [`src/wallet-server.mjs`](../src/wallet-server.mjs), backed by [`nuri-com/nuri-agent-cosigner`](https://github.com/nuri-com/nuri-agent-cosigner) (`127.0.0.1:8794`), and verified by 15 offline E2E tests in [`scripts/check-l1-0conf-fronter.mjs`](../scripts/check-l1-0conf-fronter.mjs) (run via `npm run check:prf`).

## Why Pure-L1 + Single Server Arkade Pool

Running a per-user Arkade VTXO wallet on every client forces every wallet to manage VTXO refreshes, Arkade rounds, and multi-tx unilateral exit trees. Moving to the **Muun model on Nuri's existing Taproot+CSV script** eliminates all client-side Arkade complexity:

- **User/Agent wallets hold only plain Bitcoin L1 UTXOs** at:
  `tr(MuSig2(agent, cosigner), and_v(v:pk(agent), older(nuriServerCsv)))`
- **A single server-side Arkade + L1 liquidity pool** (`createServerArkadeLiquidityPool`) handles all Lightning BOLT11 / LNURL-pay / L402 / Lightning MPP sends & receives via Arkade Intents RFQ.
- **Anti-RBF at 0-conf:** Because normal L1 spends require `nuri-agent-cosigner` (`2-of-2 MuSig2`), the cosigner atomically locks spent outpoints in SQLite (`l1_signed_outpoints`) and never co-signs a conflicting replacement.
- **Sovereign unilateral exit:** `buildUserCsvRecoveryTx` spends the Tapscript CSV leaf alone after `nuriServerCsv` expires if the server/cosigner disappears.
- **Direct on-chain BTC (`bc1...` / BIP21):** 1-tx native L1 MuSig2 spend (`payOnchainBtc`).

## Payment Flows (Muun `apollo` Model Verified)

Verified directly against `github.com/muun/apollo` (`fees.go`, `payment_analyzer.go`, `incoming_swap.go`, `FulfillIncomingSwapAction.kt`): Bitcoin Core dust rules reject P2TR outputs `< 330` sats, so sub-dust / tiny Lightning flows never broadcast 1-sat L1 outputs.

1. **Outgoing Tiny Sends (`LEND` / `micro_credit`):**
   - Sends `<= FRONTER_LEND_MAX_SATS` (default `5,000` sats, capped by `FRONTER_MAX_DEBT_SATS = 10,000` sats) backed by confirmed user L1 UTXOs are policy-authorized via cosigner `POST /v1/l1/authorize-spend` and paid immediately from the server Arkade pool with **0 L1 tx** (reverse custody — zero user custody risk).
2. **Outgoing Normal Sends (`COLLECT` + Hold-Broadcast):**
   - Wallet builds an L1 key-path P2TR PSBT paying the pool L1 deposit address (+ accumulated `debt_sats`), co-signs via `POST /v1/l1/sign-psbt` (atomically locking outpoints), and **holds broadcast** while the server Arkade pool pays Lightning.
   - On verified preimage: persists `broadcast_pending` before broadcast (crash-safe `reconcilePendingBroadcasts`), broadcasts the signed L1 tx, and seals outpoints via `POST /v1/l1/outpoints/mark-broadcast` (which registers DB-authoritative cosigned self-change as trusted 0-conf).
   - On confirmed pre-funding Lightning failure: calls `POST /v1/l1/outpoints/release` (only allowed when Esplora confirms the tx was never seen) → **0 L1 fee lost**.
   - On ambiguous timeout while a VHTLC may still settle: `safeToReleaseL1: false` preserves the L1 lock so a late settlement cannot leave an unbacked payout.
3. **Incoming Lightning → User L1 `bc1p...` (`FulfillFullDebt` + Auto-Sweep):**
   - Server Arkade pool issues & claims the BOLT11 invoice (`pushClaim` pagination loop).
   - Cancels `debt_sats` first (**0 L1 tx**).
   - If remaining + `pending_receive_sats >= FRONTER_L1_SETTLE_FLOOR_SATS` (default `5,000` sats): atomically reserves the claim in SQLite, broadcasts a 0-conf L1 P2TR payout from the pool L1 hot wallet (serialized via pool mutex + local change tracking), commits `done`, then registers the outpoint as trusted 0-conf on `nuri-agent-cosigner` (`POST /v1/l1/outpoints/register-trusted`, allowed even on inactive grants).
   - Sub-floor surplus stays in `pending_receive_sats` and auto-sweeps to L1 once it reaches the floor (or applies as instant outgoing credit).

## Verified Runtime, Security & Compatibility Findings (2026-11-24)

### 1. Live Cosigner CSV Synchronization (`46.225.135.119:8794`)
Live `nuri-agent-cosigner` on `46.225.135.119` runs `nuri_server_csv: { type: "blocks", value: 4320 }` (~30 days), whereas the library fallback was `{ type: "seconds", value: 7776256 }` (~90 days). Because `nuriServerCsv` enters the Tapscript leaf and Taproot merkle root, `createAgentL1FronterRuntime` now live-syncs `nuri_server_csv` and `l1_network` from `cosignerClient.healthz()` (5-minute TTL cache) so derived `bc1p...` addresses match byte-for-byte.

### 2. Live `@arkade-os/sdk@0.5.8` & `@arkade-os/swap@0.1.8` Probe Fixes
Probing `https://arkade.computer/v1/info` uncovered three breaking SDK runtime mismatches, all fixed and covered by E2E test #11:
- `derivePoolLightningSendLockup`: passes exact `lightningSendContract` fields (`solverPubkey`, hex string `paymentHash`, `operatorPubkey`, `claimDelay`, `refundWithoutReceiverDelay`, `refundPkScript`, `receiverPkScript`, plus `preTimelockedRefund` legacy fallback).
- `verifyLockupAddress(quote, candidates)`: fixed swapped argument order.
- Lockup lifecycle: handles `fate === "returned" | "exited"` (not `"refunded"`), paginates `pushClaim`, filters `!v.isSwept`, guards empty `resolveEmulatorPubkey`, passes `secretKey` to `nostrRfqTransport`, and honors `FRONTER_L1_DEPOSIT_ADDRESS` precedence.

### 3. Concurrency, Crash-Safety & Input Hardening
- Per-wallet and pool async mutexes + pool L1 hot-wallet spent/change tracker prevent concurrent UTXO collisions.
- Atomic SQLite inbound claim reservation prevents concurrent double payouts and non-fatal cosigner trust-register loops (covered by 5x concurrent claim storm test).
- `maxSats` enforcement includes the L1 miner fee (`estimateSendOverheadSats`).
- Trusted unconfirmed ancestor-depth cap (`<= 20`, below Bitcoin Core's 25-ancestor limit) + stale trusted UTXO pruning.
- Fixed multi-scheme `WWW-Authenticate` header parsing in `src/agent-lightning-pay.mjs`.

### 4. Consumer Nuri (`app.nuri.com` / `nuri-expo`) Compatibility
Byte-for-byte address derivation was verified against live mainnet `@lennard` (`6674432s` CSV → `bc1p3qk7647mnrzrq0fyj4zrzv5qmfrysgd7u4h9u5t7x5fqae3zlxastndvrd`) with **0-byte divergence**. Adopting this architecture in `app.nuri.com` requires **zero user address migration** and removes **~25,000+ LOC** and **3 npm packages** (`@arkade-os/sdk`, `@arkade-os/swap`, `@arkade-os/boltz-swap`) from the client.

## Configuration & Live POC Activation

| Environment Variable | Default | Purpose |
|---|---|---|
| `AGENT_BTC_CUSTODY_MODE` | `arkade` | Set `l1_0conf` to switch PRF BTC/LN wallets to Pure-L1 + server Arkade fronter |
| `FRONTER_ARKADE_PRIVKEY_HEX` | unset | 32-byte hex private key for the single server Arkade liquidity pool |
| `FRONTER_L1_PRIVKEY_HEX` | unset | 32-byte hex private key for the server L1 hot wallet (instant LN → L1 payouts) |
| `FRONTER_L1_DEPOSIT_ADDRESS` | derived from `FRONTER_L1_PRIVKEY_HEX` | Optional explicit L1 address receiving user replenishment txs |
| `FRONTER_BITCOIN_NETWORK` | synced from cosigner (`bitcoin`) | Bitcoin network (`bitcoin`, `testnet`, `signet`, `regtest`) |
| `FRONTER_ESPLORA_URL` | `https://mempool.space/api` | Esplora API for UTXOs, fee estimates, and raw tx broadcast |
| `FRONTER_L1_SETTLE_FLOOR_SATS` | `5000` | Minimum incoming LN surplus before instant 0-conf L1 settlement |
| `FRONTER_LEND_MAX_SATS` | `5000` | Maximum outgoing LN send eligible for 0-L1-tx Muun `LEND` |
| `FRONTER_MAX_DEBT_SATS` | `10000` | Per-wallet cap on unsettled `LEND` debt before `COLLECT` is required |
| `FRONTER_SERVICE_FEE_BPS` | `25` | Basis-point service fee charged on fronted outgoing Lightning payments (e.g. `200` = `2%`) |
| `FRONTER_RECEIVE_FEE_BPS` | `0` | Basis-point service fee deducted on incoming Lightning payouts/credits (e.g. `200` = `2%`) |

### Health, Public Monitor & Loopback Inspection
- `GET /healthz` exposes `btc_custody_mode`, `l1_0conf_fronter_supported: true`, and `l1_pool_configured` (`true` once `FRONTER_ARKADE_PRIVKEY_HEX` and `FRONTER_L1_PRIVKEY_HEX` / `FRONTER_L1_DEPOSIT_ADDRESS` are configured).
- `GET /v1/fronter/status` exposes a 15s-cached public read-only view of `arkadeAddress`, `l1DepositAddress`, `arkadeBalanceSats`, `l1HotBalanceSats`, `totalFloatSats`, `netFloatEquitySats`, `feesConfig`, and `ledgerTotals` (`earnedServiceFeeSats`, `completedOutSwaps`, `completedInSwaps`, `totalDebtSats`, `totalPendingReceiveSats`).
- Loopback `POST /rpc/tool` (`Bearer $SERVICE_RPC_SECRET`) supports `l1_pool_status` (`helper` tool) for live uncached pool inspection.

## Future Enhancements (Parked)
- **Overflow Liquidity via SwapKit / BitcoinVN:** When an outgoing or incoming Lightning swap exceeds live Arkade/L1 pool float, route overflow through SwapKit / BitcoinVN so swaps never block on float.
- **Cooperative L1-Out Fee Output:** Add an optional basis-point fee output (`>= 330` sats P2TR dust floor) to `sendOnchainBtc` co-signed L1 sends while keeping the unilateral Tapscript CSV exit 100% sovereign and fee-free.
