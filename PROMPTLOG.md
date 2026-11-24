# Prompt log

## 2026-11-24 — Emin; recorded by Antigravity

- **"send the 1337 to emino ... make a local wallet and send back and forth autonomously"**
  - Fixed live mainnet blocker: `mempool.space/api/fee-estimates` target-3 dropped to `0.812` sat/vB (`esplora_fee_rate_invalid` when `< 1`). Updated `createEsploraL1Client.estimateFeeRate` (`rate > 0` -> `Math.max(1, Math.ceil(rate))`) + added TEST 17 (`bf138b3`).
  - Live mainnet `1,337`-sat proof: Paid `1,337` sats from `smartcard@nuriwallet.com` to `emino@nuri.com` (`lend` mode, preimage `a1bd306e...`, `fee_sats: 32` incl. `+27` `2%` fee); plus `497`-sat inbound (`+10` `2%` fee) auto-triggered `full_debt_plus_micro` (`FulfillFullDebt`, `-373` debt cancelled).
  - Live 6-hop autonomous mainnet ping-pong: Built standalone scratch Arkade+LN wallet (`ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameeqpzepk8flwu44eu4tavgk2f64gj8lwu5p0daq5h8m905thlmyezw8qusk`) and executed 6 automated bidirectional hops (requiring concurrent `Promise.all` `pushClaim` for `@arkade-os/swap` hold invoices): Hop 1 `smartcard -> local` `430` sats (`l1_0conf_collect` real co-signed L1 tx `707619313325e9aa627a358c6df99dfbff1cf2166c91488719f7840441dcbc8b`, clearing `327` debt); Hops 2–6 bounced `419 -> 392 -> 381 -> 360 -> 349` sats via `@nuriwallet.com` + `micro_credit` until reaching the `340`-sat floor.
  - Pool profit verified on `https://nuriwallet.com/v1/fronter/status`: `completedOutSwaps: 5`, `completedInSwaps: 5`, `earnedServiceFeeSats: 86`, `netFloatEquitySats: 10098` (`+95` sats vs `10003` baseline), `totalFloatSats: 10442`, `totalDebtSats: 0`, `totalPendingReceiveSats: 344`.
- **"switch to a muun.com like model where bitcoin is always onchain ... 100% ARKADE on server pool, NOT Spark ... test on paymentrequired.com (nuriwallet.com) without touching nuri.com or arkade.nuri.com"**
  - Decision: Keep user/agent BTC funds solely in `tr(MuSig2(agent, cosigner), pk(agent) + CSV)` on Bitcoin L1 (`src/agent-l1-fronter-v2.mjs`) and run a single server-side Arkade + L1 liquidity pool (`l1_0conf` mode), leaving consumer `app.nuri.com` and `arkade.nuri.com` 100% untouched. Rejected client-side VTXO wallets (too heavy) and raw un-cosigned 0-conf (RBF-vulnerable).
  - Live discovery: `nuri-agent-cosigner` on `46.225.135.119:8794` runs `blocks: 4320` (~30d), so `wallet-paymentrequired-com` live-syncs CSV & network from cosigner `/healthz` for byte-identical `bc1p...` addresses; also verified 0-byte divergence vs live mainnet `@lennard` (`app.nuri.com`).
- **"can we use connected smartcard via cli without extension ... keep skill.md simple/passkey-first ... auto-assign nuriwallet.com LNURL ... keep nuri.com vs nuriwallet.com strictly separate"**
  - Decision: Built `nuricard connect` CLI over PC/SC + USB-HID (`nuri-com/nuri-passkey-prf-smartcard`) while keeping `/skill.md` dead-simple browser-Passkey-first (`1acfe9e`). Auto-assigned deterministic 6-letter `@nuriwallet.com` LNURLs (`64e8819`) inside `wallet.sqlite` (zero calls to `arkade.nuri.com`) and registered `smartcard@nuriwallet.com`.
- **"send Lightning to emino@nuri.com (real L1 tx) ... explain Muun 1-sat ... add 2% both ways + monitor endpoint (park SwapKit overflow for later)"**
  - Live mainnet proof: Sent `1,000` sats to `emino@nuri.com` (`preimage 62efae23...`, L1 tx `e32a6b14...` paying `1,007` sats to pool L1 + `997` sats 0-conf trusted change); received `1,001` sats via `smartcard@nuriwallet.com` (`996` sats net credit).
  - Decision: Verified Muun `libwallet` (`incoming_swap.go`, `fees/fees.go`) never broadcasts sub-dust 1-sat L1 outputs (`FulfillFullDebt` + `OutputPadding`); added `FRONTER_RECEIVE_FEE_BPS` (`2%` in & out), `earnedServiceFeeSats` tracking, `btc_unconfirmed_sats`, and `GET /v1/fronter/status`. Parked SwapKit/BitcoinVN overflow rebalancing for later.

## 2026-11-23 — Emin; recorded by Antigravity

- "tell me if i can just fund base usdc or arkade and you then do the rest ... keep base usdc but
  tempo mpp still works auto ... can we not test the tempo payment and the treg.to?" → added
  Relay Base USDC (and Arkade → Base USDC) → Tempo (`4217`) Agent EOA auto-bridge with strict
  calldata/fee verification, `$0.03` Tempo EOA fee buffer, Agent EOA balance reuse, and README
  update.
- Live `treg.to` MPP test hit `feeToken is not defined` on Tempo Safe deploy and ran a hop for
  treg's free `amount: "0"` EIP-712 proof challenge → fixed `ensureSafeDeployed(..., feeToken)`,
  added `readTokenBalanceUnits`, skipped hops on `amount === 0`, and added two-step MPP
  `402 credit_insufficient` retry with cap & Tempo balance checks.
- "why are these links expiring so fast can they please stay valid for at least 1 hour or more ...
  after fixing, also please update the changelog and github repo for it" → `startOrPollOnboarding`
  omitted `timeoutMs`, falling back to Connect's 60-minute default; now passes 24 h
  (`DEFAULT_GRANT_CONNECT_TIMEOUT_MS`, overridable via `PRF_GRANT_CONNECT_TIMEOUT_MS`) and fixes
  `parseSessionExpiresAtMs` for `expires_at: 0` no-deadline sessions.

## 2026-11-20 — Emin; recorded by Hermes

- "I need to get support for MPP tempo. For some reason our wallet can't do it." → Tempo MPP
  from the PRF Safe (PR #23): found the Base-only offer filter, chain table and hardcoded
  chainId; verified the Gnosis Safe singleton/factory live on both Tempo chains.
- "run the LNURL for the agent wallet and we use the domain nuriwallet.com" → nuriwallet.com
  LNURL handles (PR #24 + #25): read agent-arkade-v2's RFQ receive path first ("it always
  ends up inside Arkade"), registered `goose@nuriwallet.com` live, minted a real invoice.

## 2026-10-17 — Emin; recorded by Hermes

- "tldr explain what confused the model, then fix it, then test it again, is it clear that there is a split between banking, wallet, signer etc.?"

```mermaid
flowchart LR
  O[Emin: physically separate repos] --> H[Hermes subagent: wallet staging]
```

- 2026-10-16, source Emin via Hermes parent; implementer Hermes/GPT-6.1: issue #404, fix only P1 durable record-only
  guest owner plus encrypted box before adoption/ACK and P2 complete-scan caller cancellation/deadline propagation.
  Code `8bccca2040c825f3041c735eb44ad089be30c48a`, committed 2026-10-16T04:06:48+02:00
  (`src/mcp-agent-wallet.mjs:394-416`, `src/browser-bridge.mjs:484-543`, `src/signer-broker-hook.mjs:88-186`).
  Signer 19f2c45 retained; Wallet source only. No Mac product execution, new tests, secrets/provider/payment/activation,
  SSH, prod, push or PR. Static diff check passed; runtime/cloud correctness UNVERIFIED. Parent reviews and owns release.
- 2026-10-16, source Emin via Hermes parent; implementer Hermes/GPT-6.1 (Opus route exhausted): resolve timestamp ties/
  clock regression, five-minute ciphertext loss versus guest links, and local expiry recovery; coordinate owned Wallet
  and Signer endpoints, preserve approvedAt expiry/bindings/signatures/guest-key handover, historical ties fail closed.
  Source-only; no Mac product execution, new tests/dependencies, Banking edits, push or deploy. Code
  `e06df06c12e0d5e35b4631ca9866fdfb65c63ee8` (2026-10-16T03:33:17+02:00): persisted broker-order election and expired
  guest descriptor recovery (`src/signer-broker-hook.mjs:117-168`, `src/browser-session-store.mjs:51-73`,
  `src/browser-bridge.mjs:662-670,718-721`, `src/mcp-connection.mjs:285-290,346-350`). Cloud/runtime/full parity UNVERIFIED.
- 2026-10-16, source Emin via Hermes parent; implementer Hermes/Opus 5.5; Wallet parity v3,
  code b986f09a8a43a669140cf8c6c61618a65c78b4bb: "No arbitrary newest-32 window; earliest successful tap, not oldest
  link creation; verify broker approvedAt; bounded broker response latency and stop repeated outage calls; do not hide
  unreadable potentially-earlier submitted results. Source-only, Wallet clone only, no Mac product execution or deploy."
  Implemented uncapped discovery, two-pass timestamp election shared by entry points, same-wallet in-flight coalescing,
  3 s HTTP/body deadline and 5 s client failure backoff (`src/browser-session-store.mjs:52-61`,
  `src/signer-broker-hook.mjs:94-97,117-166`, `src/root-signer-client.mjs:14-54`). Full parity NOT claimed: equal
  millisecond approvals and broker's 300 s result loss need a concrete signer contract decision (sibling
  `paymentrequired-signer/src/root-signer-store.mjs:25,33,53-54`, `paymentrequired-signer/src/root-signer-envelope.mjs:17`).
  Tests/build/runtime UNVERIFIED; parent cloud gates own execution. No new schemas, dependencies or public tool fields.
- 2026-10-16, Emin via Hermes parent → Hermes/Opus 5.5 (wallet follow-up, code 9e9fe4677558): "Repair the acknowledged parity
  hole: RAM-only claimLinks loses previously issued broker claim results after restart or when a newer balance link replaces it …
  Reuse persisted bridge connection rows/context.walletId … no new store/schema … No push/deploy."
- 2026-10-16, Emin via Hermes parent → Hermes/Opus 5.5 (signer-wallet parity, code a7e7f189d7c1): "Audit and fix verified
  wallet-to-Signer parity seam omissions. Parent live guest balance claim link resolves wallet-local /bridge/privy rather than
  separate signer … local legacy URLs must stay usable … No push/deploy."
- 2026-10-14, Emin via Hermes parent → Hermes subagent (wallet staging): "Implement physically separate Wallet repository artifact for wallet.paymentrequired.com … no Wirex banking constructor/client credentials … cloud actual boot/fixture probes … no prod or publication." Follow-up: port 8e77eecc only where wallet owns the route; preserve `<db>.chain-<id>` sidecar contract.
- 2026-10-14, Emin via Hermes parent → Hermes subagent (directory-wave consumer fix), input frozen directory-wave copy:
  "Fix actual final-consumer sign-in findings in frozen Banking and Wallet copies … first banking call after already
  delivered broker result returns stale connect_required once … broker_unreachable plain failure … missing
  serveSigningPreparation to explicit 404 … Direct public /mcp stays on owners". Scope approved-scope.md.
- 2026-10-14, Emin via Hermes parent → Hermes subagent (layer optimization): "So can you please deploy and run it? What is
  the problem where you stuck can you just finish the work?" Scope: minimal Dockerfile layer fix for the cloud build inode
  blocker, serial builds on the existing host, image-only QA, no deploy. Approval issue404 comment6171722323.
