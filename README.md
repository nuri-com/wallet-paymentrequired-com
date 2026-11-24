# paymentrequired wallet service

The wallet service of paymentrequired.com, served at `wallet.paymentrequired.com`. It runs the
4-action dual-rail `wallet` MCP tool (`src/mcp-wallet-tool.mjs` + `src/mcp-wallet-prf-v2.mjs`):
**`balance`**, **`receive`**, **`pay`**, and **`history`** across **Base USDC** (`x402`, EVM `MPP`,
direct `0x` transfers, plus auto-bridged **Tempo `4217` MPP** via Relay from Base USDC or Arkade)
and **Bitcoin Lightning / Arkade** (`L402`, Lightning `MPP`, `BOLT11`,
Lightning Address `LNURL-pay`, and native `ark1` VTXOs via Arkade Intents — zero Boltz).

New wallets onboard with a single vendor-independent **Nuri Passkey PRF** tap on `connect.nuri.com`
(`operation: "agent_grant"`, bearer token `npw1_<43-char-base64url>`), deriving domain-separated
Agent EVM + Bitcoin child keys (`nuri-agent-wallet-v1`) co-signed by `nuri-agent-cosigner`
(`127.0.0.1:8794`) over a **2-of-4 Base Safe v1.4.1** and either a **2-of-2 MuSig2 + server-decay
Arkade VTXO script** (default) or **Pure-L1 2-of-2 MuSig2+CSV + Server-Only Arkade 0-Conf Fronter**
(`AGENT_BTC_CUSTODY_MODE=l1_0conf`, `src/agent-l1-fronter-v2.mjs` — Muun-style `LEND`/`COLLECT`/`FulfillFullDebt`,
hold-broadcast anti-RBF, instant 0-conf L1↔LN settlement, and direct native L1 `bc1...` sends). All existing v1 Privy/ZeroDev wallets (`44`-char and `66`-char `wallet_key`)
remain 100% live in place; see [`docs/CUSTODY-EVOLUTION.md`](docs/CUSTODY-EVOLUTION.md) and
[`docs/AGENT-DERIVATION-SPEC.md`](docs/AGENT-DERIVATION-SPEC.md).

The service holds no Wirex client and no Wirex credentials. Card, IBAN, account and bank-root
payments belong to the banking service.

```mermaid
flowchart LR
  AG[agent] -- wallet.paymentrequired.com/mcp --> W[wallet :8798]
  W -- agent_grant E2EE --> CN[connect.nuri.com]
  W -- loopback co-sign --> CS[nuri-agent-cosigner :8794]
  W -- Base Safe v1.4.1 --> BASE[Base USDC x402 / MPP]
  W -- Arkade + Intents RFQ --> ARK[arkade.computer / Lightning]
  A[peer facade :8795] -- private RPC wallet/helper/bridge --> W
  B[banking :8796] -- helper: charge/safe_address/on_tap/identity --> W
  W -- bank send top-up, helper wirex_read --> B
  W -- legacy v1 register/hydrate --> S[root signer :8797]
  P[person's browser] -- /bridge/privy, /api/browser-sessions --> W
```

## Run

```bash
npm ci && npm run build:privy      # public/privy-bridge.js (build-only deps)
cp .env.example .env               # fill the custody values; never commit .env
npm start                          # node src/wallet-server.mjs
npm run check                      # node --check every module + import-closure check
npm run check:prf                  # Passkey PRF + 2-of-4 Safe + 2-of-2 Arkade/Lightning E2E
```

Boot refuses when:
- `SERVICE_MODE` is anything other than `wallet` (`src/wallet-server.mjs:42`)
- any of `WIREX_TOKEN_URL`, `WIREX_COMPANY_ID`, `WIREX_CLIENT_ID` or `WIREX_CLIENT_SECRET` is set (`src/service-mode.mjs:24-28`)
- an agent custody value is missing (`src/server-boot-check.mjs:6-15`)
- `SERVICE_RPC_SECRET` is shorter than 32 characters (`src/service-rpc.mjs:22`)

## Pure-L1 0-Conf Arkade Fronter (`AGENT_BTC_CUSTODY_MODE=l1_0conf`)

Optional Muun-model custody mode (`src/agent-l1-fronter-v2.mjs`) where user/agent wallets hold **only plain Bitcoin L1 UTXOs** in `tr(MuSig2(agent, cosigner), pk(agent) + CSV)` and route all Lightning sends/receives through a **single server-side Arkade liquidity pool** (zero per-user Arkade VTXOs, zero VTXO renewals, 1-tx native L1 sends, and `buildUserCsvRecoveryTx` unilateral CSV exit):

- **Live cosigner sync:** syncs `nuri_server_csv` (e.g. `blocks: 4320` on `46.225.135.119`) and `l1_network` from `nuri-agent-cosigner /healthz` so `bc1p...` addresses always match byte-for-byte.
- **Zero-fee failure & tiny sends:** hold-broadcast anti-RBF locks outpoints at `nuri-agent-cosigner` until LN preimage (0 L1 fee on failure), paired with Muun-style `LEND` (`<= FRONTER_LEND_MAX_SATS`), `COLLECT`, `FulfillFullDebt`, and `FRONTER_L1_SETTLE_FLOOR_SATS` auto-sweep.
- **Activation & inspection:** configure `FRONTER_ARKADE_PRIVKEY_HEX` + `FRONTER_L1_PRIVKEY_HEX` (and optional `FRONTER_SERVICE_FEE_BPS` / `FRONTER_RECEIVE_FEE_BPS`, e.g. `200` bps = `2%`), check pool float, fees & revenue live at `GET /v1/fronter/status` or loopback `POST /rpc/tool` (`l1_pool_status`) + `GET /healthz`, then set `AGENT_BTC_CUSTODY_MODE=l1_0conf`.
- **Full findings, SDK fixes & `app.nuri.com` (`nuri-expo`) proof:** see [`docs/L1-0CONF-ARKADE-FRONTER.md`](docs/L1-0CONF-ARKADE-FRONTER.md).

## Ask AI from the agent wallet

One `wallet` tool call (`src/mcp-wallet-tool.mjs`, `ask`):

```json
{"action":"ask","wallet_key":"<your wallet_key>","prompt":"Explain x402 in one sentence.","max_amount":"0.05","quality":"fast","request_id":"explain-x402-1"}
```

Returns `answer`, `cost` (USDC), `model`, `receipt` and `request_id`, plus `ok`.
`quality` defaults to `fast`; `smart` selects the other model in `ASK_MODELS`.
The fixed router URL receives a non-streaming POST. It generates an answer, returns its
exact x402 invoice, then releases the answer after the existing wallet pay transport settles it.
No preflight generation and no new signing implementation.

Supply `request_id` before spending. Retry with the same ID and unchanged fields, including
the cap; the durable payment journal prevents a second payment, including after a restart.
An over-cap invoice signs and pays nothing: **send again with a NEW request_id and a higher
max_amount**. The rejected operation remains final; changing its cap conflicts with its binding.
If the paid response body was lost, same-ID replay reads the router's retained answer without
another payment signature (`src/agent-kernel-runtime.mjs`).

Offline checks (Node 22, no wallet credentials or network): `npm run check:ask` and
`npm run check:ask:regression`. They exercise the real x402 parsing/signing and durable journal
against a fake router, RPC, signer, Kernel account and wallet-credential adapter. CI runs these
on GitHub-hosted runners; no live payment or deployment is part of the checks.

## Surface

| Route | Source |
|---|---|
| `POST /mcp`: `initialize`, `tools/list` (= `wallet`), `tools/call` | `src/wallet-server.mjs:257-301` |
| `POST /rpc/tool` (loopback, bearer `SERVICE_RPC_SECRET`) | `src/service-rpc.mjs:21-45`, `src/wallet-server.mjs:120-154` |
| `GET /healthz` | `src/wallet-server.mjs:173-176` |
| `GET /v1/fronter/status` (15s cached public float & fee monitor) | `src/wallet-server.mjs` |
| `GET /` role page | `src/service-index.mjs:6-10` |
| `GET /bridge/privy`, `/bridge/privy/wirex`, `/bridge/privy.js` | `src/wallet-server.mjs:178-187` |
| `/api/browser-sessions/<id>[/approval\|/callback\|/connection]`, `/pending` | `src/wallet-server.mjs:188-234` |
| `GET/POST /s`, `GET /short-link.mjs` | `src/wallet-server.mjs:166-171` |

Public MCP endpoint: `https://wallet.paymentrequired.com/mcp` (catalog `wallet`,
`src/wallet-server.mjs:235,257-301`); connect links use the existing root signer broker
(`src/wallet-server.mjs:114-118`). Docs and llms files stay on the apex (`src/service-index.mjs:52-53`);
the apex `/mcp` no longer serves tools (approved-scope.md, 2026-10-14).

See `ARCHITECTURE.md` (owned stores, peers, peer-down behaviour), `DEPLOY.md` (image, mounts,
env), and `EXTRACTION.md` (what came from the monolith, and why).
