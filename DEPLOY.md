# Deploy

```mermaid
flowchart LR
  G[reviewed commit] --> I[docker build -t paymentrequired-wallet:SHA]
  I --> C[container nuri-wallet<br/>network host, 127.0.0.1:8798]
  C --> H[/healthz git_sha, service_mode=wallet, tools=[wallet]/]
  N[nginx wallet.paymentrequired.com] --> C
```

Build on the box from a reviewed commit: `docker build --build-arg GIT_SHA=$SHA -t paymentrequired-wallet:$SHA .`
(`Dockerfile`). The image ships `src/`, `public/` and production `node_modules` only.

## Runtime contract

| Item | Value | Source |
|---|---|---|
| Listen | `HOST=127.0.0.1`, port 8798 | `Dockerfile`, `src/service-mode.mjs:12` |
| State mount | directory holding `SHORT_LINKS_DB` **and every `<db>.chain-<id>` sidecar** | `src/mcp-agent-wallet.mjs:225` |
| Agent store | `AGENT_STORE_PATH` (same mount) | `src/server-boot-check.mjs:9` |
| Read-only key files | `AGENT_KERNEL_FUNDER_KEY_FILE`, optional `ROOT_SIGNER_RESULT_KEY_FILE`, `AA_PAYMASTER_SIGNER_KEY_PATH` | `src/agent-kernel-runtime.mjs:310`, `src/signer-broker-hook.mjs:27`, `src/aa-register.mjs:104` |
| Peers | `BANKING_RPC_URL`, `LEGACY_RPC_URL`, `SERVICE_RPC_SECRET` | `src/service-mode.mjs:43-47` |
| Refused | `WIREX_TOKEN_URL`, `WIREX_COMPANY_ID`, `WIREX_CLIENT_ID`, `WIREX_CLIENT_SECRET` | `src/service-mode.mjs:24-28` |

The edge publishes the browser routes listed in README "Surface" plus `POST /mcp`. `/rpc/tool`
stays private. Edge change is parent-owned; UNVERIFIED in production.

## State handoff

The target is the wallet state directory, for example `/opt/paymentrequired/state-wallet`
mounted at `/var/lib/nuri-wallet`, with `SHORT_LINKS_DB=/var/lib/nuri-wallet/wallet.sqlite`. Every
sidecar that exists next to the old database must be adopted to the same name next to the new
one: `short-links.sqlite.chain-<id>` becomes `wallet.sqlite.chain-<id>`. A missing sidecar opens
empty on first use (`src/agent-kernel-runtime.mjs:151`) and hides that chain's ops, txs and
budget. The adoption itself (state migration tooling) is not part of this repository.

Rollback: keep the previous image tag. Never restart an old writer against state this service
has already written.
