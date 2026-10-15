// SERVICE MODE (C0 §3): one code base, three processes.
//
//   unset     → the monolith exactly as before (every tool, one DB, PORT default 8796).
//   legacy    → the /mcp compatibility facade on 8795: original DB, original callbacks,
//               forwards calls it does not own to the wallet / banking owner.
//   wallet    → wallet tool only on 8798: agent custody, own DB, no Wirex client.
//   banking   → account + bank on 8796: Wirex, own DB, no agent custody env.
//
// Every value here comes from env; nothing is guessed from hostnames.

export const SERVICE_MODES = Object.freeze(["monolith", "legacy", "wallet", "banking"]);
const DEFAULT_PORT = Object.freeze({ monolith: 8796, legacy: 8795, wallet: 8798, banking: 8796 });

export function readServiceMode(env = process.env) {
  const raw = String(env.SERVICE_MODE || "").trim().toLowerCase();
  const mode = raw === "" ? "monolith" : raw;
  if (!SERVICE_MODES.includes(mode)) throw new Error(`SERVICE_MODE_invalid: one of ${SERVICE_MODES.slice(1).join(", ")} (unset = monolith)`);
  // The image pins PORT=8796 (Dockerfile:23) for the monolith; a split role listens on its own port
  // unless SERVICE_PORT says otherwise, so three roles can share one host network namespace.
  const port = Number(env.SERVICE_PORT || (mode === "monolith" ? env.PORT : "") || DEFAULT_PORT[mode]);
  const has = (name) => typeof env[name] === "string" && env[name].trim() !== "";
  // Boundaries are enforced at boot, not by convention (C0 §3, §6).
  if (mode === "legacy" && (!has("WALLET_RPC_URL") || !has("BANKING_RPC_URL") || !has("SERVICE_RPC_SECRET"))) throw new Error("legacy_peers_required: SERVICE_MODE=legacy needs WALLET_RPC_URL, BANKING_RPC_URL and SERVICE_RPC_SECRET");
  if (mode === "wallet") {
    for (const name of ["WIREX_TOKEN_URL", "WIREX_COMPANY_ID", "WIREX_CLIENT_ID", "WIREX_CLIENT_SECRET"]) {
      if (has(name)) throw new Error(`${name}_forbidden_in_wallet_service`);
    }
  }
  if (mode === "banking") {
    for (const name of ["PRIVY_AGENT_APP_SECRET", "PRIVY_AGENT_AUTHORIZATION_PRIVATE_KEY", "AGENT_STORE_PATH", "AGENT_KERNEL_FUNDER_KEY_FILE"]) {
      if (has(name)) throw new Error(`${name}_forbidden_in_banking_service`);
    }
  }
  return Object.freeze({
    mode, port,
    // legacy owns nothing: it is the compatibility facade on the old origin and forwards every tool
    // and callback to the owner over the private RPC, so there is exactly one writer per product.
    owns: Object.freeze({
      wallet: mode === "monolith" || mode === "wallet",
      banking: mode === "monolith" || mode === "banking",
    }),
    // Private RPC peers (C0 §3: explicit authenticated HTTP boundary, never public).
    walletRpcUrl: env.WALLET_RPC_URL || null,
    bankingRpcUrl: env.BANKING_RPC_URL || null,
    // Optional: the legacy facade's helper, so its retained connection rows qualify on wallet/banking.
    legacyRpcUrl: env.LEGACY_RPC_URL || null,
    rpcSecret: env.SERVICE_RPC_SECRET || null,
  });
}
