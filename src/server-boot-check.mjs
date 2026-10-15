



export function assertAgentCustodyBootEnv(env = process.env) {
  requiredAgentCustodyString(env.PRIVY_AGENT_APP_ID, "PRIVY_AGENT_APP_ID");
  requiredAgentCustodyString(env.PRIVY_AGENT_APP_SECRET, "PRIVY_AGENT_APP_SECRET");
  requiredAgentCustodyString(env.PRIVY_AGENT_AUTHORIZATION_PRIVATE_KEY, "PRIVY_AGENT_AUTHORIZATION_PRIVATE_KEY");
  requiredAgentCustodyString(env.AGENT_STORE_PATH, "AGENT_STORE_PATH");
  if (env.AGENT_CUSTODY_MODEL !== "nuri-privy-app-2of2") {
    throw new Error(env.AGENT_CUSTODY_MODEL && String(env.AGENT_CUSTODY_MODEL).trim()
      ? "agent_custody_model_unsupported"
      : "AGENT_CUSTODY_MODEL_required");
  }
}

function requiredAgentCustodyString(value, name) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name}_required`);
  return value.trim();
}
