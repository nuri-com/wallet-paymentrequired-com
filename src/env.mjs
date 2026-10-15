import { readFileSync } from "node:fs";


export function loadDotEnv(path = ".env", env = process.env) {
  let text = "";
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) continue;
    const [, key, rawValue] = match;
    if (env[key] !== undefined) continue;
    env[key] = unquoteEnvValue(rawValue.trim());
  }
  return true;
}

function unquoteEnvValue(value) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  const commentIndex = value.search(/\s+#/);
  return commentIndex >= 0 ? value.slice(0, commentIndex).trim() : value;
}



export function parseCorsExtraOrigins(value) {
  const origins = new Set();
  for (const entry of String(value || "").split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const url = new URL(trimmed);
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      throw new Error(`CORS_EXTRA_ORIGINS entry must be a bare https origin: ${trimmed}`);
    }
    origins.add(url.origin);
  }
  return origins;
}
