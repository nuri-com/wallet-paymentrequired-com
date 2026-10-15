// Import-closure check for the wallet repository (no network, no dependencies, no state).
// Fails when: a relative import does not resolve; a src/ module is not reachable from the
// entrypoint (dead code); a banking-owned module is present; or a Wirex credential variable is
// read anywhere in src/.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRIES = ["src/wallet-server.mjs", "public/privy-bridge.jsx",
  // loaded by specifier at runtime: src/signer-broker-hook.mjs:35,38
  "src/root-signer-client.mjs"];
const BANKING_ONLY = ["wirex-baas.mjs", "wirex-api.mjs", "mcp-wallet-pay.mjs", "mcp-bank-tool.mjs", "mcp-bank.mjs", "mcp-account-tool.mjs",
  "mcp-cards.mjs", "mcp-card-issuance.mjs", "mcp-card-transfers.mjs", "mcp-payouts.mjs", "mcp-products.mjs", "mcp-withdrawals.mjs",
  "mcp-transfers.mjs", "mcp-deposits.mjs", "mcp-wallets.mjs", "mcp-balances.mjs", "aa-withdrawal.mjs", "resend-onboarding.mjs", "mcp-wallet-fund-global.mjs"];
const FORBIDDEN_ENV = /process\.env\.(WIREX_CLIENT_ID|WIREX_CLIENT_SECRET|WIREX_TOKEN_URL)\b/;
const IMPORT = /(?:from\s+|import\s*\(\s*|import\s+)["']([^"']+)["']/g;

const errors = [];
const seen = new Set();
const stack = [...ENTRIES];
while (stack.length) {
  const file = stack.pop();
  if (seen.has(file)) continue;
  if (!existsSync(join(ROOT, file))) { errors.push(`missing: ${file}`); continue; }
  seen.add(file);
  const text = readFileSync(join(ROOT, file), "utf8");
  for (const [, spec] of text.matchAll(IMPORT)) {
    if (!spec.startsWith(".")) continue;
    const target = normalize(join(dirname(file), spec));
    if (target.endsWith(".json")) { if (!existsSync(join(ROOT, target))) errors.push(`missing: ${target} (from ${file})`); continue; }
    stack.push(target);
  }
}
const modules = readdirSync(join(ROOT, "src")).filter((name) => name.endsWith(".mjs")).map((name) => `src/${name}`);
for (const file of modules) {
  if (!seen.has(file)) errors.push(`unreachable: ${file}`);
  if (BANKING_ONLY.includes(file.slice(4))) errors.push(`banking_module_present: ${file}`);
  if (FORBIDDEN_ENV.test(readFileSync(join(ROOT, file), "utf8"))) errors.push(`wirex_credential_read: ${file}`);
}
if (errors.length) { console.error(errors.join("\n")); process.exit(1); }
console.log(`import closure ok: ${seen.size} files from ${ENTRIES.length} entries, ${modules.length} src modules, root ${relative(process.cwd(), ROOT) || "."}`);
