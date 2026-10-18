// Prove that the offline check rejects the original retry advice and a missing cap.
// Task-owned mutations only; restore the exact bytes even on assertion failure.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const run = () => spawnSync(process.execPath, ['--experimental-test-module-mocks', 'scripts/check-wallet-ask.mjs'], { encoding: 'utf8', timeout: 60000 });
const cases = [
  ['over-cap retry advice', 'src/mcp-wallet-tool.mjs',
    'Nothing was paid; send again with a NEW request_id and a higher max_amount.',
    'Nothing was paid. Raise max_amount only if you want to spend more.'],
  ['ceiling before signing', 'src/agent-kernel-runtime.mjs',
    "if (maxAmountUnits !== undefined) check(BigInt(offer.amount) <= BigInt(maxAmountUnits), 'payment_exceeds_max_amount');",
    '// Synthetic negative control: cap removed.'],
  ['paid answer recovery', 'src/agent-kernel-runtime.mjs',
    "url === ROUTER_CHAT_URL && op.state === 'paid' && !op.data.result?.resource",
    "false && op.state === 'paid' && !op.data.result?.resource"],
];
for (const [name, path, old, replacement] of cases) {
  const original = readFileSync(path, 'utf8');
  assert.ok(original.includes(old), `Missing mutation anchor: ${name}`);
  try {
    writeFileSync(path, original.replaceAll(old, replacement));
    const broken = run();
    assert.equal(broken.error, undefined, `${name}: test process must actually execute`);
    assert.notEqual(broken.status, 0, `${name}: check did not catch the sabotage`);
    assert.match(broken.stderr, /AssertionError/, `${name}: must fail an assertion, not startup`);
    console.log(`negative control caught: ${name} (exit ${broken.status})`);
    console.log(broken.stderr.split('\n').filter(line => /AssertionError|assert\.|NEW request_id|recovered.ok|refused.ok/.test(line)).join('\n'));
  } finally { writeFileSync(path, original); }
}
const restored = run();
process.stdout.write(restored.stdout);
process.stderr.write(restored.stderr);
assert.equal(restored.status, 0, 'Restored candidate must pass');
console.log('wallet ask regression controls ok: three mutations fail; restored candidate passes');
