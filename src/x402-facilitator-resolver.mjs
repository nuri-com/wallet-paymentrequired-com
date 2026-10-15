




















const FACILITATOR_BY_CHAIN = new Map([
  [84532, 'https://x402.org/facilitator'],
  [8453, 'https://facilitator.payai.network'],
]);


export const FACILITATOR_URL_ENV = 'X402_FACILITATOR_URL';


export function knownFacilitatorChains() {
  return [...FACILITATOR_BY_CHAIN.keys()];
}

function operatorOverride(env) {
  const raw = env && env[FACILITATOR_URL_ENV];
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  const value = raw.trim();
  let url;
  try { url = new URL(value); } catch { throw new Error(`The ${FACILITATOR_URL_ENV} setting is not a valid URL, so payments cannot be sent to it: "${value}"`); }
  if (url.protocol !== 'https:') throw new Error(`The ${FACILITATOR_URL_ENV} setting must be an https:// address, so payments cannot be sent to it: "${value}"`);
  if (url.username || url.password || url.search || url.hash) throw new Error(`The ${FACILITATOR_URL_ENV} setting must be a plain https:// address with no credentials, query or fragment: "${value}"`);
  return url.origin + url.pathname.replace(/\/+$/, '');
}














export function resolveFacilitatorUrl(chainId, { env = process.env } = {}) {
  const override = operatorOverride(env);
  if (override !== null) return override; 
  const known = FACILITATOR_BY_CHAIN.get(chainId);
  if (known === undefined) {
    throw new Error(`No x402 settlement facilitator is configured for chain ${chainId}, so a payment on this chain could never settle. Refusing to send it to a facilitator for a different chain. Chains with a built-in facilitator: ${knownFacilitatorChains().join(', ')}. To use chain ${chainId}, set ${FACILITATOR_URL_ENV} to a facilitator https:// address that lists chain ${chainId}.`);
  }
  return known;
}
