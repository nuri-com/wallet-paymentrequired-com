

export function formatSiwe({ domain, address, statement, uri, chainId, version = 1, nonce, issuedAt, expirationTime }) {
  return `${domain} wants you to sign in with your Ethereum account:
${address}

${statement}

URI: ${uri}
Version: ${version}
Chain ID: ${chainId}
Nonce: ${nonce}
Issued At: ${issuedAt}
Expiration Time: ${expirationTime}`;
}
