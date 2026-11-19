// Solana x402 exact payments for PRF Agent Wallets. The Ed25519 key is deterministically
// recoverable from the already-backed-up Agent EVM key, with domain separation.
import { hkdfSync } from "node:crypto";
import { address, createKeyPairSignerFromPrivateKeyBytes, createSolanaRpc } from "@solana/kit";
import { findAssociatedTokenPda, TOKEN_PROGRAM_ADDRESS } from "@solana-program/token";
import { ExactSvmScheme } from "@x402/svm/exact/client";
import { decodePaymentRequiredHeader, encodePaymentSignatureHeader } from "@x402/core/http";

export const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
export const SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
export const SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com";
const SOLANA_KEY_SALT = "app:nuri.com|agent-wallet|solana|v1";
const SOLANA_KEY_INFO = "ed25519";

export async function solanaSignerFromAgentKey(agentEthPrivateKeyHex) {
  const hex = String(agentEthPrivateKeyHex || "").replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("invalid_agent_evm_key");
  const seed = new Uint8Array(hkdfSync("sha256", Buffer.from(hex, "hex"), SOLANA_KEY_SALT, SOLANA_KEY_INFO, 32));
  return await createKeyPairSignerFromPrivateKeyBytes(seed, false);
}

export function parseSolanaChallenge({ headers = {}, bodyText = "" }) {
  let required;
  try {
    const h = headers["payment-required"] ?? headers["Payment-Required"];
    required = typeof h === "string" ? decodePaymentRequiredHeader(h) : JSON.parse(bodyText);
  } catch {
    return null;
  }
  if (required?.x402Version !== 2 || !Array.isArray(required.accepts)) return null;
  const offers = required.accepts.flatMap((raw, index) => {
    if (
      raw?.scheme !== "exact" || raw.network !== SOLANA_MAINNET || raw.asset !== SOLANA_USDC_MINT ||
      !/^(0|[1-9][0-9]{0,77})$/.test(String(raw.amount)) || typeof raw.payTo !== "string" ||
      !Number.isSafeInteger(raw.maxTimeoutSeconds) || raw.maxTimeoutSeconds <= 0 ||
      typeof raw.extra?.feePayer !== "string"
    ) return [];
    try {
      address(raw.payTo);
      address(raw.extra.feePayer);
    } catch {
      return [];
    }
    return [{ index, version: 2, raw, scheme: "exact", network: raw.network, asset: raw.asset,
      amount: String(raw.amount), payTo: raw.payTo, maxTimeoutSeconds: raw.maxTimeoutSeconds, extra: raw.extra }];
  });
  return offers.length ? { version: 2, required, offers } : null;
}

export function quoteSolanaOffer(offer) {
  return { scheme: offer.scheme, rail: "solana", x402_version: offer.version, network: offer.network,
    token: offer.asset, token_symbol: "USDC", decimals: 6, amount_units: offer.amount,
    pay_to: offer.payTo, max_timeout_seconds: offer.maxTimeoutSeconds, payer: "agent-solana" };
}

export async function readSolanaUsdcBalance({ owner, rpcUrl = SOLANA_RPC_URL }) {
  const [ata] = await findAssociatedTokenPda({ mint: address(SOLANA_USDC_MINT), owner: address(owner), tokenProgram: TOKEN_PROGRAM_ADDRESS });
  const rpc = createSolanaRpc(rpcUrl);
  try {
    const { value } = await rpc.getTokenAccountBalance(ata).send();
    return BigInt(value.amount);
  } catch (err) {
    if (JSON.stringify(err).includes("TokenAccountNotFound") || JSON.stringify(err).includes("could not find account")) return 0n;
    throw err;
  }
}

export async function payWithSolana({ offer, required, agentEthPrivateKeyHex, rpcUrl = SOLANA_RPC_URL }) {
  const signer = await solanaSignerFromAgentKey(agentEthPrivateKeyHex);
  const balance = await readSolanaUsdcBalance({ owner: signer.address, rpcUrl });
  if (balance < BigInt(offer.amount)) {
    throw Object.assign(new Error(`insufficient_solana_usdc:need_${offer.amount}_have_${balance}`), {
      code: "insufficient_solana_usdc", requiredUnits: offer.amount, availableUnits: balance.toString(), solanaAddress: signer.address,
    });
  }
  const signed = await new ExactSvmScheme(signer, { rpcUrl }).createPaymentPayload(2, offer.raw);
  const payload = { ...signed, accepted: offer.raw, resource: required.resource,
    ...(required.extensions === undefined ? {} : { extensions: required.extensions }) };
  return { payerAddress: signer.address, payload, headers: { "PAYMENT-SIGNATURE": encodePaymentSignatureHeader(payload) } };
}
