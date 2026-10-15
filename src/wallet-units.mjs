// Pure wallet unit/chain helpers, copied VERBATIM from the monolith's src/mcp-wallet-pay.mjs
// (source c16ab56, lines 50-65, 74-75, 143-147, 156-158, 162-168, 170-187). The wallet service
// imports only these helpers; the bank-root pay module itself (createMcpWalletPay, wallet_payments
// ledger, buy links) is owned by the banking repository and is NOT part of this artifact.
// No writer, no state: formatting and address checks only.
import * as VIEM_CHAINS from "viem/chains";
import { assets as SDK_ASSETS } from "mppx/evm/client";

export const CHAIN_ASSETS = new Map();
for (const group of Object.values(SDK_ASSETS)) {
  if (!group || typeof group !== "object") continue;
  for (const candidate of Object.values(group)) {
    if (!SDK_ASSETS.isAsset(candidate)) continue;
    const id = SDK_ASSETS.toChainId(candidate.network);
    if (!CHAIN_ASSETS.has(id)) CHAIN_ASSETS.set(id, candidate);
  }
}



export const VIEM_CHAIN_BY_ID = new Map();
for (const value of Object.values(VIEM_CHAINS)) {
  if (value && typeof value === "object" && typeof value.id === "number" && !VIEM_CHAIN_BY_ID.has(value.id)) VIEM_CHAIN_BY_ID.set(value.id, value);
}

const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

const integer = value => typeof value === "string" && /^[1-9][0-9]*$/.test(value) && value.length <= 78 && BigInt(value) < 2n ** 256n;
const address = value => {
  if (typeof value !== "string" || !ADDRESS.test(value)) throw new Error("payment_address_invalid");
  return value.toLowerCase();
};

export function connectedWalletAddress(session) {
  return address(session?.result?.signer);
}

export function walletReceiveInfo(chainId, walletAddress) {
  const asset = CHAIN_ASSETS.get(chainId);
  const chain = VIEM_CHAIN_BY_ID.get(chainId);
  return { address: walletAddress, network: chain?.name ?? `chain ${chainId}`, chain_id: chainId,
    receive: true, kyc_required: false,
    assets: asset ? [{ symbol: "USDC", contract: asset.address }] : [] };
}
export function unitsToDecimal(units, decimals) {
  if (!integer(units) && units !== "0") throw new Error("payment_units_invalid");
  const padded = String(units).padStart(decimals + 1, "0");
  const text = decimals ? `${padded.slice(0, -decimals)}.${padded.slice(-decimals)}` : padded;
  return text.includes(".") ? text.replace(/(\.\d*?)0+$/, "$1").replace(/\.$/, "") || "0" : text;
}
export function decimalToUnits(display, decimals) {
  
  
  
  const text = typeof display === "number" && Number.isFinite(display) ? String(display) : display;
  if (typeof text !== "string" || !/^(0|[1-9]\d*)(\.\d{1,18})?$/.test(text)) throw new Error("payment_max_amount_invalid: send the most you are willing to pay as a plain decimal amount, for example 0.25, as a number or as text.");
  const [whole, fraction = ""] = text.split(".");
  if (fraction.length > decimals) throw new Error("payment_max_amount_precision_exceeded: the amount has more decimal places than the coin being paid.");
  const units = BigInt(whole + fraction.padEnd(decimals, "0"));
  if (units <= 0n || units >= 2n ** 256n) throw new Error("payment_max_amount_invalid: send the most you are willing to pay as a plain decimal amount, for example 0.25, as a number or as text.");
  return units.toString();
}
