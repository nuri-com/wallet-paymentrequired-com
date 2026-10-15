import { createHash } from "node:crypto";






export function logEvent(level, event, fields = {}) {
  const line = JSON.stringify({ level, event, ...fields });
  if (level === "error") console.error(line);
  else console.log(line);
}




export function fingerprint(value) {
  const text = String(value ?? "");
  if (!text) return "";
  return createHash("sha256").update(text).digest("hex").slice(0, 12);
}



export function maskAddress(address) {
  const text = String(address ?? "");
  return text.length > 12 ? `${text.slice(0, 6)}…${text.slice(-4)}` : text;
}
