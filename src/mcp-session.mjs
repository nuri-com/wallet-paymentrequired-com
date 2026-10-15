import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_PATTERN = "^[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43}$";

function sha256Hex(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

// A value that must survive a restart but is a bearer secret (the Wirex user token)
// is sealed under the pass the caller holds. The row keeps only sha256(pass)
// (sessionCredential below), so the database alone can neither present the pass
// nor open the seal: it opens only while the person's own pass is presented.
function passKey(id, pass) {
  return Buffer.from(hkdfSync("sha256", Buffer.from(String(pass), "base64url"), Buffer.from(String(id)), Buffer.from("nuri-session-seal-v1"), 32));
}

export function sealWithPass(id, pass, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", passKey(id, pass), iv);
  const body = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final(), cipher.getAuthTag()]);
  return `${iv.toString("base64url")}.${body.toString("base64url")}`;
}

export function openWithPass(id, pass, sealed) {
  try {
    const [iv, body] = String(sealed).split(".").map((part) => Buffer.from(part, "base64url"));
    const decipher = createDecipheriv("aes-256-gcm", passKey(id, pass), iv);
    decipher.setAuthTag(body.subarray(body.length - 16));
    return Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()]).toString("utf8");
  } catch { return null; }
}








export function sessionCredential(id, session) {
  if (!session.context.secret) {
    
    
    
    if (session.context.secretSha256) return null;
    session.context.secret = randomBytes(32).toString("base64url");
    session.context.secretSha256 = sha256Hex(session.context.secret);
  }
  return `${id}.${session.context.secret}`;
}










// A damaged, unknown or foreign session is answered like a missing one: the
// connection layer (src/mcp-connection.mjs call) mints the connect link. No
// next_action here — it used to name connect_wallet, which is not in tools/list.
export function connectFirstError() {
  return connectRequiredSignal();
}







export function sessionAbsent(credential) {
  return credential === undefined || credential === null || credential === "";
}

export function connectRequiredSignal() {
  const error = new Error("reconnect_required");
  error.connect_required = true;
  return error;
}

export function authorizeSession(connection, credential) {
  if (sessionAbsent(credential)) throw connectRequiredSignal();
  if (typeof credential !== "string" || !new RegExp(SESSION_PATTERN).test(credential)) throw connectFirstError();
  const [id, secret] = credential.split(".");
  let session;
  try { session = connection(id); }
  catch (error) {
    
    
    
    if (error instanceof Error && /^connection_(expired|not_approved|type_mismatch)/.test(error.message)) throw error;
    throw connectFirstError();
  }
  
  
  
  const expected = session.context.secretSha256 || (session.context.secret ? sha256Hex(session.context.secret) : null);
  if (!expected || !timingSafeEqual(Buffer.from(sha256Hex(secret)), Buffer.from(expected))) throw connectFirstError();
  return session;
}
