





































export function readPrivyApp(env = process.env, partner = "nuri") {
  if (partner !== "nuri" && partner !== "wirex") throw new Error("partner_invalid");
  const prefix = partner === "wirex" ? "WIREX_PRIVY_" : "PRIVY_";
  const appId = text(env?.[`${prefix}APP_ID`]);
  const clientId = text(env?.[`${prefix}CLIENT_ID`]);
  const appSecret = text(env?.[`${prefix}APP_SECRET`]);
  const proxyUrl = text(env?.[`${prefix}PROXY_URL`]).replace(/\/+$/, "");
  const proxyToken = text(env?.[`${prefix}PROXY_TOKEN`]);
  if (proxyUrl) {
    let parsed;
    try { parsed = new URL(proxyUrl); } catch { throw new Error(`${prefix}PROXY_URL_invalid`); }
    
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isInternalHost(parsed.hostname))) throw new Error(`${prefix}PROXY_URL_requires_https`);
    if (!proxyToken) throw new Error(`${prefix}PROXY_TOKEN_required`);
  }
  return {
    partner,
    appId,
    clientId,
    appSecret,
    proxyUrl,
    proxyToken,
    
    
    connectable: Boolean(appId),
    
    
    cardGrant: Boolean(appId && (appSecret || proxyUrl)),
  };
}


function isInternalHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "::1" || /^127\./.test(host) || /^10\./.test(host)
    || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host) || !host.includes(".");
}

function text(value) {
  return String(value ?? "").trim();
}
