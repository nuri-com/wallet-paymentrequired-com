// Resolve our fragment-bearing links without putting their capability in an HTTP URL.
export async function resolveShortLink(value, fetchImpl = globalThis.fetch, ownOrigin = globalThis.location?.origin || "") {
  const source = new URL(value);
  const token = source.hash.slice(1);
  const local = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(source.hostname);
  const nuri = source.hostname === "nuri.com" || source.hostname.endsWith(".nuri.com");
  // The page that resolves a link is served BY the deployment that minted it, so its own origin is
  // always a host this product serves. Without this a deployment whose own name is not under
  // .nuri.com (the standalone box, paymentrequired.com) answered "no longer available" for every
  // link it handed out - its own bridge links included. Same rule as the server's own `owned()`,
  // which already accepts the deployment's origin; still refused are any other origin and any
  // plain-http host that is not one of the local ones.
  const own = Boolean(ownOrigin) && source.origin === ownOrigin && (local || source.protocol === "https:");
  if ((!local && !own && !(nuri && source.protocol === "https:")) || !["http:", "https:"].includes(source.protocol)
    || source.username || source.password || source.search || !/\/s$/.test(source.pathname) || !/^[A-Za-z0-9_-]{32}$/.test(token)) throw new Error("This link is invalid.");
  const response = await fetchImpl(`${source.origin}${source.pathname}`, {
    method: "POST", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer",
    headers: { "content-type": "application/json" }, body: JSON.stringify({ token }),
  });
  if (!response.ok) throw new Error("This link is no longer available. Ask for a new link in your chat.");
  const { url } = await response.json();
  const target = new URL(url);
  if (target.username || target.password || !(target.origin === source.origin || (target.protocol === "https:" && (target.hostname === "nuri.com" || target.hostname.endsWith(".nuri.com"))))) throw new Error("This link is invalid.");
  return target.href;
}
