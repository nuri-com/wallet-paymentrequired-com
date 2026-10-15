import { randomBytes } from "node:crypto";
import { mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { V1_APP_HOSTS } from "./wirex-public.mjs";











const USER_LINK = /(?:^|_)(?:approval|kyc|export)_url$/;
export function createShortLinks({ publicBase, path }) {
  const origin = new URL(publicBase).origin;
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  if (path !== ":memory:") chmodSync(path, 0o600);
  db.exec("PRAGMA busy_timeout = 5000; CREATE TABLE IF NOT EXISTS short_links (token TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, expires INTEGER)");
  const byUrl = db.prepare("SELECT token FROM short_links WHERE url = ?");
  const byToken = db.prepare("SELECT url, expires FROM short_links WHERE token = ?");
  const insert = db.prepare("INSERT INTO short_links (token, url, expires) VALUES (?, ?, ?)");
  const purge = db.prepare("DELETE FROM short_links WHERE expires IS NOT NULL AND expires <= ?");

  function owned(value) {
    try {
      const url = new URL(value);
      
      
      
      
      
      
      
      const v1 = V1_APP_HOSTS.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`));
      return !url.username && !url.password && !(v1 && url.origin !== origin) && (url.origin === origin || (url.protocol === "https:" && (url.hostname === "nuri.com" || url.hostname.endsWith(".nuri.com")))) ? url : null;
    } catch { return null; }
  }
  function shorten(value) {
    const url = owned(value);
    
    if (!url || (!url.search && !url.hash) || (url.origin === origin && url.pathname === new URL(`${publicBase}/s`).pathname)) return value;
    const expires = url.searchParams.has("expires") ? Number(url.searchParams.get("expires")) : null;
    if (expires !== null && (!Number.isSafeInteger(expires) || expires <= Date.now())) throw new Error("short_link_expired");
    purge.run(Date.now());
    let token = byUrl.get(value)?.token;
    if (!token) {
      token = randomBytes(24).toString("base64url");
      insert.run(token, value, expires);
    }
    
    return `${publicBase}/s#${token}`;
  }
  return {
    shorten,
    format(data) {
      if (!data || typeof data !== "object" || Array.isArray(data)) return data;
      let result;
      for (const [key, value] of Object.entries(data)) {
        if (USER_LINK.test(key) && typeof value === "string") {
          result ||= { ...data };
          result[key] = shorten(value);
          if (key.endsWith("approval_url")) {
            const alias = result[key];
            
            
            
            
            
            
            const sameTarget = (candidate) => {
              if (typeof candidate !== "string" || candidate === "") return false;
              if (candidate === value || candidate === alias) return true;
              try { return Boolean(owned(candidate)) && shorten(candidate) === alias; } catch { return false; }
            };
            
            
            
            const action = data.next_action;
            if (action && typeof action === "object" && !Array.isArray(action) && sameTarget(action.url)) {
              result.next_action = { ...action, url: alias };
            }
          }
        }
      }
      return result || data;
    },
    resolve(token) {
      if (typeof token !== "string" || !/^[A-Za-z0-9_-]{32}$/.test(token)) return null;
      const row = byToken.get(token);
      if (!row || (row.expires !== null && row.expires <= Date.now()) || !owned(row.url)) return null;
      return row.url;
    },
    close: () => db.close(),
  };
}
