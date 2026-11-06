// Public lists of confirmed phishing sites. They're downloaded and checked
// locally - the sites you visit are never sent anywhere.

import { classifyHost, normaliseHost, pathKeys } from "./detect.js";

export const FEEDS = [
  {
    id: "phishing-database",
    name: "Phishing.Database",
    url: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    format: "hosts",
  },
  {
    id: "openphish",
    name: "OpenPhish",
    url: "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    format: "urls",
  },
];

const HOSTNAME = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

/**
 * One hostname per line. Only ordinary sites are kept: the real list also
 * contains docs.google.com, bare S3 endpoints and l.instagram.com, because
 * scams get hosted on or bounced through them, and flagging all of those
 * would be worse than useless.
 */
export function parseHostList(text, { index, suffixes }) {
  const out = new Set();
  for (const line of text.split("\n")) {
    const host = normaliseHost(line.trim());
    if (!host || host.startsWith("#") || !HOSTNAME.test(host)) continue;
    const c = classifyHost(host, index, suffixes);
    if (c.kind === "site" || c.kind === "ip" || c.ownSubdomain) out.add(host);
  }
  return [...out];
}

/** One URL per line. On shared or legitimate hosts only that page (and below) is listed. */
export function parseUrlList(text, { index, suffixes }) {
  const out = new Set();
  for (const line of text.split("\n")) {
    let u;
    try {
      u = new URL(line.trim());
    } catch {
      continue;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") continue;
    const c = classifyHost(u.hostname, index, suffixes);
    if (c.kind === "site" || c.kind === "ip") {
      if (HOSTNAME.test(c.host) || c.kind === "ip") out.add(c.host);
    } else {
      const key = pathKeys(c.host, u.pathname).at(-1);
      if (key) out.add(key);
    }
  }
  return [...out];
}

/** Keys to look up for a page: the host and its parents, or path prefixes on shared hosts. */
export function lookupKeys(url, { index, suffixes }) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return [];
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return [];
  const c = classifyHost(u.hostname, index, suffixes);
  if (c.kind === "ip") return [c.host];
  if (c.ownSubdomain) return [c.host, ...pathKeys(c.host, u.pathname)];
  if (c.kind !== "site") return pathKeys(c.host, u.pathname);

  // Down to the registered domain and no further: never up into a shared
  // platform like s3.us-east-1.amazonaws.com.
  const labels = c.host.split(".");
  const keys = [];
  for (let i = 0; i < labels.length; i++) {
    const key = labels.slice(i).join(".");
    keys.push(key);
    if (key === c.parts.registered) break;
  }
  return keys;
}
