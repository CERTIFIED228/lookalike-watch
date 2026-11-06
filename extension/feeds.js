// Public lists of confirmed phishing sites. They're downloaded and checked
// locally - the sites you visit are never sent anywhere.

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
 * One hostname per line. Entries in `skip` are dropped: the feed lists
 * docs.google.com because scams get hosted there, and blocking the whole of
 * Google Docs would be worse than useless.
 */
export function parseHostList(text, skip) {
  const out = [];
  for (const line of text.split("\n")) {
    const host = line.trim().toLowerCase();
    if (!host || host.startsWith("#") || !HOSTNAME.test(host) || skip.has(host)) continue;
    out.push(host);
  }
  return out;
}

function urlKey(u) {
  const path = u.pathname.replace(/\/+$/, "");
  return path ? `url:${u.hostname}${path}` : null;
}

/** One URL per line. On shared hosts only that exact page (path) is listed. */
export function parseUrlList(text, shared) {
  const out = [];
  for (const line of text.split("\n")) {
    let u;
    try {
      u = new URL(line.trim());
    } catch {
      continue;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") continue;
    const host = u.hostname.toLowerCase();
    if (shared.has(host)) {
      const key = urlKey(u);
      if (key) out.push(key);
    } else if (HOSTNAME.test(host)) {
      out.push(host);
    }
  }
  return out;
}

/** Keys to look up for a page: its host and parent domains, or path prefixes on shared hosts. */
export function lookupKeys(url, shared) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return [];
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return [];
  const host = u.hostname.toLowerCase();

  if (shared.has(host)) {
    const segments = u.pathname.split("/").filter(Boolean);
    return segments.map((_, i) => `url:${host}/${segments.slice(0, i + 1).join("/")}`);
  }
  const labels = host.split(".");
  const keys = [];
  for (let i = 0; i <= labels.length - 2; i++) keys.push(labels.slice(i).join("."));
  return keys;
}
