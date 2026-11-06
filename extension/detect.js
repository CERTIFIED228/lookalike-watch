// Pure detection logic: no browser APIs in here, so it runs (and is tested)
// in plain Node. background.js does the I/O and calls assess().

import { EXTRA_PLATFORMS, GENERIC_WORDS, RISKY_TLDS, SCAM_WORDS, SHARED_HOSTS } from "./brands.js";
import { toUnicode } from "./punycode.js";

export const SEVERITIES = ["low", "medium", "high", "critical"];
const rank = (s) => SEVERITIES.indexOf(s);

// --- lookalike characters ------------------------------------------------------

const CONFUSABLES = {
  "а": "a", "ɑ": "a", "à": "a", "á": "a", "ä": "a", "â": "a", "ã": "a", "å": "a",
  "Ƅ": "b", "Ь": "b", "с": "c", "ϲ": "c", "ç": "c", "ԁ": "d", "ɗ": "d",
  "е": "e", "è": "e", "é": "e", "ê": "e", "ë": "e", "ė": "e", "ɡ": "g",
  "һ": "h", "і": "i", "í": "i", "ì": "i", "ï": "i", "ı": "i", "ј": "j",
  "κ": "k", "ӏ": "l", "ł": "l", "м": "m", "ո": "n", "ñ": "n",
  "о": "o", "ο": "o", "ö": "o", "ó": "o", "ò": "o", "ô": "o", "õ": "o",
  "р": "p", "ρ": "p", "ԛ": "q", "ѕ": "s", "т": "t", "υ": "u", "ü": "u",
  "ú": "u", "ù": "u", "ν": "v", "ѵ": "v", "ԝ": "w", "х": "x", "у": "y",
  "ý": "y", "ʐ": "z",
};

/**
 * What a string looks like at a glance: "pаypal" (Cyrillic а) and "paypal"
 * match, "payfal" and "paypal" don't. The two-letter tricks (rn -> m) are
 * optional because they also merge real words ("clave" -> "dave").
 */
export function skeleton(text, twoLetterTricks = true) {
  let out = "";
  for (const ch of text.toLowerCase()) out += CONFUSABLES[ch] ?? ch;
  out = out.replaceAll("0", "o").replaceAll("1", "l");
  if (twoLetterTricks) {
    out = out.replaceAll("rn", "m").replaceAll("vv", "w").replaceAll("cl", "d");
  }
  return out;
}

// "1" passes for "l" and for "i", so try both.
function skeletons(name, twoLetterTricks) {
  const out = new Set([skeleton(name, twoLetterTricks)]);
  if (name.includes("1")) out.add(skeleton(name.replaceAll("1", "i"), twoLetterTricks));
  return [...out];
}

/** Damerau-Levenshtein (optimal string alignment): a swap of neighbours is one edit. */
export function editDistance(a, b) {
  const A = [...a];
  const B = [...b];
  const d = Array.from({ length: A.length + 1 }, (_, i) => [i, ...Array(B.length).fill(0)]);
  for (let j = 0; j <= B.length; j++) d[0][j] = j;
  for (let i = 1; i <= A.length; i++) {
    for (let j = 1; j <= B.length; j++) {
      const cost = A[i - 1] === B[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && A[i - 1] === B[j - 2] && A[i - 2] === B[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[A.length][B.length];
}

function deletions(name) {
  const out = new Set([name]);
  for (let i = 0; i < name.length; i++) out.add(name.slice(0, i) + name.slice(i + 1));
  return out;
}

// --- hostnames -------------------------------------------------------------------

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const LOCAL_SUFFIXES = [".local", ".localhost", ".home.arpa", ".internal", ".lan", ".home", ".localdomain"];
const LOCAL_HOSTS = new Set(["localhost", "home.arpa", "fritz.box", "speedport.ip"]);

export function normaliseHost(host) {
  return host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

export function isIpAddress(host) {
  return IPV4.test(host) || host.includes(":");
}

/** Your own machine and home network: routers, printers, dev servers. */
export function isLocalHost(rawHost) {
  const host = normaliseHost(rawHost);
  if (LOCAL_HOSTS.has(host) || LOCAL_SUFFIXES.some((s) => host.endsWith(s))) return true;
  if (!host.includes(".") && !host.includes(":")) return true;
  if (host === "::1" || host.startsWith("fe80:") || /^f[cd][0-9a-f]{2}:/.test(host)) return true;
  if (!IPV4.test(host)) return false;
  const [a, b] = host.split(".").map(Number);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)
    || (a === 169 && b === 254);
}

/**
 * Public suffixes (co.uk) and shared platforms (github.io, myshopify.com),
 * both straight from the Public Suffix List, wildcards included.
 */
export function makeSuffixes(icann, platforms) {
  return { icann: new Set(icann), platforms: new Set([...platforms, ...EXTRA_PLATFORMS]) };
}

// How many labels at the end of the host form a suffix under these rules.
function suffixLength(labels, rules) {
  for (let k = Math.min(labels.length, 6); k >= 1; k--) {
    if (rules.has(labels.slice(-k).join("."))) return k;
    if (k >= 2 && rules.has(`*.${labels.slice(-(k - 1)).join(".")}`)) return k;
  }
  return 0;
}

/**
 * Split a hostname into the parts that matter:
 * "www.amazon.co.uk" -> sub "www", name "amazon", suffix "co.uk".
 * On shared platforms the user-chosen label is the name ("x.vercel.app" -> "x").
 * Returns null for IPs and for hosts that are themselves a suffix or platform.
 */
export function splitHost(rawHost, suffixes) {
  const host = normaliseHost(rawHost);
  if (!host || isIpAddress(host) || !host.includes(".")) return null;
  const labels = host.split(".");

  const onPlatform = suffixLength(labels, suffixes.platforms);
  const icann = suffixLength(labels, suffixes.icann);
  const k = Math.max(onPlatform, icann, 1);
  if (labels.length <= k) return null;

  const suffix = labels.slice(-k).join(".");
  const label = labels.at(-k - 1);
  return {
    host,
    sub: labels.slice(0, -k - 1).join("."),
    name: toUnicode(label),
    suffix,
    registered: `${label}.${suffix}`,
    platform: onPlatform && onPlatform >= icann ? suffix : null,
  };
}

// --- the index of sites worth protecting ------------------------------------------

/**
 * kind "brand": hand-picked, most phished brands (strongest warnings)
 * kind "mine":  sites the user logs into
 * kind "top":   the 10,000 most visited sites in Chrome
 * knownSites:    the next most visited ones, only used to avoid false alarms
 */
export function buildIndex({ brands = [], topSites = [], mySites = [], knownSites = [] }, suffixes) {
  const entries = [];
  const legit = new Set();
  const byDomain = new Map();
  const generic = new Set([...GENERIC_WORDS, ...SCAM_WORDS]);

  for (const b of brands) {
    const entry = { kind: "brand", label: b.label, name: b.name, domain: b.domains[0], typos: b.typos };
    entries.push(entry);
    for (const d of b.domains) {
      legit.add(d);
      if (!byDomain.has(d)) byDomain.set(d, entry);
    }
  }
  for (const [kind, list] of [["mine", mySites], ["top", topSites]]) {
    for (const domain of list) {
      const parts = splitHost(domain, suffixes);
      if (!parts || parts.platform) continue;
      legit.add(domain);
      if (parts.name.length < 3) continue;
      const entry = { kind, label: domain, name: parts.name, domain };
      entries.push(entry);
      if (!byDomain.has(domain)) byDomain.set(domain, entry);
    }
  }
  // Popular sites below the top 10k: never protected against, never flagged.
  for (const domain of knownSites) {
    if (!suffixes.platforms.has(domain)) legit.add(domain);
  }

  const byName = new Map();
  const bySkeleton = new Map();     // protected brands and your sites
  const byTopSkeleton = new Map();  // top sites, single-character tricks only
  const byDeletion = new Map();
  const byComboName = new Map();
  const push = (map, key, e) => (map.has(key) ? map.get(key).push(e) : map.set(key, [e]));

  for (const e of entries) {
    if (!byName.has(e.name)) byName.set(e.name, e);
    if (e.kind !== "top") {
      const sk = skeleton(e.name);
      if (!bySkeleton.has(sk)) bySkeleton.set(sk, e);
    } else if (e.name.length >= 5) {
      const sk = skeleton(e.name, false);
      if (!byTopSkeleton.has(sk)) byTopSkeleton.set(sk, e);
    }
    // Typo matching only for brands and your own sites. Against the whole
    // top-10k list it flagged ~7 real sites for every phishing site it caught.
    if (e.kind !== "top" && e.typos !== false && e.name.length >= 5) {
      for (const v of deletions(e.name)) push(byDeletion, v, e);
    }
    if (e.kind !== "top" || (e.name.length >= 6 && !generic.has(e.name))) push(byComboName, e.name, e);
  }
  return { legit, byDomain, byName, bySkeleton, byTopSkeleton, byDeletion, byComboName };
}

function isLegitHost(parts, index) {
  // Government platforms like service.gov.uk only host real services.
  if (parts.platform) return index.legit.has(parts.registered) || parts.platform.split(".").includes("gov");
  const labels = parts.host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    if (index.legit.has(labels.slice(i).join("."))) return true;
  }
  return false;
}

/**
 * What sort of host this is, for the phishing feeds and the trust list:
 *  "site":   an ordinary site (or one tenant of a shared platform)
 *  "legit":  a popular or protected site; only ever matched page by page
 *  "shared": a host serving many people's content (docs.google.com, a bare
 *            S3 endpoint); also only matched page by page
 *  "ip":     a raw IP address
 */
export function classifyHost(rawHost, index, suffixes) {
  const host = normaliseHost(rawHost);
  if (isIpAddress(host)) return { host, kind: "ip", parts: null };
  if (SHARED_HOSTS.includes(host)) return { host, kind: "shared", parts: null };
  const parts = splitHost(host, suffixes);
  if (!parts) return { host, kind: "shared", parts: null };
  return { host, kind: isLegitHost(parts, index) ? "legit" : "site", parts };
}

/** "url:" keys for a page and every folder above it, for page-by-page matching. */
export function pathKeys(host, pathname) {
  const segments = pathname.split("/").filter(Boolean);
  return segments.map((_, i) => `url:${host}/${segments.slice(0, i + 1).join("/")}`);
}

/**
 * What "I trust this site" should remember. Never more than the site that
 * was flagged: one page on sites.google.com mustn't trust all of Google.
 */
export function trustKey(url, index, suffixes) {
  const u = new URL(url);
  const c = classifyHost(u.hostname, index, suffixes);
  if (c.kind === "site") return c.parts.registered;
  if (c.kind === "ip") return c.host;
  return pathKeys(c.host, u.pathname).at(-1) ?? `url:${c.host}`;
}

function isTrusted(u, trusted, c) {
  if (c.kind === "site") return trusted.has(c.parts.registered) || trusted.has(c.host);
  if (c.kind === "ip") return trusted.has(c.host);
  return [`url:${c.host}`, ...pathKeys(c.host, u.pathname)].some((k) => trusted.has(k));
}

// --- lookalike checks ----------------------------------------------------------------

const strong = (e) => e.kind !== "top";
const pick = (e, ifStrong, ifTop) => (strong(e) ? ifStrong : ifTop);

/**
 * Protected names hidden inside a longer name: "hmrc-tax-refund" contains
 * "hmrc", "paypallogin" contains "paypal". Short names (dpd, nhs, ups) only
 * count as a whole word or at the very start or end, or "pickups" would
 * contain "ups".
 */
function brandsInside(name, index) {
  const found = new Set();
  const compact = name.replaceAll("-", "");
  for (const token of [...name.split("-"), compact.slice(0, 3), compact.slice(0, 4), compact.slice(-3), compact.slice(-4)]) {
    for (const e of index.byComboName.get(token) ?? []) {
      if (e.name.length < 5) found.add(e);
    }
  }
  for (const token of name.split("-")) {
    for (const e of index.byComboName.get(token) ?? []) found.add(e);
  }
  // Anywhere in the name for protected brands; only at the start or end for
  // top sites, or "allviralcollections" would contain lectio.dk.
  for (let i = 0; i < compact.length; i++) {
    for (let j = i + 5; j <= compact.length; j++) {
      const edge = i === 0 || j === compact.length;
      for (const e of index.byComboName.get(compact.slice(i, j)) ?? []) {
        if (edge || strong(e)) found.add(e);
      }
    }
  }
  return [...found].filter((e) => e.name !== name);
}

/**
 * A scam word next to the brand. Short ones (tax, fee, fine) have to stand
 * alone, or appletaxi.co.uk would be "Apple + tax".
 */
function scamWordIn(name, brandName) {
  const tokens = name.split("-");
  const rest = name.replaceAll("-", "").replace(brandName, "");
  return SCAM_WORDS.find((w) => tokens.includes(w) || rest === w
    || (w.length >= 6 && (rest.startsWith(w) || rest.endsWith(w))));
}

function lookalikeMatches(parts, index, suffixes) {
  const { name } = parts;
  const found = [];
  const add = (target, severity, reason) => found.push({ target, severity, reasons: [reason] });

  // 1. Looks identical once lookalike characters are swapped back
  const twin = skeletons(name, true).map((s) => index.bySkeleton.get(s)).find(Boolean)
    ?? skeletons(name, false).map((s) => index.byTopSkeleton.get(s)).find(Boolean);
  if (twin && twin.name !== name) {
    const m = { target: twin, severity: pick(twin, "critical", "high"), reasons: [`looks identical to ${twin.domain} at a glance`] };
    if (!/^[\x00-\x7f]*$/.test(name)) {
      m.reasons.push(`uses non-Latin letters: its real name is ${parts.registered}`);
    }
    found.push(m);
  }

  // 2. Exactly the same name on an ending the brand doesn't use. Country
  //    endings are left alone (amazon.de, paypal.fr are real), and big brands
  //    own plenty of others (netflix.shop), so it's only high on a risky one.
  const same = index.byName.get(name);
  const tld = parts.suffix.split(".").at(-1);
  if (same && strong(same) && !parts.platform && tld.length > 2) {
    add(same, RISKY_TLDS.includes(tld) ? "high" : "medium",
      `same name as ${same.domain} but on .${parts.suffix}, which ${same.label} doesn't use`);
  }

  // 3. One character off (unless step 1 already explained it)
  const seen = new Set(found.map((m) => m.target));
  for (const v of deletions(name)) {
    for (const t of index.byDeletion.get(v) ?? []) {
      if (seen.has(t) || t.name === name) continue;
      seen.add(t);
      if (editDistance(name, t.name) === 1) {
        // 5-letter names have lots of real neighbours (monzo/mondo/moneo)
        add(t, t.name.length >= 6 ? "high" : "medium", `1 character different from ${t.domain}`);
      }
    }
  }

  // 4. Brand + scam word, and brand names on shared platforms
  for (const t of brandsInside(name, index)) {
    const word = scamWordIn(name, t.name);
    if (word) {
      add(t, pick(t, "high", "medium"), `contains "${t.name}" plus "${word}", a word common in scams`);
    }
    if (parts.platform && strong(t)) {
      add(t, "medium", `puts ${t.label}'s name on ${parts.platform}, where anyone can make a site`);
    }
  }

  if (!parts.sub) return found;
  const subLabels = parts.sub.split(".");

  // 5. A real domain used as a fake subdomain: paypal.com.secure-check.bid
  fake: for (let i = 0; i < subLabels.length - 1; i++) {
    for (let j = subLabels.length; j >= i + 2; j--) {
      const fake = subLabels.slice(i, j).join(".");
      if (!index.legit.has(fake)) continue;
      const byName = index.byName.get(splitHost(fake, suffixes)?.name);
      const t = (byName && strong(byName) ? byName : index.byDomain.get(fake))
        ?? { kind: "top", label: fake, domain: fake };
      add(t, "high", `starts with ${fake} to look real, but the site is actually ${parts.registered}`);
      break fake;
    }
  }

  // 6. A protected name in the subdomain: paypal-login.secure-host.net
  const subTokens = parts.sub.split(/[.-]/);
  const already = new Set(found.map((m) => m.target.name));
  for (const token of new Set(subTokens)) {
    const t = index.byComboName.get(token)?.find(strong);
    if (!t || already.has(t.name)) continue;
    already.add(t.name);
    const word = SCAM_WORDS.find((w) => subTokens.includes(w) || name.split("-").includes(w));
    add(t, word ? "high" : "medium",
      `mentions ${t.label} in the subdomain, but the site is actually ${parts.registered}`);
  }

  return found;
}

// --- warning signs that apply to any domain --------------------------------------------

function scriptsIn(text) {
  const scripts = new Set();
  for (const ch of text) {
    if (/\p{Script=Latin}/u.test(ch)) scripts.add("Latin");
    else if (/\p{Script=Cyrillic}/u.test(ch)) scripts.add("Cyrillic");
    else if (/\p{Script=Greek}/u.test(ch)) scripts.add("Greek");
    else if (/\p{L}/u.test(ch)) scripts.add("other");
  }
  return [...scripts];
}

export function warningSigns(url, parts, page) {
  const signs = [];
  if (isIpAddress(normaliseHost(url.hostname))) {
    signs.push([2, "the address is a raw IP address instead of a domain name"]);
  }
  if (url.protocol === "http:" && page.hasLogin) {
    signs.push([2, "asks for a password over an unencrypted (http) connection"]);
  }
  if (parts) {
    // Latin mixed with Cyrillic or Greek is the homoglyph trick. Chinese or
    // Japanese next to Latin letters is normal in those countries.
    const scripts = scriptsIn(parts.name).filter((x) => x !== "other");
    if (scripts.length > 1) {
      signs.push([2, `mixes letters from different alphabets (${scripts.join(" and ")}) in one name`]);
    }
    const tld = parts.suffix.split(".").at(-1);
    if (RISKY_TLDS.includes(tld)) {
      signs.push([1, `.${tld} addresses are used a lot for phishing`]);
    }
    if (parts.name.split("-").length > 3 || parts.name.length > 30) {
      signs.push([1, "has an unusually long or hyphen-heavy name"]);
    }
    if (parts.sub.split(".").length >= 4) {
      signs.push([1, "has an unusually deep chain of subdomains"]);
    }
    if (parts.platform && page.hasLogin) {
      signs.push([1, `is a login page on a shared platform (${parts.platform})`]);
    }
  }
  return signs;
}

// --- putting it together -----------------------------------------------------------------

const QUIET = Object.freeze({ severity: null, show: false, title: "", brand: null, realDomain: null, reasons: [] });

/**
 * Decide how suspicious a page is.
 *  feedHit: { source } when the page is on a phishing feed
 *  scanHit: an entry from an imported lookalike-watch scan report
 */
export function assess({ url, page = { hasLogin: false }, index, suffixes, trusted = new Set(), feedHit = null, scanHit = null }) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return QUIET;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return QUIET;
  if (isLocalHost(u.hostname)) return QUIET;

  const c = classifyHost(u.hostname, index, suffixes);
  if (isTrusted(u, trusted, c)) return QUIET;
  const { parts } = c;

  const results = [];
  if (feedHit) {
    results.push({
      severity: "critical", title: "Known phishing site", brand: null, realDomain: null,
      reasons: [`listed as a confirmed phishing site by ${feedHit.source}`],
    });
  }
  if (scanHit && SEVERITIES.includes(scanHit.level)) {
    results.push({
      severity: scanHit.level, title: "Flagged by your lookalike scan", brand: null, realDomain: null,
      reasons: [`flagged by your lookalike-watch scan (score ${scanHit.score})`, ...(scanHit.reasons ?? []).slice(0, 2)],
    });
  }

  const legit = c.kind === "legit" || c.kind === "shared";
  if (legit && !results.length) return QUIET;

  if (c.kind === "site") {
    for (const m of lookalikeMatches(parts, index, suffixes)) {
      results.push({
        severity: m.severity,
        title: `This looks like a fake ${m.target.label} site`,
        brand: m.target.label,
        realDomain: m.target.domain,
        reasons: m.reasons,
      });
    }
  }

  const signs = legit ? [] : warningSigns(u, parts, page);
  const signTotal = signs.reduce((n, [w]) => n + w, 0);
  if (!results.length) {
    if (signTotal < 2) return QUIET;
    results.push({
      severity: signTotal >= 4 ? "medium" : "low",
      title: "Be careful on this page", brand: null, realDomain: null, reasons: [],
    });
  }

  results.sort((a, b) => rank(b.severity) - rank(a.severity));
  const top = results[0];
  const reasons = [...new Set([...results.flatMap((r) => r.reasons), ...signs.map(([, r]) => r)])];
  const show = rank(top.severity) >= rank("high") || page.hasLogin === true;
  return { ...top, reasons, show };
}
