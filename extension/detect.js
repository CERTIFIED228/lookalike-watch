// Pure detection logic: no browser APIs in here, so it runs (and is tested)
// in plain Node. background.js does the I/O and calls assess().

import { FREE_HOSTING, RISKY_TLDS, SCAM_WORDS } from "./brands.js";
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
  if (twoLetterTricks) {
    out = out.replaceAll("rn", "m").replaceAll("vv", "w").replaceAll("cl", "d");
  }
  return out.replaceAll("0", "o").replaceAll("1", "l");
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
const PLATFORMS = [...FREE_HOSTING].sort((a, b) => b.length - a.length);

export function isIpAddress(host) {
  return IPV4.test(host) || host.includes(":") || host.startsWith("[");
}

/** Your own machine and home network: routers, printers, dev servers. */
export function isLocalHost(rawHost) {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (!host.includes(".") && !host.includes(":")) return true;
  if (host === "::1" || host.startsWith("fe80:") || /^f[cd][0-9a-f]{2}:/.test(host)) return true;
  if (!IPV4.test(host)) return false;
  const [a, b] = host.split(".").map(Number);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)
    || (a === 169 && b === 254);
}

/**
 * Split a hostname into the parts that matter:
 * "www.amazon.co.uk" -> sub "www", name "amazon", suffix "co.uk".
 * On free hosting the user-chosen label is the name ("x.vercel.app" -> "x").
 */
export function splitHost(rawHost, suffixes) {
  const host = rawHost.toLowerCase().replace(/\.$/, "");
  if (!host || isIpAddress(host) || !host.includes(".")) return null;
  const labels = host.split(".");

  for (const platform of PLATFORMS) {
    if (host.endsWith(`.${platform}`)) {
      const rest = host.slice(0, -platform.length - 1).split(".");
      const label = rest.pop();
      return {
        host, sub: rest.join("."), name: toUnicode(label), suffix: platform,
        registered: `${label}.${platform}`, platform,
      };
    }
  }

  let suffix = labels.at(-1);
  for (let k = Math.min(labels.length - 1, 4); k >= 2; k--) {
    const candidate = labels.slice(-k).join(".");
    if (suffixes.has(candidate)) {
      suffix = candidate;
      break;
    }
  }
  const suffixLen = suffix.split(".").length;
  if (labels.length <= suffixLen) return null;
  const label = labels.at(-suffixLen - 1);
  return {
    host, sub: labels.slice(0, -suffixLen - 1).join("."), name: toUnicode(label), suffix,
    registered: `${label}.${suffix}`, platform: null,
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
  const platforms = new Set(FREE_HOSTING);

  for (const b of brands) {
    entries.push({ kind: "brand", label: b.label, name: b.name, domain: b.domains[0], typos: b.typos });
    b.domains.forEach((d) => legit.add(d));
  }
  for (const [kind, list] of [["mine", mySites], ["top", topSites]]) {
    for (const domain of list) {
      if (platforms.has(domain)) continue;
      const parts = splitHost(domain, suffixes);
      if (!parts || parts.platform) continue;
      legit.add(domain);
      if (parts.name.length >= 3) entries.push({ kind, label: domain, name: parts.name, domain });
    }
  }

  // Popular sites below the top 10k: never protected against, never flagged.
  for (const domain of knownSites) {
    if (!platforms.has(domain)) legit.add(domain);
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
    if (e.kind !== "top" || e.name.length >= 6) push(byComboName, e.name, e);
  }
  return { legit, byName, bySkeleton, byTopSkeleton, byDeletion, byComboName };
}

function isLegitHost(parts, index) {
  if (parts.platform) return index.legit.has(parts.registered);
  const labels = parts.host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    if (index.legit.has(labels.slice(i).join("."))) return true;
  }
  return false;
}

// --- lookalike checks ----------------------------------------------------------------

const strong = (e) => e.kind !== "top";
const pick = (e, ifStrong, ifTop) => (strong(e) ? ifStrong : ifTop);

/**
 * Protected names hidden inside a longer name: "hmrc-tax-refund" contains
 * "hmrc", "paypallogin" contains "paypal". Short names (dpd, nhs, ups) only
 * count as a whole word, or "pickups" would contain "ups".
 */
function brandsInside(name, index) {
  const found = new Set();
  for (const token of name.split("-")) {
    for (const e of index.byComboName.get(token) ?? []) found.add(e);
  }
  const compact = name.replaceAll("-", "");
  for (let i = 0; i < compact.length; i++) {
    for (let j = i + 5; j <= compact.length; j++) {
      for (const e of index.byComboName.get(compact.slice(i, j)) ?? []) found.add(e);
    }
  }
  return [...found].filter((e) => e.name !== name);
}

function lookalikeMatches(parts, index) {
  const { name } = parts;
  const found = [];
  const add = (target, severity, reason) =>
    found.push({ target, severity, reasons: [reason] });

  // 1. Looks identical once lookalike characters are swapped back
  const twin = index.bySkeleton.get(skeleton(name)) ?? index.byTopSkeleton.get(skeleton(name, false));
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
        const sev = t.name.length >= 6 ? "high" : "medium";
        add(t, sev, `1 character different from ${t.domain}`);
      }
    }
  }

  // 4. Brand + scam word, and brand names on free hosting
  for (const t of brandsInside(name, index)) {
    const rest = name.replaceAll("-", "").replace(t.name, "");
    const word = SCAM_WORDS.find((w) => rest.includes(w));
    if (word) {
      add(t, pick(t, "high", "medium"),
        `contains "${t.name}" plus "${word}", a word common in scams`);
    }
    if (parts.platform) {
      add(t, "medium",
        `puts ${t.label}'s name on ${parts.platform}, free hosting that ${t.label} doesn't use`);
    }
  }

  // 5. A real domain used as a fake subdomain: paypal.com.secure-check.bid
  if (parts.sub) {
    const labels = parts.sub.split(".");
    for (let i = 0; i < labels.length - 1; i++) {
      for (let j = i + 2; j <= labels.length; j++) {
        const fake = labels.slice(i, j).join(".");
        if (index.legit.has(fake)) {
          const t = index.byName.get(splitHost(fake, new Set())?.name) ?? { kind: "top", label: fake, domain: fake };
          add({ ...t, domain: fake }, "high",
            `starts with ${fake} to look real, but the site is actually ${parts.registered}`);
        }
      }
    }
  }

  return found;
}

// --- warning signs that apply to any domain --------------------------------------------

function scriptsIn(text) {
  const scripts = new Set();
  for (const ch of text) {
    if (/[a-z]/.test(ch)) scripts.add("Latin");
    else if (/[Ѐ-ӿ]/.test(ch)) scripts.add("Cyrillic");
    else if (/[Ͱ-Ͽ]/.test(ch)) scripts.add("Greek");
    else if (/[À-ɏ]/.test(ch)) scripts.add("Latin");
    else if (/[^\x00-\x7f]/.test(ch)) scripts.add("other");
  }
  return [...scripts];
}

export function warningSigns(url, parts, page) {
  const signs = [];
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIpAddress(host)) {
    signs.push([2, "the address is a raw IP address instead of a domain name"]);
  }
  if (url.protocol === "http:" && page.hasLogin) {
    signs.push([2, "asks for a password over an unencrypted (http) connection"]);
  }
  if (parts) {
    const scripts = scriptsIn(parts.name);
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
      signs.push([1, `is a login page on free hosting (${parts.platform})`]);
    }
  }
  return signs;
}

// --- putting it together -----------------------------------------------------------------

const QUIET = Object.freeze({ severity: null, show: false, title: "", brand: null, realDomain: null, reasons: [] });

/**
 * Decide how suspicious a page is.
 *  feedHit: { source } when the host is on a phishing feed
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

  const parts = splitHost(u.hostname, suffixes);
  const key = parts?.registered ?? u.hostname;
  if (trusted.has(key) || trusted.has(u.hostname)) return QUIET;

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

  const legit = parts ? isLegitHost(parts, index) : false;
  if (legit && !results.length) return QUIET;

  if (parts && !legit) {
    for (const m of lookalikeMatches(parts, index)) {
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
