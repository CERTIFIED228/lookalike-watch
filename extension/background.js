import { DEFAULT_BRANDS, SHARED_HOSTS } from "./brands.js";
import { assess, buildIndex, splitHost } from "./detect.js";
import { FEEDS, lookupKeys, parseHostList, parseUrlList } from "./feeds.js";
import { findFeedHit, replaceFeed } from "./store.js";

const REFRESH_MINUTES = 6 * 60;
const MIN_FEED_SIZE = { hosts: 1000, urls: 20 }; // anything smaller is a broken download
const DAYS_TO_LEARN = 2;
const MAX_MY_SITES = 300;

const DEFAULTS = {
  customBrands: [],
  mySites: [],
  trusted: [],
  scanBlocklist: {},
  loginSeen: {},
  feedStatus: {},
};

const BADGE_COLOURS = { critical: "#b3261e", high: "#c2410c", medium: "#a16207", low: "#475569" };

// --- the lookalike index (rebuilt when your brands or sites change) -----------------

let cached = null;

async function bundled(path) {
  const resp = await fetch(chrome.runtime.getURL(path));
  return resp.json();
}

async function getIndex() {
  if (cached) return cached;
  const [topSites, knownSites, suffixList, settings] = await Promise.all([
    bundled("data/top-sites.json"),
    bundled("data/known-sites.json"),
    bundled("data/suffixes.json"),
    chrome.storage.local.get({ customBrands: [], mySites: [] }),
  ]);
  const suffixes = new Set(suffixList);
  const index = buildIndex({
    brands: [...DEFAULT_BRANDS, ...settings.customBrands],
    topSites,
    knownSites,
    mySites: settings.mySites,
  }, suffixes);
  cached = { index, suffixes, shared: new Set([...SHARED_HOSTS, ...index.legit]) };
  return cached;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.customBrands || changes.mySites)) cached = null;
});

// --- checking a page ------------------------------------------------------------------

function hostParts(url, suffixes) {
  try {
    return splitHost(new URL(url).hostname, suffixes);
  } catch {
    return null;
  }
}

async function check(url, hasLogin) {
  const settings = await chrome.storage.local.get({ trusted: [], scanBlocklist: {} });
  const { index, suffixes, shared } = await getIndex();

  let feedHit = null;
  try {
    feedHit = await findFeedHit(lookupKeys(url, shared));
  } catch (err) {
    console.warn("feed lookup failed", err);
  }
  const parts = hostParts(url, suffixes);
  const scanHit = parts
    ? settings.scanBlocklist[parts.registered] ?? settings.scanBlocklist[parts.host] ?? null
    : null;

  return assess({
    url, page: { hasLogin }, index, suffixes, feedHit, scanHit,
    trusted: new Set(settings.trusted),
  });
}

async function showOnToolbar(tabId, url, verdict) {
  const flagged = verdict.show && verdict.severity;
  await chrome.action.setBadgeText({ tabId, text: flagged ? "!" : "" });
  if (flagged) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLOURS[verdict.severity] });
  }
  await chrome.storage.session.set({ [`tab:${tabId}`]: { url, verdict } });
}

// --- learning the sites you log into ---------------------------------------------------

async function learnLogin(url) {
  const verdict = await check(url, true);
  if (verdict.severity) return; // never learn a site we were warning about
  const { suffixes } = await getIndex();
  const parts = hostParts(url, suffixes);
  if (!parts || parts.platform) return;

  const { loginSeen, mySites } = await chrome.storage.local.get({ loginSeen: {}, mySites: [] });
  const today = new Date().toISOString().slice(0, 10);
  const days = new Set(loginSeen[parts.registered] ?? []);
  days.add(today);
  loginSeen[parts.registered] = [...days].slice(-5);

  // Logging in on two different days, so a one-off visit (or a phishing
  // page that slipped through) doesn't become "your site".
  if (days.size >= DAYS_TO_LEARN && !mySites.includes(parts.registered)) {
    mySites.push(parts.registered);
    mySites.splice(0, Math.max(0, mySites.length - MAX_MY_SITES));
  }
  await chrome.storage.local.set({ loginSeen, mySites });
}

// --- phishing feeds -------------------------------------------------------------------

async function download(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 60_000);
  try {
    const resp = await fetch(url, { signal: ctrl.signal, cache: "no-store" });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.text();
  } finally {
    clearTimeout(timer);
  }
}

async function refreshFeeds() {
  const { shared } = await getIndex();
  const { feedStatus } = await chrome.storage.local.get({ feedStatus: {} });

  for (const feed of FEEDS) {
    const previous = feedStatus[feed.id] ?? {};
    try {
      const text = await download(feed.url);
      const keys = feed.format === "hosts" ? parseHostList(text, shared) : parseUrlList(text, shared);
      if (keys.length < MIN_FEED_SIZE[feed.format]) {
        throw new Error(`only ${keys.length} entries, keeping the previous list`);
      }
      await replaceFeed(feed.id, keys);
      feedStatus[feed.id] = { count: keys.length, updatedAt: Date.now(), error: null };
    } catch (err) {
      // Keep whatever we had: an old list beats an empty one.
      feedStatus[feed.id] = { ...previous, error: String(err.message ?? err), triedAt: Date.now() };
    }
  }
  await chrome.storage.local.set({ feedStatus });
  return feedStatus;
}

async function refreshIfStale() {
  const { feedStatus } = await chrome.storage.local.get({ feedStatus: {} });
  const oldest = Math.min(...FEEDS.map((f) => feedStatus[f.id]?.updatedAt ?? 0));
  if (Date.now() - oldest > REFRESH_MINUTES * 60_000) await refreshFeeds();
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("refresh-feeds", { periodInMinutes: REFRESH_MINUTES });
  refreshIfStale();
});
chrome.runtime.onStartup.addListener(() => refreshIfStale());
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "refresh-feeds") refreshFeeds();
});

// --- messages from the page, popup and settings -------------------------------------------

async function addTrusted(url) {
  const { suffixes } = await getIndex();
  const parts = hostParts(url, suffixes);
  const key = parts?.registered ?? new URL(url).hostname;
  const { trusted } = await chrome.storage.local.get({ trusted: [] });
  if (!trusted.includes(key)) trusted.push(key);
  await chrome.storage.local.set({ trusted });
}

async function handle(msg, sender) {
  const tabId = sender.tab?.id;
  switch (msg.type) {
    case "check": {
      const verdict = await check(msg.url, msg.hasLogin);
      if (tabId !== undefined) await showOnToolbar(tabId, msg.url, verdict);
      return verdict;
    }
    case "trust":
      await addTrusted(msg.url);
      if (tabId !== undefined) await chrome.action.setBadgeText({ tabId, text: "" });
      return { ok: true };
    case "loggedIn":
      await learnLogin(msg.url);
      return { ok: true };
    case "leave":
      if (tabId !== undefined) await chrome.tabs.update(tabId, { url: "chrome://newtab/" });
      return { ok: true };
    case "refreshFeeds":
      return refreshFeeds();
    case "status": {
      const settings = await chrome.storage.local.get(DEFAULTS);
      const { index } = await getIndex();
      return { ...settings, legitCount: index.legit.size, feeds: FEEDS };
    }
    default:
      return { error: `unknown message ${msg.type}` };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  handle(msg, sender).then(reply, (err) => reply({ error: String(err) }));
  return true; // reply asynchronously
});
