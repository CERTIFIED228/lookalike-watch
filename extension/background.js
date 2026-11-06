import { DEFAULT_BRANDS } from "./brands.js";
import { assess, buildIndex, classifyHost, makeSuffixes, splitHost, trustKey } from "./detect.js";
import { FEEDS, lookupKeys, parseHostList, parseUrlList } from "./feeds.js";
import { deleteOtherGenerations, findFeedHit, writeGeneration } from "./store.js";

const REFRESH_MINUTES = 6 * 60;
const MIN_FEED_SIZE = { hosts: 1000, urls: 20 }; // anything smaller is a broken download
const DAYS_TO_LEARN = 2;
const MAX_MY_SITES = 300;
const LOGIN_MEMORY_DAYS = 90;

const BADGE_COLOURS = { critical: "#b3261e", high: "#c2410c", medium: "#a16207", low: "#475569" };

// --- the lookalike index (rebuilt when your brands or sites change) -----------------

let indexPromise = null;

async function bundled(path) {
  const resp = await fetch(chrome.runtime.getURL(path));
  return resp.json();
}

async function buildEverything() {
  const [topSites, knownSites, popularHosts, icann, platforms, settings] = await Promise.all([
    bundled("data/top-sites.json"),
    bundled("data/known-sites.json"),
    bundled("data/popular-hosts.json"),
    bundled("data/suffixes.json"),
    bundled("data/platforms.json"),
    chrome.storage.local.get({ customBrands: [], mySites: [] }),
  ]);
  const suffixes = makeSuffixes(icann, platforms);
  const index = buildIndex({
    brands: [...DEFAULT_BRANDS, ...settings.customBrands],
    topSites,
    knownSites,
    popularHosts,
    mySites: settings.mySites,
  }, suffixes);
  return { index, suffixes };
}

// Cache the promise, not the result, so tabs restored together share one build.
function getIndex() {
  indexPromise ??= buildEverything().catch((err) => {
    indexPromise = null;
    throw err;
  });
  return indexPromise;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.customBrands || changes.mySites)) indexPromise = null;
});

// --- checking a page ------------------------------------------------------------------

async function activeGenerations() {
  const { feedStatus } = await chrome.storage.local.get({ feedStatus: {} });
  return FEEDS
    .filter((f) => feedStatus[f.id]?.generation)
    .map((f) => ({ generation: feedStatus[f.id].generation, name: f.name }));
}

async function check(url, hasLogin) {
  const settings = await chrome.storage.local.get({ trusted: [], scanBlocklist: {} });
  const ctx = await getIndex();

  let feedHit = null;
  try {
    feedHit = await findFeedHit(lookupKeys(url, ctx), await activeGenerations());
  } catch (err) {
    console.warn("feed lookup failed", err);
  }
  let parts = null;
  try {
    parts = splitHost(new URL(url).hostname, ctx.suffixes);
  } catch {
    // not a URL with a host
  }
  const scanHit = parts
    ? settings.scanBlocklist[parts.registered] ?? settings.scanBlocklist[parts.host] ?? null
    : null;

  return assess({
    url, page: { hasLogin }, index: ctx.index, suffixes: ctx.suffixes, feedHit, scanHit,
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

// High and critical warnings also go to a system notification. The card
// inside the page can in the end be covered up by a determined page; this
// and the toolbar badge can't be touched by it.
async function notify(tabId, url, verdict) {
  if (!verdict.show || !["high", "critical"].includes(verdict.severity)) return;
  const host = new URL(url).hostname;
  const key = `notified:${tabId}`;
  const { [key]: already } = await chrome.storage.session.get(key);
  if (already === host) return; // once per site per tab
  await chrome.storage.session.set({ [key]: host });
  chrome.notifications.create(`tab-${tabId}`, {
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/128.png"),
    title: `${verdict.severity.toUpperCase()}: ${verdict.title}`,
    message: verdict.reasons.slice(0, 2).join("\n"),
    contextMessage: host,
    priority: 2,
  });
}

chrome.notifications.onClicked.addListener((id) => {
  const tabId = Number(id.replace("tab-", ""));
  if (Number.isInteger(tabId)) chrome.tabs.update(tabId, { active: true }).catch(() => {});
  chrome.notifications.clear(id);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`tab:${tabId}`, `notified:${tabId}`]);
});

// --- learning the sites you log into ---------------------------------------------------

function pruneLoginHistory(loginSeen) {
  const cutoff = new Date(Date.now() - LOGIN_MEMORY_DAYS * 86_400_000).toISOString().slice(0, 10);
  for (const [domain, days] of Object.entries(loginSeen)) {
    const recent = days.filter((d) => d >= cutoff);
    if (recent.length) loginSeen[domain] = recent;
    else delete loginSeen[domain];
  }
}

async function learnLogin(url) {
  const verdict = await check(url, true);
  if (verdict.severity) return; // never learn a site we were warning about
  const { index, suffixes } = await getIndex();
  const c = classifyHost(new URL(url).hostname, index, suffixes);
  if (c.kind !== "site" && c.kind !== "legit") return;
  if (!c.parts || c.parts.platform) return;
  const domain = c.parts.registered;

  const { loginSeen, mySites } = await chrome.storage.local.get({ loginSeen: {}, mySites: [] });
  pruneLoginHistory(loginSeen);
  const days = new Set(loginSeen[domain] ?? []);
  days.add(new Date().toISOString().slice(0, 10));
  loginSeen[domain] = [...days].sort().slice(-5);

  // Logging in on two different days, so a one-off visit (or a phishing
  // page that slipped through) doesn't become "your site".
  if (days.size >= DAYS_TO_LEARN && !mySites.includes(domain)) {
    mySites.push(domain);
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

// An extension API call resets the service worker's 30-second idle timer,
// so a slow write on an old laptop isn't cut off halfway.
const keepAlive = () => chrome.runtime.getPlatformInfo();

async function refreshFeed(feed, ctx) {
  const { feedStatus } = await chrome.storage.local.get({ feedStatus: {} });
  const previous = feedStatus[feed.id] ?? {};
  try {
    const text = await download(feed.url);
    const keys = feed.format === "hosts" ? parseHostList(text, ctx) : parseUrlList(text, ctx);
    if (keys.length < MIN_FEED_SIZE[feed.format]) {
      throw new Error(`only ${keys.length} entries, keeping the previous list`);
    }
    const generation = `${feed.id}@${Date.now()}`;
    await writeGeneration(generation, keys, { between: keepAlive });
    feedStatus[feed.id] = { count: keys.length, updatedAt: Date.now(), triedAt: Date.now(), generation, error: null };
    await chrome.storage.local.set({ feedStatus });
    await deleteOtherGenerations(feed.id, generation);
  } catch (err) {
    // Keep whatever we had: an old list beats an empty one.
    feedStatus[feed.id] = { ...previous, error: String(err.message ?? err), triedAt: Date.now() };
    await chrome.storage.local.set({ feedStatus });
  }
}

// One refresh at a time: two overlapping ones would each delete the
// generation the other was writing.
let refreshing = null;

function refreshFeeds(options = {}) {
  refreshing ??= runRefresh(options).finally(() => {
    refreshing = null;
  });
  return refreshing;
}

async function runRefresh({ onlyStale = false } = {}) {
  const ctx = await getIndex();
  const { feedStatus } = await chrome.storage.local.get({ feedStatus: {} });
  const due = Date.now() - REFRESH_MINUTES * 60_000;
  for (const feed of FEEDS) {
    const st = feedStatus[feed.id] ?? {};
    // A feed that keeps failing is retried at the normal rate, not on every start.
    if (onlyStale && (st.updatedAt ?? 0) > due) continue;
    if (onlyStale && (st.triedAt ?? 0) > due) continue;
    await refreshFeed(feed, ctx);
  }
  return (await chrome.storage.local.get({ feedStatus: {} })).feedStatus;
}

// Alarms can be cleared when the browser restarts, so check on every wake-up.
async function ensureAlarm() {
  if (!(await chrome.alarms.get("refresh-feeds"))) {
    await chrome.alarms.create("refresh-feeds", { periodInMinutes: REFRESH_MINUTES });
  }
}

ensureAlarm();
chrome.runtime.onInstalled.addListener(() => refreshFeeds({ onlyStale: true }));
chrome.runtime.onStartup.addListener(() => refreshFeeds({ onlyStale: true }));
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "refresh-feeds") refreshFeeds();
});

// --- messages ---------------------------------------------------------------------------

async function addTrusted(url) {
  const { index, suffixes } = await getIndex();
  const key = trustKey(url, index, suffixes);
  const { trusted } = await chrome.storage.local.get({ trusted: [] });
  if (!trusted.includes(key)) trusted.push(key);
  await chrome.storage.local.set({ trusted });
}

async function addBrand(label, domains) {
  const { suffixes } = await getIndex();
  const parts = splitHost(domains[0], suffixes);
  if (!parts) throw new Error(`${domains[0]} isn't a domain`);
  const { customBrands } = await chrome.storage.local.get({ customBrands: [] });
  customBrands.push({ label, name: parts.name, domains });
  await chrome.storage.local.set({ customBrands });
}

async function status() {
  const settings = await chrome.storage.local.get({
    customBrands: [], mySites: [], trusted: [], scanBlocklist: {}, loginSeen: {}, feedStatus: {},
  });
  return { ...settings, feeds: FEEDS.map(({ id, name }) => ({ id, name })) };
}

// Pages can't message the extension directly, but the content script runs
// inside every page, so only trust what Chrome itself says about the sender:
// the page's real URL comes from `sender.url`, never from the message.
async function fromPage(msg, sender) {
  const tabId = sender.tab?.id;
  const url = sender.url;
  if (tabId === undefined || !url) return { error: "no page" };
  switch (msg.type) {
    case "check": {
      const verdict = await check(url, msg.hasLogin === true);
      await showOnToolbar(tabId, url, verdict);
      await notify(tabId, url, verdict);
      return verdict;
    }
    case "loggedIn":
      await learnLogin(url);
      return { ok: true };
    case "leave":
      await chrome.tabs.update(tabId, { url: "chrome://newtab/" });
      return { ok: true };
    default:
      return { error: `unknown message ${msg.type}` };
  }
}

async function trustTab(tabId) {
  const key = `tab:${tabId}`;
  const { [key]: saved } = await chrome.storage.session.get(key);
  if (!saved) return { error: "This tab hasn't been checked." };
  await addTrusted(saved.url);
  await chrome.action.setBadgeText({ tabId, text: "" });
  await chrome.storage.session.set({ [key]: { ...saved, verdict: { ...saved.verdict, severity: null, show: false } } });
  chrome.tabs.sendMessage(tabId, { type: "trusted" }).catch(() => {});
  return { ok: true };
}

// The settings page and popup are the only places allowed to read or change
// settings, including "I trust this site": a web page can't fake a click in
// the toolbar popup or cover it up.
async function fromExtension(msg) {
  switch (msg.type) {
    case "status":
      return status();
    case "trustTab":
      return trustTab(msg.tabId);
    case "refreshFeeds":
      return refreshFeeds();
    case "addBrand":
      await addBrand(msg.label, msg.domains);
      return { ok: true };
    case "preview": {
      // "Check a link" in the popup: judge it as if it were a login page,
      // without ever loading it.
      const text = String(msg.url ?? "").trim();
      const url = /^https?:\/\//i.test(text) ? text : `https://${text}`;
      try {
        new URL(url);
      } catch {
        return { error: "That doesn't look like a link." };
      }
      return check(url, true);
    }
    default:
      return { error: `unknown message ${msg.type}` };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return false;
  const own = sender.url?.startsWith(chrome.runtime.getURL(""));
  (own ? fromExtension(msg) : fromPage(msg, sender))
    .then(reply, (err) => reply({ error: String(err.message ?? err) }));
  return true; // reply asynchronously
});
