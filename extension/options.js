import { DEFAULT_BRANDS } from "./brands.js";
import { FEEDS } from "./feeds.js";

const $ = (id) => document.getElementById(id);
const store = chrome.storage.local;

function cleanDomain(text) {
  const value = text.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0].replace(/^www\./, "");
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(value) ? value : null;
}

// items: [{ text, value }]. Removing compares the stored value itself.
function listInto(ul, items, onRemove, empty) {
  ul.replaceChildren();
  if (!items.length) {
    const li = document.createElement("li");
    li.textContent = empty;
    li.className = "muted";
    ul.append(li);
    return;
  }
  for (const { text, value } of items) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = text;
    const remove = document.createElement("button");
    remove.textContent = "Remove";
    remove.addEventListener("click", () => onRemove(value));
    li.append(label, remove);
    ul.append(li);
  }
}

async function removeFrom(key, value) {
  const current = (await store.get({ [key]: [] }))[key];
  await store.set({ [key]: current.filter((x) => JSON.stringify(x) !== JSON.stringify(value)) });
  render();
}

// Forget the login days too, or the next login would add it straight back.
async function removeMySite(domain) {
  const { mySites, loginSeen } = await store.get({ mySites: [], loginSeen: {} });
  delete loginSeen[domain];
  await store.set({ mySites: mySites.filter((d) => d !== domain), loginSeen });
  render();
}

function when(ms) {
  return ms ? new Date(ms).toLocaleString() : "never";
}

async function render() {
  const s = await chrome.runtime.sendMessage({ type: "status" });

  const feeds = $("feeds");
  feeds.replaceChildren();
  for (const feed of FEEDS) {
    const st = s.feedStatus[feed.id] ?? {};
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = `${feed.name}: ${(st.count ?? 0).toLocaleString()} sites, updated ${when(st.updatedAt)}`;
    li.append(name);
    if (st.error) {
      const err = document.createElement("span");
      err.className = "bad";
      err.textContent = `last try failed: ${st.error}`;
      li.append(err);
    }
    feeds.append(li);
  }

  listInto($("my-sites"), s.mySites.map((d) => ({ text: d, value: d })), removeMySite, "None yet.");
  listInto($("trusted"), s.trusted.map((t) => ({ text: t.replace(/^url:/, ""), value: t })),
    (t) => removeFrom("trusted", t), "None.");
  listInto($("brands"), s.customBrands.map((b) => ({ text: `${b.label}: ${b.domains.join(", ")}`, value: b })),
    (b) => removeFrom("customBrands", b), "None added.");
  const remembered = Object.keys(s.loginSeen).length;
  $("login-history").textContent = `Login history: ${remembered} site${remembered === 1 ? "" : "s"} remembered (kept for 90 days).`;
  $("brand-count").textContent = DEFAULT_BRANDS.length;
  const imported = Object.keys(s.scanBlocklist).length;
  $("scan-count").textContent = imported ? `${imported} domains imported from scans so far.` : "Nothing imported yet.";
}

$("refresh").addEventListener("click", async () => {
  $("refresh").disabled = true;
  $("refresh-msg").textContent = "Downloading...";
  await chrome.runtime.sendMessage({ type: "refreshFeeds" });
  $("refresh-msg").textContent = "";
  $("refresh").disabled = false;
  render();
});

$("add-site").addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = cleanDomain($("site").value);
  if (!domain) return;
  const { mySites } = await store.get({ mySites: [] });
  if (!mySites.includes(domain)) await store.set({ mySites: [...mySites, domain] });
  $("site").value = "";
  render();
});

$("add-brand").addEventListener("submit", async (e) => {
  e.preventDefault();
  const label = $("brand-name").value.trim();
  const domains = $("brand-domains").value.split(",").map(cleanDomain).filter(Boolean);
  if (!label || !domains.length) {
    $("brand-msg").textContent = "Add a name and at least one real domain.";
    return;
  }
  const result = await chrome.runtime.sendMessage({ type: "addBrand", label, domains });
  $("brand-msg").textContent = result.error ? `Couldn't add it: ${result.error}` : `Added ${label}.`;
  if (!result.error) {
    $("brand-name").value = "";
    $("brand-domains").value = "";
  }
  render();
});

$("forget-logins").addEventListener("click", async () => {
  await store.set({ loginSeen: {} });
  render();
});

$("report").addEventListener("change", async () => {
  const file = $("report").files[0];
  if (!file) return;
  try {
    const report = JSON.parse(await file.text());
    if (!Array.isArray(report.findings)) throw new Error("not a lookalike-watch report");
    const { scanBlocklist } = await store.get({ scanBlocklist: {} });
    let added = 0;
    for (const f of report.findings) {
      if (typeof f.ascii !== "string" || !(f.score >= 50)) continue;
      scanBlocklist[f.ascii] = { score: f.score, level: f.level, reasons: (f.reasons ?? []).slice(0, 3) };
      added++;
    }
    await store.set({ scanBlocklist });
    $("scan-msg").textContent = `Imported ${added} domains from ${report.target ?? "the report"}.`;
  } catch (err) {
    $("scan-msg").textContent = `Couldn't read that file: ${err.message}`;
  }
  $("report").value = "";
  render();
});

$("clear-scan").addEventListener("click", async () => {
  await store.set({ scanBlocklist: {} });
  $("scan-msg").textContent = "Cleared.";
  render();
});

render();
