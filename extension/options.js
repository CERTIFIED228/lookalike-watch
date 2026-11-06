import { DEFAULT_BRANDS } from "./brands.js";
import { FEEDS } from "./feeds.js";

const $ = (id) => document.getElementById(id);
const store = chrome.storage.local;

function cleanDomain(text) {
  const value = text.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0].replace(/^www\./, "");
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(value) ? value : null;
}

function listInto(ul, items, onRemove, empty) {
  ul.replaceChildren();
  if (!items.length) {
    const li = document.createElement("li");
    li.textContent = empty;
    li.className = "muted";
    ul.append(li);
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = item.label ?? item;
    const remove = document.createElement("button");
    remove.textContent = "Remove";
    remove.addEventListener("click", () => onRemove(item));
    li.append(label, remove);
    ul.append(li);
  }
}

async function removeFrom(key, value) {
  const current = (await store.get({ [key]: [] }))[key];
  await store.set({ [key]: current.filter((x) => JSON.stringify(x) !== JSON.stringify(value)) });
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

  listInto($("my-sites"), s.mySites, (d) => removeFrom("mySites", d), "None yet.");
  listInto($("trusted"), s.trusted, (d) => removeFrom("trusted", d), "None.");
  listInto($("brands"), s.customBrands.map((b) => ({ ...b, label: `${b.label} (${b.domains.join(", ")})` })),
    (b) => removeFrom("customBrands", { label: b.label.split(" (")[0], name: b.name, domains: b.domains }),
    "None added.");
  $("brand-count").textContent = DEFAULT_BRANDS.length;
  const imported = Object.keys(s.scanBlocklist).length;
  $("scan-count").textContent = imported ? `${imported} domains imported from scans so far.` : "Nothing imported yet.";
}

$("refresh").addEventListener("click", async () => {
  $("refresh-msg").textContent = "Downloading...";
  await chrome.runtime.sendMessage({ type: "refreshFeeds" });
  $("refresh-msg").textContent = "";
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
  if (!label || !domains.length) return;
  const name = domains[0].split(".")[0];
  const { customBrands } = await store.get({ customBrands: [] });
  await store.set({ customBrands: [...customBrands, { label, name, domains }] });
  $("brand-name").value = "";
  $("brand-domains").value = "";
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
