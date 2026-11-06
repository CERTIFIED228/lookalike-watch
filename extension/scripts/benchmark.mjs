// Measure false alarms and catch rate against real lists of hostnames.
//
//   node scripts/benchmark.mjs legit-hosts.txt phishing-hosts.txt
//
// legit-hosts.txt: sites from the Chrome UX Report ranked below the top
//   100k (so the extension has never seen them)
// phishing-hosts.txt: a sample of Phishing.Database's active list
//
// Pattern checks are measured without the feeds (a listed site would be
// caught whatever its name). Pass a downloaded copy of the Phishing.Database
// list as a third argument to also count feed false alarms on the legit set.
import { readFileSync } from "node:fs";
import { DEFAULT_BRANDS } from "../brands.js";
import { assess, buildIndex, makeSuffixes } from "../detect.js";
import { lookupKeys, parseHostList } from "../feeds.js";

const data = (name) => JSON.parse(readFileSync(new URL(`../data/${name}`, import.meta.url), "utf8"));
const suffixes = makeSuffixes(data("suffixes.json"), data("platforms.json"));
const index = buildIndex({
  brands: DEFAULT_BRANDS, topSites: data("top-sites.json"), knownSites: data("known-sites.json"),
}, suffixes);

function rate(file, hasLogin) {
  const hosts = readFileSync(file, "utf8").split("\n").map((h) => h.trim()).filter(Boolean);
  const bySeverity = {};
  let shown = 0;
  for (const host of hosts) {
    const v = assess({ url: `https://${host}/`, page: { hasLogin }, index, suffixes });
    if (!v.show) continue;
    shown++;
    bySeverity[v.severity] = (bySeverity[v.severity] ?? 0) + 1;
  }
  const pct = ((100 * shown) / hosts.length).toFixed(3);
  return `${shown}/${hosts.length} warned (${pct}%) ${JSON.stringify(bySeverity)}`;
}

function feedFalseAlarms(legitFile, feedFile) {
  const ctx = { index, suffixes };
  const listed = new Set(parseHostList(readFileSync(feedFile, "utf8"), ctx));
  const hosts = readFileSync(legitFile, "utf8").split("\n").map((h) => h.trim()).filter(Boolean);
  const hits = hosts.filter((h) => lookupKeys(`https://${h}/`, ctx).some((k) => listed.has(k)));
  return `${hits.length}/${hosts.length} legit hosts match the feed ${JSON.stringify(hits.slice(0, 15))}`;
}

const [legit, phish, feed] = process.argv.slice(2);
if (!legit || !phish) {
  console.error("usage: node scripts/benchmark.mjs legit-hosts.txt phishing-hosts.txt [feed.txt]");
  process.exit(2);
}
console.log("legit, normal page:  ", rate(legit, false));
console.log("legit, login page:   ", rate(legit, true));
console.log("phishing, login page:", rate(phish, true));
if (feed) console.log("feed on legit hosts: ", feedFalseAlarms(legit, feed));
