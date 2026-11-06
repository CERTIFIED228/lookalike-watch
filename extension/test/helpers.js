import { readFileSync } from "node:fs";
import { DEFAULT_BRANDS } from "../brands.js";
import { buildIndex, makeSuffixes } from "../detect.js";

const load = (name) => JSON.parse(readFileSync(new URL(`../data/${name}`, import.meta.url), "utf8"));

export const SUFFIXES = makeSuffixes(load("suffixes.json"), load("platforms.json"));
export const TOP_SITES = load("top-sites.json");
export const KNOWN_SITES = load("known-sites.json");
export const POPULAR_HOSTS = load("popular-hosts.json");

export function makeIndex({ mySites = [], knownSites = [], popularHosts = [], brands = DEFAULT_BRANDS } = {}) {
  return buildIndex({ brands, topSites: TOP_SITES, mySites, knownSites, popularHosts }, SUFFIXES);
}
