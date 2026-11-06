import { readFileSync } from "node:fs";
import { DEFAULT_BRANDS } from "../brands.js";
import { buildIndex } from "../detect.js";

const load = (name) => JSON.parse(readFileSync(new URL(`../data/${name}`, import.meta.url), "utf8"));

export const SUFFIXES = new Set(load("suffixes.json"));
export const TOP_SITES = load("top-sites.json");
export const KNOWN_SITES = load("known-sites.json");

export function makeIndex({ mySites = [], knownSites = [], brands = DEFAULT_BRANDS } = {}) {
  return buildIndex({ brands, topSites: TOP_SITES, mySites, knownSites }, SUFFIXES);
}
