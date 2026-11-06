import { test } from "node:test";
import assert from "node:assert/strict";
import { lookupKeys, parseHostList, parseUrlList } from "../feeds.js";

const SKIP = new Set(["docs.google.com", "google.com", "weeblysite.com"]);

test("host lists keep valid hostnames only", () => {
  const text = [
    "# comment", "", "Paypal-Merchant.RU", "0046.paypal-merchant.ru", "%20mandrillapp.com",
    "localhost", "-bad.com", "fine-site.top", "docs.google.com", "weeblysite.com",
  ].join("\n");
  assert.deepEqual(parseHostList(text, SKIP),
    ["paypal-merchant.ru", "0046.paypal-merchant.ru", "fine-site.top"]);
});

test("url lists become host keys, or url keys on shared platforms", () => {
  const text = [
    "https://e3x4x3w.pages.dev/",
    "https://394834binance.com/icloud/signin?client_id=5d9",
    "https://docs.google.com/forms/d/e/1FAIpQ/viewform?usp=sf_link",
    "not a url",
  ].join("\n");
  assert.deepEqual(parseUrlList(text, new Set(["docs.google.com"])), [
    "e3x4x3w.pages.dev",
    "394834binance.com",
    "url:docs.google.com/forms/d/e/1FAIpQ/viewform",
  ]);
});

test("lookups check the host and its parent domains", () => {
  const keys = lookupKeys("https://a.b.paypal-merchant.ru/login", new Set());
  assert.deepEqual(keys, ["a.b.paypal-merchant.ru", "b.paypal-merchant.ru", "paypal-merchant.ru"]);
});

test("lookups on shared platforms use the page path, never the bare host", () => {
  const keys = lookupKeys("https://docs.google.com/forms/d/e/1FAIpQ/viewform?x=1", new Set(["docs.google.com"]));
  assert.deepEqual(keys, [
    "url:docs.google.com/forms",
    "url:docs.google.com/forms/d",
    "url:docs.google.com/forms/d/e",
    "url:docs.google.com/forms/d/e/1FAIpQ",
    "url:docs.google.com/forms/d/e/1FAIpQ/viewform",
  ]);
});

test("bad urls give no keys", () => {
  assert.deepEqual(lookupKeys("chrome://newtab", new Set()), []);
  assert.deepEqual(lookupKeys("nonsense", new Set()), []);
});
