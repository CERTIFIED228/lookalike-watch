import { test } from "node:test";
import assert from "node:assert/strict";
import { lookupKeys, parseHostList, parseUrlList } from "../feeds.js";
import { makeIndex, SUFFIXES } from "./helpers.js";

const ctx = { index: makeIndex(), suffixes: SUFFIXES };

test("host lists keep phishing hosts", () => {
  const text = ["# comment", "", "Paypal-Merchant.RU", "0046.paypal-merchant.ru", "%20mandrillapp.com",
    "localhost", "-bad.com", "fine-site.top", "abc.weeblysite.com"].join("\n");
  assert.deepEqual(parseHostList(text, ctx),
    ["paypal-merchant.ru", "0046.paypal-merchant.ru", "fine-site.top", "abc.weeblysite.com"]);
});

test("host lists drop whole services and the brands' own hosts", () => {
  // all of these are in the real Phishing.Database list
  const text = ["docs.google.com", "s3.us-east-1.amazonaws.com", "filesusr.com", "weeblysite.com",
    "l.instagram.com", "storage.cloud.google.com", "click.email.microsoftonline.com"].join("\n");
  assert.deepEqual(parseHostList(text, ctx), []);
});

test("url lists keep the page on shared or legit hosts", () => {
  const text = [
    "https://e3x4x3w.pages.dev/",
    "https://394834binance.com/icloud/signin?client_id=5d9",
    "https://docs.google.com/forms/d/e/1FAIpQ/viewform?usp=sf_link",
    "https://github.com/someone/phish-kit",
    "https://docs.google.com/",
    "not a url",
  ].join("\n");
  assert.deepEqual(parseUrlList(text, ctx), [
    "e3x4x3w.pages.dev",
    "394834binance.com",
    "url:docs.google.com/forms/d/e/1FAIpQ/viewform",
    "url:github.com/someone/phish-kit",
  ]);
});

test("lookups check the host and its parents, down to the registered domain", () => {
  assert.deepEqual(lookupKeys("https://a.b.paypal-merchant.ru/login", ctx),
    ["a.b.paypal-merchant.ru", "b.paypal-merchant.ru", "paypal-merchant.ru"]);
});

test("lookups never climb into a shared platform", () => {
  assert.deepEqual(lookupKeys("https://evil-bucket.s3.us-east-1.amazonaws.com/x", ctx),
    ["evil-bucket.s3.us-east-1.amazonaws.com"]);
});

test("lookups on shared or legit hosts only use the path", () => {
  assert.deepEqual(lookupKeys("https://docs.google.com/forms/d/x?y=1", ctx), [
    "url:docs.google.com/forms", "url:docs.google.com/forms/d", "url:docs.google.com/forms/d/x",
  ]);
  assert.deepEqual(lookupKeys("https://s3.eu-west-2.amazonaws.com/my-bucket/menu.pdf", ctx), [
    "url:s3.eu-west-2.amazonaws.com/my-bucket", "url:s3.eu-west-2.amazonaws.com/my-bucket/menu.pdf",
  ]);
  assert.deepEqual(lookupKeys("https://l.instagram.com/", ctx), []);
});

test("a trailing dot doesn't dodge the lists", () => {
  assert.deepEqual(lookupKeys("https://uk-toll-pay.top./", ctx), ["uk-toll-pay.top"]);
});

test("bad urls give no keys", () => {
  assert.deepEqual(lookupKeys("chrome://newtab", ctx), []);
  assert.deepEqual(lookupKeys("nonsense", ctx), []);
});
