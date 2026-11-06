import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, trustKey } from "../detect.js";
import { makeIndex, SUFFIXES } from "./helpers.js";

const index = makeIndex();
const key = (url) => trustKey(url, index, SUFFIXES);

test("normal sites are trusted by registered domain", () => {
  assert.equal(key("https://www.paypa1.com/login"), "paypa1.com");
});

test("a site on a shared platform only trusts that one tenant", () => {
  assert.equal(key("https://paypal-login.vercel.app/x"), "paypal-login.vercel.app");
});

test("pages on shared or legitimate services only trust that page", () => {
  assert.equal(key("https://sites.google.com/view/scam/home"), "url:sites.google.com/view/scam/home");
  assert.equal(key("https://s3.eu-west-2.amazonaws.com/bucket/file.pdf"),
    "url:s3.eu-west-2.amazonaws.com/bucket/file.pdf");
});

test("trusting one page on a shared host doesn't trust the rest of it", () => {
  const trusted = new Set([key("https://sites.google.com/view/one")]);
  const feedHit = { source: "OpenPhish" };
  const run = (url) => assess({ url, index, suffixes: SUFFIXES, trusted, feedHit });
  assert.equal(run("https://sites.google.com/view/one").severity, null);
  assert.equal(run("https://sites.google.com/view/two").severity, "critical");
});
