import { test } from "node:test";
import assert from "node:assert/strict";
import { editDistance, skeleton, splitHost } from "../detect.js";
import { SUFFIXES } from "./helpers.js";

test("skeleton collapses lookalike characters", () => {
  assert.equal(skeleton("pаypаl"), skeleton("paypal"));
  assert.equal(skeleton("rnicrosoft"), skeleton("microsoft"));
  assert.equal(skeleton("g00gle"), skeleton("google"));
  assert.notEqual(skeleton("paypal"), skeleton("payfal"));
});

test("edit distance counts a swap as one edit", () => {
  assert.equal(editDistance("paypal", "papyal"), 1);
  assert.equal(editDistance("paypal", "paypl"), 1);
  assert.equal(editDistance("paypal", "pay"), 3);
});

test("splits hosts on the public suffix list", () => {
  assert.deepEqual(
    splitHost("www.amazon.co.uk", SUFFIXES),
    { host: "www.amazon.co.uk", sub: "www", name: "amazon", suffix: "co.uk", registered: "amazon.co.uk", platform: null },
  );
  assert.equal(splitHost("login.paypal.com", SUFFIXES).registered, "paypal.com");
  assert.equal(splitHost("shop.example.com.au", SUFFIXES).registered, "example.com.au");
});

test("treats each site on free hosting as its own domain", () => {
  const parts = splitHost("paypal-login.vercel.app", SUFFIXES);
  assert.equal(parts.name, "paypal-login");
  assert.equal(parts.registered, "paypal-login.vercel.app");
  assert.equal(parts.platform, "vercel.app");
});

test("decodes punycode so we see what the user sees", () => {
  assert.equal(splitHost("xn--pypal-4ve.com", SUFFIXES).name, "pаypal");
});

test("ip addresses and single-label hosts aren't domains", () => {
  assert.equal(splitHost("192.168.1.1", SUFFIXES), null);
  assert.equal(splitHost("localhost", SUFFIXES), null);
  assert.equal(splitHost("[::1]", SUFFIXES), null);
});

test("i and l are not treated as lookalikes in lowercase addresses", () => {
  assert.notEqual(skeleton("hoteis"), skeleton("hotels"));
});
