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

test("shared platforms from the public suffix list are split per tenant", () => {
  assert.equal(splitHost("paypal-login.uk.com", SUFFIXES).platform, "uk.com");
  assert.equal(splitHost("shop.myshopify.com", SUFFIXES).name, "shop");
  assert.equal(splitHost("evil.wordpress.com", SUFFIXES).platform, "wordpress.com");
  assert.equal(splitHost("abc.weeblysite.com", SUFFIXES).name, "abc");
});

test("platforms with an extra level use the right label", () => {
  const azure = splitHost("myacct.z13.web.core.windows.net", SUFFIXES);
  assert.equal(azure.name, "myacct");
  assert.equal(azure.suffix, "z13.web.core.windows.net");
  assert.equal(splitHost("myapp.uc.r.appspot.com", SUFFIXES).name, "myapp");
});

test("a host that is itself a platform root has no name", () => {
  assert.equal(splitHost("s3.us-east-1.amazonaws.com", SUFFIXES), null);
  assert.equal(splitHost("bucket.s3.us-east-1.amazonaws.com", SUFFIXES).name, "bucket");
});

test("wildcard public suffixes are respected", () => {
  assert.equal(splitHost("shop.example.com.bd", SUFFIXES).registered, "example.com.bd");
});

test("a trailing dot doesn't change anything", () => {
  assert.equal(splitHost("paypa1.com.", SUFFIXES).registered, "paypa1.com");
});

test("digits are swapped back before two-letter tricks", () => {
  assert.equal(skeleton("ic1oud"), skeleton("icloud"));
});
