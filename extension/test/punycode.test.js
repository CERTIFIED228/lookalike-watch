import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeLabel, toUnicode } from "../punycode.js";

test("decodes a Cyrillic homoglyph label", () => {
  assert.equal(decodeLabel("xn--pypal-4ve"), "pаypal");
});

test("decodes accented and non-Latin labels", () => {
  assert.equal(decodeLabel("xn--mnchen-3ya"), "münchen");
  assert.equal(decodeLabel("xn--wgv71a119e"), "日本語");
});

test("leaves plain ascii labels alone", () => {
  assert.equal(decodeLabel("paypal"), "paypal");
});

test("decodes every label of a hostname", () => {
  assert.equal(toUnicode("www.xn--pypal-4ve.com"), "www.pаypal.com");
});

test("returns garbage input unchanged instead of throwing", () => {
  assert.equal(toUnicode("xn--!!!.com"), "xn--!!!.com");
});
