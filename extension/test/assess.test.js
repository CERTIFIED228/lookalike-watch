import { test } from "node:test";
import assert from "node:assert/strict";
import { assess } from "../detect.js";
import { makeIndex, SUFFIXES } from "./helpers.js";

const index = makeIndex();
const check = (url, extra = {}) =>
  assess({ url, page: { hasLogin: false }, index, suffixes: SUFFIXES, trusted: new Set(), ...extra });
const onLoginPage = (url, extra = {}) => check(url, { page: { hasLogin: true }, ...extra });
const said = (v, text) => v.reasons.some((r) => r.includes(text));

// --- real sites stay quiet -------------------------------------------------
for (const url of [
  "https://www.paypal.com/signin",
  "https://paypal.me/someone",
  "https://www.amazon.co.uk/",
  "https://amazon.de/",
  "https://s3.amazonaws.com/bucket/file",
  "https://login.microsoftonline.com/",
  "https://www.linkedin.com/feed/",
  "https://www.gov.uk/government/organisations/hm-revenue-customs",
  "https://www.nhs.uk/",
  "https://docs.google.com/document/d/abc",
  "https://github.com/",
  "https://paypal.github.io/",            // brand's own pages on a platform
  "https://my-holiday-blog.netlify.app/",
  "http://localhost:8000/",
  "chrome://settings/",
  "not a url",
]) {
  test(`quiet on ${url}`, () => {
    const v = onLoginPage(url);
    assert.equal(v.show, false, JSON.stringify(v));
  });
}

// --- lookalikes of curated brands -------------------------------------------
test("cyrillic homoglyph of a protected brand is critical", () => {
  const v = check("https://xn--pypal-4ve.com/login");
  assert.equal(v.severity, "critical");
  assert.equal(v.show, true);
  assert.equal(v.brand, "PayPal");
  assert.equal(v.realDomain, "paypal.com");
  assert.ok(said(v, "looks identical to paypal.com"));
  assert.ok(said(v, "non-Latin"));
});

test("digit homoglyph is critical", () => {
  assert.equal(check("https://paypa1.com/").severity, "critical");
  assert.equal(check("https://arnazon.co.uk/").severity, "critical");
});

test("one-letter typo of a brand is high", () => {
  const v = check("https://www.paypl.com/");
  assert.equal(v.severity, "high");
  assert.ok(said(v, "1 character different from paypal.com"));
});

for (const url of [
  "https://paypal-login.com/",
  "https://secure-barclays.co.uk/",
  "https://hmrc-tax-refund.com/",
  "https://royalmail-redelivery.com/",
  "https://evri-parcel.co.uk/",
  "https://dvla-fine-payment.com/",
  "https://ups-customs-fee.net/",
  "https://chatgpt-billing.com/",
  "https://gov-uk-refund.com/",
]) {
  test(`brand plus scam word: ${url}`, () => {
    const v = check(url);
    assert.equal(v.severity, "high", JSON.stringify(v));
    assert.ok(said(v, "common in scams"), v.reasons.join(" | "));
  });
}

test("short brand names need an exact word match", () => {
  assert.equal(check("https://pickups-update.com/").severity, null);
  assert.equal(check("https://hsbd.com/").severity, null);
});

test("brand name alone with a harmless word is fine", () => {
  assert.equal(check("https://paypal-community.com/").severity, null);
  assert.equal(check("https://amazonfans-blog.com/").severity, null);
});

test("same name on a generic ending the brand doesn't use is high", () => {
  const v = check("https://paypal.top/");
  assert.equal(v.severity, "high");
  assert.ok(said(v, ".top"));
});

// --- brand in the wrong place ----------------------------------------------------
test("levelsquatting: real domain used as a fake subdomain", () => {
  const v = check("https://paypal.com.secure-check.bid/login");
  assert.equal(v.severity, "high");
  assert.ok(said(v, "secure-check.bid"), v.reasons.join(" | "));
});

test("brand on free hosting is high", () => {
  const v = check("https://royalmail-redelivery.vercel.app/");
  assert.equal(v.severity, "high");
  assert.ok(said(v, "vercel.app"));
});

// --- any popular site, not just curated ones ------------------------------------
test("homoglyph of any top-10k site is high", () => {
  const v = check("https://www.y0utube.com/");
  assert.equal(v.severity, "high", JSON.stringify(v));
  assert.ok(said(v, "youtube.com"));
});

test("one-letter typos only count for protected brands and your sites", () => {
  // Measured on 100k real sites: typo matches against the whole top-10k list
  // caused ~7 false alarms for every real phishing site they caught.
  assert.equal(onLoginPage("https://githhub.com/").severity, null);
  assert.equal(check("https://linkedn.com/").severity, "high");
});

test("names made of a common word can opt out of typo matching", () => {
  assert.equal(onLoginPage("https://my.pcloud.com/").show, false);
  assert.equal(check("https://icloud-verify.com/").severity, "high");
});

test("popular sites are never flagged as lookalikes of each other", () => {
  assert.equal(check("https://amazon.es/").severity, null);
  assert.equal(check("https://xvideos3.com/").severity, null);
});

// --- your own sites ---------------------------------------------------------------
test("lookalikes of a site you log into are treated like brands", () => {
  const mine = makeIndex({ mySites: ["leedsbuildingsociety.co.uk"] });
  const v = check("https://leedsbuildingsociety-verify.co.uk/", { index: mine });
  assert.equal(v.severity, "high");
  const typo = check("https://leedsbuildingsocety.co.uk/", { index: mine });
  assert.equal(typo.severity, "high");
});

// --- known phishing lists -------------------------------------------------------
test("a hit on a phishing feed is critical even with an innocent name", () => {
  const v = check("https://uk-toll-pay.top/pay", { feedHit: { source: "Phishing.Database" } });
  assert.equal(v.severity, "critical");
  assert.equal(v.title, "Known phishing site");
  assert.ok(said(v, "Phishing.Database"));
});

test("a hit from an imported lookalike-watch scan uses the scan's level", () => {
  const v = check("https://totally-unrelated.xyz/", {
    scanHit: { score: 82, level: "critical", reasons: ["has a live web host"] },
  });
  assert.equal(v.severity, "critical");
  assert.ok(said(v, "your lookalike-watch scan"));
});

// --- warning signs on any domain ---------------------------------------------------
test("login over plain http on a raw IP address is a warning", () => {
  const v = onLoginPage("http://185.23.1.9/login");
  assert.equal(v.show, true);
  assert.ok(["low", "medium"].includes(v.severity));
  assert.ok(said(v, "IP address"));
  assert.ok(said(v, "unencrypted"));
});

test("warning signs alone stay silent on pages without a login form", () => {
  assert.equal(check("http://185.23.1.9/").show, false);
});

test("risky endings add a reason to an existing match", () => {
  const v = check("https://paypal-verify.top/");
  assert.ok(said(v, ".top"));
});

test("mixed alphabets in one name is a warning sign", () => {
  const v = onLoginPage("https://xn--bnk-shop-16g.com/");
  assert.ok(said(v, "different alphabets"), JSON.stringify(v));
});

// --- the user is in charge ------------------------------------------------------------
test("trusted sites are always quiet", () => {
  const v = check("https://paypa1.com/", { trusted: new Set(["paypa1.com"]) });
  assert.equal(v.severity, null);
  assert.equal(v.show, false);
});

test("home network devices like a router login page stay quiet", () => {
  for (const url of ["http://192.168.1.1/login", "http://10.0.0.1/", "http://router.local/", "http://127.0.0.1:5000/"]) {
    assert.equal(onLoginPage(url).show, false, url);
  }
});

test("popular sites outside the top 10k are never flagged", () => {
  const withKnown = makeIndex({ knownSites: ["anpost.com"] });
  assert.equal(check("https://www.anpost.com/", { index: withKnown }).severity, null);
});

test("short popular names don't produce rn/m lookalikes", () => {
  assert.equal(check("https://pom.go.id/").severity, null);
});

test("amazon and microsoft work domains are recognised", () => {
  assert.equal(check("https://atoz-login.amazon.work/").severity, null);
  assert.equal(check("https://outlook.office.com.mcas.ms/").severity, null);
});

test("multi-letter tricks (cl -> d) only apply to protected brands", () => {
  assert.equal(check("https://support.dave.com/").severity, null);
  assert.equal(check("https://www.c1oudflare.com/").severity, "high");
});

test("short brand typos and same-name-other-ending are medium, so login pages only", () => {
  assert.equal(check("https://www.mondo.co.za/").severity, "medium");
  assert.equal(check("https://www.mondo.co.za/").show, false);
  assert.equal(check("https://www.netflix.shop/").severity, "medium");
  assert.equal(onLoginPage("https://www.netflix.shop/").show, true);
});

test("brand on free hosting without a scam word is medium", () => {
  assert.equal(check("https://google-pacman.github.io/").severity, "medium");
});

test("google's own service domains are not scams", () => {
  assert.equal(check("https://www.googleadservices.com/").severity, null);
});

test("the same lookalike isn't explained twice", () => {
  const v = check("https://xn--pypal-4ve.com/");
  assert.ok(!said(v, "1 character different"), v.reasons.join(" | "));
});
