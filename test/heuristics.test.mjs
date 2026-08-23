import test from "node:test";
import assert from "node:assert/strict";
import { analyseHost, editDistance, entropy, isInternalName, looksAlgorithmic } from "../src/heuristics.mjs";

const ids = (h, opts) => analyseHost(h, opts).signals.map((s) => s.id);
const weight = (h, opts) => analyseHost(h, opts).weight;

/**
 * The single most important property of this module: it must stay silent on the
 * names that fill a real resolver log. A verifier that flags a company's own CDN
 * gets switched off, and then it catches nothing at all.
 */
test("ordinary and first-party names produce no signals", () => {
  const quiet = [
    "www.google.com", "accounts.google.com", "graph.facebook.com", "cdn.jsdelivr.net",
    "www.googleusercontent.com", "apple-cloudkit.com", "gateway.icloud.com",
    "outlook.office365.com", "s3.us-east-1.amazonaws.com", "example.com",
    "en.wikipedia.org", "raw.githubusercontent.com", "registry.npmjs.org",
  ];
  for (const h of quiet) {
    assert.equal(weight(h), 0, `${h} should be silent but scored ${weight(h)} via ${ids(h)}`);
  }
});

test("brand TLDs belong to the brand", () => {
  assert.ok(!ids("dns.google").includes("brand-in-apex"));
  assert.ok(!ids("dns.google").includes("brand-lookalike"));
  assert.ok(ids("dns.google").includes("doh-resolver"), "but it is still a public resolver");
});

test("a brand under someone else's apex is the strongest impersonation shape", () => {
  assert.ok(ids("paypal.com.secure-login.cfd").includes("brand-subdomain-spoof"));
  assert.ok(ids("my-paypal-verify-account.xyz").includes("brand-in-apex"));
  assert.ok(ids("paypa1-secure.tk").includes("brand-lookalike"));
});

test("punycode and non-ASCII are called out", () => {
  assert.ok(ids("xn--pypal-4ve.com").includes("punycode"));
  assert.ok(ids("pаypal.com").includes("non-ascii"));
});

test("machine-generated labels are detected, real words are not", () => {
  assert.ok(looksAlgorithmic("kjxhqwbrmzptv7").hit);
  assert.ok(looksAlgorithmic("a4f2c9d1e8b7c0a1").hit);
  assert.ok(!looksAlgorithmic("googleusercontent").hit);
  assert.ok(!looksAlgorithmic("cloudfront").hit);
  assert.ok(!looksAlgorithmic("short").hit, "too short to judge");
});

test("an allowlisted apex silences the judgemental signals", () => {
  const opts = { allowApexes: new Set(["secure-login.cfd"]) };
  assert.ok(!ids("paypal.com.secure-login.cfd", opts).includes("brand-subdomain-spoof"));
});

test("reserved internal names are recognised", () => {
  assert.ok(isInternalName("printer.lan"));
  assert.ok(isInternalName("intranet.corp.example"));
  assert.ok(!isInternalName("example.com"));
  assert.ok(ids("printer.lan").includes("internal-name"));
});

test("entropy and edit distance behave", () => {
  assert.equal(entropy(""), 0);
  assert.equal(entropy("aaaa"), 0);
  assert.ok(entropy("abcd") > 1.9);
  assert.equal(editDistance("paypal", "paypa1"), 1);
  assert.equal(editDistance("paypal", "paypal"), 0);
  assert.ok(editDistance("paypal", "completely-different", 2) > 2);
});
