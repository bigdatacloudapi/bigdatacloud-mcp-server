import test from "node:test";
import assert from "node:assert/strict";
import { apexOf, classifyIP, inCidr, isHostname, normaliseHost, normaliseIP, parseIP, tldOf } from "../src/net.mjs";

test("IPv4 parsing rejects the ambiguous forms", () => {
  assert.equal(parseIP("1.2.3.4").version, 4);
  assert.equal(parseIP("255.255.255.255").version, 4);
  assert.equal(parseIP("1.2.3.256"), null);
  assert.equal(parseIP("01.2.3.4"), null, "leading zeros are octal-ambiguous and must be refused");
  assert.equal(parseIP("1.2.3"), null);
  assert.equal(parseIP(""), null);
});

test("IPv6 parsing handles :: and zone ids", () => {
  assert.equal(normaliseIP("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1");
  assert.equal(normaliseIP("[2001:db8::1]"), "2001:db8::1");
  assert.equal(normaliseIP("fe80::1%en0"), "fe80::1");
  assert.equal(parseIP("2001:db8:::1"), null);
  assert.equal(parseIP("gggg::1"), null);
});

test("IPv4-mapped v6 collapses to the v4 address it names", () => {
  const p = parseIP("::ffff:8.8.8.8");
  assert.equal(p.version, 4);
  assert.equal(normaliseIP("::ffff:8.8.8.8"), "8.8.8.8");
  // and therefore classifies as the v4 address, not as some v6 special block
  assert.equal(classifyIP("::ffff:192.168.1.5").special, "private (RFC1918)");
});

test("CIDR membership", () => {
  assert.ok(inCidr("160.79.104.5", "160.79.104.0/21"));
  assert.ok(!inCidr("160.79.120.5", "160.79.104.0/21"));
  assert.ok(inCidr("10.1.2.3", "10.0.0.0/8"));
  assert.ok(inCidr("2001:db8::5", "2001:db8::/32"));
  assert.ok(!inCidr("2001:db9::5", "2001:db8::/32"));
  assert.ok(!inCidr("1.2.3.4", "2001:db8::/32"), "family mismatch is false, not a throw");
  assert.ok(inCidr("1.2.3.4", "0.0.0.0/0"));
});

test("special-use classification", () => {
  assert.equal(classifyIP("8.8.8.8").special, null);
  assert.equal(classifyIP("8.8.8.8").routable, true);
  assert.equal(classifyIP("100.72.3.1").special, "CGNAT (RFC6598)");
  assert.equal(classifyIP("169.254.1.1").routable, false);
  assert.equal(classifyIP("203.0.113.1").special, "documentation (TEST-NET-3)");
  assert.equal(classifyIP("fd00::1").special, "unique local (ULA)");
  assert.equal(classifyIP("not-an-ip"), null);
});

test("hostname normalisation accepts what real exports contain", () => {
  assert.equal(normaliseHost("HTTPS://Example.COM/a/b?c=1"), "example.com");
  assert.equal(normaliseHost("example.com."), "example.com");
  assert.equal(normaliseHost("*.example.com"), "example.com");
  assert.equal(normaliseHost("example.com:8443"), "example.com");
  assert.ok(isHostname("a-b.example.co.uk"));
  assert.ok(!isHostname("localhost"), "a single label has no registrable domain");
  assert.ok(!isHostname("8.8.8.8"));
  assert.ok(!isHostname("-bad.example.com"));
});

test("apex extraction covers multi-label suffixes", () => {
  assert.equal(apexOf("a.b.example.co.uk"), "example.co.uk");
  assert.equal(apexOf("www.google.com"), "google.com");
  assert.equal(apexOf("deep.sub.example.com"), "example.com");
  assert.equal(apexOf("myapp.pages.dev"), "myapp.pages.dev", "pages.dev is a suffix, not an apex");
  assert.equal(apexOf("bucket.s3.amazonaws.com"), "bucket.s3.amazonaws.com");
  assert.equal(tldOf("a.example.co.uk"), "uk");
});
