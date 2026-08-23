import test from "node:test";
import assert from "node:assert/strict";
import { extract } from "../src/csv.mjs";
import { UrlscanClient } from "../src/urlscan.mjs";
import { crossCheckPair, verifyExtraction, verifyHost, verifyIP } from "../src/verify.mjs";

/** A client whose search results are scripted, so verdict logic is testable offline. */
function stubClient(byQuery) {
  const hit = (o = {}) => ({
    _id: o.uuid || "11111111-2222-3333-4444-555555555555",
    sort: [1, 2],
    result: "https://urlscan.io/api/v1/result/x/",
    page: {
      domain: o.domain, apexDomain: o.apex, ip: o.ip, asn: o.asn, asnname: o.asnname,
      country: o.country, apexDomainAgeDays: o.apexAge, umbrellaRank: o.rank,
    },
    task: { time: o.time || "2026-02-01T00:00:00.000Z", tags: o.tags || [] },
  });
  return new UrlscanClient({
    key: "00000000-0000-0000-0000-000000000000",
    pacingMs: 0,
    fetchImpl: async (url) => {
      const q = decodeURIComponent(new URL(url).searchParams.get("q") || "");
      const spec = byQuery[q] || { total: 0, hits: [] };
      return new Response(JSON.stringify({ total: spec.total, results: (spec.hits || []).map(hit) }), {
        headers: { "content-type": "application/json" },
      });
    },
  });
}

test("a threat tag in the archive is categorical", async () => {
  const client = stubClient({
    'page.domain:"evil.example"': { total: 3, hits: [{ domain: "evil.example", tags: ["phishing", "paypal"], asn: "AS1", ip: "1.2.3.4" }] },
  });
  const r = await verifyHost("evil.example", { client });
  assert.equal(r.severity, "critical");
  assert.ok(r.signals.some((s) => s.id === "threat-tagged"));
  assert.deepEqual(r.evidence.threatTags, ["phishing"]);
});

test("benign tags do not raise the verdict", async () => {
  const client = stubClient({
    'page.domain:"shop.example"': { total: 2, hits: [{ domain: "shop.example", tags: ["ecommerce"], asn: "AS1", rank: 4000, apexAge: 900 }] },
  });
  const r = await verifyHost("shop.example", { client });
  assert.equal(r.severity, "clean");
});

test("an unscanned host is unknown, never clean", async () => {
  const client = stubClient({});
  const r = await verifyHost("telemetry.internal-vendor.com", { client });
  assert.equal(r.severity, "unknown");
  assert.equal(r.scans, 0);
  assert.ok(r.signals.some((s) => s.id === "never-scanned"));
});

test("a newly registered domain is a finding on its own", async () => {
  const client = stubClient({
    'page.domain:"brandnew.example"': { total: 1, hits: [{ domain: "brandnew.example", apexAge: 4, asn: "AS1" }] },
  });
  const r = await verifyHost("brandnew.example", { client });
  assert.ok(r.signals.some((s) => s.id === "newly-registered"));
  // 4 days old and holding no popularity rank compounds into "check this".
  assert.equal(r.severity, "warning");
});

test("the apex is only searched when there is a reason to widen", async () => {
  let queries = [];
  const client = stubClient({});
  const orig = client.search.bind(client);
  client.search = (q, o) => (queries.push(q), orig(q, o));

  await verifyHost("boring.example.com", { client });
  assert.equal(queries.length, 1, "a quiet name costs exactly one call");

  queries = [];
  await verifyHost("login.paypal-verify.xyz", { client });
  assert.equal(queries.length, 2, "a suspicious subdomain earns the extra apex lookup");
  assert.ok(queries[1].includes("apexDomain"));
});

test("an address hosting flagged content is critical", async () => {
  const client = stubClient({
    'page.ip:"45.9.148.11"': { total: 5, hits: [{ domain: "bad.example", ip: "45.9.148.11", tags: ["malware"], asn: "AS999" }] },
  });
  const r = await verifyIP("45.9.148.11", { client });
  assert.equal(r.severity, "critical");
});

test("a private answer for a public name is rebinding; for an internal name it is not", async () => {
  const asAnswer = await verifyIP("192.168.1.9", { asAnswer: true });
  assert.equal(asAnswer.severity, "warning");
  assert.ok(asAnswer.signals.some((s) => s.id === "private-answer"));

  const csv = "question,answers\nprinter.lan,192.168.1.9";
  const report = await verifyExtraction(extract(csv), { client: null });
  const ip = report.ips.find((i) => i.ip === "192.168.1.9");
  assert.ok(!ip.signals.some((s) => s.id === "private-answer"), "a .lan name answering privately is DNS working");
});

test("0.0.0.0 is a block, not a threat", async () => {
  const r = await verifyIP("0.0.0.0", { asAnswer: true });
  assert.ok(r.signals.some((s) => s.id === "sinkhole-answer"));
  assert.equal(r.weight, 0);
});

test("resolution mismatch needs solid evidence before it fires", () => {
  const host = {
    scans: 9,
    evidence: { scope: "hostname", ips: ["1.1.1.1", "1.0.0.1"], asns: [{ asn: "AS13335" }] },
  };
  const different = crossCheckPair({ host: "x.example", ip: "45.9.148.11", count: 1 }, host, {
    evidence: { asns: [{ asn: "AS999" }] },
  });
  assert.ok(different.signals.some((s) => s.id === "resolution-mismatch"));

  const sameNetwork = crossCheckPair({ host: "x.example", ip: "1.0.0.99", count: 1 }, host, {
    evidence: { asns: [{ asn: "AS13335" }] },
  });
  assert.ok(!sameNetwork.signals.some((s) => s.id === "resolution-mismatch"), "same network is a CDN edge, not a hijack");

  const thin = crossCheckPair({ host: "x.example", ip: "45.9.148.11", count: 1 }, { evidence: { scope: "hostname", ips: ["1.1.1.1"], asns: [] } }, { evidence: { asns: [{ asn: "AS999" }] } });
  assert.ok(!thin.signals.some((s) => s.id === "resolution-mismatch"), "one observation is not a baseline");
});

test("a pair finding is folded back onto the hostname row", async () => {
  const client = stubClient({
    'page.domain:"bank.example"': {
      total: 8,
      hits: [
        { domain: "bank.example", ip: "1.1.1.1", asn: "AS13335", asnname: "Cloudflare" },
        { domain: "bank.example", ip: "1.0.0.1", asn: "AS13335", asnname: "Cloudflare" },
      ],
    },
    'page.ip:"45.9.148.11"': { total: 1, hits: [{ domain: "other.example", ip: "45.9.148.11", asn: "AS999" }] },
  });
  const report = await verifyExtraction(extract("question,answers\nbank.example,45.9.148.11"), { client });
  const host = report.hosts.find((h) => h.host === "bank.example");
  assert.ok(host.signals.some((s) => s.id === "resolution-mismatch"), "the reader should see it on the host row");
});

test("the whole pipeline runs offline and sorts worst-first", async () => {
  const csv = "domain\ngood.example.com\npaypal.com.secure-login.cfd\nkjxhqwbrmzptv7.top";
  const report = await verifyExtraction(extract(csv), { client: null });
  assert.equal(report.api.offline, true);
  assert.equal(report.hosts[0].host, "paypal.com.secure-login.cfd");
  assert.equal(report.scope.uniqueHosts, 3);
});

test("limitHosts caps the work without dropping the count", async () => {
  const csv = "domain\na.example.com\nb.example.com\nc.example.com";
  const report = await verifyExtraction(extract(csv), { client: null, limitHosts: 2 });
  assert.equal(report.scope.uniqueHosts, 3);
  assert.equal(report.scope.hostsChecked, 2);
});
