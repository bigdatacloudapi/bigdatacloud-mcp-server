import test from "node:test";
import assert from "node:assert/strict";
import { buildExports, selectEntries } from "../src/blocklist.mjs";

const report = {
  generatedAt: "2026-02-01T00:00:00.000Z",
  hosts: [
    { host: "evil.example", severity: "critical" },
    { host: "maybe.example", severity: "warning" },
    { host: "fine.example", severity: "clean" },
    { host: "quiet.example", severity: "unknown" },
  ],
  ips: [
    { ip: "45.9.148.11", severity: "critical", routable: true },
    { ip: "2001:db8::5", severity: "critical", routable: true },
    { ip: "192.168.1.1", severity: "critical", routable: false },
  ],
};

test("only the requested verdicts are included, and never the unknowns", () => {
  const crit = selectEntries(report, { severities: ["critical"] });
  assert.deepEqual(crit.hosts, ["evil.example"]);

  const both = selectEntries(report, { severities: ["critical", "warning"] });
  assert.deepEqual(both.hosts, ["evil.example", "maybe.example"]);
  assert.ok(!both.hosts.includes("quiet.example"), "'no evidence' must never become a block");
});

test("non-routable addresses are never written into a firewall set", () => {
  const { ips } = selectEntries(report, { severities: ["critical"] });
  assert.ok(!ips.includes("192.168.1.1"));
});

test("every documented format is produced", () => {
  const f = buildExports(report);
  assert.deepEqual(Object.keys(f).sort(), [
    "README.txt", "dnsmasq-block.conf", "dnsmasq-ipset.conf", "dnsmasq-nftset.conf",
    "domains.txt", "hosts.txt", "nftables-addresses.nft", "pbr-policy.conf",
  ]);
});

test("the OpenWrt formats are syntactically what the tools expect", () => {
  const f = buildExports(report, { setName: "my set!", interface: "vpn" });
  assert.match(f["dnsmasq-block.conf"], /^address=\/evil\.example\/$/m);
  assert.match(f["hosts.txt"], /^0\.0\.0\.0 evil\.example$/m);
  // fw4 is the nftables table OpenWrt 22.03+ uses; the 4/6 suffixes are the family
  assert.match(f["dnsmasq-nftset.conf"], /^nftset=\/evil\.example\/4#inet#fw4#my_set,\/evil\.example\/6#inet#fw4#my_set6$/m);
  assert.match(f["dnsmasq-ipset.conf"], /^ipset=\/evil\.example\/my_set$/m);
  assert.match(f["pbr-policy.conf"], /option interface 'vpn'/);
});

test("set names are sanitised without leaving separator debris", () => {
  const f = buildExports(report, { setName: "urlscan verify!" });
  assert.match(f["dnsmasq-nftset.conf"], /#fw4#urlscan_verify,/);
  assert.ok(!/urlscan_verify_[,\s]/.test(f["dnsmasq-nftset.conf"]));
});

test("addresses split by family into the right nft sets", () => {
  const f = buildExports(report);
  const nft = f["nftables-addresses.nft"];
  assert.match(nft, /type ipv4_addr[\s\S]*elements = \{ 45\.9\.148\.11 \}/);
  assert.match(nft, /type ipv6_addr[\s\S]*elements = \{ 2001:db8::5 \}/);
});

test("every file carries the review warning", () => {
  const f = buildExports(report);
  for (const [name, body] of Object.entries(f)) {
    assert.match(body, /(Review before deploying|Before you deploy)/, `${name} should warn before use`);
  }
});

test("an empty selection still produces valid files", () => {
  const f = buildExports({ generatedAt: "x", hosts: [], ips: [] });
  assert.match(f["nftables-addresses.nft"], /# no IPv4 entries/);
  assert.ok(f["domains.txt"].length > 0);
});
