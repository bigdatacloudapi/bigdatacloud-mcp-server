import test from "node:test";
import assert from "node:assert/strict";
import { detectColumns, extract, parseCSV, sniffDelimiter, toCSV } from "../src/csv.mjs";

test("RFC 4180 quoting, including newlines inside fields", () => {
  const rows = parseCSV('a,b\n"one, two","line\nbreak"\n"he said ""hi""",x');
  assert.deepEqual(rows[1], ["one, two", "line\nbreak"]);
  assert.deepEqual(rows[2], ['he said "hi"', "x"]);
});

test("a UTF-8 BOM does not poison the header", () => {
  const cols = detectColumns(parseCSV("﻿domain,ip\nexample.com,1.1.1.1"));
  assert.equal(cols.headers[0], "domain");
});

test("delimiter sniffing prefers consistency over raw count", () => {
  assert.equal(sniffDelimiter("a\tb\tc\n1\t2\t3"), "\t");
  assert.equal(sniffDelimiter("a;b\n1;2"), ";");
  assert.equal(sniffDelimiter("a,b\n1,2"), ",");
});

test("columns are found by content when the header says nothing", () => {
  const cols = detectColumns(parseCSV("alpha,beta\nexample.com,1.1.1.1\nfoo.org,8.8.8.8"));
  assert.deepEqual(cols.hostCols.map((c) => c.header), ["alpha"]);
  assert.deepEqual(cols.ipCols.map((c) => c.header), ["beta"]);
});

test("a file with no header row is still read", () => {
  const r = extract("example.com,1.1.1.1\ntest.org,8.8.8.8");
  assert.deepEqual(r.hosts.map((h) => h.host).sort(), ["example.com", "test.org"]);
  assert.equal(r.ips.length, 2);
  assert.equal(r.rowCount, 2, "no header means both rows are data");
});

test("multi-value answer cells split, and CNAME targets land with the hosts", () => {
  const r = extract("question,answers\nx.example.com,1.1.1.1;2.2.2.2\ny.example.com,cdn.example.net");
  assert.equal(r.ips.length, 2);
  assert.ok(r.hosts.some((h) => h.host === "cdn.example.net"));
});

test("source addresses are verified but never paired with the query name", () => {
  const csv =
    "question,sourceIp,answers\n" +
    "a.example.com,203.0.113.9,1.1.1.1\n" +
    "b.example.com,203.0.113.9,2.2.2.2";
  const r = extract(csv);
  assert.ok(r.ips.some((i) => i.ip === "203.0.113.9"), "the client address is still checked");
  assert.deepEqual(
    r.pairs.map((p) => `${p.host}->${p.ip}`).sort(),
    ["a.example.com->1.1.1.1", "b.example.com->2.2.2.2"],
    "pairing the query with the client address would manufacture a mismatch on every row"
  );
});

test("occurrence counts aggregate across rows", () => {
  const r = extract("domain\nx.com\nx.com\ny.com");
  assert.equal(r.hosts.find((h) => h.host === "x.com").count, 2);
  assert.equal(r.hosts[0].host, "x.com", "most frequent first");
});

test("a real Control D export shape parses without configuration", () => {
  const header =
    "timestamp,userId,endpointId,clientId,profileId,question,action,trigger,triggerValue,spoofTarget," +
    "protocol,rrType,statusCode,sourceIp,sourceASN,sourceISP,sourceCity,sourceCountryCode,answers," +
    "answerASN,answerISP,answerCity,answerCountryCode";
  const row =
    "2026-02-01T09:14:02Z,u1,ep,c1,p1,graph.facebook.com,1,default,,,DOH,A,0,203.0.113.10,AS577,Bell," +
    "Calgary,CA,157.240.22.35,AS32934,Facebook,Menlo Park,US";
  const r = extract(`${header}\n${row}`);
  assert.deepEqual(r.hosts.map((h) => h.host), ["graph.facebook.com"]);
  assert.ok(r.ips.some((i) => i.ip === "157.240.22.35"));
  assert.equal(r.pairs.length, 1);
});

test("round-trips through the writer", () => {
  const rows = [["a", "b"], ['x,"y"', "z\nw"]];
  assert.deepEqual(parseCSV(toCSV(rows)), rows);
});

test("an explicitly chosen column keeps its source/answer role", () => {
  const csv =
    "question,sourceIp,answers\n" +
    "a.example.com,203.0.113.9,1.1.1.1\n" +
    "b.example.com,203.0.113.9,2.2.2.2";
  // What the web app sends when the user confirms the detected columns.
  const r = extract(csv, { hostColumns: [0], ipColumns: [2, 1] });
  assert.ok(r.ips.some((i) => i.ip === "203.0.113.9"));
  assert.deepEqual(
    r.pairs.map((p) => `${p.host}->${p.ip}`).sort(),
    ["a.example.com->1.1.1.1", "b.example.com->2.2.2.2"],
    "picking columns by hand must not promote sourceIp to an answer column"
  );
});
