import test from "node:test";
import assert from "node:assert/strict";
import { extract } from "../src/csv.mjs";
import { parseCSV } from "../src/csv.mjs";
import { renderCSV, renderMarkdown, renderTerminal } from "../src/report.mjs";
import { verifyExtraction } from "../src/verify.mjs";

const build = () =>
  verifyExtraction(
    extract("question,answers\npaypal.com.secure-login.cfd,203.0.113.9\ngraph.facebook.com,157.240.1.1"),
    { client: null }
  );

test("the terminal report never calls an unscanned name clean", async () => {
  const out = renderTerminal(await build(), { colour: false });
  assert.match(out, /No evidence/);
  assert.match(out, /means neither safe nor unsafe/);
  assert.ok(!/\x1b\[/.test(out), "colour:false must emit no escape codes");
});

test("markdown states the verdicts.overall caveat", async () => {
  const md = renderMarkdown(await build());
  assert.match(md, /# urlscan-verify report/);
  assert.match(md, /verdicts\.overall\.malicious/);
  assert.match(md, /\| Verdict \| Hostnames \| Addresses \| Meaning \|/);
});

test("the CSV export is well-formed and round-trips", async () => {
  const csv = renderCSV(await build());
  const rows = parseCSV(csv);
  assert.equal(rows[0][0], "type");
  assert.ok(rows.length > 2);
  // details contain commas and pipes; every row must still have the same width
  const width = rows[0].length;
  for (const r of rows) assert.equal(r.length, width);
  assert.ok(rows.some((r) => r[1] === "paypal.com.secure-login.cfd" && r[2] === "warning"));
});
