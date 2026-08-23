/**
 * Guards for the two published Claude Artifacts in artifacts/.
 *
 * These are source assertions, not functional tests — the artifacts are
 * single-file HTML that only really runs in a browser, and this package has no
 * dependencies to drive one with. What they protect is the set of faults that
 * actually shipped during development, each of which is silent: the page looks
 * fine, and the failure only appears in a viewer's browser.
 *
 * Full behavioural coverage lives in the browser harness described in
 * docs/artifact-workflow.md and is run with Playwright when the artifacts are
 * edited.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const triage = fs.readFileSync(path.join(ROOT, "artifacts/resolver-triage.html"), "utf8");
const verdict = fs.readFileSync(path.join(ROOT, "artifacts/verdict-board.html"), "utf8");

// --------------------------------------------------------------- both pages

for (const [name, src] of [["resolver-triage", triage], ["verdict-board", verdict]]) {
  test(`${name}: names itself and loads no external resources`, () => {
    assert.match(src, /<title>[^<]+<\/title>/, "the title is the artifact's name in the gallery and the browser tab");

    // The artifact CSP admits Google Fonts and nothing else; any other remote
    // reference fails silently and the page renders in a fallback face.
    const remote = src.match(/(?:src|href)="https?:\/\/[^"]+"/g) || [];
    for (const ref of remote) {
      assert.match(
        ref,
        /fonts\.(googleapis|gstatic)\.com/,
        `${ref} is not a Google Fonts URL, and every other host is blocked by the artifact CSP`
      );
    }
  });

  test(`${name}: theme tokens are defined on bare :root`, () => {
    // A colour whose only definition sits inside a media or [data-theme] block
    // never applies in the default "system" state, which renders one theme's
    // text on the other theme's ground. Check the bare block defines the
    // palette outright.
    const bare = src.match(/(?:^|\n):root\s*\{([\s\S]*?)\n\}/);
    assert.ok(bare, "a bare :root block must define the complete light palette");
    for (const token of ["--ground", "--panel", "--ink", "--muted", "--rule", "--accent"]) {
      assert.ok(bare[1].includes(token), `${token} must be defined on bare :root, not only behind a media query`);
    }
    assert.match(src, /:root:not\(\[data-theme="light"\]\)/, "the dark media query must yield to an explicit light choice");
    assert.match(src, /:root\[data-theme="dark"\]/, "an explicit dark choice must win over a light OS");
    assert.match(src, /body\s*\{[\s\S]*?background:\s*var\(--ground\)/, "a transparent body borrows the host's ground");
  });
}

// ------------------------------------------------------------ triage intake

test("resolver-triage: the file input stays reachable", () => {
  const input = triage.match(/<input type="file"[^>]*>/);
  assert.ok(input, "the file input must exist");

  // An accept filter greys out the file the user actually has — Control D
  // exports XLSX as readily as CSV, and the picker then refuses to select it.
  assert.doesNotMatch(input[0], /accept=/, "an accept filter blocks valid exports; sniff the content instead");

  // display:none makes a programmatic .click() unreliable in a sandboxed
  // frame, which is exactly where this page runs.
  assert.doesNotMatch(triage, /input\[type="file"\]\s*\{\s*display:\s*none/, "use the clip technique, not display:none");
  assert.match(triage, /<label class="btn" for="file">/, "a native label activates the input where a scripted click cannot");
});

test("resolver-triage: pasting is a single action", () => {
  // Where a file picker is blocked outright — an Android web view, for one —
  // pasting is the only route in, so it must not need a second gesture.
  assert.match(triage, /\$\("csv"\)\.addEventListener\("paste"/, "pasting must analyse without a further click");
});

test("resolver-triage: reads XLSX without a library", () => {
  assert.match(triage, /DecompressionStream/, "an .xlsx is a deflate ZIP; the platform can inflate it");
  assert.match(triage, /xl\/sharedStrings\.xml/, "shared strings hold the actual cell text");
  assert.match(triage, /0x50 && u8\[1\] === 0x4b/, "sniff the PK magic rather than trusting the extension");
});

// -------------------------------------------------- triage false positives

test("resolver-triage: a company's own CDN is never impersonation", () => {
  // Without this list googleusercontent.com and apple-cloudkit.com read as
  // brand abuse. A verifier that cries wolf on Google's own CDN stops being
  // read, which is the only real failure mode a tool like this has.
  for (const apex of [
    "googleusercontent.com", "gstatic.com", "apple-cloudkit.com", "cdn-apple.com",
    "akamaiedge.net", "fbcdn.net", "twimg.com", "licdn.com", "cloudfront.net"
  ]) {
    // The list is a space-separated string split across several source lines,
    // so an entry may sit against a quote as readily as a space.
    const bounded = new RegExp(`[\\s"]${apex.replace(/\./g, "\\.")}[\\s"]`);
    assert.match(triage, bounded, `${apex} must be in FIRST_PARTY_APEXES or it will be flagged as impersonation`);
  }
});

test("resolver-triage: identified infrastructure is named, not scored", () => {
  // From the field framework in docs/analysis-framework.md — these were all
  // being re-flagged by shape before they were recognised. Match the readable
  // name each entry carries, not its matching pattern, which is a regex
  // literal and so contains escapes.
  for (const vendor of ["RevenueCat", "Verisoul", "Superwall", "Split.io", "Gist —", "Tencent Cloud EdgeOne"]) {
    assert.ok(triage.includes(vendor), `${vendor} must be recognised and named rather than scored on shape`);
  }
  assert.match(triage, /var allowed = [^;]*!!vendor/, "a recognised vendor must suppress the shape signals");
  assert.match(triage, /add\("known-vendor", 0,/, "identification carries no weight; it replaces a score");
});

test("resolver-triage: the session window bounds itself", () => {
  // Part 3 of the framework: a name means nothing without what surrounded it.
  assert.match(triage, /WINDOW_MS\s*=\s*\d+/, "the co-occurrence window needs a bound");
  assert.match(triage, /WINDOW_ROWS\s*=\s*\d+/, "exports without a clock still need a fallback window");
  assert.match(triage, /coOccurring/, "the window is what distinguishes an app session from an ad waterfall");
});

// -------------------------------------------------- verdict board self-write

test("verdict-board: rebuilds itself with the right closing tags", () => {
  // The bug this guards: <style> was closed with </style>'s script-shaped
  // sibling, which swallowed the whole regenerated document. The page still
  // published fine and only the NEXT load was broken.
  assert.match(verdict, /close\("style"\)/, "the style block must close with </style>");
  assert.match(verdict, /close\("title"\)/, "the title must close with </title>");
  assert.match(verdict, /close\("script"\)/, "script blocks must close with </script>");

  const fn = verdict.slice(verdict.indexOf("function renderPage"));
  const body = fn.slice(0, fn.indexOf("\n}"));
  assert.doesNotMatch(body, /END/, "a single shared closing constant is how the tags got crossed");
});

test("verdict-board: never serialises the live DOM", () => {
  // documentElement.outerHTML carries viewer-session state and the runtime's
  // injected scripts; the replacement must be built from authored parts.
  assert.doesNotMatch(verdict, /documentElement\.outerHTML/, "build the page from its source, not from the live DOM");
  assert.match(verdict, /getElementById\("app-style"\)/, "the stylesheet is read back as authored text");
  assert.match(verdict, /getElementById\("app-script"\)/, "the script reads itself, which avoids a quine");
});

test("verdict-board: escapes state that could close its own block", () => {
  assert.match(verdict, /JSON\.stringify\(next\)\.replace\(\/</,
    "a hostname containing < would otherwise terminate the JSON script block early");
});

test("verdict-board: handles a read-only viewer without lying", () => {
  for (const code of ["conflict", "not_writer", "not_granted", "rate_limited", "too_large"]) {
    assert.ok(verdict.includes(`"${code}"`), `${code} is a documented publish outcome and needs its own branch`);
  }
  assert.match(verdict, /btn\.disabled = true/, "a control must not offer what this view cannot do");
});

test("both artifacts: exports avoid the rejected .conf extension", () => {
  // The downloads allowlist refuses .conf, so router configs go out as .txt
  // and are renamed on the router.
  for (const [name, src] of [["resolver-triage", triage], ["verdict-board", verdict]]) {
    const filenames = src.match(/filename:\s*"[^"]+"/g) || [];
    for (const f of filenames) {
      assert.doesNotMatch(f, /\.conf"/, `${name}: ${f} would be rejected by the save allowlist`);
    }
  }
  assert.match(verdict, /dnsmasq-block\.txt/, "the dnsmasq config ships as .txt");
});
