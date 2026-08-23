/**
 * The hosted build, exercised end to end.
 *
 * Vercel's Node runtime hands functions the same (req, res) pair node:http
 * does, so mounting the real handler modules on a local server tests the actual
 * deployed code path — routing, auth, the MCP protocol and the full OAuth
 * dance — without needing a deployment.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";

process.env.MCP_SIGNING_SECRET = "a".repeat(64);
process.env.MCP_PASSWORD = "correct horse battery staple";
process.env.URLSCAN_VERIFY_HOME = `/tmp/urlscan-verify-hosted-test-${process.pid}`;
delete process.env.URLSCAN_API_KEY;

const api = await import("../api/[...slug].mjs");
const mcp = await import("../api/mcp.mjs");
const register = await import("../api/oauth-register.mjs");
const authorize = await import("../api/oauth-authorize.mjs");
const token = await import("../api/oauth-token.mjs");
const wellknownAs = await import("../api/wellknown-as.mjs");
const wellknownPrm = await import("../api/wellknown-prm.mjs");

/** The routing table vercel.json declares, so the test exercises the real map. */
const ROUTES = [
  [/^\/mcp$/, mcp.default],
  [/^\/oauth\/register$/, register.default],
  [/^\/oauth\/authorize$/, authorize.default],
  [/^\/oauth\/token$/, token.default],
  [/^\/\.well-known\/oauth-authorization-server(\/mcp)?$/, wellknownAs.default],
  [/^\/\.well-known\/oauth-protected-resource(\/mcp)?$/, wellknownPrm.default],
  [/^\/api\//, api.default],
];

let server;
let base;

test.before(async () => {
  server = http.createServer(async (req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    const hit = ROUTES.find(([re]) => re.test(path));
    if (!hit) {
      res.statusCode = 404;
      return res.end("not found");
    }
    try {
      await hit[1](req, res);
    } catch (e) {
      if (!res.headersSent) res.statusCode = 500;
      res.end(JSON.stringify({ error: e.message }));
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => server?.close());

const rpc = (body, headers = {}) =>
  fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

// ------------------------------------------------------------- the web API

test("status reports hosted capabilities, not local ones", async () => {
  const s = await (await fetch(`${base}/api/status`)).json();
  assert.equal(s.deployment, "hosted");
  assert.equal(s.canStoreKey, false, "a serverless filesystem cannot hold a key");
  assert.equal(s.canWriteFiles, false);
  assert.equal(s.maxBatch, 25);
});

test("a hosted deployment refuses to store a key and says where it goes", async () => {
  const r = await fetch(`${base}/api/key`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key: "00000000-0000-0000-0000-000000000000" }),
  });
  assert.equal(r.status, 400);
  assert.match((await r.json()).error, /URLSCAN_API_KEY environment variable/);
});

test("analyze returns the extraction the client will feed back", async () => {
  const csv = "question,answers\npaypal.com.secure-login.cfd,203.0.113.9\nprinter.lan,192.168.1.9";
  const d = await (
    await fetch(`${base}/api/analyze`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ csv }),
    })
  ).json();
  assert.equal(d.uniqueHosts, 2);
  assert.equal(d.uniqueIPs, 2);
  assert.equal(d.pairs.length, 2);
  // printer.lan is reserved-internal, so its private answer must not be armed.
  assert.deepEqual(d.answerIPs, ["203.0.113.9"]);
});

test("an oversized batch is refused rather than silently truncated", async () => {
  const hosts = Array.from({ length: 30 }, (_, i) => `h${i}.example.com`);
  const r = await fetch(`${base}/api/verify-batch`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ hosts, offline: true }),
  });
  assert.equal(r.status, 400);
  assert.match((await r.json()).error, /at most 25/);
});

test("a batch verifies offline and finalize assembles a report", async () => {
  const batch = await (
    await fetch(`${base}/api/verify-batch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        hosts: [{ host: "paypal.com.secure-login.cfd", count: 1 }],
        ips: [{ ip: "192.168.1.9", count: 1 }],
        offline: true,
        answerIPs: ["192.168.1.9"],
      }),
    })
  ).json();
  assert.equal(batch.hosts[0].severity, "warning");
  assert.equal(batch.ips[0].severity, "warning", "a public name answered privately is a finding");

  const report = await (
    await fetch(`${base}/api/finalize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hosts: batch.hosts, ips: batch.ips, pairs: [], scope: { rowCount: 1 } }),
    })
  ).json();
  assert.equal(report.summary.hosts.warning, 1);
  assert.equal(report.hosts[0].host, "paypal.com.secure-login.cfd");
});

test("assembly is idempotent — re-finalizing does not double-count", async () => {
  const hosts = [{ host: "bank.example", count: 1 }];
  const b = await (
    await fetch(`${base}/api/verify-batch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hosts, ips: [{ ip: "45.9.148.11", count: 1 }], offline: true }),
    })
  ).json();

  const body = { hosts: b.hosts, ips: b.ips, pairs: [{ host: "bank.example", ip: "45.9.148.11", count: 1 }], scope: {} };
  const once = await (await fetch(`${base}/api/finalize`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
  const twice = await (await fetch(`${base}/api/finalize`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
  // The client re-finalizes after every batch to show partial results, so this
  // runs many times over the same records during one run.
  assert.equal(once.hosts[0].weight, twice.hosts[0].weight);
  assert.equal(once.hosts[0].signals.length, twice.hosts[0].signals.length);
});

test("blocklist export returns file contents instead of writing them", async () => {
  const report = { generatedAt: "2026-01-01T00:00:00Z", hosts: [{ host: "evil.tk", severity: "critical" }], ips: [] };
  const d = await (
    await fetch(`${base}/api/export`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ report, format: "blocklist", setName: "phone_block" }),
    })
  ).json();
  assert.match(d.files["dnsmasq-nftset.conf"], /#fw4#phone_block,/);

  const save = await fetch(`${base}/api/export/save`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ report }),
  });
  assert.equal(save.status, 400, "a hosted deployment must not pretend it wrote to disk");
});

// -------------------------------------------------------------------- MCP

test("ipallow mode rejects anything outside Anthropic's egress range", async () => {
  process.env.AUTH_MODE = "ipallow";
  const r = await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { "x-forwarded-for": "203.0.113.7" });
  assert.equal(r.status, 403);
  assert.match((await r.json()).error_description, /160\.79\.104\.0\/21/);
});

test("ipallow mode admits Anthropic's connector traffic", async () => {
  process.env.AUTH_MODE = "ipallow";
  const r = await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { "x-forwarded-for": "160.79.104.9" });
  assert.equal(r.status, 200);
  const names = (await r.json()).result.tools.map((t) => t.name);
  assert.ok(names.includes("verify_csv"));
  assert.ok(!names.includes("verification_report"), "filesystem-bound tools must not be offered");
});

test("the hosted verify_csv works inline and reports how much is left", async () => {
  process.env.AUTH_MODE = "ipallow";
  const csv = ["domain", "paypal.com.secure-login.cfd", "kjxhqwbrmzptv7.top", "www.google.com", "cdn.jsdelivr.net"].join("\n");
  const call = (args) =>
    rpc({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "verify_csv", arguments: args } }, { "x-forwarded-for": "160.79.104.9" });

  const first = await (await call({ content: csv, offline: true, maxEntries: 2 })).json();
  const a = JSON.parse(first.result.content[0].text);
  assert.equal(a.progress.checked, 2);
  assert.equal(a.progress.remaining, 2);
  assert.equal(a.progress.nextOffset, 2);

  const second = await (await call({ content: csv, offline: true, offset: 2, maxEntries: 25 })).json();
  const b = JSON.parse(second.result.content[0].text);
  assert.equal(b.progress.remaining, 0);
  assert.equal(b.progress.nextOffset, null);
});

test("a tool failure comes back as a readable result, not a protocol error", async () => {
  process.env.AUTH_MODE = "ipallow";
  const r = await (
    await rpc(
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "verify_csv", arguments: { path: "/etc/passwd" } } },
      { "x-forwarded-for": "160.79.104.9" }
    )
  ).json();
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /cannot read local files/);
});

test("GET is refused with a usable explanation", async () => {
  process.env.AUTH_MODE = "ipallow";
  const r = await fetch(`${base}/mcp`, { headers: { "x-forwarded-for": "160.79.104.9" } });
  assert.equal(r.status, 405);
  assert.equal(r.headers.get("allow"), "POST");
});

// ------------------------------------------------------------------ OAuth

test("discovery documents point at the right endpoints", async () => {
  const as = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
  assert.deepEqual(as.code_challenge_methods_supported, ["S256"], "Claude always sends PKCE S256");
  assert.match(as.registration_endpoint, /\/oauth\/register$/);

  const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
  assert.match(prm.resource, /\/mcp$/, "resource must match the URL typed into Claude, path included");
});

test("oauth mode challenges an unauthenticated call per RFC 9728", async () => {
  process.env.AUTH_MODE = "oauth";
  const r = await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(r.status, 401);
  assert.match(r.headers.get("www-authenticate"), /resource_metadata="http.*oauth-protected-resource"/);
  process.env.AUTH_MODE = "ipallow";
});

test("registration refuses redirect URIs that are not Claude's or loopback", async () => {
  const r = await fetch(`${base}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["https://evil.example/steal"] }),
  });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "invalid_redirect_uri");
});

test("the whole authorization code flow works, and PKCE is enforced", async () => {
  process.env.AUTH_MODE = "oauth";
  const redirect_uri = "https://claude.ai/api/mcp/auth_callback";

  // 1. Dynamic client registration
  const reg = await (
    await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: [redirect_uri], client_name: "Claude" }),
    })
  ).json();
  assert.ok(reg.client_id);

  // 2. PKCE pair
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  const q = new URLSearchParams({
    client_id: reg.client_id,
    redirect_uri,
    state: "xyz",
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: "urlscan",
  });

  // 3. The consent screen renders
  const form = await fetch(`${base}/oauth/authorize?${q}`);
  assert.equal(form.status, 200);
  assert.match(await form.text(), /Connector password/);

  // 4. A wrong password does not mint a code
  const bad = await fetch(`${base}/oauth/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...Object.fromEntries(q), password: "wrong" }),
    redirect: "manual",
  });
  assert.equal(bad.status, 401);

  // 5. The right one redirects back with a code
  const good = await fetch(`${base}/oauth/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...Object.fromEntries(q), password: process.env.MCP_PASSWORD }),
    redirect: "manual",
  });
  assert.equal(good.status, 302);
  const back = new URL(good.headers.get("location"));
  assert.equal(back.searchParams.get("state"), "xyz");
  const code = back.searchParams.get("code");
  assert.ok(code);

  // 6. Exchanging with the wrong verifier fails with an RFC 6749 code
  const wrongPkce = await (
    await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri, code_verifier: "not-it" }),
    })
  ).json();
  assert.equal(wrongPkce.error, "invalid_grant");

  // 7. The real verifier yields a token pair
  const tok = await (
    await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri, code_verifier: verifier }),
    })
  ).json();
  assert.equal(tok.token_type, "Bearer");
  assert.ok(tok.access_token && tok.refresh_token);

  // 8. That token opens the MCP endpoint
  const ok = await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { authorization: `Bearer ${tok.access_token}` });
  assert.equal(ok.status, 200);
  assert.ok((await ok.json()).result.tools.length > 0);

  // 9. Refresh rotates, and the replacement works
  const refreshed = await (
    await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tok.refresh_token }),
    })
  ).json();
  assert.ok(refreshed.access_token);
  assert.notEqual(refreshed.refresh_token, tok.refresh_token, "public clients require rotation");

  // 10. A token this server did not sign is refused
  const forged = await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { authorization: "Bearer forged.token" });
  assert.equal(forged.status, 401);

  process.env.AUTH_MODE = "ipallow";
});
