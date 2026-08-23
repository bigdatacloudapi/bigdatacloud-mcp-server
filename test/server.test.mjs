/**
 * The local server's request guard.
 *
 * This is the part that matters most for a process holding an API key: a
 * loopback service is reachable from any page the user has open, and via DNS
 * rebinding from a hostname that resolves to 127.0.0.1.
 */

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createServer } from "../src/server.mjs";

/**
 * A raw request, because `fetch` refuses to set a Host header — it is a
 * forbidden header name in undici, so a rebinding test written with fetch
 * silently tests nothing at all.
 */
function raw(port, { path = "/api/status", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path, method: "GET", headers, setHost: false }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function withServer(opts, fn) {
  const server = createServer(opts);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    server.close();
  }
}

test("a loopback server refuses a rebound hostname", async () => {
  await withServer({}, async (base) => {
    const port = Number(new URL(base).port);
    const ok = await raw(port, { headers: { Host: `127.0.0.1:${port}` } });
    assert.equal(ok.status, 200);

    // What a DNS-rebinding attack looks like from the server's side: the
    // request arrives on loopback but claims a hostname the attacker controls.
    const rebound = await raw(port, { headers: { Host: "rebind.example.com" } });
    assert.equal(rebound.status, 403);
    assert.match(JSON.parse(rebound.body).error, /localhost only/);
  });
});

test("a cross-origin page cannot drive the server, exposed or not", async () => {
  for (const exposed of [false, true]) {
    await withServer({ exposed }, async (base) => {
      const r = await fetch(`${base}/api/status`, { headers: { Origin: "http://evil.example" } });
      assert.equal(r.status, 403, `exposed=${exposed}`);
      assert.match((await r.json()).error, /cross-origin/);
    });
  }
});

test("exposed mode drops the host pin but keeps everything else", async () => {
  const host = "my-mac.tail1234.ts.net:8787";
  await withServer({ exposed: true }, async (base) => {
    // Reaching it by LAN address or tailnet name has to work, and we cannot
    // know in advance which name that will be.
    const r = await raw(Number(new URL(base).port), { headers: { Host: host } });
    assert.equal(r.status, 200);
  });
  // The same request must still be refused when it was not opened up.
  await withServer({}, async (base) => {
    const r = await raw(Number(new URL(base).port), { headers: { Host: host } });
    assert.equal(r.status, 403, "exposed mode is the only thing that lifts the host pin");
  });
});

test("static files are served and directory traversal is refused", async () => {
  await withServer({}, async (base) => {
    const page = await fetch(`${base}/`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-type"), /text\/html/);
    assert.equal(page.headers.get("x-content-type-options"), "nosniff");

    const manifest = await fetch(`${base}/manifest.webmanifest`);
    assert.equal(manifest.status, 200);
    assert.equal(JSON.parse(await manifest.text()).display, "standalone");

    // fetch normalises ../ out of a path, so ask for it in a form that survives.
    const escaped = await fetch(`${base}/..%2f..%2fetc%2fpasswd`);
    assert.ok(escaped.status === 403 || escaped.status === 404, `got ${escaped.status}`);
  });
});

test("an unknown API route answers with JSON, not an HTML page", async () => {
  await withServer({}, async (base) => {
    const r = await fetch(`${base}/api/nope`);
    assert.equal(r.status, 404);
    assert.match(r.headers.get("content-type"), /application\/json/);
  });
});
