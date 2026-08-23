import test from "node:test";
import assert from "node:assert/strict";
import { Cache } from "../src/config.mjs";
import { RateLimitError, UrlscanClient, UrlscanError, esc } from "../src/urlscan.mjs";

const jsonRes = (body, headers = {}, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

test("a missing key fails loudly at construction", () => {
  assert.throws(() => new UrlscanClient({}), /API key/);
});

test("the API-Key header carries the key, and nothing else does", async () => {
  let seen = null;
  const c = new UrlscanClient({
    key: "secret-key",
    pacingMs: 0,
    fetchImpl: async (url, init) => {
      seen = { url, headers: init.headers };
      return jsonRes({ total: 0, results: [] });
    },
  });
  await c.search("page.domain:x");
  assert.equal(seen.headers["API-Key"], "secret-key");
  assert.ok(!seen.url.includes("secret-key"), "the key must never reach a query string");
});

test("a rate limit is retried once, then surfaces with the reset time", async () => {
  let calls = 0;
  const c = new UrlscanClient({
    key: "k",
    pacingMs: 0,
    maxRetries: 1,
    fetchImpl: async () => {
      calls++;
      return jsonRes({}, { "x-rate-limit-action": "search", "x-rate-limit-reset-after": "0", "x-rate-limit-window": "60", "x-rate-limit-limit": "10" }, 429);
    },
  });
  await assert.rejects(() => c.search("q"), (e) => {
    assert.ok(e instanceof RateLimitError);
    assert.match(e.message, /search/);
    assert.equal(e.action, "search");
    return true;
  });
  assert.equal(calls, 2, "one attempt plus one retry");
});

test("a rejected key says what a urlscan key actually looks like", async () => {
  const c = new UrlscanClient({
    key: "k",
    pacingMs: 0,
    fetchImpl: async () => new Response("Invalid API key", { status: 401 }),
  });
  await assert.rejects(() => c.search("q"), (e) => {
    assert.ok(e instanceof UrlscanError);
    assert.match(e.message, /UUID from Settings & API/);
    return true;
  });
});

test("404 on a result reads as pending, not missing", async () => {
  const c = new UrlscanClient({ key: "k", pacingMs: 0, fetchImpl: async () => new Response("", { status: 404 }) });
  await assert.rejects(() => c.result("abc"), /not finished/);
});

test("5xx is retried, then gives up with the status", async () => {
  let n = 0;
  const c = new UrlscanClient({
    key: "k",
    pacingMs: 0,
    maxRetries: 2,
    fetchImpl: async () => {
      n++;
      return n < 3 ? new Response("boom", { status: 503 }) : jsonRes({ total: 1, results: [] });
    },
  });
  const r = await c.search("q");
  assert.equal(r.total, 1);
  assert.equal(n, 3);
});

test("repeated searches are served from cache", async (t) => {
  let calls = 0;
  const dir = `${process.env.TMPDIR || "/tmp"}/urlscan-verify-test-${process.pid}`;
  const cache = new Cache({ dir, ttlHours: 1 });
  t.after(() => cache.clear());

  const c = new UrlscanClient({
    key: "k",
    pacingMs: 0,
    cache,
    fetchImpl: async () => {
      calls++;
      return jsonRes({ total: 7, results: [] });
    },
  });
  await c.search("page.domain:cached.example");
  const second = await c.search("page.domain:cached.example");
  assert.equal(calls, 1, "the second lookup must not spend quota");
  assert.equal(second.total, 7);
  assert.equal(second.cached, true);
  assert.equal(c.cacheHits, 1);
});

test("calls are serialised and paced", async () => {
  const times = [];
  const c = new UrlscanClient({
    key: "k",
    pacingMs: 30,
    fetchImpl: async () => {
      times.push(Date.now());
      return jsonRes({ total: 0, results: [] });
    },
  });
  await Promise.all([c.search("a"), c.search("b"), c.search("c")]);
  assert.equal(times.length, 3);
  assert.ok(times[2] - times[0] >= 55, `three paced calls should span at least two gaps, spanned ${times[2] - times[0]}ms`);
});

test("one failure does not stall the queue behind it", async () => {
  let n = 0;
  const c = new UrlscanClient({
    key: "k",
    pacingMs: 0,
    maxRetries: 0,
    fetchImpl: async () => (++n === 1 ? new Response("nope", { status: 400 }) : jsonRes({ total: 2, results: [] })),
  });
  await assert.rejects(() => c.search("bad"));
  const ok = await c.search("good");
  assert.equal(ok.total, 2);
});

test("query-string escaping covers the ElasticSearch specials", () => {
  assert.equal(esc("a/b:c"), "a\\/b\\:c");
  assert.equal(esc('a"b'), 'a\\"b');
  assert.equal(esc("plain"), "plain");
});
