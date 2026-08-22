/**
 * urlscan.io client.
 *
 * Serialised on purpose. urlscan enforces fixed-window limits per action with
 * separate minute/hour/day buckets, so firing searches in parallel does not go
 * faster — it just converts throughput into 429s, and a partially rate-limited
 * verification is worse than a slower complete one.
 *
 * Behaviours below were established against the live service and are easy to
 * get wrong from the docs alone:
 *   - quotas live at /user/quotas/, NOT under /api/v1 (that path 403s with a
 *     misleading "not set up for Pro access")
 *   - search hits carry no `verdicts` block; verdicts need a full /result/ fetch
 *   - /result/ returns 404 while a scan is still running — pending, not missing
 *   - verdicts.overall.malicious is gated below Pro and reads false even on
 *     scans a submitter tagged phishing, so nothing here may depend on it
 */

import { Cache } from "./config.mjs";

export const API = "https://urlscan.io/api/v1";
const UA = "urlscan-verify/1.0 (+https://github.com/demonad112/urlscan-verify)";

export class RateLimitError extends Error {
  constructor(message, { action, resetAfter, window } = {}) {
    super(message);
    this.name = "RateLimitError";
    this.action = action;
    this.resetAfter = resetAfter;
    this.window = window;
  }
}

export class UrlscanError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "UrlscanError";
    this.status = status;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class UrlscanClient {
  /**
   * @param {object} o
   * @param {string} o.key      urlscan API key (UUID from Settings & API)
   * @param {number} o.pacingMs minimum gap between requests
   * @param {Cache}  o.cache    optional response cache
   * @param {number} o.maxRetries retries for 429 / transient network failures
   */
  constructor({ key, pacingMs = 900, cache = null, maxRetries = 2, fetchImpl = fetch } = {}) {
    if (!key) throw new UrlscanError("No urlscan API key. Set URLSCAN_API_KEY or run `urlscan-verify config --key <uuid>`.", 0);
    this.key = key;
    this.pacingMs = pacingMs;
    this.cache = cache || new Cache({ enabled: false });
    this.maxRetries = maxRetries;
    this.fetch = fetchImpl;
    this.lastRate = null;
    this.calls = 0;
    this.cacheHits = 0;
    this.#chain = Promise.resolve();
    this.#lastAt = 0;
  }

  #chain;
  #lastAt;

  /** Run `fn` after the pacing gap, with every other queued call. */
  #enqueue(fn) {
    const run = this.#chain.then(async () => {
      const wait = this.pacingMs - (Date.now() - this.#lastAt);
      if (wait > 0) await sleep(wait);
      try {
        return await fn();
      } finally {
        this.#lastAt = Date.now();
      }
    });
    // Keep the chain alive after a rejection, or one failure stalls the queue.
    this.#chain = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  static #rateOf(res) {
    const g = (k) => res.headers.get(k);
    const n = (v) => (v == null || v === "" ? null : Number(v));
    return {
      scope: g("x-rate-limit-scope"),
      action: g("x-rate-limit-action"),
      window: g("x-rate-limit-window"),
      limit: n(g("x-rate-limit-limit")),
      remaining: n(g("x-rate-limit-remaining")),
      reset: g("x-rate-limit-reset"),
      resetAfter: n(g("x-rate-limit-reset-after")),
    };
  }

  async #request(url, { method = "GET", body, raw = false, cacheable = false } = {}) {
    const cacheKey = cacheable ? `${method} ${url}` : null;
    if (cacheKey) {
      const hit = this.cache.get(cacheKey);
      if (hit) {
        this.cacheHits++;
        return { data: hit.data, rate: hit.rate ?? null, cached: true };
      }
    }

    let attempt = 0;
    for (;;) {
      const result = await this.#enqueue(async () => {
        this.calls++;
        const res = await this.fetch(url, {
          method,
          headers: {
            "API-Key": this.key,
            "User-Agent": UA,
            Accept: raw ? "text/html,*/*" : "application/json",
            ...(body ? { "Content-Type": "application/json" } : {}),
          },
          ...(body ? { body: JSON.stringify(body) } : {}),
        });
        const rate = UrlscanClient.#rateOf(res);
        if (rate.limit != null) this.lastRate = rate;
        const text = await res.text();
        return { res, rate, text };
      });

      const { res, rate, text } = result;

      if (res.status === 429) {
        const wait = Math.min((rate.resetAfter ?? 20) * 1000, 65_000);
        if (attempt < this.maxRetries) {
          attempt++;
          await sleep(wait + 250);
          continue;
        }
        throw new RateLimitError(
          `Rate limited on "${rate.action || "request"}" (${rate.window || "?"} window, limit ${rate.limit ?? "?"}). Resets in ${rate.resetAfter ?? "?"}s.`,
          rate
        );
      }

      if (res.status === 401 || res.status === 403) {
        throw new UrlscanError(
          /api key/i.test(text)
            ? `urlscan rejected the API key (HTTP ${res.status}). It must be the UUID from Settings & API on urlscan.io.`
            : `urlscan refused the request (HTTP ${res.status}): ${text.slice(0, 300)}`,
          res.status
        );
      }
      if (res.status === 404) throw new UrlscanError("Not found — or the scan has not finished yet.", 404);
      if (res.status === 410) throw new UrlscanError("That scan result was deleted.", 410);
      if (!res.ok) {
        if (res.status >= 500 && attempt < this.maxRetries) {
          attempt++;
          await sleep(1000 * attempt);
          continue;
        }
        throw new UrlscanError(`urlscan returned HTTP ${res.status}: ${text.slice(0, 300)}`, res.status);
      }

      let data;
      if (raw) data = text;
      else {
        try {
          data = JSON.parse(text);
        } catch {
          throw new UrlscanError(`urlscan returned non-JSON (HTTP ${res.status}): ${text.slice(0, 200)}`, res.status);
        }
      }

      if (cacheKey) this.cache.set(cacheKey, { data, rate });
      return { data, rate, cached: false };
    }
  }

  /**
   * Archive search. `datasource` selects the index — `scans` is the default and
   * the only one that carries page/task metadata.
   */
  async search(q, { size = 100, searchAfter, datasource = "scans", cacheable = true } = {}) {
    const base = datasource === "scans" ? `${API}/search/` : `${API}/${datasource}/search/`;
    const params = new URLSearchParams({ q, size: String(Math.min(Math.max(size, 1), 1000)) });
    if (searchAfter) params.set("search_after", Array.isArray(searchAfter) ? searchAfter.join(",") : String(searchAfter));
    const { data, rate, cached } = await this.#request(`${base}?${params}`, { cacheable });
    const results = data.results || [];
    const last = results[results.length - 1];
    return {
      total: data.total ?? 0,
      hasMore: data.has_more ?? false,
      results,
      searchAfter: last?.sort ?? null,
      rate,
      cached,
    };
  }

  /** Full scan document by UUID. 404 here means "still running". */
  async result(uuid, { cacheable = true } = {}) {
    const { data, rate, cached } = await this.#request(`${API}/result/${encodeURIComponent(uuid)}/`, { cacheable });
    return { data, rate, cached };
  }

  /** Rendered DOM snapshot as text. */
  async dom(uuid) {
    const { data } = await this.#request(`https://urlscan.io/dom/${encodeURIComponent(uuid)}/`, {
      raw: true,
      cacheable: true,
    });
    return data;
  }

  /**
   * Submit a scan. Defaults to `unlisted`: `public` puts the URL and its
   * screenshot in a feed the operators of that URL can watch, which is exactly
   * what you do not want while looking into them.
   */
  async scan(url, { visibility = "unlisted", tags, country, referer, customagent } = {}) {
    const body = { url, visibility };
    if (Array.isArray(tags) && tags.length) body.tags = tags.slice(0, 10);
    if (country) body.country = country;
    if (referer) body.referer = referer;
    if (customagent) body.customagent = customagent;
    const { data, rate } = await this.#request(`${API}/scan/`, { method: "POST", body });
    return { ...data, rate };
  }

  /** Submit, then poll until the result document exists. */
  async scanAndWait(url, { visibility = "unlisted", tags, timeoutSeconds = 120, onProgress } = {}) {
    const sub = await this.scan(url, { visibility, tags });
    const deadline = Date.now() + timeoutSeconds * 1000;
    // urlscan needs ~30s minimum; polling before that only spends quota on 404s.
    await sleep(30_000);
    let lastErr = null;
    while (Date.now() < deadline) {
      try {
        const { data } = await this.result(sub.uuid, { cacheable: false });
        return data;
      } catch (e) {
        lastErr = e;
        if (e.status === 410) throw e;
        onProgress?.({ uuid: sub.uuid, waiting: true });
        await sleep(5000);
      }
    }
    throw new UrlscanError(
      `Scan ${sub.uuid} had not finished after ${timeoutSeconds}s (${lastErr?.message ?? "no result yet"}). Report: ${sub.result}`,
      408
    );
  }

  /** Account quotas. Note the path is outside /api/v1 — see the file header. */
  async quotas() {
    const { data } = await this.#request("https://urlscan.io/user/quotas/", { cacheable: false });
    return data;
  }

  /** Cheapest possible authenticated call, for "is this key good?". */
  async testKey() {
    const q = await this.quotas();
    return { ok: true, quotas: q };
  }
}

/** Escape a value for the ElasticSearch query-string syntax urlscan uses. */
export function esc(value) {
  return String(value).replace(/([+\-=&|><!(){}\[\]^"~*?:\\/])/g, "\\$1");
}
