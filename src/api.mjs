/**
 * The HTTP API, shared by the local server and the hosted build.
 *
 * Both run on Node-style (req, res), so there is one implementation rather than
 * two that drift. What differs between them is capability, not logic, and that
 * is carried in a single `local` flag: only the local build may store an API key
 * on disk or write export files, because a serverless filesystem is read-only
 * and its key belongs in the platform's environment.
 *
 * ## Why verification is batched
 *
 * A real resolver export holds several hundred unique names, and urlscan's free
 * tier is paced at roughly one lookup per second. That is minutes of work — far
 * longer than a serverless function is allowed to live.
 *
 * So the client drives the loop: it analyses the file once, then asks for small
 * batches until it has them all, and hands the accumulated records back to be
 * assembled into a report. Each request is short, the work survives a function
 * timeout, and a run interrupted by a rate limit resumes from where it stopped
 * instead of starting again. The local server takes the same path — it does not
 * need to, but one code path that is exercised everywhere beats two.
 */

import { extract, detectColumns, parseCSV } from "./csv.mjs";
import { Cache, looksLikeKey, maskKey, readConfig, resolveKey, writeConfig } from "./config.mjs";
import { UrlscanClient, UrlscanError } from "./urlscan.mjs";
import { answerAddresses, assembleReport, verifyBatch } from "./verify.mjs";
import { renderCSV, renderMarkdown } from "./report.mjs";
import { buildExports } from "./blocklist.mjs";

/**
 * Ceiling on one batch.
 *
 * At ~900 ms per lookup, 25 names is a little over 20 seconds — comfortably
 * inside even a Hobby-tier function limit, with room for a retried 429. Asking
 * for more is a client bug, so it is refused rather than silently truncated:
 * a truncated batch would look like a completed one and quietly skip names.
 */
export const MAX_BATCH = 25;
export const MAX_BODY = 64 * 1024 * 1024;

export const json = (res, status, body) => {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
  });
  res.end(payload);
};

export async function readBody(req) {
  if (typeof req.body === "string") return req.body;
  if (req.body && typeof req.body === "object") return JSON.stringify(req.body);
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) throw new Error(`Body larger than ${Math.round(MAX_BODY / 1e6)} MB.`);
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function readJson(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const t = await readBody(req);
  if (!t) return {};
  try {
    return JSON.parse(t);
  } catch {
    throw new Error("Request body was not valid JSON.");
  }
}

function clientFor({ noCache = false } = {}) {
  const { key } = resolveKey();
  if (!key) return null;
  const cfg = readConfig();
  return new UrlscanClient({
    key,
    pacingMs: Number(process.env.URLSCAN_PACING_MS) || cfg.pacingMs,
    cache: new Cache({ ttlHours: noCache ? 0 : cfg.cacheTtlHours, enabled: !noCache }),
  });
}

/**
 * Handle one API request.
 *
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{local?: boolean, pathname?: string}} opts
 */
export async function handleApi(req, res, opts = {}) {
  const local = opts.local !== false;
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const route = opts.pathname || url.pathname;

  // ---------------------------------------------------------------- status
  if (route === "/api/status" && req.method === "GET") {
    const { key, source } = resolveKey();
    const cfg = readConfig();
    return json(res, 200, {
      keyConfigured: Boolean(key),
      keyMasked: key ? maskKey(key) : null,
      keySource: source,
      keyLooksValid: key ? looksLikeKey(key) : null,
      // The page renders different controls depending on these two.
      canStoreKey: local,
      canWriteFiles: local,
      deployment: local ? "local" : "hosted",
      maxBatch: MAX_BATCH,
      pacingMs: Number(process.env.URLSCAN_PACING_MS) || cfg.pacingMs,
      version: "1.1.0",
    });
  }

  // ------------------------------------------------------------------ key
  if (route === "/api/key" && (req.method === "POST" || req.method === "DELETE")) {
    if (!local) {
      return json(res, 400, {
        error:
          "This deployment reads its key from the URLSCAN_API_KEY environment variable and cannot store one. " +
          "Set it in your hosting provider's project settings and redeploy.",
      });
    }
    if (req.method === "DELETE") {
      writeConfig({ apiKey: null });
      return json(res, 200, { ok: true });
    }
    const { key } = await readJson(req);
    const trimmed = String(key || "").trim();
    if (!trimmed) return json(res, 400, { error: "No key supplied." });
    // Verify before storing: a key that does not work is worse than no key,
    // because every later failure gets blamed on the CSV.
    try {
      const probe = new UrlscanClient({ key: trimmed, pacingMs: 0 });
      const quotas = await probe.quotas();
      writeConfig({ apiKey: trimmed });
      return json(res, 200, { ok: true, keyMasked: maskKey(trimmed), quotas });
    } catch (e) {
      const hint =
        e instanceof UrlscanError && (e.status === 401 || e.status === 403)
          ? "urlscan rejected it. The key is the UUID under Settings & API on urlscan.io — not your password and not the account e-mail."
          : e.message;
      return json(res, 400, { error: hint });
    }
  }

  if (route === "/api/quotas" && req.method === "GET") {
    const client = clientFor();
    if (!client) return json(res, 400, { error: "No API key configured." });
    try {
      return json(res, 200, await client.quotas());
    } catch (e) {
      return json(res, 502, { error: e.message });
    }
  }

  // -------------------------------------------------------------- analyze
  // Parse a CSV and report what is in it. No urlscan calls, so this is instant
  // and free — the user confirms the right columns before spending any quota.
  if (route === "/api/analyze" && req.method === "POST") {
    const raw = await readBody(req);
    let text = raw;
    let hostColumns;
    let ipColumns;
    // Accept either a bare CSV body or a JSON envelope with column overrides.
    if (raw.trimStart().startsWith("{")) {
      try {
        const env = JSON.parse(raw);
        if (typeof env.csv === "string") {
          text = env.csv;
          hostColumns = env.hostColumns;
          ipColumns = env.ipColumns;
        }
      } catch {
        /* not an envelope; treat the body as CSV */
      }
    }
    if (!text.trim()) return json(res, 400, { error: "That file was empty." });

    const rows = parseCSV(text);
    const columns = detectColumns(rows);
    const extraction = extract(text, { hostColumns, ipColumns });
    return json(res, 200, {
      rowCount: extraction.rowCount,
      columns: {
        headers: columns.headers,
        hasHeader: columns.hasHeader,
        hostCols: columns.hostCols,
        ipCols: columns.ipCols,
      },
      preview: rows.slice(0, 6),
      uniqueHosts: extraction.hosts.length,
      uniqueIPs: extraction.ips.length,
      // The client holds these and feeds them back a batch at a time.
      hosts: extraction.hosts,
      ips: extraction.ips,
      pairs: extraction.pairs,
      // Which addresses are answers to a *public* name, and so should arm the
      // rebinding check. Computed here because it needs the reserved-TLD table.
      answerIPs: [...answerAddresses(extraction.pairs)],
    });
  }

  // ---------------------------------------------------------- verify-batch
  if (route === "/api/verify-batch" && req.method === "POST") {
    const body = await readJson(req);
    const hosts = Array.isArray(body.hosts) ? body.hosts : [];
    const ips = Array.isArray(body.ips) ? body.ips : [];
    if (hosts.length + ips.length > MAX_BATCH) {
      return json(res, 400, {
        error: `A batch may hold at most ${MAX_BATCH} entries; this one had ${hosts.length + ips.length}.`,
      });
    }

    const offline = Boolean(body.offline);
    const client = offline ? null : clientFor({ noCache: body.noCache });
    if (!offline && !client) {
      return json(res, 400, {
        error: local
          ? "No API key configured. Add one, or run in offline mode."
          : "This deployment has no URLSCAN_API_KEY set. Add it in your hosting provider's project settings and redeploy, or run in offline mode.",
      });
    }

    try {
      const out = await verifyBatch({
        hosts,
        ips,
        client,
        allow: Array.isArray(body.allow) ? body.allow : [],
        deep: Boolean(body.deep),
        answerIPs: new Set(Array.isArray(body.answerIPs) ? body.answerIPs : []),
      });
      return json(res, 200, {
        hosts: out.hosts,
        ips: out.ips,
        rateLimited: out.rateLimited,
        api: client ? { calls: client.calls, cacheHits: client.cacheHits, rate: client.lastRate } : { offline: true },
      });
    } catch (e) {
      return json(res, 502, { error: e.message });
    }
  }

  // -------------------------------------------------------------- finalize
  // Fold the accumulated records into a report: cross-checks, tallies, order.
  if (route === "/api/finalize" && req.method === "POST") {
    const body = await readJson(req);
    const report = assembleReport({
      hosts: body.hosts || [],
      ips: body.ips || [],
      pairs: body.pairs || [],
      scope: body.scope || {},
      api: body.api || null,
      stoppedEarly: Boolean(body.stoppedEarly),
    });
    report.source = body.filename || "uploaded CSV";
    return json(res, 200, report);
  }

  // ---------------------------------------------------------------- export
  if (route === "/api/export" && req.method === "POST") {
    const body = await readJson(req);
    const report = body.report;
    if (!report) return json(res, 400, { error: "No report supplied." });

    const format = String(body.format || "json");
    if (format === "json") return json(res, 200, report);
    if (format === "csv") {
      res.writeHead(200, { "Content-Type": "text/csv; charset=utf-8", "Cache-Control": "no-store" });
      return res.end(renderCSV(report));
    }
    if (format === "markdown") {
      res.writeHead(200, { "Content-Type": "text/markdown; charset=utf-8", "Cache-Control": "no-store" });
      return res.end(renderMarkdown(report));
    }
    if (format === "blocklist") {
      return json(res, 200, {
        files: buildExports(report, {
          severities: body.severities || ["critical"],
          setName: body.setName,
          source: report.source,
          interface: body.interface,
        }),
      });
    }
    return json(res, 400, { error: `Unknown export format "${format}".` });
  }

  // Writing the bundle straight to disk is a local-only convenience; making
  // someone save eight files one at a time through a browser would be silly.
  if (route === "/api/export/save" && req.method === "POST") {
    if (!local) {
      return json(res, 400, { error: "A hosted deployment cannot write to disk. Download the files instead." });
    }
    const fs = await import("node:fs");
    const path = await import("node:path");
    const body = await readJson(req);
    const report = body.report;
    if (!report) return json(res, 400, { error: "No report supplied." });
    const dir = path.resolve(process.cwd(), String(body.dir || "urlscan-verify-export"));
    const files = buildExports(report, {
      severities: body.severities || ["critical"],
      setName: body.setName,
      source: report.source,
      interface: body.interface,
    });
    try {
      fs.mkdirSync(dir, { recursive: true });
      for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
      return json(res, 200, { ok: true, dir, files: Object.keys(files) });
    } catch (e) {
      return json(res, 500, { error: `Could not write to ${dir}: ${e.message}` });
    }
  }

  return json(res, 404, { error: `No route ${req.method} ${route}` });
}

export { answerAddresses };
