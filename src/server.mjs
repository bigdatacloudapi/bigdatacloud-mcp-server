/**
 * The local app.
 *
 * Binds to the loopback interface only. The CSV you drop in is parsed in this
 * process and never uploaded anywhere — the only thing that leaves the machine
 * is one urlscan query per unique hostname or address, which is the whole point
 * of the exercise. The API key is read from disk here and never sent to the
 * browser; the page only ever sees a masked form of it.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { extract, detectColumns, parseCSV } from "./csv.mjs";
import { Cache, looksLikeKey, maskKey, readConfig, resolveKey, writeConfig } from "./config.mjs";
import { UrlscanClient, UrlscanError } from "./urlscan.mjs";
import { verifyExtraction } from "./verify.mjs";
import { renderCSV, renderMarkdown } from "./report.mjs";
import { buildExports } from "./blocklist.mjs";

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public");
const MAX_BODY = 64 * 1024 * 1024;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

/** The most recent report, so exports do not have to round-trip through the page. */
let lastReport = null;

const json = (res, status, body) => {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
  });
  res.end(payload);
};

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) throw new Error(`Body larger than ${Math.round(MAX_BODY / 1e6)} MB.`);
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const readJson = async (req) => {
  const t = await readBody(req);
  if (!t) return {};
  try {
    return JSON.parse(t);
  } catch {
    throw new Error("Request body was not valid JSON.");
  }
};

/**
 * A page served from another origin must not be able to drive this server.
 *
 * Loopback services are reachable from any website the user has open — and via
 * DNS rebinding, from a hostname that resolves to 127.0.0.1. Pinning both the
 * Host and the Origin closes both doors, which matters here because this process
 * holds an API key and reads local files.
 */
function sameOriginOnly(req) {
  const host = String(req.headers.host || "");
  const hostname = host.replace(/:\d+$/, "");
  if (!["localhost", "127.0.0.1", "[::1]", "::1"].includes(hostname)) {
    return `Refusing a request for host "${host}". This server answers on localhost only.`;
  }
  const origin = req.headers.origin;
  if (origin && origin !== `http://${host}` && origin !== `https://${host}`) {
    return `Refusing a cross-origin request from ${origin}.`;
  }
  return null;
}

function clientFor({ key, noCache } = {}) {
  const cfg = readConfig();
  const resolved = resolveKey(key);
  if (!resolved.key) return null;
  return new UrlscanClient({
    key: resolved.key,
    pacingMs: cfg.pacingMs,
    cache: new Cache({ ttlHours: noCache ? 0 : cfg.cacheTtlHours, enabled: !noCache }),
  });
}

// ------------------------------------------------------------------ routes

async function handleApi(req, res, url) {
  const route = url.pathname;

  if (route === "/api/status" && req.method === "GET") {
    const { key, source } = resolveKey();
    const cfg = readConfig();
    return json(res, 200, {
      keyConfigured: Boolean(key),
      keyMasked: key ? maskKey(key) : null,
      keySource: source,
      keyLooksValid: key ? looksLikeKey(key) : null,
      pacingMs: cfg.pacingMs,
      cacheTtlHours: cfg.cacheTtlHours,
      version: "1.0.0",
    });
  }

  if (route === "/api/key" && req.method === "POST") {
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

  if (route === "/api/key" && req.method === "DELETE") {
    writeConfig({ apiKey: null });
    return json(res, 200, { ok: true });
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

  // Parse and preview a CSV. No urlscan calls — this is instant feedback so the
  // user can confirm the right columns were picked before spending any quota.
  if (route === "/api/analyze" && req.method === "POST") {
    const text = await readBody(req);
    if (!text.trim()) return json(res, 400, { error: "That file was empty." });
    const rows = parseCSV(text);
    const columns = detectColumns(rows);
    const extraction = extract(text);
    return json(res, 200, {
      rowCount: extraction.rowCount,
      columns: {
        headers: columns.headers,
        hasHeader: columns.hasHeader,
        hostCols: columns.hostCols,
        ipCols: columns.ipCols,
      },
      preview: rows.slice(0, 6),
      hosts: extraction.hosts.slice(0, 20).map((h) => h.host),
      ips: extraction.ips.slice(0, 20).map((i) => i.ip),
      uniqueHosts: extraction.hosts.length,
      uniqueIPs: extraction.ips.length,
      pairs: extraction.pairs.length,
    });
  }

  /**
   * Run a verification, streaming progress as newline-delimited JSON.
   *
   * A 900-name file takes a quarter of an hour at urlscan's pacing. A progress
   * bar is not decoration at that length — without one the only honest UI is a
   * spinner and a promise, and the user cannot tell a slow run from a hung one.
   */
  if (route === "/api/verify" && req.method === "POST") {
    const body = await readJson(req);
    const text = String(body.csv || "");
    if (!text.trim()) return json(res, 400, { error: "No CSV content received." });

    const offline = Boolean(body.offline);
    const client = offline ? null : clientFor({ noCache: body.noCache });
    if (!offline && !client) return json(res, 400, { error: "No API key configured. Add one, or run in offline mode." });

    const extraction = extract(text, {
      hostColumns: body.hostColumns,
      ipColumns: body.ipColumns,
    });

    res.writeHead(200, {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Accel-Buffering": "no",
    });
    const emit = (o) => res.write(JSON.stringify(o) + "\n");

    emit({
      type: "start",
      rowCount: extraction.rowCount,
      hosts: extraction.hosts.length,
      ips: extraction.ips.length,
      offline,
    });

    try {
      const report = await verifyExtraction(extraction, {
        client,
        limitHosts: Number(body.limitHosts) || 0,
        limitIPs: Number(body.limitIPs) || 0,
        allow: Array.isArray(body.allow) ? body.allow : [],
        deep: Boolean(body.deep),
        onProgress: (p) => emit({ type: "progress", ...p }),
      });
      report.source = body.filename || "uploaded CSV";
      lastReport = report;
      emit({ type: "done", report });
    } catch (e) {
      emit({ type: "error", error: e.message });
    }
    return res.end();
  }

  if (route === "/api/export" && req.method === "POST") {
    const body = await readJson(req);
    const report = body.report || lastReport;
    if (!report) return json(res, 400, { error: "No report to export yet." });

    const format = String(body.format || "json");
    if (format === "json") return json(res, 200, report);
    if (format === "csv") {
      res.writeHead(200, { "Content-Type": "text/csv; charset=utf-8" });
      return res.end(renderCSV(report));
    }
    if (format === "markdown") {
      res.writeHead(200, { "Content-Type": "text/markdown; charset=utf-8" });
      return res.end(renderMarkdown(report));
    }
    if (format === "blocklist") {
      const files = buildExports(report, {
        severities: body.severities || ["critical"],
        setName: body.setName,
        source: report.source,
        interface: body.interface,
      });
      return json(res, 200, { files });
    }
    return json(res, 400, { error: `Unknown export format "${format}".` });
  }

  // Write the blocklist bundle straight to disk. This is a local app; making the
  // user save eight files one at a time through the browser would be silly.
  if (route === "/api/export/save" && req.method === "POST") {
    const body = await readJson(req);
    const report = body.report || lastReport;
    if (!report) return json(res, 400, { error: "No report to export yet." });
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

function serveStatic(req, res, url) {
  const rel = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const file = path.join(PUBLIC_DIR, rel);
  // Refuse anything that escapes the public directory.
  if (!file.startsWith(PUBLIC_DIR)) {
    res.writeHead(403).end("forbidden");
    return;
  }
  fs.readFile(file, (err, buf) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" }).end("not found");
      return;
    }
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    });
    res.end(buf);
  });
}

export function createServer() {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const bad = sameOriginOnly(req);
    if (bad) return json(res, 403, { error: bad });

    if (url.pathname.startsWith("/api/")) {
      try {
        await handleApi(req, res, url);
      } catch (e) {
        if (!res.headersSent) json(res, 500, { error: e.message });
        else res.end();
      }
      return;
    }
    serveStatic(req, res, url);
  });
}

export function serve({ port = 8787, host = "127.0.0.1" } = {}) {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", (e) => {
      if (e.code === "EADDRINUSE") {
        reject(new Error(`Port ${port} is already in use. Try: urlscan-verify serve --port ${port + 1}`));
      } else reject(e);
    });
    server.listen(port, host, () => {
      const { key } = resolveKey();
      process.stdout.write(
        [
          "",
          `  urlscan-verify is running at  http://localhost:${port}`,
          "",
          key ? "  API key: configured" : "  API key: not set — add it on the page, or run `urlscan-verify config --key <uuid>`",
          "  Bound to loopback only. Your CSV is parsed locally and never uploaded.",
          "",
          "  Ctrl-C to stop.",
          "",
        ].join("\n")
      );
      resolve(server);
    });
  });
}
