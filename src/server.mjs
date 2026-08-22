/**
 * The local app.
 *
 * Binds to the loopback interface only. The CSV you drop in is parsed in this
 * process and never uploaded anywhere — the only thing that leaves the machine
 * is one urlscan query per unique hostname or address, which is the whole point
 * of the exercise. The API key is read from disk here and never sent to the
 * browser; the page only ever sees a masked form of it.
 *
 * The routes themselves live in api.mjs, shared with the hosted build.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { handleApi, json } from "./api.mjs";
import { resolveKey } from "./config.mjs";

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json",
  ".txt": "text/plain; charset=utf-8",
};

/**
 * A page served from another origin must not be able to drive this server.
 *
 * Loopback services are reachable from any website the user has open — and via
 * DNS rebinding, from a hostname that resolves to 127.0.0.1. Pinning both the
 * Host and the Origin closes both doors, which matters here because this process
 * holds an API key and reads local files.
 *
 * When the server has been deliberately opened to the network (`--host`), the
 * Host pin has to go: we cannot know which name or address the user will reach
 * it by. The Origin check stays, so a hostile page still cannot drive it.
 */
function sameOriginOnly(req, { exposed = false } = {}) {
  const host = String(req.headers.host || "");
  const hostname = host.replace(/:\d+$/, "");
  if (!exposed && !["localhost", "127.0.0.1", "[::1]", "::1"].includes(hostname)) {
    return `Refusing a request for host "${host}". This server answers on localhost only — pass --host to open it to your network.`;
  }
  const origin = req.headers.origin;
  if (origin && origin !== `http://${host}` && origin !== `https://${host}`) {
    return `Refusing a cross-origin request from ${origin}.`;
  }
  return null;
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

/** 0.0.0.0 is not a thing you can type into a browser; suggest something usable. */
const hostLabel = (h) => (h === "0.0.0.0" || h === "::" ? "<this-machine>" : h);

export function createServer({ exposed = false } = {}) {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const bad = sameOriginOnly(req, { exposed });
    if (bad) return json(res, 403, { error: bad });

    if (url.pathname.startsWith("/api/")) {
      try {
        await handleApi(req, res, { local: true });
      } catch (e) {
        if (!res.headersSent) json(res, 500, { error: e.message });
        else res.end();
      }
      return;
    }
    serveStatic(req, res, url);
  });
}

const LOOPBACK = ["127.0.0.1", "localhost", "::1"];

export function serve({ port = 8787, host = "127.0.0.1" } = {}) {
  const exposed = !LOOPBACK.includes(host);
  return new Promise((resolve, reject) => {
    const server = createServer({ exposed });
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
          `  urlscan-verify is running at  http://${exposed ? hostLabel(host) : "localhost"}:${port}`,
          "",
          key ? "  API key: configured" : "  API key: not set — add it on the page, or run `urlscan-verify config --key <uuid>`",
          exposed
            ? `  Listening on ${host} — anyone who can reach this machine on port ${port} can\n  spend your urlscan quota. Only do this on a network you trust, or a tailnet.`
            : "  Bound to loopback only. Your CSV is parsed locally and never uploaded.",
          "",
          "  Ctrl-C to stop.",
          "",
        ].join("\n")
      );
      resolve(server);
    });
  });
}
