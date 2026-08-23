/**
 * Authorization endpoint. Single-user password gate.
 *
 *   GET  -> the consent form
 *   POST -> check MCP_PASSWORD, mint a PKCE-bound authorization code, 302 back
 *
 * The code is a signed blob carrying the code_challenge and redirect_uri, so
 * the token endpoint can verify PKCE with no shared storage between the two
 * functions — which matters because on serverless there is no guarantee they
 * even run on the same instance.
 */

import crypto from "node:crypto";
import { safeEqual, sign, verify } from "../src/auth.mjs";

const CODE_TTL_MS = 60_000;

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function page({ q, error }) {
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Authorize urlscan-verify</title>
<style>
 body{font:16px/1.5 system-ui,-apple-system,sans-serif;background:#0f1115;color:#e6e6e6;display:grid;place-items:center;min-height:100vh;margin:0;padding:1rem}
 form{background:#181b21;padding:2rem;border-radius:12px;max-width:26rem;width:100%;border:1px solid #262b34}
 h1{font-size:1.1rem;margin:0 0 .25rem} p{color:#9aa4b2;font-size:.9rem;margin:.25rem 0 1.25rem}
 code{background:#0f1115;padding:.1rem .3rem;border-radius:4px;font-size:.8rem;word-break:break-all}
 input{width:100%;padding:.75rem;margin:.4rem 0 1.25rem;border-radius:8px;border:1px solid #333a45;background:#0f1115;color:#e6e6e6;box-sizing:border-box;font-size:1rem}
 button{width:100%;padding:.8rem;border:0;border-radius:8px;background:#3b1fd4;color:#fff;font-weight:600;font-size:1rem;cursor:pointer}
 .err{color:#ff8a80;font-size:.9rem;margin-bottom:1rem}
</style>
<form method=post>
 <h1>Authorize urlscan-verify</h1>
 <p>Client: <code>${esc(q.client_name)}</code><br>Redirect: <code>${esc(q.redirect_uri)}</code></p>
 ${error ? `<div class=err>${esc(error)}</div>` : ""}
 <input type=password name=password placeholder="Connector password" autofocus autocomplete=current-password required>
 ${["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope"]
   .map((k) => `<input type=hidden name=${k} value="${esc(q[k])}">`)
   .join("")}
 <button type=submit>Authorize</button>
</form>`;
}

async function formBody(req) {
  let body = req.body;
  if (body && typeof body === "object") return body;
  let raw = typeof body === "string" ? body : "";
  if (!raw) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    raw = Buffer.concat(chunks).toString();
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

export default async function handler(req, res) {
  const url = new URL(req.url, "https://placeholder.invalid");
  const g = (k) => url.searchParams.get(k);

  const fail = (code, desc) => {
    res.statusCode = 400;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ error: code, error_description: desc }));
  };

  if (req.method === "GET") {
    const client = verify(g("client_id"), "client");
    if (!client) return fail("invalid_client", "Unknown or malformed client_id. Re-register via /oauth/register.");
    if (!client.redirect_uris.includes(g("redirect_uri")))
      return fail("invalid_request", "redirect_uri does not match the registered client.");
    if (g("code_challenge_method") !== "S256")
      return fail("invalid_request", "PKCE with code_challenge_method=S256 is required.");
    if (!g("code_challenge")) return fail("invalid_request", "code_challenge is required.");

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    return res.end(
      page({
        q: {
          client_id: g("client_id"),
          client_name: client.name,
          redirect_uri: g("redirect_uri"),
          state: g("state"),
          code_challenge: g("code_challenge"),
          code_challenge_method: g("code_challenge_method"),
          scope: g("scope"),
        },
      })
    );
  }

  if (req.method !== "POST") {
    res.statusCode = 405;
    return res.end();
  }

  const body = await formBody(req);
  const client = verify(body.client_id, "client");
  if (!client) return fail("invalid_client", "Unknown client_id.");
  if (!client.redirect_uris.includes(body.redirect_uri)) return fail("invalid_request", "redirect_uri mismatch.");

  const expected = process.env.MCP_PASSWORD;
  if (!expected) return fail("server_error", "MCP_PASSWORD is not configured on this deployment.");

  if (!safeEqual(body.password, expected)) {
    res.statusCode = 401;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(page({ q: { ...body, client_name: client.name }, error: "Incorrect password." }));
  }

  const code = sign({
    t: "code",
    exp: Date.now() + CODE_TTL_MS,
    cc: body.code_challenge,
    ru: body.redirect_uri,
    scope: body.scope || "urlscan",
  });

  const to = new URL(body.redirect_uri);
  to.searchParams.set("code", code);
  if (body.state) to.searchParams.set("state", body.state);

  res.statusCode = 302;
  res.setHeader("Location", to.toString());
  res.end();
}
