/**
 * RFC 7591 Dynamic Client Registration.
 *
 * Stateless: the client_id is itself a signed blob carrying its own
 * redirect_uris, so nothing needs persisting and there is no client table to
 * grow unbounded.
 *
 * Body is application/json here — the token endpoint uses form-urlencoded.
 * Different parsers, same server; getting that backwards produces intermittent
 * 415s that look like network flakiness.
 */
import { sign } from "../src/auth.mjs";

const ALLOWED_REDIRECTS = [
  /^https:\/\/claude\.ai\/api\/mcp\/auth_callback$/,
  /^https:\/\/[a-z0-9-]+\.claude\.ai\/api\/mcp\/auth_callback$/,
  /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/callback$/,
];

export default async function handler(req, res) {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.statusCode = 405;
    return res.end(JSON.stringify({ error: "invalid_request" }));
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = null;
    }
  }
  if (!body) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    try {
      body = JSON.parse(Buffer.concat(chunks).toString() || "{}");
    } catch {
      body = {};
    }
  }

  const redirect_uris = body.redirect_uris || [];
  if (!redirect_uris.length || !redirect_uris.every((u) => ALLOWED_REDIRECTS.some((re) => re.test(u)))) {
    res.statusCode = 400;
    return res.end(
      JSON.stringify({
        error: "invalid_redirect_uri",
        error_description:
          "redirect_uris must be https://claude.ai/api/mcp/auth_callback or a loopback /callback.",
      })
    );
  }

  try {
    const client_id = sign({
      t: "client",
      redirect_uris,
      name: String(body.client_name || "unknown").slice(0, 120),
      iat: Date.now(),
    });
    res.statusCode = 201;
    res.end(
      JSON.stringify({
        client_id,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      })
    );
  } catch (e) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "server_error", error_description: e.message }));
  }
}
