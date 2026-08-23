/**
 * Token endpoint.
 *
 * Three details here are load-bearing and easy to get wrong:
 *
 * - It must accept application/x-www-form-urlencoded (RFC 6749 §4.1.3). Claude
 *   sends both the initial exchange and refreshes that way, and a JSON-only
 *   parser returns 415, which surfaces as intermittent connection failures
 *   rather than as an obvious error.
 * - Refresh tokens rotate. DCR registers Claude as a public client, and the MCP
 *   auth spec requires rotation for those. The replacement is returned in the
 *   same response that invalidates the old one.
 * - Errors must use RFC 6749 codes (`invalid_grant`, never something custom) or
 *   Claude's reactive refresh-on-401 cannot recover and the connector just dies.
 */

import crypto from "node:crypto";
import { sign, verify } from "../src/auth.mjs";

const ACCESS_TTL_MS = 60 * 60 * 1000; // 1h
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30d

export default async function handler(req, res) {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");

  const fail = (code, desc, status = 400) => {
    res.statusCode = status;
    res.end(JSON.stringify({ error: code, error_description: desc }));
  };

  if (req.method !== "POST") return fail("invalid_request", "POST required", 405);

  let body = req.body;
  if (!body || typeof body === "string") {
    let raw = typeof body === "string" ? body : "";
    if (!raw) {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      raw = Buffer.concat(chunks).toString();
    }
    body = Object.fromEntries(new URLSearchParams(raw));
  }

  const issue = (scope) => {
    const access = sign({ t: "access", exp: Date.now() + ACCESS_TTL_MS, scope });
    const refresh = sign({ t: "refresh", exp: Date.now() + REFRESH_TTL_MS, scope, jti: crypto.randomUUID() });
    res.statusCode = 200;
    res.end(
      JSON.stringify({
        access_token: access,
        token_type: "Bearer",
        expires_in: Math.floor(ACCESS_TTL_MS / 1000),
        refresh_token: refresh,
        scope,
      })
    );
  };

  try {
    if (body.grant_type === "authorization_code") {
      const code = verify(body.code, "code");
      if (!code) return fail("invalid_grant", "Authorization code is invalid or expired.");
      if (code.ru !== body.redirect_uri) return fail("invalid_grant", "redirect_uri mismatch.");
      if (!body.code_verifier) return fail("invalid_request", "code_verifier is required.");

      const challenge = crypto.createHash("sha256").update(body.code_verifier).digest("base64url");
      if (challenge !== code.cc) return fail("invalid_grant", "PKCE verification failed.");

      return issue(code.scope || "urlscan");
    }

    if (body.grant_type === "refresh_token") {
      const r = verify(body.refresh_token, "refresh");
      if (!r) return fail("invalid_grant", "Refresh token is invalid or expired.");
      return issue(r.scope || "urlscan");
    }
  } catch (e) {
    return fail("server_error", e.message, 500);
  }

  return fail("unsupported_grant_type", `Unsupported grant_type: ${body.grant_type}`);
}
