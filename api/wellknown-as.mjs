/**
 * RFC 8414 authorization server metadata.
 *
 * code_challenge_methods_supported: ["S256"] is mandatory — Claude sends PKCE
 * S256 on every authorization request regardless of how the client registered.
 */
import { publicUrl } from "../src/auth.mjs";

export default function handler(req, res) {
  const base = publicUrl(req);
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "public, max-age=300");
  res.end(
    JSON.stringify({
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      scopes_supported: ["urlscan", "offline_access"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    })
  );
}
