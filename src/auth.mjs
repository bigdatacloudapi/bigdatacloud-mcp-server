/**
 * Auth for the hosted build. Fully stateless — no database, no KV, no addons.
 *
 * Tokens are HMAC-SHA256-signed compact blobs, so a serverless function can mint
 * and verify them with nothing but a shared secret. The OAuth `client_id` and
 * the authorization code are themselves signed blobs carrying their own
 * contents, which is why there is no client table to persist or grow.
 *
 * Two modes, chosen with AUTH_MODE:
 *
 *   "ipallow" (default) — authless MCP restricted to Anthropic's documented
 *     connector egress range. Nothing else on the internet can reach it.
 *     Residual risk: any Claude user who learns your URL arrives from that same
 *     range, so this protects your urlscan quota but is not an identity
 *     boundary. Fine for a personal deployment.
 *
 *   "oauth" — OAuth 2.1 with Dynamic Client Registration and PKCE S256, gated
 *     by a single password you set. Use this if the URL might get out.
 *
 * Claude's connector UI supports OAuth only — there is no field for a bearer
 * token or a custom header, and the MCP auth spec prohibits credentials in the
 * connector URL. Those two modes are the whole available design space.
 */

import crypto from "node:crypto";
import { inCidr } from "./net.mjs";

export const AUTH_MODE = () => process.env.AUTH_MODE || "ipallow";

/** Anthropic's documented outbound range for connector traffic. */
export const ANTHROPIC_EGRESS = "160.79.104.0/21";

const secret = () => {
  const s = process.env.MCP_SIGNING_SECRET;
  if (!s) throw new Error("MCP_SIGNING_SECRET is not set. Generate one with: openssl rand -hex 32");
  return s;
};

const b64u = (b) => Buffer.from(b).toString("base64url");
const unb64u = (s) => Buffer.from(s, "base64url");

export function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const mac = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  return `${body}.${mac}`;
}

export function verify(token, expectedType) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [body, mac] = token.split(".");
  let want;
  try {
    want = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  } catch {
    return null;
  }
  // Constant-time compare; lengths must match first or timingSafeEqual throws.
  if (mac.length !== want.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return null;
  let p;
  try {
    p = JSON.parse(unb64u(body).toString());
  } catch {
    return null;
  }
  if (expectedType && p.t !== expectedType) return null;
  if (p.exp && Date.now() > p.exp) return null;
  return p;
}

/** Constant-time string equality that does not leak length through a throw. */
export function safeEqual(a, b) {
  const x = Buffer.from(String(a ?? ""));
  const y = Buffer.from(String(b ?? ""));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

/** Client IP as seen through the platform proxy. Left-most XFF entry is the origin. */
export function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return req.socket?.remoteAddress || "";
}

export function publicUrl(req) {
  if (process.env.MCP_PUBLIC_URL) return process.env.MCP_PUBLIC_URL.replace(/\/$/, "");
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `https://${host}`;
}

/**
 * Gate a request. Returns null when allowed, or {status, headers, body} to send.
 */
export function guard(req) {
  if (AUTH_MODE() === "oauth") {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token || !verify(token, "access")) {
      // RFC 9728: point the client at the protected-resource metadata so it can
      // discover the authorization server without being told out of band.
      const prm = `${publicUrl(req)}/.well-known/oauth-protected-resource`;
      return {
        status: 401,
        headers: { "WWW-Authenticate": `Bearer resource_metadata="${prm}"` },
        body: { error: "invalid_token", error_description: "Valid bearer token required." },
      };
    }
    return null;
  }

  const ip = clientIp(req);
  const extra = (process.env.EXTRA_ALLOW_CIDRS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const allowed = [ANTHROPIC_EGRESS, ...extra].some((c) => inCidr(ip, c));
  if (!allowed) {
    return {
      status: 403,
      headers: {},
      body: {
        error: "forbidden",
        error_description:
          `Source ${ip || "unknown"} is outside the allowed ranges. This endpoint accepts Anthropic ` +
          `connector traffic (${ANTHROPIC_EGRESS}) only. Set EXTRA_ALLOW_CIDRS to test from your own address, ` +
          `or AUTH_MODE=oauth for per-user consent.`,
      },
    };
  }
  return null;
}
