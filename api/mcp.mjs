/**
 * MCP over HTTP, for Claude on the web and on a phone.
 *
 * Stateless JSON POST rather than SSE: Claude's connector infrastructure does
 * not use SSE, and a serverless function has no long-lived process to hold a
 * session in anyway. The JSON-RPC handling and the tools themselves come from
 * src/mcp.mjs, so the connector and the local stdio server behave identically —
 * except that the hosted tool set drops the ones needing a filesystem.
 */

import { createTools, handleMessage } from "../src/mcp.mjs";
import { guard } from "../src/auth.mjs";

const TOOLS = createTools({ local: false });
const TOOL_MAP = Object.fromEntries(TOOLS.map((t) => [t.name, t]));

export const config = { maxDuration: 60 };

export default async function handler(req, res) {
  if (!process.env.URLSCAN_VERIFY_HOME) process.env.URLSCAN_VERIFY_HOME = "/tmp/urlscan-verify";
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "GET" || req.method === "DELETE") {
    // No SSE stream, and no session to terminate in stateless mode.
    res.statusCode = 405;
    res.setHeader("Allow", "POST");
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify({ error: "Use POST for stateless JSON MCP." }));
  }
  if (req.method !== "POST") {
    res.statusCode = 405;
    return res.end();
  }

  const denied = guard(req);
  if (denied) {
    res.statusCode = denied.status;
    for (const [k, v] of Object.entries(denied.headers)) res.setHeader(k, v);
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify(denied.body));
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }));
    }
  }
  if (!body) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    try {
      body = JSON.parse(Buffer.concat(chunks).toString() || "null");
    } catch {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }));
    }
  }

  const batch = Array.isArray(body) ? body : [body];
  const out = (await Promise.all(batch.map((m) => handleMessage(m, TOOL_MAP)))).filter(Boolean);

  res.setHeader("Content-Type", "application/json");
  if (!out.length) {
    res.statusCode = 202; // notifications only
    return res.end();
  }
  res.statusCode = 200;
  res.end(JSON.stringify(Array.isArray(body) ? out : out[0]));
}
