/**
 * RFC 9728 protected resource metadata.
 *
 * `resource` must exactly match the URL typed into Claude, path included.
 * A mismatch here is the single most common cause of "Couldn't reach the MCP
 * server", because the client rejects the metadata before it ever tries to
 * authenticate.
 */
import { publicUrl } from "../src/auth.mjs";

export default function handler(req, res) {
  const base = publicUrl(req);
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "public, max-age=300");
  res.end(
    JSON.stringify({
      resource: `${base}/mcp`,
      authorization_servers: [base],
      scopes_supported: ["urlscan", "offline_access"],
      bearer_methods_supported: ["header"],
    })
  );
}
