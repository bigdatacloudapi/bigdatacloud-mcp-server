/**
 * The web app's API on a hosted deployment.
 *
 * A catch-all so every /api/* route is served by the same shared handler the
 * local server uses. `local: false` is what tells it this deployment reads its
 * key from the environment and has no filesystem to write to.
 */

import { handleApi } from "../src/api.mjs";

export default async function handler(req, res) {
  // The only writable path on a serverless filesystem. The response cache is
  // best-effort here — a warm instance keeps it, a cold one starts empty — but
  // "sometimes free" beats "never".
  if (!process.env.URLSCAN_VERIFY_HOME) process.env.URLSCAN_VERIFY_HOME = "/tmp/urlscan-verify";

  try {
    await handleApi(req, res, { local: false });
  } catch (e) {
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: e.message }));
    } else res.end();
  }
}
