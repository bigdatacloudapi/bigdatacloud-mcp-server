/**
 * Where the urlscan API key lives, and the on-disk response cache.
 *
 * The key is stored under the user's home directory with 0600 permissions, not
 * in the repo and not in an env file that a build step might copy. Precedence is
 * explicit argument, then URLSCAN_API_KEY, then the config file — so CI and
 * one-off runs never need to touch stored state.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

export const HOME_DIR =
  process.env.URLSCAN_VERIFY_HOME || path.join(os.homedir(), ".urlscan-verify");
export const CONFIG_PATH = path.join(HOME_DIR, "config.json");
export const CACHE_DIR = path.join(HOME_DIR, "cache");

const DEFAULTS = {
  apiKey: null,
  // urlscan's free tier allows a search every few seconds; 900ms between calls
  // keeps a long run inside the per-minute bucket without stalling it.
  pacingMs: 900,
  cacheTtlHours: 24,
  port: 8787,
};

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

export function readConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, "utf8");
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULTS };
  }
}

export function writeConfig(patch) {
  ensureDir(HOME_DIR);
  const next = { ...readConfig(), ...patch };
  // Write-then-rename so an interrupted write cannot truncate a stored key.
  const tmp = `${CONFIG_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(next, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_PATH);
  fs.chmodSync(CONFIG_PATH, 0o600);
  return next;
}

/**
 * The key to use, or null. `source` tells the UI where it came from so it can
 * say "using URLSCAN_API_KEY from the environment" rather than implying the
 * stored one is in play.
 */
export function resolveKey(explicit) {
  if (explicit) return { key: String(explicit).trim(), source: "argument" };
  if (process.env.URLSCAN_API_KEY) {
    return { key: process.env.URLSCAN_API_KEY.trim(), source: "environment" };
  }
  const c = readConfig();
  if (c.apiKey) return { key: String(c.apiKey).trim(), source: "config file" };
  return { key: null, source: null };
}

/** urlscan keys are UUIDs. Catching a pasted dashboard URL here saves a 401. */
export function looksLikeKey(k) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(k || "").trim());
}

/** Never render a key in full — enough to confirm which one, and no more. */
export function maskKey(k) {
  const s = String(k || "");
  if (s.length < 12) return "••••";
  return `${s.slice(0, 4)}••••${s.slice(-4)}`;
}

// ------------------------------------------------------------------ cache

/**
 * A tiny content-addressed disk cache.
 *
 * Re-running a verification over the same CSV is the normal case — you tweak a
 * threshold, you add a column, you show someone the result. Without a cache
 * every one of those costs a fresh trip through a rate-limited quota, which is
 * the difference between a tool you use and a tool you ration.
 */
export class Cache {
  constructor({ dir = CACHE_DIR, ttlHours = 24, enabled = true } = {}) {
    this.dir = dir;
    this.ttlMs = ttlHours * 3600_000;
    this.enabled = enabled && ttlHours > 0;
    this.hits = 0;
    this.misses = 0;
    if (this.enabled) {
      try {
        ensureDir(this.dir);
      } catch {
        this.enabled = false;
      }
    }
  }

  #file(key) {
    const h = crypto.createHash("sha256").update(key).digest("hex");
    return path.join(this.dir, `${h.slice(0, 2)}`, `${h.slice(2)}.json`);
  }

  get(key) {
    if (!this.enabled) return null;
    try {
      const f = this.#file(key);
      const st = fs.statSync(f);
      if (Date.now() - st.mtimeMs > this.ttlMs) return null;
      const v = JSON.parse(fs.readFileSync(f, "utf8"));
      this.hits++;
      return v;
    } catch {
      this.misses++;
      return null;
    }
  }

  set(key, value) {
    if (!this.enabled) return;
    try {
      const f = this.#file(key);
      ensureDir(path.dirname(f));
      fs.writeFileSync(f, JSON.stringify(value), { mode: 0o600 });
    } catch {
      // A cache that cannot write is a slow cache, not a broken run.
    }
  }

  clear() {
    try {
      fs.rmSync(this.dir, { recursive: true, force: true });
    } catch {
      /* nothing to remove */
    }
  }
}
