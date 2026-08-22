#!/usr/bin/env node
/**
 * urlscan-verify — command line entry point.
 *
 * Subcommands:
 *   verify <file.csv>   check the domains and addresses in a CSV
 *   serve               run the local web app
 *   mcp                 run the MCP server on stdio (for Claude Code)
 *   config              store or inspect the urlscan API key
 *   quotas              show what is left of your urlscan budget
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import readline from "node:readline";

import { extract } from "../src/csv.mjs";
import { Cache, CACHE_DIR, CONFIG_PATH, looksLikeKey, maskKey, readConfig, resolveKey, writeConfig } from "../src/config.mjs";
import { UrlscanClient } from "../src/urlscan.mjs";
import { verifyExtraction } from "../src/verify.mjs";
import { renderCSV, renderMarkdown, renderTerminal } from "../src/report.mjs";
import { buildExports } from "../src/blocklist.mjs";

const USAGE = `
urlscan-verify — check the domains and IPs in a CSV against urlscan.io

  urlscan-verify verify <file.csv> [options]
  urlscan-verify serve [--port 8787]
  urlscan-verify mcp
  urlscan-verify config [--key <uuid>] [--show] [--clear-cache]
  urlscan-verify quotas

verify options
  --key <uuid>        urlscan API key (else URLSCAN_API_KEY, else stored config)
  --offline           structure checks only; never contacts urlscan
  --limit <n>         only check the n most frequent hostnames (0 = all, default 0)
  --limit-ips <n>     same for addresses (default 0)
  --deep              widen searches to the apex when a name looks interesting
  --allow <a,b,c>     domains you already trust; suppresses brand/lure signals
  --no-cache          ignore the on-disk response cache
  --json <path>       write the full report as JSON
  --csv <path>        write a flat CSV of every verdict
  --md <path>         write a Markdown report
  --blocklist <dir>   write dnsmasq / nftables / OpenWrt pbr exports
  --block-severity    which verdicts to block (default critical)
  --set-name <name>   nftables/ipset set name for the exports
  --pbr-interface     interface for the generated pbr policy (default wan)
  --verbose           list every hostname, including the quiet ones
  --quiet             suppress the terminal report

Exit status is 2 when anything was flagged, 1 on error, 0 otherwise.
`;

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      out._.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    const key = (eq === -1 ? a.slice(2) : a.slice(2, eq)).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    let value = eq === -1 ? null : a.slice(eq + 1);
    if (value === null) {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        value = next;
        i++;
      } else value = true;
    }
    out[key] = value;
  }
  return out;
}

const fail = (msg) => {
  process.stderr.write(`\x1b[31merror:\x1b[0m ${msg}\n`);
  process.exit(1);
};

function makeClient(args, { required = true } = {}) {
  const cfg = readConfig();
  const { key, source } = resolveKey(args.key === true ? null : args.key);
  if (!key) {
    if (!required) return null;
    fail(
      "No urlscan API key.\n" +
        "  Get one free at https://urlscan.io/user/apikey then either:\n" +
        "    urlscan-verify config --key <uuid>\n" +
        "    export URLSCAN_API_KEY=<uuid>\n" +
        "  Or run with --offline for structure checks only."
    );
  }
  if (!looksLikeKey(key)) {
    process.stderr.write(
      `\x1b[33mnote:\x1b[0m the key from the ${source} is not shaped like a urlscan key (a UUID). Continuing anyway.\n`
    );
  }
  return new UrlscanClient({
    key,
    pacingMs: Number(args.pacing) || cfg.pacingMs,
    cache: new Cache({ ttlHours: args.noCache ? 0 : cfg.cacheTtlHours, enabled: !args.noCache }),
  });
}

// ------------------------------------------------------------------ verify

async function cmdVerify(args) {
  const file = args._[0];
  if (!file) fail("Which CSV? usage: urlscan-verify verify <file.csv>");
  if (!fs.existsSync(file)) fail(`No such file: ${file}`);

  const text = fs.readFileSync(file, "utf8");
  const extraction = extract(text, { delimiter: args.delimiter });

  if (!extraction.hosts.length && !extraction.ips.length) {
    fail(
      `Found no hostnames or addresses in ${path.basename(file)}.\n` +
        `  Detected columns: ${extraction.columns.headers?.join(", ") || "none"}\n` +
        "  If the values are in an unusual column, the web app (urlscan-verify serve) lets you pick it."
    );
  }

  const offline = Boolean(args.offline);
  const client = offline ? null : makeClient(args);
  const quiet = Boolean(args.quiet);

  if (!quiet) {
    process.stderr.write(
      `Reading ${path.basename(file)}: ${extraction.rowCount.toLocaleString()} rows, ` +
        `${extraction.hosts.length} hostnames, ${extraction.ips.length} addresses\n`
    );
    if (offline) process.stderr.write("Offline mode — structure checks only, urlscan is not contacted.\n");
  }

  const started = Date.now();
  const report = await verifyExtraction(extraction, {
    client,
    limitHosts: Number(args.limit) || 0,
    limitIPs: Number(args.limitIps) || 0,
    allow: String(args.allow || "").split(",").map((s) => s.trim()).filter(Boolean),
    deep: Boolean(args.deep),
    onProgress: quiet || !process.stderr.isTTY
      ? null
      : ({ done, total, current }) => {
          const pct = total ? Math.round((done / total) * 100) : 0;
          readline.clearLine(process.stderr, 0);
          readline.cursorTo(process.stderr, 0);
          process.stderr.write(`  ${String(pct).padStart(3)}%  ${done}/${total}  ${current.slice(0, 50)}`);
        },
  });
  report.source = path.basename(file);
  report.elapsedMs = Date.now() - started;

  if (process.stderr.isTTY && !quiet) {
    readline.clearLine(process.stderr, 0);
    readline.cursorTo(process.stderr, 0);
  }

  if (!quiet) process.stdout.write(renderTerminal(report, { colour: process.stdout.isTTY, verbose: Boolean(args.verbose) }) + "\n");

  if (args.json) writeOut(args.json, JSON.stringify(report, null, 2));
  if (args.csv) writeOut(args.csv, renderCSV(report));
  if (args.md) writeOut(args.md, renderMarkdown(report));
  if (args.blocklist) {
    const dir = args.blocklist === true ? "blocklist" : args.blocklist;
    const files = buildExports(report, {
      severities: String(args.blockSeverity || "critical").split(",").map((s) => s.trim()).filter(Boolean),
      setName: args.setName === true ? undefined : args.setName,
      source: report.source,
      interface: args.pbrInterface === true ? undefined : args.pbrInterface,
    });
    fs.mkdirSync(dir, { recursive: true });
    for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), body);
    process.stderr.write(`Wrote ${Object.keys(files).length} blocklist files to ${dir}/\n`);
  }

  const flagged = report.summary.hosts.critical + report.summary.ips.critical + report.summary.hosts.warning + report.summary.ips.warning;
  process.exit(flagged > 0 ? 2 : 0);
}

function writeOut(target, body) {
  const p = target === true ? "report" : target;
  fs.mkdirSync(path.dirname(path.resolve(p)), { recursive: true });
  fs.writeFileSync(p, body);
  process.stderr.write(`Wrote ${p}\n`);
}

// ------------------------------------------------------------------ config

async function cmdConfig(args) {
  if (args.clearCache) {
    new Cache().clear();
    process.stdout.write(`Cleared ${CACHE_DIR}\n`);
  }
  if (args.key && args.key !== true) {
    if (!looksLikeKey(args.key)) {
      process.stderr.write("note: that does not look like a urlscan API key (they are UUIDs). Storing it anyway.\n");
    }
    writeConfig({ apiKey: String(args.key).trim() });
    process.stdout.write(`Stored key ${maskKey(args.key)} in ${CONFIG_PATH} (mode 0600)\n`);
    return;
  }
  const { key, source } = resolveKey();
  const cfg = readConfig();
  process.stdout.write(
    [
      `config file   ${CONFIG_PATH}${fs.existsSync(CONFIG_PATH) ? "" : "  (not created yet)"}`,
      `api key       ${key ? `${maskKey(key)}  (from ${source})` : "not set"}`,
      `pacing        ${cfg.pacingMs} ms between urlscan calls`,
      `cache         ${CACHE_DIR}  (${cfg.cacheTtlHours}h TTL)`,
      `port          ${cfg.port}`,
      "",
    ].join("\n")
  );
}

async function cmdQuotas(args) {
  const client = makeClient(args);
  const q = await client.quotas();
  const limits = q?.limits || {};
  const rows = Object.entries(limits).flatMap(([action, windows]) =>
    Object.entries(windows).map(([w, v]) => [action, w, v.used ?? 0, v.limit ?? 0, (v.limit ?? 0) - (v.used ?? 0)])
  );
  if (!rows.length) {
    process.stdout.write(JSON.stringify(q, null, 2) + "\n");
    return;
  }
  process.stdout.write("action        window     used    limit     left\n");
  for (const [a, w, used, limit, left] of rows) {
    process.stdout.write(
      `${a.padEnd(13)} ${w.padEnd(9)} ${String(used).padStart(5)} ${String(limit).padStart(8)} ${String(left).padStart(8)}\n`
    );
  }
}

// -------------------------------------------------------------------- main

const [, , rawCmd, ...rest] = process.argv;
const args = parseArgs(rest);
const cmd = rawCmd || "help";

try {
  switch (cmd) {
    case "verify":
      await cmdVerify(args);
      break;
    case "serve": {
      const { serve } = await import("../src/server.mjs");
      await serve({ port: Number(args.port) || readConfig().port });
      break;
    }
    case "mcp": {
      const { runMcpServer } = await import("../src/mcp.mjs");
      await runMcpServer();
      break;
    }
    case "config":
      await cmdConfig(args);
      break;
    case "quotas":
      await cmdQuotas(args);
      break;
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(USAGE);
      break;
    default:
      process.stderr.write(`Unknown command "${cmd}".\n${USAGE}`);
      process.exit(1);
  }
} catch (e) {
  fail(e.message);
}
