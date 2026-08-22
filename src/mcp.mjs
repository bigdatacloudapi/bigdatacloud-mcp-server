/**
 * MCP server over stdio.
 *
 * This is the half of the project that lets Claude Code drive the verifier
 * directly: you point Claude at a CSV and ask what looks wrong, and it calls
 * these tools. The reasoning happens in whatever Claude session is already
 * running — your existing subscription — so nothing here needs an Anthropic API
 * key. The only key involved is your urlscan one.
 *
 * The JSON-RPC layer is hand-rolled rather than pulled from the SDK, which keeps
 * the whole project dependency-free: `git clone` and `node` is the entire
 * install. MCP's stdio transport is newline-delimited JSON, so this is a small
 * amount of code to own.
 *
 * Rule for this file: stdout carries protocol messages and nothing else.
 * Anything diagnostic goes to stderr, or it corrupts the stream.
 */

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";

import { extract } from "./csv.mjs";
import { Cache, maskKey, readConfig, resolveKey } from "./config.mjs";
import { UrlscanClient, esc } from "./urlscan.mjs";
import { verifyExtraction } from "./verify.mjs";
import { renderMarkdown } from "./report.mjs";
import { buildExports } from "./blocklist.mjs";

const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
const SERVER_INFO = { name: "urlscan-verify", version: "1.0.0" };

/** The most recent report, so export_blocklist does not need it passed back in. */
let lastReport = null;

const log = (...a) => process.stderr.write(a.join(" ") + "\n");

function client({ noCache = false } = {}) {
  const { key } = resolveKey();
  if (!key) {
    throw new Error(
      "No urlscan API key configured. Run `urlscan-verify config --key <uuid>` or set URLSCAN_API_KEY. Get a free key at https://urlscan.io/user/apikey"
    );
  }
  const cfg = readConfig();
  return new UrlscanClient({
    key,
    pacingMs: cfg.pacingMs,
    cache: new Cache({ ttlHours: noCache ? 0 : cfg.cacheTtlHours, enabled: !noCache }),
  });
}

/**
 * Trim a report to what is worth putting in a model's context.
 *
 * A 900-name run produces a report megabytes wide, almost all of it "no
 * evidence" rows. Sending that whole thing would crowd out the conversation it
 * is supposed to inform, so the quiet verdicts are counted and named, and only
 * the ones carrying signals are described in full.
 */
function compactReport(report, { maxDetailed = 60 } = {}) {
  const interesting = [...report.hosts, ...report.ips].filter(
    (r) => r.severity === "critical" || r.severity === "warning" || r.severity === "notice"
  );
  const quiet = (sev, rows) => rows.filter((r) => r.severity === sev).map((r) => r.host ?? r.ip);

  return {
    scope: report.scope,
    api: report.api,
    summary: report.summary,
    stoppedEarly: report.stoppedEarly,
    findings: interesting.slice(0, maxDetailed).map((r) => ({
      value: r.host ?? r.ip,
      kind: r.host ? "hostname" : "address",
      verdict: r.severity,
      score: r.weight,
      occurrences: r.count,
      urlscanScans: r.scans,
      threatTags: r.evidence?.threatTags ?? [],
      networks: (r.evidence?.asns ?? []).map((a) => `${a.asn}${a.name ? ` ${a.name}` : ""}`),
      countries: r.evidence?.countries ?? [],
      lastScanned: r.evidence?.newest?.time ?? null,
      newestScanURL: r.evidence?.newest?.uuid ? `https://urlscan.io/result/${r.evidence.newest.uuid}/` : null,
      reasons: r.signals.filter((s) => s.weight > 0).map((s) => s.detail),
      notes: r.signals.filter((s) => s.weight === 0).map((s) => s.detail),
      lookupError: r.error ?? undefined,
    })),
    findingsTruncated: Math.max(0, interesting.length - maxDetailed),
    noSignal: quiet("clean", [...report.hosts, ...report.ips]).slice(0, 200),
    noEvidence: quiet("unknown", [...report.hosts, ...report.ips]).slice(0, 200),
    interpretation:
      "'No evidence' means nobody has ever submitted that name to urlscan — normal for first-party " +
      "telemetry, and it means neither safe nor unsafe. 'No signal' means it was scanned and nothing " +
      "stood out. Threat verdicts come from urlscan submitter tags, not verdicts.overall.malicious, " +
      "which is gated below a Pro plan and reads false even on scans tagged as phishing.",
  };
}

const commonVerifyProps = {
  offline: { type: "boolean", default: false, description: "Skip urlscan entirely and run structure checks only. Free and instant." },
  limitHosts: { type: "integer", minimum: 0, default: 0, description: "Only check the N most frequent hostnames. 0 checks all of them." },
  limitIPs: { type: "integer", minimum: 0, default: 0, description: "Same cap for addresses." },
  allow: { type: "array", items: { type: "string" }, description: "Domains the operator already trusts; suppresses brand and lure signals for them." },
  deep: { type: "boolean", default: false, description: "When a name looks interesting but has no scans, widen the search to its apex. Costs an extra call per name." },
};

export const TOOLS = [
  {
    name: "verify_csv",
    description:
      "Verify every domain and IP address in a CSV against urlscan.io plus offline structure checks. " +
      "Detects the relevant columns automatically, so Control D and Pi-hole exports, firewall logs and " +
      "plain domain lists all work without configuration. Returns findings worst-first with the reasons " +
      "for each verdict. This is the main tool — reach for it whenever someone asks whether the names or " +
      "addresses in a file look wrong.",
    annotations: { readOnlyHint: true, openWorldHint: true },
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the CSV file on disk." },
        content: { type: "string", description: "CSV content inline, if there is no file." },
        ...commonVerifyProps,
      },
      required: [],
    },
    async handler(a) {
      let text = a.content;
      let source = "inline CSV";
      if (!text) {
        if (!a.path) throw new Error("Give either `path` or `content`.");
        const file = path.resolve(a.path);
        if (!fs.existsSync(file)) throw new Error(`No such file: ${file}`);
        text = fs.readFileSync(file, "utf8");
        source = path.basename(file);
      }
      const extraction = extract(text);
      if (!extraction.hosts.length && !extraction.ips.length) {
        return {
          error: "No hostnames or addresses found in that file.",
          detectedColumns: extraction.columns.headers,
          hint: "If the values sit in an unusual column, say which one and re-run — or use verify_domains with an explicit list.",
        };
      }
      const report = await verifyExtraction(extraction, {
        client: a.offline ? null : client(),
        limitHosts: a.limitHosts ?? 0,
        limitIPs: a.limitIPs ?? 0,
        allow: a.allow ?? [],
        deep: Boolean(a.deep),
      });
      report.source = source;
      lastReport = report;
      return compactReport(report);
    },
  },
  {
    name: "verify_domains",
    description:
      "Verify an explicit list of hostnames. Same checks as verify_csv without a file — use it when the " +
      "names came from a conversation, a log excerpt, or a previous tool result.",
    annotations: { readOnlyHint: true, openWorldHint: true },
    inputSchema: {
      type: "object",
      properties: {
        domains: { type: "array", items: { type: "string" }, description: "Hostnames or URLs." },
        ...commonVerifyProps,
      },
      required: ["domains"],
    },
    async handler(a) {
      const extraction = {
        rowCount: a.domains.length,
        columns: null,
        hosts: a.domains.map((d) => ({ host: String(d), count: 1 })),
        ips: [],
        pairs: [],
      };
      const report = await verifyExtraction(extraction, {
        client: a.offline ? null : client(),
        allow: a.allow ?? [],
        deep: Boolean(a.deep),
      });
      report.source = "explicit domain list";
      lastReport = report;
      return compactReport(report);
    },
  },
  {
    name: "verify_ips",
    description:
      "Verify an explicit list of IP addresses: special-use classification, what urlscan has seen hosted " +
      "there, the announcing networks, and whether any scan of that address was tagged hostile.",
    annotations: { readOnlyHint: true, openWorldHint: true },
    inputSchema: {
      type: "object",
      properties: {
        ips: { type: "array", items: { type: "string" } },
        asAnswers: {
          type: "boolean",
          default: false,
          description: "True when these came from DNS answers, which makes a non-routable value a finding rather than just a fact.",
        },
        ...commonVerifyProps,
      },
      required: ["ips"],
    },
    async handler(a) {
      const extraction = {
        rowCount: a.ips.length,
        columns: null,
        hosts: [],
        ips: a.ips.map((i) => ({ ip: String(i), count: 1 })),
        // A synthetic pair marks these as answers without inventing a hostname.
        pairs: a.asAnswers ? a.ips.map((i) => ({ host: "supplied.answer", ip: String(i), count: 1 })) : [],
      };
      const report = await verifyExtraction(extraction, {
        client: a.offline ? null : client(),
        limitIPs: a.limitIPs ?? 0,
      });
      report.source = "explicit address list";
      lastReport = report;
      return compactReport(report);
    },
  },
  {
    name: "urlscan_search",
    description:
      "Raw urlscan archive search in ElasticSearch query-string syntax, for pivots the verifier does not " +
      "cover. Field names are case-sensitive. Search hits carry NO verdicts block — fetch urlscan_result " +
      "for that. Always bound time, e.g. `date:>now-30d`. " +
      'Examples: page.domain:"example.com" AND date:>now-7d | page.asn:AS13335 AND task.tags:phishing',
    annotations: { readOnlyHint: true, openWorldHint: true },
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string" },
        size: { type: "integer", minimum: 1, maximum: 100, default: 20 },
        datasource: { type: "string", enum: ["scans", "hostnames", "certificates", "files"], default: "scans" },
      },
      required: ["q"],
    },
    async handler({ q, size = 20, datasource = "scans" }) {
      const r = await client().search(q, { size, datasource });
      return {
        total: r.total,
        returned: r.results.length,
        hasMore: r.hasMore,
        rateLimit: r.rate,
        results: r.results.map((h) => ({
          uuid: h._id,
          time: h.task?.time,
          url: h.page?.url ?? h.task?.url,
          domain: h.page?.domain,
          apexDomain: h.page?.apexDomain,
          ip: h.page?.ip,
          asn: h.page?.asn,
          asnname: h.page?.asnname,
          country: h.page?.country,
          server: h.page?.server,
          tlsIssuer: h.page?.tlsIssuer,
          domainAgeDays: h.page?.domainAgeDays,
          apexDomainAgeDays: h.page?.apexDomainAgeDays,
          umbrellaRank: h.page?.umbrellaRank,
          visibility: h.task?.visibility,
          tags: h.task?.tags ?? [],
          result: h.result,
        })),
      };
    },
  },
  {
    name: "urlscan_result",
    description:
      "Fetch one finished scan by UUID: verdicts, page and TLS identity, contacted domains and addresses, " +
      "redirect chain. HTTP 404 means the scan has not finished yet, not that it is missing. The raw " +
      "document is roughly 5 MB, so this returns a summary unless you ask for the whole thing.",
    annotations: { readOnlyHint: true, openWorldHint: true },
    inputSchema: {
      type: "object",
      properties: {
        uuid: { type: "string" },
        full: { type: "boolean", default: false, description: "Return the raw ~5MB document. Rarely worth it." },
      },
      required: ["uuid"],
    },
    async handler({ uuid, full = false }) {
      const { data } = await client().result(uuid);
      if (full) return data;
      const p = data.page || {};
      const lists = data.lists || {};
      return {
        uuid,
        reportURL: data.task?.reportURL,
        submittedURL: data.task?.url,
        effectiveURL: p.url,
        time: data.task?.time,
        visibility: data.task?.visibility,
        tags: data.task?.tags ?? [],
        page: {
          domain: p.domain, apexDomain: p.apexDomain, ip: p.ip, ptr: p.ptr,
          asn: p.asn, asnname: p.asnname, country: p.country, server: p.server,
          title: p.title, status: p.status, tlsIssuer: p.tlsIssuer,
          tlsValidDays: p.tlsValidDays, tlsAgeDays: p.tlsAgeDays,
          domainAgeDays: p.domainAgeDays, apexDomainAgeDays: p.apexDomainAgeDays,
          umbrellaRank: p.umbrellaRank,
        },
        stats: {
          requests: data.stats?.requests,
          uniqIPs: data.stats?.uniqIPs ?? (lists.ips || []).length,
          uniqCountries: data.stats?.uniqCountries ?? (lists.countries || []).length,
          securePercentage: data.stats?.securePercentage,
        },
        domains: (lists.domains || []).slice(0, 40),
        ips: (lists.ips || []).slice(0, 40),
        countries: lists.countries || [],
        asns: lists.asns || [],
        servers: (lists.servers || []).slice(0, 15),
        certificates: (lists.certificates || []).slice(0, 10),
        note:
          "verdicts.overall.malicious is gated below a Pro plan and reads false even on scans tagged as " +
          "phishing. Read task.tags, not that field.",
      };
    },
  },
  {
    name: "urlscan_scan",
    description:
      "Submit a URL to urlscan for a fresh scan. Defaults to `unlisted`. Never use `public` for anything " +
      "under investigation — public scans and their screenshots are permanently searchable by anyone, " +
      "including the operator of the URL you are looking at. Returns a UUID; results take about 30 seconds.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string" },
        visibility: { type: "string", enum: ["unlisted", "private", "public"], default: "unlisted" },
        tags: { type: "array", items: { type: "string" }, maxItems: 10 },
        wait: { type: "boolean", default: false, description: "Block until the scan finishes (at least 30s) and return the summary." },
      },
      required: ["url"],
    },
    async handler({ url, visibility = "unlisted", tags, wait = false }) {
      const c = client();
      if (!wait) {
        const r = await c.scan(url, { visibility, tags });
        return { uuid: r.uuid, result: r.result, api: r.api, visibility, note: "Poll urlscan_result in about 30 seconds." };
      }
      const data = await c.scanAndWait(url, { visibility, tags, timeoutSeconds: 150 });
      return { uuid: data.task?.uuid, verdictTags: data.task?.tags ?? [], page: data.page ?? {}, reportURL: data.task?.reportURL };
    },
  },
  {
    name: "urlscan_quotas",
    description:
      "How much urlscan budget is left, per action and per minute/hour/day window. Worth checking before " +
      "a large verification run and after any rate-limit error.",
    annotations: { readOnlyHint: true, openWorldHint: true },
    inputSchema: { type: "object", properties: {} },
    async handler() {
      return await client().quotas();
    },
  },
  {
    name: "export_blocklist",
    description:
      "Turn the last verification into router-ready files: a dnsmasq blocking config, a hosts file, an " +
      "OpenWrt dnsmasq→nftables set (and the older ipset form), an nftables address set, and a policy " +
      "stanza for the OpenWrt pbr package. Writes them to a directory and reports what was written.",
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    inputSchema: {
      type: "object",
      properties: {
        dir: { type: "string", default: "urlscan-verify-export", description: "Directory to write into." },
        severities: {
          type: "array",
          items: { type: "string", enum: ["critical", "warning", "notice"] },
          default: ["critical"],
          description: "Which verdicts to include. Blocking on `notice` will break working services.",
        },
        setName: { type: "string", default: "urlscan_verify", description: "nftables/ipset set name." },
        interface: { type: "string", default: "wan", description: "Interface for the generated pbr policy." },
      },
      required: [],
    },
    async handler(a) {
      if (!lastReport) throw new Error("Nothing to export — run verify_csv or verify_domains first.");
      const dir = path.resolve(a.dir || "urlscan-verify-export");
      const files = buildExports(lastReport, {
        severities: a.severities ?? ["critical"],
        setName: a.setName,
        source: lastReport.source,
        interface: a.interface,
      });
      fs.mkdirSync(dir, { recursive: true });
      for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), body);
      const counts = {
        hostnames: (files["domains.txt"].match(/^[^#\n].*$/gm) || []).length,
      };
      return {
        dir,
        files: Object.keys(files),
        included: a.severities ?? ["critical"],
        ...counts,
        warning:
          "Review domains.txt before deploying. These verdicts are urlscan submitter tags plus structural " +
          "analysis, not an audited feed — every false positive is a name the network can no longer reach.",
      };
    },
  },
  {
    name: "verification_report",
    description:
      "The last verification rendered as a Markdown report, ready to save or paste. Run a verify_* tool first.",
    annotations: { readOnlyHint: true },
    inputSchema: {
      type: "object",
      properties: { savePath: { type: "string", description: "Optional path to write it to." } },
      required: [],
    },
    async handler({ savePath }) {
      if (!lastReport) throw new Error("Nothing to report — run verify_csv or verify_domains first.");
      const md = renderMarkdown(lastReport);
      if (savePath) {
        const p = path.resolve(savePath);
        fs.mkdirSync(path.dirname(p), { recursive: true });
        fs.writeFileSync(p, md);
        return { written: p, bytes: md.length };
      }
      return { markdown: md };
    },
  },
];

const TOOL_MAP = Object.fromEntries(TOOLS.map((t) => [t.name, t]));

// ---------------------------------------------------------------- protocol

const ok = (id, result) => ({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });

async function handleMessage(msg) {
  const { id, method, params } = msg || {};

  switch (method) {
    case "initialize": {
      const asked = params?.protocolVersion;
      return ok(id, {
        protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      });
    }
    case "ping":
      return ok(id, {});
    case "tools/list":
      return ok(id, {
        tools: TOOLS.map(({ name, description, inputSchema, annotations }) => ({
          name,
          description,
          inputSchema,
          annotations,
        })),
      });
    case "tools/call": {
      const tool = TOOL_MAP[params?.name];
      if (!tool) return err(id, -32602, `Unknown tool: ${params?.name}`);
      try {
        const out = await tool.handler(params.arguments || {});
        return ok(id, { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] });
      } catch (e) {
        // A tool failure is a result the model can read and act on, not a
        // protocol error it can only give up on.
        return ok(id, { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true });
      }
    }
    default:
      if (id === undefined || id === null) return null; // notification
      return err(id, -32601, `Method not found: ${method}`);
  }
}

/** Run the server until stdin closes. */
export async function runMcpServer({ input = process.stdin, output = process.stdout } = {}) {
  const { key } = resolveKey();
  log(`urlscan-verify MCP server ready. urlscan key: ${key ? maskKey(key) : "NOT CONFIGURED"}`);

  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  // Requests are handled in order, which keeps the shared urlscan pacing queue
  // and the lastReport handoff between verify and export predictable.
  let queue = Promise.resolve();

  rl.on("line", (line) => {
    if (!line.trim()) return;
    queue = queue.then(async () => {
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        output.write(JSON.stringify(err(null, -32700, "Parse error")) + "\n");
        return;
      }
      const batch = Array.isArray(msg) ? msg : [msg];
      const out = (await Promise.all(batch.map(handleMessage))).filter(Boolean);
      if (!out.length) return;
      output.write(JSON.stringify(Array.isArray(msg) ? out : out[0]) + "\n");
    });
  });

  await new Promise((resolve) => rl.on("close", resolve));
  await queue;
}
