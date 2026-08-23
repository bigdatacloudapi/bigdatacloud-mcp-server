/**
 * Rendering a verification report for humans and for other tools.
 *
 * The wording here is load-bearing. "Unknown" must never read as "fine", and
 * "clean" must never read as "audited" — the archive can only tell you what
 * somebody has already looked at.
 */

import { toCSV } from "./csv.mjs";
import { SEVERITY_ORDER } from "./verify.mjs";

export const SEVERITY_LABEL = {
  critical: "Flagged",
  warning: "Check this",
  notice: "Worth a look",
  clean: "No signal",
  unknown: "No evidence",
};

export const SEVERITY_BLURB = {
  critical: "urlscan submitters have tagged this as hostile, or the structural signals are overwhelming.",
  warning: "Several signals line up. Confirm this is something you expect before trusting it.",
  notice: "One mild signal. Usually benign, listed so the judgement is yours.",
  clean: "Scanned, and nothing in the archive or the name itself stands out.",
  unknown: "Nobody has submitted this to urlscan. That is normal for first-party telemetry and means neither safe nor unsafe.",
};

const ICON = { critical: "!!", warning: "! ", notice: "· ", clean: "ok", unknown: "? " };

// ---------------------------------------------------------------- terminal

const COLOURS = {
  critical: "\x1b[1;31m",
  warning: "\x1b[33m",
  notice: "\x1b[36m",
  clean: "\x1b[32m",
  unknown: "\x1b[90m",
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
};

export function renderTerminal(report, { colour = true, verbose = false } = {}) {
  const c = (k, s) => (colour ? `${COLOURS[k]}${s}${COLOURS.reset}` : s);
  const out = [];
  const s = report.scope;

  out.push("");
  out.push(c("bold", "urlscan-verify"));
  out.push(
    c("dim", `${s.rowCount.toLocaleString()} rows · ${s.uniqueHosts} unique hostnames · ${s.uniqueIPs} unique addresses`)
  );
  if (s.columns) {
    out.push(c("dim", `columns → hosts: ${s.columns.hosts.join(", ") || "none"} · addresses: ${s.columns.ips.join(", ") || "none"}`));
  }
  out.push(
    c("dim", `${report.api.offline ? "offline (structure only)" : `${report.api.calls} urlscan calls, ${report.api.cacheHits} from cache`}`)
  );
  out.push("");

  const line = (r, name) => {
    const bits = [c(r.severity, ICON[r.severity]), name.padEnd(44).slice(0, 44), c("dim", String(r.count ?? "").padStart(6))];
    return "  " + bits.join(" ");
  };

  const section = (title, rows) => {
    if (!rows.length) return;
    out.push(c("bold", title));
    for (const r of rows) {
      const name = r.host ?? r.ip;
      out.push(line(r, name));
      const show = verbose ? r.signals : r.signals.filter((x) => x.weight > 0 || r.severity === "unknown");
      for (const sig of show) {
        out.push(c("dim", `        ${sig.detail}`));
      }
      if (r.error) out.push(c("warning", `        lookup failed: ${r.error}`));
    }
    out.push("");
  };

  for (const sev of SEVERITY_ORDER) {
    const rows = [...report.hosts, ...report.ips].filter((r) => r.severity === sev);
    if (!rows.length) continue;
    // The quiet buckets are counted, not enumerated, unless asked for.
    if ((sev === "clean" || sev === "unknown") && !verbose) {
      out.push(c(sev, `${SEVERITY_LABEL[sev]}: ${rows.length}`));
      out.push(c("dim", `  ${SEVERITY_BLURB[sev]}`));
      out.push("");
      continue;
    }
    section(`${SEVERITY_LABEL[sev]} — ${SEVERITY_BLURB[sev]}`, rows);
  }

  if (report.stoppedEarly) {
    out.push(c("warning", "Stopped early: urlscan rate limit reached. Re-run to continue — completed lookups are cached."));
    out.push("");
  }
  return out.join("\n");
}

// ---------------------------------------------------------------- markdown

export function renderMarkdown(report) {
  const s = report.scope;
  const L = [];
  L.push("# urlscan-verify report");
  L.push("");
  L.push(`Generated ${report.generatedAt}`);
  L.push("");
  L.push(`- **Rows read:** ${s.rowCount.toLocaleString()}`);
  L.push(`- **Unique hostnames:** ${s.uniqueHosts} (${s.hostsChecked} checked)`);
  L.push(`- **Unique addresses:** ${s.uniqueIPs} (${s.ipsChecked} checked)`);
  if (s.columns) {
    L.push(`- **Columns used:** hostnames from \`${s.columns.hosts.join("`, `") || "—"}\`; addresses from \`${s.columns.ips.join("`, `") || "—"}\``);
  }
  L.push(
    `- **urlscan:** ${report.api.offline ? "not queried (structure-only run)" : `${report.api.calls} calls, ${report.api.cacheHits} served from cache`}`
  );
  L.push("");

  L.push("## Summary");
  L.push("");
  L.push("| Verdict | Hostnames | Addresses | Meaning |");
  L.push("|---|---:|---:|---|");
  for (const sev of SEVERITY_ORDER) {
    L.push(`| ${SEVERITY_LABEL[sev]} | ${report.summary.hosts[sev] ?? 0} | ${report.summary.ips[sev] ?? 0} | ${SEVERITY_BLURB[sev]} |`);
  }
  L.push("");

  const detail = (rows, kind) => {
    const interesting = rows.filter((r) => r.severity === "critical" || r.severity === "warning" || r.severity === "notice");
    if (!interesting.length) {
      L.push(`No ${kind} needed attention.`);
      L.push("");
      return;
    }
    for (const r of interesting) {
      L.push(`### ${r.host ?? r.ip} — ${SEVERITY_LABEL[r.severity]}`);
      L.push("");
      if (r.count) L.push(`Seen on ${r.count} row${r.count > 1 ? "s" : ""}.`);
      if (r.scans) L.push(`${r.scans} urlscan scan${r.scans > 1 ? "s" : ""} on record${r.evidence?.newest?.time ? `, most recent ${r.evidence.newest.time.slice(0, 10)}` : ""}.`);
      L.push("");
      for (const sig of r.signals.filter((x) => x.weight > 0)) L.push(`- ${sig.detail}`);
      if (r.evidence?.newest?.uuid) {
        L.push(`- Newest scan: https://urlscan.io/result/${r.evidence.newest.uuid}/`);
      }
      L.push("");
    }
  };

  L.push("## Hostnames");
  L.push("");
  detail(report.hosts, "hostnames");
  L.push("## Addresses");
  L.push("");
  detail(report.ips, "addresses");

  L.push("## How to read this");
  L.push("");
  L.push(
    "urlscan.io only knows about URLs somebody submitted to it. A hostname with no scans is not " +
      "vouched for — it simply has no public history, which is the normal state for first-party " +
      "telemetry endpoints. Threat verdicts here come from submitter tags, not from " +
      "`verdicts.overall.malicious`: that field is gated below a Pro plan and reads `false` even on " +
      "scans a submitter tagged as phishing, so anything built on it would call everything clean."
  );
  L.push("");
  return L.join("\n");
}

// -------------------------------------------------------------------- csv

export function renderCSV(report) {
  const rows = [
    ["type", "value", "verdict", "score", "occurrences", "urlscan_scans", "threat_tags", "signals", "detail", "last_seen", "asn", "country", "newest_scan"],
  ];
  const push = (type, value, r) => {
    const ev = r.evidence || {};
    rows.push([
      type,
      value,
      r.severity,
      r.weight,
      r.count ?? "",
      r.scans ?? 0,
      (ev.threatTags || []).join(" "),
      r.signals.map((s) => s.id).join(" "),
      r.signals.filter((s) => s.weight > 0).map((s) => s.detail).join(" | "),
      ev.newest?.time ?? "",
      (ev.asns || []).map((a) => a.asn).join(" "),
      (ev.countries || []).join(" "),
      ev.newest?.uuid ? `https://urlscan.io/result/${ev.newest.uuid}/` : "",
    ]);
  };
  for (const h of report.hosts) push("host", h.host, h);
  for (const i of report.ips) push("address", i.ip, i);
  for (const p of report.pairs) {
    rows.push([
      "pair",
      `${p.host} -> ${p.ip}`,
      p.severity,
      p.weight,
      p.count ?? "",
      "",
      "",
      p.signals.map((s) => s.id).join(" "),
      p.signals.map((s) => s.detail).join(" | "),
      "", "", "", "",
    ]);
  }
  return toCSV(rows);
}
