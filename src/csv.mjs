/**
 * CSV in, hostnames and addresses out.
 *
 * The point of this module is that the user should not have to describe their
 * file. Delimiter, quoting style and which columns hold the interesting values
 * are all detected from the data. Header names are a hint; what the cells
 * actually contain is the decider, because plenty of exports label a column
 * `name` or `value` and leave you to work it out.
 */

import { isHostname, isIP, normaliseHost, normaliseIP, apexOf } from "./net.mjs";

// ---------------------------------------------------------------- parsing

/** Strip a UTF-8 BOM, which Excel adds and which otherwise poisons header matching. */
const stripBom = (s) => (s.charCodeAt(0) === 0xfeff ? s.slice(1) : s);

/**
 * Pick a delimiter by consistency, not by frequency. The right delimiter is the
 * one that yields the same field count on most lines; a comma inside prose beats
 * a real tab delimiter on raw count alone.
 */
export function sniffDelimiter(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim()).slice(0, 40);
  if (!lines.length) return ",";
  let best = ",";
  let bestScore = -1;
  for (const d of [",", "\t", ";", "|"]) {
    const counts = lines.map((l) => splitLine(l, d).length);
    const first = counts[0];
    if (first < 2) continue;
    const agree = counts.filter((c) => c === first).length / counts.length;
    const score = agree * 100 + Math.min(first, 40);
    if (score > bestScore) {
      bestScore = score;
      best = d;
    }
  }
  return best;
}

/** Single-line split honouring RFC 4180 quoting. Used only by the sniffer. */
function splitLine(line, delim) {
  const out = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i++;
        } else q = false;
      } else cur += c;
    } else if (c === '"' && cur === "") q = true;
    else if (c === delim) {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  out.push(cur);
  return out;
}

/**
 * Full RFC 4180 parse, including newlines inside quoted fields. Returns an array
 * of string arrays; ragged rows are preserved rather than dropped so a column
 * offset stays visible instead of silently eating data.
 */
export function parseCSV(text, delimiter) {
  const src = stripBom(String(text));
  const delim = delimiter || sniffDelimiter(src);
  const rows = [];
  let row = [];
  let cur = "";
  let q = false;
  let started = false;

  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) {
      if (c === '"') {
        if (src[i + 1] === '"') {
          cur += '"';
          i++;
        } else q = false;
      } else cur += c;
      continue;
    }
    if (c === '"' && !started) {
      q = true;
      started = true;
      continue;
    }
    if (c === delim) {
      row.push(cur);
      cur = "";
      started = false;
      continue;
    }
    if (c === "\r") continue;
    if (c === "\n") {
      row.push(cur);
      rows.push(row);
      row = [];
      cur = "";
      started = false;
      continue;
    }
    cur += c;
    started = true;
  }
  if (cur !== "" || row.length) {
    row.push(cur);
    rows.push(row);
  }
  return rows.filter((r) => r.length > 1 || (r[0] ?? "").trim() !== "");
}

/** Serialise rows back to RFC 4180 CSV. */
export function toCSV(rows) {
  const cell = (v) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return rows.map((r) => r.map(cell).join(",")).join("\n");
}

// -------------------------------------------------------- column detection

/**
 * Header tokens worth trusting, strongest first. Matched against a normalised
 * header (lowercase, punctuation stripped).
 */
const HOST_HEADERS = [
  "question", "queryname", "query", "hostname", "host", "domain", "domainname",
  "fqdn", "apex", "apexdomain", "sni", "servername", "site", "website", "cname",
  "name", "url", "page", "pageurl", "requesturl", "referer", "referrer", "target",
];
const IP_HEADERS = [
  "answers", "answer", "ip", "ipaddress", "ipaddr", "address", "addr",
  "resolvedip", "resolved", "destination", "destinationip", "dest", "dst", "dstip",
  "sourceip", "srcip", "src", "source", "remoteip", "clientip", "serverip",
  "a", "aaaa", "record", "rdata", "value",
];

/**
 * Address columns that describe *who asked*, not *what was answered*. They are
 * still worth verifying — an unexpected egress address is a real finding — but
 * they must not be paired with the row's hostname, because "client 1.2.3.4
 * asked about example.com" is not a claim that example.com resolves to
 * 1.2.3.4, and treating it as one manufactures mismatches on every row.
 */
const SOURCE_IP_HEADERS = ["sourceip", "srcip", "src", "source", "clientip", "remoteip"];

const ipRole = (header) => (SOURCE_IP_HEADERS.includes(normHeader(header)) ? "source" : "answer");

const normHeader = (h) => String(h ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");

/** Split a cell that may pack several values: `a;b`, `a b`, `a, b`, `a|b`. */
export function splitCell(v) {
  return String(v ?? "")
    .split(/[;,|\s]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/**
 * Score every column for how host-like and address-like its cells are, then
 * choose. A column qualifies on content alone; a matching header only breaks
 * ties and rescues sparse columns.
 */
export function detectColumns(rows, { sampleSize = 400 } = {}) {
  if (!rows.length) return { headers: [], hostCols: [], ipCols: [], hasHeader: false };

  const width = Math.max(...rows.map((r) => r.length));
  const first = rows[0];

  // A header row is one where no cell parses as a host or an address and at
  // least one cell matches a known header token.
  const firstLooksLikeData = first.some((c) => isHostname(c) || isIP(c));
  const firstMatchesHeaders = first.some((c) => {
    const n = normHeader(c);
    return HOST_HEADERS.includes(n) || IP_HEADERS.includes(n);
  });
  const hasHeader = !firstLooksLikeData && (firstMatchesHeaders || first.every((c) => /^[a-zA-Z_][\w \-./]*$/.test(String(c).trim())));

  const headers = hasHeader
    ? first.map((h, i) => String(h).trim() || `col${i + 1}`)
    : Array.from({ length: width }, (_, i) => `col${i + 1}`);
  const body = hasHeader ? rows.slice(1) : rows;
  const sample = body.slice(0, sampleSize);

  const stats = headers.map((h, i) => {
    let filled = 0;
    let host = 0;
    let ip = 0;
    for (const r of sample) {
      const raw = r[i];
      if (raw === undefined || String(raw).trim() === "") continue;
      filled++;
      const parts = splitCell(raw);
      // A cell counts once, even when it packs several values.
      if (parts.some((p) => isIP(p))) ip++;
      else if (parts.some((p) => isHostname(p))) host++;
    }
    const n = normHeader(h);
    return {
      index: i,
      header: h,
      filled,
      hostRatio: filled ? host / filled : 0,
      ipRatio: filled ? ip / filled : 0,
      headerHost: HOST_HEADERS.indexOf(n),
      headerIp: IP_HEADERS.indexOf(n),
    };
  });

  const rank = (arr, key, headerKey) =>
    arr
      .filter((s) => s.filled > 0 && (s[key] >= 0.6 || (s[headerKey] !== -1 && s[key] >= 0.15)))
      .sort((a, b) => {
        const ha = a[headerKey] === -1 ? 999 : a[headerKey];
        const hb = b[headerKey] === -1 ? 999 : b[headerKey];
        if (ha !== hb) return ha - hb;
        return b[key] - a[key];
      });

  const ipCols = rank(stats, "ipRatio", "headerIp");
  const ipTaken = new Set(ipCols.map((s) => s.index));
  const hostCols = rank(stats, "hostRatio", "headerHost").filter((s) => !ipTaken.has(s.index));

  return {
    headers,
    hasHeader,
    hostCols: hostCols.map((s) => ({ index: s.index, header: s.header, ratio: s.hostRatio })),
    ipCols: ipCols.map((s) => ({ index: s.index, header: s.header, ratio: s.ipRatio, role: ipRole(s.header) })),
    stats,
  };
}

// ---------------------------------------------------------------- extraction

/**
 * Pull the verifiable material out of a CSV.
 *
 * Returns hosts and addresses with their occurrence counts, plus `pairs`: the
 * host/address combinations that appeared on the same row. Pairs are what make
 * a resolution-mismatch check possible later — a row saying `bank.example`
 * answered `203.0.113.9` is a claim that can be checked, and a bare list of
 * domains is not.
 */
export function extract(text, opts = {}) {
  const rows = parseCSV(text, opts.delimiter);
  if (!rows.length) {
    return { hosts: [], ips: [], pairs: [], rowCount: 0, columns: { headers: [], hostCols: [], ipCols: [] } };
  }

  const columns = opts.columns || detectColumns(rows);
  const body = columns.hasHeader ? rows.slice(1) : rows;

  const hostIdx = (opts.hostColumns ?? columns.hostCols.map((c) => c.index));
  // Explicitly chosen columns still get their role from the header, so picking
  // columns by hand in the UI cannot silently turn a client-address column into
  // an answer column — which would pair every query with the client that made
  // it and report a mismatch on every row.
  const ipCols = opts.ipColumns
    ? opts.ipColumns.map((i) => ({ index: i, role: ipRole(columns.headers?.[i]) }))
    : columns.ipCols;
  const ipIdx = ipCols.map((c) => c.index);
  const answerIdx = new Set(ipCols.filter((c) => c.role !== "source").map((c) => c.index));

  const hosts = new Map();
  const ips = new Map();
  const pairs = new Map();

  for (let r = 0; r < body.length; r++) {
    const row = body[r];
    const rowHosts = new Set();
    const rowIPs = new Set();
    const rowAnswers = new Set();

    for (const i of hostIdx) {
      for (const part of splitCell(row[i])) {
        const h = normaliseHost(part);
        if (h && isHostname(h)) rowHosts.add(h);
      }
    }
    for (const i of ipIdx) {
      for (const part of splitCell(row[i])) {
        if (isIP(part)) {
          const norm = normaliseIP(part);
          rowIPs.add(norm);
          if (answerIdx.has(i)) rowAnswers.add(norm);
        } else {
          // Some exports put a CNAME target in the answer column alongside
          // addresses. Those are hostnames and belong with the hosts.
          const h = normaliseHost(part);
          if (h && isHostname(h)) rowHosts.add(h);
        }
      }
    }

    for (const h of rowHosts) {
      const e = hosts.get(h) || { host: h, apex: apexOf(h), count: 0, firstRow: r + 1 };
      e.count++;
      hosts.set(h, e);
    }
    for (const ip of rowIPs) {
      const e = ips.get(ip) || { ip, count: 0, firstRow: r + 1 };
      e.count++;
      ips.set(ip, e);
    }
    for (const h of rowHosts) {
      for (const ip of rowAnswers) {
        const k = `${h}|${ip}`;
        const e = pairs.get(k) || { host: h, ip, count: 0 };
        e.count++;
        pairs.set(k, e);
      }
    }
  }

  const byCount = (a, b) => b.count - a.count || String(a.host ?? a.ip).localeCompare(String(b.host ?? b.ip));
  return {
    rowCount: body.length,
    columns,
    hosts: [...hosts.values()].sort(byCount),
    ips: [...ips.values()].sort(byCount),
    pairs: [...pairs.values()].sort(byCount),
  };
}
