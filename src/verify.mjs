/**
 * The verification engine.
 *
 * Takes the hostnames, addresses and host/address pairs pulled out of a CSV and
 * decides, for each one, whether there is anything to worry about — combining
 * free offline structure checks with urlscan.io's archive.
 *
 * Two principles run through the whole file:
 *
 * 1. **Absence of evidence is reported as absence of evidence.** urlscan only
 *    knows about URLs somebody submitted. Most first-party telemetry endpoints
 *    have never been scanned, and calling those "clean" would be a lie that
 *    makes the whole report worthless. They come back `unknown`.
 *
 * 2. **`verdicts.overall.malicious` is not used.** That field is gated below
 *    Pro: searching it returns 403, and reading it off a result document returns
 *    false even for scans a submitter tagged `phishing`. A verifier built on it
 *    would pronounce every domain clean. Submitter tags (`task.tags`) are what
 *    the archive actually returns on a normal plan, so tags are the signal.
 */

import { analyseHost, isInternalName } from "./heuristics.mjs";
import { apexOf, classifyIP, isSubdomainOf, normaliseHost } from "./net.mjs";
import { esc, RateLimitError } from "./urlscan.mjs";

/** Substrings that mark a submitter tag as a threat claim. */
export const THREAT_TAGS = [
  "phish", "malware", "malicious", "threat", "scam", "fraud", "c2", "cnc",
  "botnet", "ransom", "stealer", "trojan", "credential", "spam", "abuse",
  "exploit", "skimmer", "magecart", "cobalt", "redline", "agenttesla",
  "formbook", "qakbot", "emotet", "loader", "dropper", "apt", "suspicious",
];

/** Addresses that mean "this name was blocked", not "this name is hostile". */
const SINKHOLE_ANSWERS = new Set(["0.0.0.0", "127.0.0.1", "::", "::1"]);

export const SEVERITY_ORDER = ["critical", "warning", "notice", "clean", "unknown"];

const isThreatTag = (t) => {
  const s = String(t).toLowerCase();
  return THREAT_TAGS.some((k) => s.includes(k));
};

/**
 * Map an accumulated weight, plus the hard facts, onto a severity.
 *
 * A threat tag in the archive is categorical: somebody looked at this and said
 * it was hostile. Nothing else can reach `critical` on weight alone below 60.
 */
function severityFor({ weight, threatTagged, hasEvidence }) {
  if (threatTagged) return "critical";
  if (weight >= 60) return "critical";
  if (weight >= 26) return "warning";
  if (weight >= 10) return "notice";
  return hasEvidence ? "clean" : "unknown";
}

// ------------------------------------------------------------------ hosts

/** Flatten one search response into the facts a verdict needs. */
function digestHostSearch(results) {
  const tags = new Set();
  const ips = new Set();
  const asns = new Map();
  const countries = new Set();
  let newest = null;
  let minApexAge = null;
  let umbrellaRank = null;

  for (const hit of results) {
    const p = hit.page || {};
    const t = hit.task || {};
    for (const tag of t.tags || []) tags.add(String(tag).toLowerCase());
    if (p.ip) ips.add(p.ip);
    if (p.asn) asns.set(p.asn, p.asnname || asns.get(p.asn) || null);
    if (p.country) countries.add(p.country);
    if (!newest || (t.time && t.time > newest.time)) {
      newest = { time: t.time, uuid: hit._id, url: p.url || t.url, result: hit.result };
    }
    if (typeof p.apexDomainAgeDays === "number") {
      minApexAge = minApexAge === null ? p.apexDomainAgeDays : Math.min(minApexAge, p.apexDomainAgeDays);
    }
    if (typeof p.umbrellaRank === "number") {
      umbrellaRank = umbrellaRank === null ? p.umbrellaRank : Math.min(umbrellaRank, p.umbrellaRank);
    }
  }

  return {
    tags: [...tags],
    threatTags: [...tags].filter(isThreatTag),
    ips: [...ips],
    asns: [...asns].map(([asn, name]) => ({ asn, name })),
    countries: [...countries],
    newest,
    apexAgeDays: minApexAge,
    umbrellaRank,
  };
}

/**
 * Verify one hostname.
 *
 * @param {string} host
 * @param {object} ctx  { client, allowApexes, deep }
 */
export async function verifyHost(host, ctx = {}) {
  const { client, allowApexes, deep = false } = ctx;
  const h = normaliseHost(host) || host;
  const apex = apexOf(h);

  const structural = analyseHost(h, { allowApexes });
  const signals = [...structural.signals];
  const add = (id, weight, detail) => signals.push({ id, weight, detail });

  const record = {
    host: h,
    apex,
    signals,
    evidence: null,
    scans: 0,
    error: null,
  };

  if (allowApexes?.has(apex)) {
    record.allowlisted = true;
  }

  if (client) {
    try {
      const direct = await client.search(`page.domain:"${esc(h)}"`, { size: 20 });
      let digest = digestHostSearch(direct.results);
      let scans = direct.total;
      let scope = "hostname";

      // Nothing on the exact name? The apex still carries useful context — a
      // sibling subdomain tagged phishing is worth knowing about. Only worth a
      // second call when there is already a reason to look, or in deep mode.
      const worthWideningSearch = deep || structural.weight >= 10;
      if (scans === 0 && apex && apex !== h && worthWideningSearch) {
        const wide = await client.search(`page.apexDomain:"${esc(apex)}"`, { size: 20 });
        if (wide.total > 0) {
          digest = digestHostSearch(wide.results);
          scans = wide.total;
          scope = "apex";
        }
      }

      record.evidence = { ...digest, scope };
      record.scans = scans;

      if (digest.threatTags.length) {
        add(
          "threat-tagged",
          70,
          `urlscan submitters tagged ${scope === "apex" ? `${apex} (a sibling of this name)` : "this host"} as: ${digest.threatTags.join(", ")}`
        );
      } else if (digest.tags.length) {
        add("tagged-benign", 0, `Tagged in the archive, none of them threat tags: ${digest.tags.slice(0, 6).join(", ")}`);
      }

      if (typeof digest.apexAgeDays === "number") {
        if (digest.apexAgeDays < 30) {
          add("newly-registered", 24, `The registrable domain is about ${digest.apexAgeDays} days old — newly registered domains are disproportionately hostile`);
        } else if (digest.apexAgeDays < 120) {
          add("young-domain", 10, `The registrable domain is about ${digest.apexAgeDays} days old`);
        }
      }

      if (scans === 0) {
        add("never-scanned", 0, "Nobody has ever submitted this host to urlscan. That is normal for first-party telemetry and carries no safety meaning either way");
      } else if (digest.umbrellaRank === null && typeof digest.apexAgeDays === "number" && digest.apexAgeDays < 365) {
        add("no-popularity-rank", 8, "Scanned, but the domain holds no Cisco Umbrella popularity rank — combined with its age, no established traffic history");
      }
    } catch (e) {
      record.error = e.message;
      if (e instanceof RateLimitError) record.rateLimited = true;
    }
  }

  const weight = signals.reduce((a, s) => a + s.weight, 0);
  const threatTagged = signals.some((s) => s.id === "threat-tagged");
  record.weight = weight;
  record.severity = record.allowlisted && !threatTagged
    ? "clean"
    : severityFor({ weight, threatTagged, hasEvidence: record.scans > 0 });
  return record;
}

// -------------------------------------------------------------- addresses

/** Flatten a `page.ip:` search into hosting facts. */
function digestIPSearch(results) {
  const tags = new Set();
  const domains = new Set();
  const apexes = new Set();
  const asns = new Map();
  const countries = new Set();
  let newest = null;

  for (const hit of results) {
    const p = hit.page || {};
    const t = hit.task || {};
    for (const tag of t.tags || []) tags.add(String(tag).toLowerCase());
    if (p.domain) {
      domains.add(p.domain);
      const a = apexOf(p.domain);
      if (a) apexes.add(a);
    }
    if (p.asn) asns.set(p.asn, p.asnname || asns.get(p.asn) || null);
    if (p.country) countries.add(p.country);
    if (!newest || (t.time && t.time > newest.time)) newest = { time: t.time, uuid: hit._id };
  }

  return {
    tags: [...tags],
    threatTags: [...tags].filter(isThreatTag),
    domains: [...domains],
    apexes: [...apexes],
    asns: [...asns].map(([asn, name]) => ({ asn, name })),
    countries: [...countries],
    newest,
  };
}

/**
 * Verify one address.
 *
 * @param {string} ip
 * @param {object} ctx { client, asAnswer }  `asAnswer` marks addresses that the
 *   CSV presents as DNS answers, where a non-routable value is a finding rather
 *   than just a fact about a client.
 */
export async function verifyIP(ip, ctx = {}) {
  const { client, asAnswer = false } = ctx;
  const cls = classifyIP(ip);
  const signals = [];
  const add = (id, weight, detail) => signals.push({ id, weight, detail });

  const record = { ip: cls?.ip ?? String(ip), signals, evidence: null, scans: 0, error: null };
  if (!cls) {
    record.signals.push({ id: "unparseable", weight: 30, detail: "Not a valid IPv4 or IPv6 address" });
    record.weight = 30;
    record.severity = "warning";
    return record;
  }

  record.version = cls.version;
  record.special = cls.special;
  record.routable = cls.routable;

  if (cls.special) {
    if (SINKHOLE_ANSWERS.has(cls.ip)) {
      add("sinkhole-answer", 0, `${cls.ip} is the standard "blocked" answer — a filter returned it instead of a real address. Informational, not a threat`);
    } else if (!cls.routable && asAnswer) {
      add(
        "private-answer",
        30,
        `A public name was answered with ${cls.ip} (${cls.special}). That is DNS rebinding, a split-horizon override, or a misconfigured local record — worth explaining before trusting it`
      );
    } else {
      add("special-use", 0, `${cls.special} address (${cls.cidr}) — not routable on the public internet`);
    }
  }

  if (client && cls.routable) {
    try {
      const res = await client.search(`page.ip:"${esc(cls.ip)}"`, { size: 30 });
      const digest = digestIPSearch(res.results);
      record.evidence = digest;
      record.scans = res.total;

      if (digest.threatTags.length) {
        add("hosts-flagged-content", 55, `urlscan has scans of this address serving content tagged: ${digest.threatTags.join(", ")}`);
      }
      if (digest.apexes.length >= 15) {
        add(
          "densely-shared",
          6,
          `${digest.apexes.length}+ unrelated registrable domains observed on this address — shared or bulletproof hosting; the address itself says little about any one site`
        );
      }
      if (res.total === 0) {
        add("never-scanned", 0, "No urlscan scan has ever resolved to this address");
      }
    } catch (e) {
      record.error = e.message;
      if (e instanceof RateLimitError) record.rateLimited = true;
    }
  }

  const weight = signals.reduce((a, s) => a + s.weight, 0);
  record.weight = weight;
  record.severity = severityFor({
    weight,
    threatTagged: signals.some((s) => s.id === "hosts-flagged-content"),
    hasEvidence: record.scans > 0 || Boolean(cls.special),
  });
  return record;
}

// ------------------------------------------------------------------ pairs

/**
 * Cross-check a hostname against the address the CSV says it resolved to.
 *
 * This is the check a bare domain list cannot support, and the one that catches
 * the interesting failures: a name that has only ever been seen on Cloudflare
 * suddenly answering from a residential ASN is a hijack, a poisoned cache, or
 * someone's captive portal — and all three are things you want to be told.
 *
 * Deliberately conservative. A CDN legitimately answers from hundreds of
 * addresses, so a mismatch is only raised when the archive has a solid set of
 * observations AND the observed set shares no announcing network with ours.
 */
export function crossCheckPair(pair, hostRecord, ipRecord) {
  const signals = [];
  const add = (id, weight, detail) => signals.push({ id, weight, detail });

  const observedIPs = hostRecord?.evidence?.ips ?? [];
  const observedASNs = new Set((hostRecord?.evidence?.asns ?? []).map((a) => a.asn));
  const ourASNs = new Set((ipRecord?.evidence?.asns ?? []).map((a) => a.asn));
  const cls = classifyIP(pair.ip);

  if (cls && !cls.routable && !SINKHOLE_ANSWERS.has(cls.ip)) {
    if (isInternalName(pair.host)) {
      add(
        "internal-resolution",
        0,
        `${pair.host} answered ${cls.ip} (${cls.special}) — expected for a reserved internal name`
      );
    } else {
      add("non-routable-answer", 0, `${pair.host} was answered with ${cls.ip} (${cls.special}) — see the address entry`);
    }
  }

  const enoughEvidence =
    observedIPs.length >= 2 &&
    hostRecord?.evidence?.scope === "hostname" &&
    observedASNs.size > 0;

  if (enoughEvidence && cls?.routable) {
    const ipMatch = observedIPs.includes(cls.ip);
    const asnMatch = ourASNs.size > 0 && [...ourASNs].some((a) => observedASNs.has(a));
    if (!ipMatch && !asnMatch && ourASNs.size > 0) {
      add(
        "resolution-mismatch",
        20,
        `urlscan has only ever seen ${pair.host} on ${[...observedASNs].join(", ")}, but this file says it answered ${cls.ip} on ${[...ourASNs].join(", ")}. Different network entirely — confirm this is a CDN edge you expect and not a redirected answer`
      );
    }
  }

  const weight = signals.reduce((a, s) => a + s.weight, 0);
  return {
    host: pair.host,
    ip: pair.ip,
    count: pair.count,
    signals,
    weight,
    severity: severityFor({ weight, threatTagged: false, hasEvidence: enoughEvidence }),
  };
}

// ------------------------------------------------------------------ driver

/**
 * Verify an extraction.
 *
 * @param {{hosts:Array,ips:Array,pairs:Array}} extraction  from csv.extract()
 * @param {object} opts
 * @param {import('./urlscan.mjs').UrlscanClient|null} opts.client
 * @param {number} [opts.limitHosts]  cap on hostnames sent to urlscan (0 = all)
 * @param {number} [opts.limitIPs]    cap on addresses sent to urlscan (0 = all)
 * @param {string[]} [opts.allow]     apexes to treat as expected
 * @param {boolean} [opts.deep]       widen searches and spend more quota
 * @param {(p:object)=>void} [opts.onProgress]
 */
export async function verifyExtraction(extraction, opts = {}) {
  const {
    client = null,
    limitHosts = 0,
    limitIPs = 0,
    allow = [],
    deep = false,
    onProgress = null,
  } = opts;

  const allowApexes = new Set(allow.map((a) => apexOf(a) || normaliseHost(a)).filter(Boolean));

  // An address only counts as "an answer that should have been public" when the
  // name being resolved was itself public. `printer.lan` answering 192.168.1.9
  // is DNS working correctly, and flagging it would bury the real rebinding
  // cases under every internal record on the network.
  const answerIPs = new Set(extraction.pairs.filter((p) => !isInternalName(p.host)).map((p) => p.ip));

  const hostTargets = limitHosts > 0 ? extraction.hosts.slice(0, limitHosts) : extraction.hosts;
  const ipTargets = limitIPs > 0 ? extraction.ips.slice(0, limitIPs) : extraction.ips;
  const total = hostTargets.length + ipTargets.length;
  let done = 0;
  let stopped = false;

  const hosts = [];
  for (const h of hostTargets) {
    if (stopped) break;
    const rec = await verifyHost(h.host, { client, allowApexes, deep });
    rec.count = h.count;
    hosts.push(rec);
    done++;
    onProgress?.({ phase: "hosts", done, total, current: h.host, severity: rec.severity });
    if (rec.rateLimited) stopped = true;
  }

  const ips = [];
  for (const i of ipTargets) {
    if (stopped) break;
    const rec = await verifyIP(i.ip, { client, asAnswer: answerIPs.has(i.ip) });
    rec.count = i.count;
    ips.push(rec);
    done++;
    onProgress?.({ phase: "ips", done, total, current: i.ip, severity: rec.severity });
    if (rec.rateLimited) stopped = true;
  }

  const hostBy = new Map(hosts.map((h) => [h.host, h]));
  const ipBy = new Map(ips.map((i) => [i.ip, i]));
  const pairs = extraction.pairs
    .map((p) => crossCheckPair(p, hostBy.get(p.host), ipBy.get(p.ip)))
    .filter((p) => p.signals.length > 0);

  // A pair-level finding is a fact about the hostname; fold it back so a reader
  // scanning the host table sees it without cross-referencing.
  for (const p of pairs) {
    const host = hostBy.get(p.host);
    if (!host) continue;
    for (const s of p.signals) {
      if (s.weight > 0) {
        host.signals.push({ ...s, detail: s.detail });
        host.weight += s.weight;
        host.severity = severityFor({
          weight: host.weight,
          threatTagged: host.signals.some((x) => x.id === "threat-tagged"),
          hasEvidence: host.scans > 0,
        });
      }
    }
  }

  const tally = (rows) =>
    SEVERITY_ORDER.reduce((m, s) => ((m[s] = rows.filter((r) => r.severity === s).length), m), {});

  return {
    generatedAt: new Date().toISOString(),
    stoppedEarly: stopped,
    scope: {
      rowCount: extraction.rowCount,
      uniqueHosts: extraction.hosts.length,
      uniqueIPs: extraction.ips.length,
      hostsChecked: hosts.length,
      ipsChecked: ips.length,
      pairsChecked: extraction.pairs.length,
      columns: extraction.columns
        ? {
            hosts: extraction.columns.hostCols?.map((c) => c.header) ?? [],
            ips: extraction.columns.ipCols?.map((c) => `${c.header}${c.role === "source" ? " (source)" : ""}`) ?? [],
          }
        : null,
    },
    api: client
      ? { calls: client.calls, cacheHits: client.cacheHits, rate: client.lastRate }
      : { calls: 0, cacheHits: 0, rate: null, offline: true },
    summary: { hosts: tally(hosts), ips: tally(ips), findings: pairs.length },
    hosts: hosts.sort(bySeverity),
    ips: ips.sort(bySeverity),
    pairs: pairs.sort(bySeverity),
  };
}

const bySeverity = (a, b) => {
  const d = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  return d !== 0 ? d : b.weight - a.weight || (b.count ?? 0) - (a.count ?? 0);
};

/** Everything a reader should act on, worst first. */
export function actionable(report) {
  return [...report.hosts, ...report.ips].filter((r) => r.severity === "critical" || r.severity === "warning");
}
