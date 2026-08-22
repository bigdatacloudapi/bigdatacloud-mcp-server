/**
 * Address and hostname primitives. No dependencies, no network.
 *
 * Everything here is deliberately offline: classifying an address as CGNAT or a
 * hostname as malformed costs nothing and must never burn urlscan quota.
 */

// ---------------------------------------------------------------- IPv4

/** Parse dotted-quad to a uint32, or null. Rejects octal/short forms on purpose. */
export function parseIPv4(s) {
  if (typeof s !== "string") return null;
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    // Leading zeros mean someone's tool wrote an octal-looking octet; treat the
    // string as untrustworthy rather than silently picking an interpretation.
    if (m[i].length > 1 && m[i][0] === "0") return null;
    n = n * 256 + o;
  }
  return n >>> 0;
}

/** Expand an IPv6 string to sixteen bytes, or null. Handles :: and v4-mapped tails. */
export function parseIPv6(s) {
  if (typeof s !== "string") return null;
  let str = s.trim().toLowerCase();
  if (str.startsWith("[") && str.endsWith("]")) str = str.slice(1, -1);
  const zone = str.indexOf("%");
  if (zone !== -1) str = str.slice(0, zone);
  if (!str.includes(":")) return null;

  // A trailing dotted-quad (::ffff:1.2.3.4) becomes two hex groups.
  const lastColon = str.lastIndexOf(":");
  const tail = str.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseIPv4(tail);
    if (v4 === null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    str = `${str.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = str.split("::");
  if (halves.length > 2) return null;
  const split = (part) => (part === "" ? [] : part.split(":"));
  const head = split(halves[0]);
  const tailGroups = halves.length === 2 ? split(halves[1]) : [];
  const groups =
    halves.length === 2
      ? [...head, ...Array(8 - head.length - tailGroups.length).fill("0"), ...tailGroups]
      : head;
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(groups[i])) return null;
    const v = parseInt(groups[i], 16);
    bytes[i * 2] = v >>> 8;
    bytes[i * 2 + 1] = v & 0xff;
  }
  return bytes;
}

/**
 * { version, value } for a valid address, else null.
 *
 * IPv4-mapped v6 (`::ffff:1.2.3.4`) is unwrapped to plain IPv4. Resolver
 * exports mix the two spellings for the same host, and every downstream check —
 * dedupe, special-use classification, urlscan lookup — wants them to be one
 * address, not two.
 */
export function parseIP(s) {
  const v4 = parseIPv4(s);
  if (v4 !== null) return { version: 4, value: v4 };
  const v6 = parseIPv6(s);
  if (!v6) return null;
  const mappedPrefix = v6.slice(0, 10).every((b) => b === 0) && v6[10] === 0xff && v6[11] === 0xff;
  if (mappedPrefix) {
    return { version: 4, value: (((v6[12] << 24) >>> 0) + (v6[13] << 16) + (v6[14] << 8) + v6[15]) >>> 0 };
  }
  return { version: 6, value: v6 };
}

export const isIP = (s) => parseIP(s) !== null;

/** Normalise for comparison and display: IPv6 collapses to its shortest form. */
export function normaliseIP(s) {
  const p = parseIP(s);
  if (!p) return null;
  if (p.version === 4) {
    const n = p.value;
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(((p.value[i] << 8) | p.value[i + 1]).toString(16));

  // Collapse the longest run of zero groups (>=2), per RFC 5952.
  let bestStart = -1;
  let bestLen = 0;
  let start = -1;
  for (let i = 0; i <= groups.length; i++) {
    if (i < groups.length && groups[i] === "0") {
      if (start === -1) start = i;
    } else if (start !== -1) {
      const len = i - start;
      if (len > bestLen && len >= 2) {
        bestLen = len;
        bestStart = start;
      }
      start = -1;
    }
  }
  if (bestStart === -1) return groups.join(":");
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

// ---------------------------------------------------------------- CIDR

/** True when `ip` falls inside `cidr`. Mismatched families are simply false. */
export function inCidr(ip, cidr) {
  const a = typeof ip === "object" && ip ? ip : parseIP(ip);
  if (!a) return false;
  const slash = cidr.lastIndexOf("/");
  const base = parseIP(slash === -1 ? cidr : cidr.slice(0, slash));
  if (!base || base.version !== a.version) return false;
  const bits = slash === -1 ? (a.version === 4 ? 32 : 128) : Number(cidr.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0) return false;

  if (a.version === 4) {
    if (bits > 32) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (a.value & mask) >>> 0 === (base.value & mask) >>> 0;
  }
  if (bits > 128) return false;
  const full = bits >> 3;
  for (let i = 0; i < full; i++) if (a.value[i] !== base.value[i]) return false;
  const rem = bits & 7;
  if (rem === 0) return true;
  const mask = (0xff << (8 - rem)) & 0xff;
  return (a.value[full] & mask) === (base.value[full] & mask);
}

// ------------------------------------------------- special-use registry

/**
 * IANA special-purpose address blocks, ordered most-specific first so the first
 * match wins. `routable: false` means the address cannot legitimately appear as
 * a public answer — seeing one in a resolver log is itself the finding.
 */
export const SPECIAL_USE = [
  // IPv4
  { cidr: "0.0.0.0/8", label: "this-network", routable: false },
  { cidr: "10.0.0.0/8", label: "private (RFC1918)", routable: false },
  { cidr: "100.64.0.0/10", label: "CGNAT (RFC6598)", routable: false },
  { cidr: "127.0.0.0/8", label: "loopback", routable: false },
  { cidr: "169.254.0.0/16", label: "link-local", routable: false },
  { cidr: "172.16.0.0/12", label: "private (RFC1918)", routable: false },
  { cidr: "192.0.0.0/24", label: "IETF protocol assignments", routable: false },
  { cidr: "192.0.2.0/24", label: "documentation (TEST-NET-1)", routable: false },
  { cidr: "192.88.99.0/24", label: "6to4 relay anycast (deprecated)", routable: false },
  { cidr: "192.168.0.0/16", label: "private (RFC1918)", routable: false },
  { cidr: "198.18.0.0/15", label: "benchmarking", routable: false },
  { cidr: "198.51.100.0/24", label: "documentation (TEST-NET-2)", routable: false },
  { cidr: "203.0.113.0/24", label: "documentation (TEST-NET-3)", routable: false },
  { cidr: "224.0.0.0/4", label: "multicast", routable: false },
  { cidr: "240.0.0.0/4", label: "reserved", routable: false },
  { cidr: "255.255.255.255/32", label: "broadcast", routable: false },
  // IPv6
  { cidr: "::/128", label: "unspecified", routable: false },
  { cidr: "::1/128", label: "loopback", routable: false },
  { cidr: "64:ff9b::/96", label: "NAT64 well-known prefix", routable: true },
  { cidr: "100::/64", label: "discard-only", routable: false },
  { cidr: "2001:db8::/32", label: "documentation", routable: false },
  { cidr: "2001::/32", label: "Teredo", routable: true },
  { cidr: "2002::/16", label: "6to4", routable: true },
  { cidr: "fc00::/7", label: "unique local (ULA)", routable: false },
  { cidr: "fe80::/10", label: "link-local", routable: false },
  { cidr: "ff00::/8", label: "multicast", routable: false },
];

/**
 * Classify an address. Returns null for unparseable input, otherwise
 * { ip, version, special, routable }.
 */
export function classifyIP(s) {
  const p = parseIP(s);
  if (!p) return null;
  const hit = SPECIAL_USE.find((b) => inCidr(p, b.cidr));
  return {
    ip: normaliseIP(s),
    version: p.version,
    special: hit ? hit.label : null,
    cidr: hit ? hit.cidr : null,
    routable: hit ? hit.routable : true,
  };
}

// ---------------------------------------------------------------- hostnames

const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-_]{1,63}(?<!-)(\.(?!-)[a-z0-9-_]{1,63}(?<!-))*\.?$/;

/**
 * Normalise a hostname for lookup: lowercase, strip a trailing dot, strip a
 * leading `*.` wildcard and a `www.` that carries no signal of its own.
 */
export function normaliseHost(input) {
  if (typeof input !== "string") return null;
  let h = input.trim().toLowerCase();
  if (!h) return null;
  // Accept a full URL, a bare host, or host:port.
  if (h.includes("://")) {
    try {
      h = new URL(h).hostname;
    } catch {
      return null;
    }
  } else if (/^[^/\s]+:\d{1,5}$/.test(h) && !h.includes("::")) {
    h = h.slice(0, h.lastIndexOf(":"));
  }
  h = h.replace(/^\*\./, "").replace(/\.$/, "");
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (!h) return null;
  return h;
}

/** A syntactically usable DNS name — not an IP, not an empty label. */
export function isHostname(s) {
  const h = normaliseHost(s);
  if (!h) return false;
  if (isIP(h)) return false;
  if (!h.includes(".")) return false; // single labels carry no registrable domain
  return HOSTNAME_RE.test(h);
}

/**
 * Public-suffix-aware-ish apex extraction using a compact multi-label suffix
 * table. This is not a full PSL — it covers the multi-label suffixes that
 * actually show up in resolver logs, and falls back to last-two-labels.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "com.br", "net.br", "org.br", "gov.br",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "lg.jp",
  "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "co.in", "net.in", "org.in", "gov.in", "ac.in", "res.in",
  "com.mx", "org.mx", "gob.mx", "com.ar", "gob.ar", "org.ar",
  "com.tr", "gov.tr", "org.tr", "com.sg", "com.hk", "com.tw",
  "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
  "co.za", "org.za", "gov.za", "com.my", "com.ph", "com.vn",
  "co.il", "org.il", "gov.il", "com.ua", "com.pl", "gov.pl",
  "co.id", "or.id", "go.id", "com.sa", "com.eg", "com.ng",
  "gc.ca", "on.ca", "qc.ca", "bc.ca", "ab.ca",
  "com.es", "gob.es", "co.th", "in.th", "go.th",
  "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net",
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
  "herokuapp.com", "firebaseapp.com", "web.app", "appspot.com", "r2.dev",
  "duckdns.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "loca.lt",
]);

/** The registrable domain (`apex`) for a hostname, e.g. a.b.example.co.uk -> example.co.uk */
export function apexOf(host) {
  const h = normaliseHost(host);
  if (!h || isIP(h)) return null;
  const parts = h.split(".").filter(Boolean);
  if (parts.length < 2) return null;
  for (let take = Math.min(5, parts.length); take >= 3; take--) {
    const candidate = parts.slice(-take).join(".");
    const suffix = parts.slice(-(take - 1)).join(".");
    if (MULTI_LABEL_SUFFIXES.has(suffix)) return candidate;
  }
  return parts.slice(-2).join(".");
}

/** The effective TLD label, lowercased and without a dot. */
export function tldOf(host) {
  const h = normaliseHost(host);
  if (!h || isIP(h)) return null;
  const parts = h.split(".").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : null;
}

/** Is `host` equal to, or a subdomain of, `parent`? */
export function isSubdomainOf(host, parent) {
  const h = normaliseHost(host);
  const p = normaliseHost(parent);
  if (!h || !p) return false;
  return h === p || h.endsWith(`.${p}`);
}
