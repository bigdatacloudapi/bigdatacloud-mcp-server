/**
 * Offline signals for hostnames.
 *
 * Every check here runs on the string alone: no network, no quota, no waiting.
 * That matters because a 40,000-row resolver export has maybe 900 unique names,
 * and most of them can be triaged — or cleared — before spending a single
 * rate-limited search on them.
 *
 * Each signal returns a weight and a plain-language reason. Weights are additive
 * and deliberately modest: no single structural quirk should be able to condemn
 * a hostname on its own, because every one of these fires on legitimate names
 * somewhere.
 */

import { apexOf, normaliseHost, tldOf } from "./net.mjs";

/**
 * TLDs with a persistently poor abuse-to-registration ratio in public reporting,
 * plus the two Google TLDs whose names collide with file extensions.
 *
 * Presence here is a nudge, never a verdict. Plenty of ordinary sites live on
 * .xyz and .top.
 */
export const RISKY_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "cyou", "sbs", "cfd",
  "rest", "click", "link", "quest", "monster", "bar", "beauty", "makeup",
  "skin", "hair", "mom", "lol", "icu", "wang", "work", "loan", "download",
  "racing", "win", "bid", "party", "review", "stream", "trade", "date",
  "zip", "mov", "kim", "country", "gdn", "men", "accountant", "science",
]);

/**
 * Suffixes offering free subdomains, tunnels or ephemeral hosting. Legitimate in
 * development; also the cheapest way to stand up a throwaway phishing host, and
 * a common egress for tunnelled traffic that bypasses a router's policy.
 */
export const EPHEMERAL_SUFFIXES = [
  "duckdns.org", "no-ip.org", "no-ip.com", "ddns.net", "hopto.org", "zapto.org",
  "sytes.net", "myftp.org", "serveo.net", "localtunnel.me", "loca.lt",
  "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "tunnelto.dev",
  "pagekite.me", "localhost.run", "telebit.io", "bore.pub",
  "workers.dev", "pages.dev", "r2.dev", "vercel.app", "netlify.app",
  "onrender.com", "glitch.me", "repl.co", "replit.dev", "github.io",
  "herokuapp.com", "firebaseapp.com", "web.app", "appspot.com", "azurewebsites.net",
  "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com",
];

/**
 * Public DoH/DoT endpoints.
 *
 * On a network that deliberately routes DNS through one resolver — a Control D
 * profile, a Pi-hole, an OpenWrt policy — a device talking to one of these is
 * routing around the filter. That is not malware by itself (browsers ship with
 * DoH on), but it is precisely the "something is wrong" the operator wants told.
 */
export const DOH_ENDPOINTS = new Set([
  "dns.google", "dns64.dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
  "security.cloudflare-dns.com", "family.cloudflare-dns.com", "one.one.one.one",
  "dns.quad9.net", "dns9.quad9.net", "dns11.quad9.net", "dns.nextdns.io",
  "doh.opendns.com", "familyshield.opendns.com", "dns.adguard.com",
  "dns-family.adguard.com", "dns-unfiltered.adguard.com", "doh.cleanbrowsing.org",
  "doh.dns.sb", "dns.sb", "doh.mullvad.net", "dns.controld.com", "freedns.controld.com",
  "dns.alidns.com", "doh.pub", "doh.360.cn", "dns.yandex.ru", "resolver.dnscrypt.info",
  "odoh.cloudflare-dns.com", "mask.icloud.com", "mask-h2.icloud.com", "mask-canary.icloud.com",
]);

/**
 * Names that are not meant to resolve on the public internet: RFC 6761/8375
 * reserved TLDs plus the conventional internal ones.
 *
 * These matter twice. A private answer for `printer.lan` is correct behaviour,
 * not rebinding — and a query for one of these reaching a public resolver at all
 * means internal naming is leaking off the network.
 */
export const INTERNAL_TLDS = new Set([
  "local", "localhost", "localdomain", "lan", "home", "home-arpa", "internal",
  "intranet", "corp", "private", "test", "invalid", "example", "domain", "onion",
]);

export const isInternalName = (host) => INTERNAL_TLDS.has(String(tldOf(host) || ""));

/** Brands whose names show up in lookalike domains far more than in real ones. */
export const WATCHED_BRANDS = [
  "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "onedrive",
  "google", "gmail", "youtube", "amazon", "aws", "netflix", "facebook", "instagram",
  "whatsapp", "linkedin", "twitter", "coinbase", "binance", "metamask", "ledger",
  "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays", "revolut",
  "dhl", "fedex", "ups", "usps", "royalmail", "canadapost", "steam", "roblox",
  "discord", "telegram", "signal", "dropbox", "docusign", "adobe", "okta", "duo",
];

/**
 * Apexes that legitimately carry a watched brand's name without being that
 * brand's primary domain, plus the first-party CDN and telemetry endpoints that
 * dominate any real resolver export.
 *
 * This list exists to keep the brand check honest. Without it `googleusercontent.com`
 * and `apple-cloudkit.com` look like impersonation, and a verifier that cries
 * wolf on a company's own CDN gets ignored — which is the only real failure mode
 * a tool like this has.
 */
export const FIRST_PARTY_APEXES = new Set([
  // Google
  "google.com", "googleapis.com", "googleusercontent.com", "googlevideo.com",
  "gstatic.com", "googletagmanager.com", "googlesyndication.com", "google-analytics.com",
  "youtube.com", "ytimg.com", "ggpht.com", "googleadservices.com", "withgoogle.com",
  // Apple
  "apple.com", "icloud.com", "icloud-content.com", "apple-cloudkit.com", "cdn-apple.com",
  "mzstatic.com", "aaplimg.com", "apple-dns.net", "push.apple.com",
  // Microsoft
  "microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com",
  "outlook.com", "windows.net", "azure.com", "azureedge.net", "msftncsi.com",
  "msn.com", "bing.com", "sharepoint.com", "onedrive.com", "skype.com", "xbox.com",
  // Amazon
  "amazon.com", "amazonaws.com", "cloudfront.net", "media-amazon.com", "ssl-images-amazon.com",
  "amazontrust.com", "a2z.com", "aiv-cdn.net",
  // Meta
  "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net",
  "messenger.com", "fb.com", "cdninstagram.com",
  // other majors and infrastructure
  "netflix.com", "nflxvideo.net", "nflximg.net", "linkedin.com", "licdn.com",
  "twitter.com", "x.com", "twimg.com", "dropbox.com", "dropboxstatic.com",
  "adobe.com", "adobe.io", "typekit.net", "okta.com", "oktacdn.com", "duosecurity.com",
  "docusign.net", "docusign.com", "discord.com", "discordapp.com", "discord.gg",
  "telegram.org", "t.me", "signal.org", "steamstatic.com", "steampowered.com",
  "steamcommunity.com", "roblox.com", "rbxcdn.com", "coinbase.com", "binance.com",
  "paypal.com", "paypalobjects.com", "venmo.com",
  "cloudflare.com", "cloudflare-dns.com", "akamai.net", "akamaiedge.net", "akamaized.net",
  "fastly.net", "fastlylb.net", "jsdelivr.net", "unpkg.com", "cdnjs.com",
  "github.com", "githubusercontent.com", "githubassets.com", "gitlab.com",
  "mozilla.com", "mozilla.org", "mozilla.net", "firefox.com",
  "ubuntu.com", "canonical.com", "debian.org", "archlinux.org",
]);

/** Words that read as a login funnel when bolted onto an unrelated apex. */
const LURE_WORDS = [
  "login", "signin", "verify", "verification", "secure", "security", "account",
  "update", "confirm", "recover", "unlock", "suspended", "billing", "invoice",
  "payment", "wallet", "support", "helpdesk", "webmail", "auth", "sso", "mfa",
  "otp", "password", "reset", "alert", "notice", "refund", "claim", "gift",
];

/** Shannon entropy in bits per character. */
export function entropy(s) {
  if (!s) return 0;
  const freq = new Map();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const vowelRatio = (s) => (s.match(/[aeiou]/g) || []).length / Math.max(s.length, 1);
const digitRatio = (s) => (s.match(/\d/g) || []).length / Math.max(s.length, 1);
const longestConsonantRun = (s) => Math.max(0, ...(s.match(/[bcdfghjklmnpqrstvwxyz]+/g) || [""]).map((x) => x.length));

/**
 * Does `label` look machine-generated?
 *
 * Tuned to stay quiet on real names. `googleusercontent`, `cloudfront`, and
 * hyphenated product names all score low; a 16-character consonant soup with
 * digits sprinkled through it scores high.
 */
export function looksAlgorithmic(label) {
  const l = String(label || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  if (l.length < 10) return { hit: false, score: 0 };
  const h = entropy(l);
  const v = vowelRatio(l);
  const d = digitRatio(l);
  const run = longestConsonantRun(l);

  let score = 0;
  if (h > 3.4) score += (h - 3.4) * 2;
  if (v < 0.26) score += (0.26 - v) * 6;
  if (run >= 5) score += (run - 4) * 0.4;
  if (d > 0.3) score += (d - 0.3) * 3;
  if (/^[0-9a-f]{16,}$/.test(l)) score += 3; // hex blob
  if (/^[a-z2-7]{26,}$/.test(l)) score += 2; // base32 blob

  return { hit: score >= 1.6, score: Number(score.toFixed(2)), entropy: Number(h.toFixed(2)) };
}

/** Levenshtein distance, capped — used only for short brand comparisons. */
export function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      best = Math.min(best, cur[j]);
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

/**
 * Structural analysis of one hostname.
 *
 * @param {string} host
 * @param {object} [opts]
 * @param {Set<string>} [opts.allowApexes] apexes the operator has accepted; these
 *   suppress brand and lure signals, which otherwise fire constantly on a
 *   company's own `login.acme.com`.
 * @returns {{host, apex, tld, signals: Array<{id, weight, detail}>, weight: number}}
 */
export function analyseHost(host, { allowApexes } = {}) {
  const h = normaliseHost(host) || String(host || "").toLowerCase();
  const apex = apexOf(h);
  const tld = tldOf(h);
  const labels = h.split(".");
  const signals = [];
  const add = (id, weight, detail) => signals.push({ id, weight, detail });

  const allowed = allowApexes?.has(apex) ?? false;

  // --- encoding and script ------------------------------------------------
  if (labels.some((l) => l.startsWith("xn--"))) {
    add("punycode", 22, `Internationalised (punycode) label — renders as non-Latin text and can imitate another name: ${labels.filter((l) => l.startsWith("xn--")).join(", ")}`);
  }
  if (/[^\x00-\x7f]/.test(String(host))) {
    add("non-ascii", 18, "Contains non-ASCII characters — check for a homograph of a name you trust");
  }

  // --- shape --------------------------------------------------------------
  if (h.length > 60) add("very-long", 6, `Unusually long hostname (${h.length} characters)`);
  if (labels.length >= 6) add("deep-nesting", 6, `${labels.length} labels deep — deep nesting is common in tracking and in wildcard abuse`);
  if (/\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/.test(h)) {
    add("embedded-address", 8, "An IPv4 address is embedded in the hostname — typical of auto-generated hosting PTRs and of malware fallback names");
  }
  const hyphens = (h.match(/-/g) || []).length;
  if (hyphens >= 4) add("hyphen-heavy", 5, `${hyphens} hyphens — long hyphenated names are a phishing staple`);

  // --- the registrable label ---------------------------------------------
  const apexLabel = apex ? apex.split(".")[0] : labels[0];
  const alg = looksAlgorithmic(apexLabel);
  if (alg.hit) {
    add("algorithmic-name", Math.min(24, 8 + alg.score * 4), `Registrable label "${apexLabel}" looks machine-generated (entropy ${alg.entropy}) — the shape of a DGA or a throwaway host`);
  }

  // --- registry and hosting choices ---------------------------------------
  if (tld && RISKY_TLDS.has(tld)) {
    add("risky-tld", 12, `.${tld} carries a persistently high abuse rate — not damning on its own, but worth confirming`);
  }
  const ephemeral = EPHEMERAL_SUFFIXES.find((s) => h === s || h.endsWith(`.${s}`));
  if (ephemeral && !allowed) {
    add("ephemeral-host", 10, `Hosted on ${ephemeral} — free/tunnelled hosting, trivially disposable, and a common way to bypass network policy`);
  }

  // --- naming scope -------------------------------------------------------
  if (tld && INTERNAL_TLDS.has(tld)) {
    add(
      "internal-name",
      4,
      `.${tld} is reserved for internal use and is not meant to resolve publicly. Seeing it in a public resolver log means internal naming is leaking off the network`
    );
  }

  // --- resolver bypass ----------------------------------------------------
  if (DOH_ENDPOINTS.has(h)) {
    add("doh-resolver", 20, "A public encrypted-DNS endpoint. If this network filters DNS at one resolver, a device reaching this is routing around the filter");
  }

  // --- impersonation ------------------------------------------------------
  //
  // A brand name in a hostname is only interesting when the *registrable*
  // domain is not the brand's. Checking that properly means three things: brand
  // TLDs are real (`dns.google` is Google), first-party CDNs rarely spell the
  // brand exactly (`googleusercontent.com`), and the strongest signal of all is
  // a brand sitting in a subdomain of someone else's apex
  // (`paypal.com.secure-login.xyz`).
  if (!allowed && apex && !FIRST_PARTY_APEXES.has(apex)) {
    const apexLabelRaw = apex.slice(0, apex.length - (tld ? tld.length + 1 : 0));
    // Split on separators and digit boundaries so "paypa1-secure" and
    // "secure0amazon" both yield comparable tokens.
    const tokens = apexLabelRaw.split(/[^a-z0-9]+/).filter(Boolean);
    const subLabels = labels.slice(0, Math.max(0, labels.length - apex.split(".").length));

    for (const brand of WATCHED_BRANDS) {
      // Does this hostname legitimately belong to the brand?
      if (tld === brand) break;                       // .google, .apple, .microsoft
      if (apexLabelRaw === brand) break;              // paypal.com, paypal.co.uk

      if (subLabels.includes(brand)) {
        add("brand-subdomain-spoof", 30, `"${brand}" appears as a subdomain label but the registrable domain is ${apex} — the shape of ${brand}.com.${apex}`);
        break;
      }
      if (tokens.includes(brand)) {
        add("brand-in-apex", 22, `The registrable domain ${apex} contains the brand "${brand}" — verify this domain is genuinely theirs`);
        break;
      }

      // Near-misses on any single token: paypa1, arnazon, g00gle.
      const near = tokens.find((t) => t.length >= 5 && Math.abs(t.length - brand.length) <= 2 && editDistance(t, brand, 2) <= 2 && t !== brand);
      if (near) {
        add("brand-lookalike", 26, `"${near}" in ${apex} is a near-miss for "${brand}" — classic typosquat shape`);
        break;
      }

      if (h.includes(brand)) {
        add("brand-in-name", 14, `The hostname mentions "${brand}" but resolves under ${apex}`);
        break;
      }
    }

    const lures = LURE_WORDS.filter((w) => h.includes(w));
    if (lures.length >= 2) {
      add("lure-words", 12, `Login-funnel wording in the hostname: ${lures.slice(0, 4).join(", ")}`);
    }
  }

  const weight = signals.reduce((a, s) => a + s.weight, 0);
  return { host: h, apex, tld, signals, weight };
}
