# urlscan.io + DNS Forensic Analysis — Reference Framework

Paste this into a new chat as context when sharing urlscan.io JSON/MHT exports or
Control D DNS CSVs. It encodes the analytical method, field reference, and
known-pattern library built up across a live household DNS forensics + PBR/tunneling
investigation. Companion to any Control D export — this framework is specifically
for verifying individual domains found in that corpus via urlscan.io.

## Response format — always

**Facts → Interpretation → Recommended action.** State what the data literally shows
first, with no hedging. Then interpret it. Then say what (if anything) to do next.
Self-correct explicitly and immediately if a prior claim in the same thread turns out
wrong — state the correction, don't bury it.

---

## Part 1 — Reading a single urlscan.io result JSON

### Fields that matter, and what they tell you

| Field | What to check | Red flag |
|---|---|---|
| `page.domain` / `page.apexDomain` | Is the domain what it claims to be? | Apex domain unrelated to the subdomain's apparent brand |
| `page.ip` + `data.requests[].response.response.remoteIPAddress` | Can differ (anycast/multi-IP) — not itself a flag | IP doesn't match ASN claimed elsewhere in the record |
| `...asn.description` / `...asn.name` | The org that owns the IP | Org unrelated to the domain's claimed identity |
| `...rdns.ptr` | Reverse DNS of the IP | A PTR naming a totally different service (worth explaining, not assuming malice) |
| `securityDetails.subjectName` / `sanList` | TLS cert identity | SAN list includes domains that don't belong together |
| `securityDetails.issuer` | CA that issued the cert | Unusual/unknown CA for a major brand |
| `securityDetails.signedCertificateTimestampList` | CT log inclusion | Missing/absent SCTs on a cert claiming to be from a major brand |
| `page.status` | HTTP status of the primary request | See status-code table below |
| `page.tlsValidDays` / `tlsAgeDays` | Cert freshness | Extremely new domain + extremely new cert = weak signal alone, but stack with other flags |
| `page.apexDomainAgeDays` / `domainAgeDays` | Domain registration age | Freshly-registered apex domain fronting sensitive-looking traffic |
| `page.server` | Server header | Not authoritative (spoofable) — corroborate with ASN/PTR |
| `verdicts.overall/.urlscan/.engines/.community` | Automated + crowd verdicts | `malicious: true` or nonzero `score`; note `hasVerdicts: false` means "not enough signal to score," not "confirmed clean" |
| `task.tags` | Tags the *submitter* applied | Can reveal WHY someone scanned it (e.g. `["hacked"]`) — this is someone else's investigation context riding along with the scan, not a fact about your own traffic |
| `task.method` (`manual` vs `api`) + `task.source` | Was this a human clicking scan, or an automated pipeline? | Distinguishes "someone investigated this by hand" from routine crawling |
| `task.visibility` | public/private | Public scans are what your urlscan **search** queries will surface later |
| `data.requests[].response.failed` | `net::ERR_ABORTED`, `net::ERR_CONNECTION_REFUSED`, etc. | Usually benign (browser aborting non-HTML nav, server dropping unauthenticated probe) — don't over-read without checking the status code first |

### Status-code cheat sheet (don't over-interpret these)
| Code | Typical honest meaning |
|---|---|
| 404 on `/` | Normal for API-only/POST-only backends (mobile SDK ingestion endpoints never serve a root page) |
| 403 on an S3/CloudFront asset root | Normal — no public bucket listing configured, not a compromise signal |
| 504 Gateway Timeout | Backend didn't respond in time — common on low-traffic telemetry/logging shards under an unsolicited probe with no valid session |
| No response at all (`status`/`remoteIPAddress` both null) | Internal-style load balancer silently dropping an unauthenticated bare connection — routine for backend APIs not meant for public GET |
| 400 "plain HTTP sent to HTTPS port" | The scan hit the TLS port without a handshake — server correctly rejected it, confirms the port/service exists |
| Self-signed "Kubernetes Ingress Controller Fake Certificate" | Default un-configured k8s ingress — extremely common, not inherently malicious |

### `data.requests[].response.processors.download` (when present)
Gives you the **actual content type and hash** independent of the `Content-Type`
header — useful because trackers often lie in the header (e.g. a real PNG served as
`application/octet-stream`). A tiny (~1KB, small pixel dimensions) image response on
a `/d/<opaque-id>?...` path is the standard shape of an **analytics/impression
tracking pixel**, not a payload of concern.

---

## Part 2 — The urlscan.io SEARCH technique (higher value than a single result)

`https://urlscan.io/search/#<domain-or-string>` shows **every other public scan**
that touched that exact hostname. This is the single most useful move for
disambiguating an unfamiliar domain: it reveals **who else uses the same
infrastructure**, which either confirms shared/multi-tenant hosting (benign) or
narrows to a specific vendor.

### How to extract the data from a saved MHT
Saved-page MHTs are MIME-multipart; the rendered result rows live in the `text/html`
part as static markup (Chrome captures the post-render DOM). Parse rows with a
regex anchored on the repeating structure:
```python
rows = re.findall(
    r'title="([^"]+)"\s*>[^<]*</a>.*?IP:.*?>([\d\.a-fA-F:]+)</a>.*?'
    r'Server:.*?>([^<]+)</a>.*?country:([A-Z]{2}).*?asn:AS(\d+)',
    html, re.S)
```
or, when the layout differs slightly (score/flag ordering varies by urlscan UI
version), fall back to:
```python
rows = re.findall(
    r'title="([^"]+)"\s*>[^<]*</a>.*?<span class="(?:green|orange|red)">(\d+)</span>'
    r'.*?flag-icon-([a-z]{2})', html, re.S)
```
Total result count is usually in a `"<N,NNN> results"` string near the top.

### CRITICAL CAVEAT — selection bias in what gets scanned
**urlscan's index only contains pages someone manually navigated a browser to (or an
automated pipeline chose to fetch) and submitted for scanning.** It is NOT a random
sample of "who uses this vendor." Security researchers disproportionately scan
gambling, crypto/PTC, and adult sites — those categories will always be
over-represented in a search result set for any widely-used
fraud-detection/analytics vendor, **regardless of that vendor's actual overall
customer mix.** A native mobile app's internal SDK calls (e.g., a fitness or photo
app's own backend) essentially never get scanned this way at all, because they never
generate a browsable page.

**Rule: before reading a search result's composition as meaningful, check what your
own DNS export shows the domain co-occurring with.** If it fires in the same
session-window as a confirmed first-party app's own hostnames (e.g., alongside
`api.<yourapp>.com`, a payment processor, a subscription-billing vendor), that
direct co-occurrence outranks the urlscan search's category skew every time.

---

## Part 3 — Cross-referencing urlscan findings against a DNS export (Control D or similar)

1. **Never judge a domain in isolation** — pull the ±2–5 minute window around its
   first appearance in the DNS CSV and read the full hostname list. A single-app
   session (native SDK stack initializing) looks structurally different from an
   ad-mediation waterfall or a browser page load:
   - **Native app session**: first-party API hosts (`config`/`identity`/`sync`/`api.<app>.com`)
     firing in a tight, ordered sequence, alongside a *coherent, small* SDK set
     (analytics + crash reporting + one payments/subscription vendor).
   - **Ad-mediation waterfall**: 40–100+ unrelated ad-network/DSP hostnames firing
     in a 1–2 second burst, nonsense-phrase `.com`/`.site` domains, multiple
     redundant bidders.
   - **Browser page load**: consent-management platform (OneTrust/Cookielaw),
     Google Tag Manager, a full programmatic-ad-auction stack, plus the page's own
     first-party domain — mixed with unrelated tabs if multiple sites loaded near
     the same second.
2. **App Store install signature** (iOS) — a reliable, checkable sequence when you
   suspect a fresh install:
   `amp-api-search-edge.apps.apple.com` (search) → `iosapps.itunes.apple.com` +
   `downloaddispatch.itunes.apple.com` (binary download) → `p*-buy.itunes.apple.com`
   + `mzstorekit.*` (StoreKit purchase/receipt flow, fires even for free apps) →
   `app-site-association.cdn-apple.com` (Universal Links registration — this
   specifically only fires on a genuine new install, not a background retry) → the
   new app's own first-run API burst, typically 15–30s later.
   **Caveat**: `inappcheck.itunes.apple.com` / generic `buy-lb.*` hosts fire
   repeatedly all day for unrelated reasons (background receipt re-validation) —
   don't treat their mere presence near a burst as corroborating; only the specific
   download-dispatch + app-site-association pairing is diagnostic.
3. **Answer-side validation** — cross-check every answer IP's ASN against an
   independent BGP source (`ipverse/asn-ip` GitHub dataset works well, is
   fetchable, and doesn't require an API key). Expect a handful of harmless
   same-org dual-announcements (e.g. Apple AS6185/AS714, Amazon AS14618/AS16509) —
   these are not mismatches.

---

## Part 4 — Known infrastructure fingerprints (avoid re-flagging these)

| Signature | Identity | Note |
|---|---|---|
| Server: `TencentEdgeOne`, hostname pattern `<anything>.eo.dnse2.com`, ASN 139341 | Tencent Cloud EdgeOne CDN (China's Cloudflare-equivalent) | Massive shared multi-tenant CDN — expect wildly unrelated brands (cosmetics companies, security vendors, random dev subdomains) all sharing this suffix. Not evidence of deliberate cloaking; it's just which CDN a customer chose. |
| `x-daiquiri-instance` header, `ak8s-prod-*` hostnames | Apple's internal Kubernetes ingress ("Daiquiri") | Apple's own production edge naming convention |
| Random-word-pair `.herokuapp.com` subdomain appearing across dozens of unrelated small Shopify storefronts | A shared third-party Shopify app/plugin backend | Not a dedicated backend for any one store — Heroku's default naming for un-customized dyno names |
| `sc-gw.com`, `sc-cdn.net`, `app-analytics-v2.snapchat.com` | Snapchat SDK telemetry | Confirmed benign first-party across many sessions |
| `*.split.io` (`sdk`/`auth`/`streaming`/`events`) | Split.io (Harness) — feature-flag/experimentation SDK | Common bundled dependency, not a standalone app |
| `*.superwall.com` / `api.superwall.me` | Superwall — paywall-presentation/A-B-testing SDK | Firing = a paywall screen was evaluated/shown |
| `api.revenuecat.com` | RevenueCat — subscription/IAP management SaaS | Extremely common, mainstream, used by thousands of apps |
| `js.verisoul.ai` / `ingest.prod.verisoul.ai` | Verisoul — AI device-fingerprinting/fraud-detection | Legitimate anti-fraud vendor; check DNS co-occurrence before assuming high-risk-industry usage — see selection-bias caveat above |
| `*.gist.build` (`code.`/`renderer.`) | Gist — in-app messaging/onboarding popup platform | Same functional category as Intercom; benign marketing-tech |
| `*.pawwalls.com` | "Paywalls" — smaller paywall-SaaS vendor | CloudFront/S3-fronted, legitimate, low public profile |

---

## Part 5 — What to always ask for / check when a new urlscan JSON or MHT arrives

1. Full `task`, `page`, `verdicts` blocks first — cheapest signal, read before anything else.
2. Every request in `data.requests[]` — method, URL, status, remoteIP, server header.
3. TLS cert subject/SAN/issuer/CT-compliance if present.
4. If the domain is unfamiliar: run the **urlscan search** technique (Part 2) AND
   pull the DNS export's context window around its first appearance (Part 3) —
   **do both, don't substitute one for the other.** The search tells you who else
   uses it; the DNS context tells you which app on *this* device is actually using
   it.
5. State explicitly when DNS/urlscan data's limits are reached — e.g. "this
   confirms resolution/hosting only, not what the subsequent HTTPS session actually
   did" — and name the next artifact that would answer the remaining question
   (on-device Storage/Purchase History check, packet capture, router traffic log).
