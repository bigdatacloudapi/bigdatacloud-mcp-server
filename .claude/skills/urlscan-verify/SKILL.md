---
name: urlscan-verify
description: Verify the domains and IP addresses in a CSV, log export, or list — checking urlscan.io's archive plus offline structure analysis to find impersonation, newly registered domains, DNS rebinding, resolver bypass and hosts serving flagged content. Use whenever someone asks whether the names or addresses in a file look wrong, hands over a DNS/resolver/firewall export (Control D, Pi-hole, AdGuard, pfSense), asks to triage a domain or IP list, or wants a blocklist built from what was found.
---

# Verifying domains and addresses

The `urlscan-verify` MCP server is running in this project. Prefer its tools over
hand-rolling urlscan queries — they carry the rate limiting, the caching and the
verdict logic.

## Which tool

| Situation | Tool |
|---|---|
| A CSV, log export or spreadsheet on disk | `verify_csv` with `path` |
| Names pasted into the conversation | `verify_domains` |
| Addresses pasted into the conversation | `verify_ips` |
| A pivot the verifier does not cover | `urlscan_search` |
| Detail on one specific scan | `urlscan_result` |
| Turning findings into router config | `export_blocklist` |
| A saved write-up | `verification_report` |

`verify_csv` detects the relevant columns itself. Do not pre-process the file,
do not extract the domains into a list first, and do not ask which column to
use — hand it the path.

## Reading the verdicts

Five verdicts come back. The two quiet ones are the ones people misread:

- **critical** — urlscan submitters tagged it hostile, or the structural signals
  are overwhelming. Say so plainly.
- **warning** — several signals line up. Worth the user's attention.
- **notice** — one mild signal. Mention it; do not alarm.
- **clean** — scanned, nothing stood out. Not an audit.
- **unknown** — *nobody has ever submitted this name to urlscan.* This is the
  normal state for first-party telemetry endpoints and it means neither safe nor
  unsafe. **Never report an `unknown` as safe, clean, or fine.** On a typical
  home-network export most rows land here, and that is not a finding.

Threat verdicts come from urlscan submitter tags, not `verdicts.overall.malicious`.
That field is gated below a Pro plan and reads `false` even on scans a submitter
tagged as phishing, so never quote it as evidence of anything.

## Spending quota well

urlscan's free tier is limited per minute, hour and day, and the server paces one
call per unique name. A 900-name export is a genuinely long run.

- Start with `limitHosts: 50` on a large unfamiliar file to see the shape of it,
  then run the whole thing if it looks worth the time.
- Use `offline: true` when the user wants a fast structural pass, or when they
  have no API key. It costs nothing and still catches typosquats, punycode,
  DGA-shaped names and rebinding.
- Results are cached for a day, so re-running the same file is free. Say so
  rather than avoiding a re-run.
- Pass domains the user has already vouched for in `allow` — it silences brand
  and lure signals on their own infrastructure.

## Reporting back

Lead with what is actionable. A useful answer names the handful of things worth
checking and says what to do about each; it does not recite the whole table.

Two things worth surfacing explicitly when they appear, because users rarely
think to ask:

- **`doh-resolver`** — a device is talking to a public encrypted-DNS endpoint. On
  a network that filters DNS at one resolver, that device is routing around the
  filter.
- **`private-answer` / `resolution-mismatch`** — a public name answered from a
  private address or from an unrelated network. That is rebinding, a
  split-horizon override, or a redirected answer, and it is worth explaining
  before trusting it.

If the user wants to act on the findings, `export_blocklist` writes dnsmasq,
hosts, nftables and OpenWrt `pbr` files. Default it to `critical` only, and tell
them to read `domains.txt` before deploying — a false positive there becomes a
name their network can no longer reach.
