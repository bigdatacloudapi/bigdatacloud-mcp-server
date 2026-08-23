# The two boards, and how to run them

**Resolver Triage** — https://claude.ai/code/artifact/c7e3cb44-06b8-4327-b3b3-eda4d934d4a9
**Verdict Board** — https://claude.ai/code/artifact/86911d70-2f6f-4616-959d-383dae22d473

Both work on Windows, on your phone, and in any browser. Nothing to install,
nothing hosted, no API key anywhere.

---

## The loop

```
1. Control D → Activity Log → Export CSV        (lands in %USERPROFILE%\Downloads)
2. Resolver Triage  → drop the CSV in → "Copy briefing for Claude"
3. A Claude chat    → paste the prompt below + the briefing      ← the AI step
4. Verdict Board    → paste Claude's reply → decide each name → Export
5. Router           → copy the file across, rename, restart dnsmasq
```

Step 3 is where the intelligence lives. Steps 2 and 4 are structure and record-keeping.

---

## Step 3 — the prompt to reuse

Paste this into a Claude conversation, then the briefing under it.

```
I've triaged a resolver export. Below is the briefing from my triage console.
It is structural analysis only — the page has no network access, so it judges
the shape of a name and nothing else.

For each name in the Flagged and Check this sections:

1. Tell me what the domain actually is, if it's identifiable.
2. Attribute it — which app, SDK, or vendor contacts it? Say explicitly when
   attribution is unknown; absence of evidence is not evidence of cleanliness.
3. Cross-reference it against urlscan.io and current public threat reporting.
   Note when a name has simply never been scanned — that's the normal state
   for first-party telemetry and means neither safe nor unsafe.
4. Give me a recommendation: block, allow, or investigate further, with your
   reasoning.

Be sceptical of the structural scores. They flag shapes, not facts — a high
score on a CDN hostname is a false positive and I want you to say so. Equally,
tell me if something scored low that you think deserves attention.

Format your answer so I can paste it straight into my Verdict Board: one name
per line starting the line, with your analysis as bullets underneath it. Keep
the section headings (Flagged / Check this / Worth a look) from the briefing.

--- BRIEFING ---
[paste here]
```

The Verdict Board parses that format directly. It also copes with the raw
briefing, with plain lists of domains, and with prose — but the format above
gives the cleanest cards.

---

## Notes on each board

**Resolver Triage** detects which columns hold names and which hold addresses
from the cell contents, so Control D, Pi-hole, AdGuard and pfSense exports all
work unconfigured. Columns headed `sourceIp`/`clientIp`/`src` are treated as
the client that asked, never as a DNS answer — otherwise every row would look
like a resolution mismatch.

*Allowlist field:* put your own domains in and the brand and lure signals stop
firing for them. It re-scores as you type.

*"No evidence" is not "safe".* With no network access the page can only say
nothing stood out. It never claims a name is clean, and neither should you.

**Verdict Board** keeps your decisions. Press **Save decisions** and they're
written into the artifact itself, so the board looks the same on your phone as
on your PC. Between saves they're held in that browser's local storage, so a
refresh won't lose work. If you open a view that can't write, the Save button
disables itself and says so rather than failing silently.

*Add to what is there* merges a second briefing into the existing board
instead of replacing it — useful when you triage several exports in a week.

---

## Step 5 — getting it onto the router (Windows)

Pick a format in the Export dropdown. Everything saves as `.txt` because the
artifact download allowlist rejects `.conf` — rename it on the router.

```powershell
scp "$env:USERPROFILE\Downloads\dnsmasq-block.txt" root@192.168.1.1:/etc/dnsmasq.d/verdict-board.conf
ssh root@192.168.1.1 "dnsmasq --test"
ssh root@192.168.1.1 "/etc/init.d/dnsmasq restart"
```

Windows 10 and 11 ship OpenSSH, so `scp` and `ssh` work in PowerShell with
nothing installed.

**Run `dnsmasq --test` before the restart.** A malformed file takes DNS down
for the whole network, and you'd be debugging that without working DNS.

**Don't open the exported files in classic Notepad.** They use Unix line
endings, which OpenWrt wants. VS Code or Notepad++ leave them alone.

For policy-based routing rather than blocking, export the nftset format and
pair it with the pbr policy — dnsmasq puts every resolved address into the
named nftables set, which is how pbr routes by domain instead of by address.

---

## What this can't do

It never queries the urlscan archive with your API key, so there are no
submitter threat tags and no domain-age signal. No artifact can — the sandbox
blocks every external host. What you get instead is impersonation, DGA-shaped
names, resolver bypass and rebinding, all caught offline, plus Claude's
reasoning and web lookup at step 3.

If you later want the archive itself, that needs a process on your machine:
Node 20+, Claude Code, and `$env:URLSCAN_API_KEY` set in PowerShell against
the `Demonad112/bigdatacloud-mcp-server` clone. That path gives live archive
lookups at your desk, but doesn't reach your phone. The two complement each
other rather than replacing one another.
