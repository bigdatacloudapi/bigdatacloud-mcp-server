# Triage on Android — attach the file to Claude instead

The artifact can't open a file picker inside the Claude Android app's web view.
That's a limit of the web view, not of the page, and no version of the artifact
can work around it. But the Claude app itself takes files fine — so attach the
export to a message and let Claude do the triage.

**On Android the flow becomes:**

```
1. Control D app/site → export the Activity Log
2. Claude app → 📎 → attach the export → paste the prompt below
3. Claude replies with the briefing
4. Copy Claude's reply (long-press → Copy, or the copy button)
5. Verdict Board artifact → long-press the box → Paste → decide → Export
```

Pasting *text* works fine on Android — it's only the file picker that's blocked.
So step 5 works normally.

---

## The prompt

Attach your CSV or XLSX, then send this with it.

```
Attached is a DNS resolver export (Control D or similar). Triage it for me.

STEP 1 — read the file
Work out which column holds the queried hostname and which holds the answer
address, from the cell contents rather than the header names. Treat any column
headed sourceIp / srcIp / src / clientIp / remoteIp as the CLIENT that asked,
never as a DNS answer — pairing those with the row's hostname would claim every
query resolved to the device that made it. Note the row count and the unique
hostname count.

STEP 2 — score each unique hostname on structure alone
Impersonation, only when the registrable domain is NOT the brand's own:
  30  a brand name as a SUBDOMAIN label under someone else's apex
      (the paypal.com.secure-login.xyz shape) — the strongest signal
  26  a near-miss on a brand in the apex, edit distance <= 2 (paypa1, arnazon)
  22  a brand token inside the registrable domain itself
  14  the hostname mentions a brand but resolves under an unrelated apex
Never treat a company's own CDN as impersonation: googleusercontent.com,
gstatic.com, apple-cloudkit.com, cdn-apple.com, akamaiedge.net, fbcdn.net,
twimg.com, licdn.com and their kin are first-party. Skip the check entirely when
the TLD is the brand (dns.google) or the apex label is exactly the brand.
Shape:  22 punycode (xn--) · 18 non-ASCII · 8 an IPv4 embedded in the name
        6 over 60 chars · 6 six-plus labels deep · 5 four-plus hyphens
Machine-generated names: score the registrable label — high entropy, few vowels,
long consonant runs, heavy digits. A 16+ character hex or base32 blob is the
clearest case. Weight 8–24 depending on how strong the shape is.
Registry: 12 for a high-abuse TLD (tk ml ga cf gq top xyz buzz cyou sbs cfd
click link quest icu work loan win bid zip mov and similar) · 10 for ephemeral
or tunnelled hosting (duckdns, ngrok, trycloudflare, workers.dev, pages.dev,
herokuapp, repl.co, ddns.net and similar) · 20 for a public DoH/DoT endpoint
(dns.google, cloudflare-dns.com, one.one.one.one, dns.quad9.net, dns.nextdns.io,
dns.adguard.com, mask.icloud.com and similar) — on a network that routes DNS
through one resolver, a device reaching those is routing around the filter ·
4 for a reserved internal TLD (.local .lan .home .corp .internal) appearing in a
PUBLIC resolver log, which means internal naming is leaking off the network ·
12 when two or more login-funnel words appear (login signin verify secure
account update confirm unlock billing invoice payment wallet auth otp password).

Addresses: classify against the IANA special-use registry. A PUBLIC hostname
answered with a non-routable address scores 30 — that's rebinding, a split-horizon
override, or a bad local record. But 0.0.0.0 / 127.0.0.1 / :: as an answer is a
SINKHOLE, meaning the filter blocked it — informational, never a threat. And a
reserved internal name answered privately (printer.lan → 192.168.1.9) is correct
behaviour, not a finding.

Verdicts: >=60 Flagged · >=26 Check this · >=10 Worth a look · else No evidence.
Nothing is ever "clean" — structure alone cannot clear a name.

STEP 3 — identify known infrastructure instead of scoring it
Where you recognise a host, name it rather than flagging it, and drop its shape
signals. Among others: RevenueCat (subscriptions), Superwall and Pawwalls
(paywalls), Split.io and LaunchDarkly (feature flags), Verisoul (anti-fraud),
Gist (in-app messaging), Snapchat's sc-gw.com / sc-cdn.net, Tencent EdgeOne
(*.eo.dnse2.com, a big shared CDN so unrelated brands share it), Apple's
ak8s-prod-* ingress, Firebase/Crashlytics, Branch/AppsFlyer/Adjust (attribution),
Amplitude/Mixpanel/Segment (analytics), OneTrust (consent, fires on page loads).

STEP 4 — the session window, which decides what a name means
For every Flagged and Check this name, list what else the device was talking to
within about two minutes of its first appearance. Then say which pattern it fits:
  · a native app session — first-party API hosts (config/identity/sync/api.<app>)
    in a tight ordered sequence with a small coherent SDK set
  · an ad-mediation waterfall — 40+ unrelated ad-network hosts in a second or two,
    nonsense-phrase domains, redundant bidders
  · a browser page load — consent platform, tag manager, a full ad-auction stack,
    plus the page's own domain
This co-occurrence outranks anything a urlscan search suggests about the vendor's
customer mix: urlscan only indexes pages someone chose to submit, so researchers'
interest in gambling, crypto and adult sites skews every result set. A native
app's own SDK calls are essentially never in there at all.

STEP 5 — answer as Facts → Interpretation → Recommended action
Facts first with no hedging, then what they mean, then what to do. For each name
worth attention: what it is, which app or SDK contacts it, what public reporting
says, and block / allow / investigate. Say plainly when a name has never been
scanned anywhere — that is the normal state for first-party telemetry and means
neither safe nor unsafe. Correct yourself explicitly if something you said
earlier in the thread turns out wrong.

FORMAT so I can paste it into my Verdict Board: keep the section headings
(Flagged / Check this / Worth a look), put each hostname alone at the start of
its line, and put your analysis as bullets underneath it.
```

---

## Why not just fix the artifact

An Android web view opens a file picker only if the host app implements
`onShowFileChooser`. When it doesn't, the tap is swallowed with no error and no
dialog — exactly what you saw. Nothing in the page's markup or JavaScript can
force it, and there's no dragging on a phone to fall back to.

The artifact still works normally on a desktop browser, and the Verdict Board
works everywhere because pasting text is never blocked.
