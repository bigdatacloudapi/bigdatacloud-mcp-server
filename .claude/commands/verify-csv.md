---
description: Verify the domains and IPs in a CSV against urlscan.io and report what looks wrong
argument-hint: [path/to/file.csv] [--offline] [--limit N]
---

Verify the domains and IP addresses in `$ARGUMENTS` using the `urlscan-verify`
MCP tools.

1. If no path was given, look for CSV files in the working directory and ask
   which one — do not guess between several.
2. Call `verify_csv` with the path. Add `offline: true` if the user passed
   `--offline`, and `limitHosts` if they passed `--limit`.
3. Report back:
   - what the file contained (rows, unique names, unique addresses)
   - everything that came back `critical` or `warning`, each with the reason and
     what you would do about it
   - `notice` findings in one line
   - the `unknown` count as *"no public scan history"*, explicitly not as clean
4. Offer `export_blocklist` if anything was flagged.

Do not pre-extract the domains or reshape the file — `verify_csv` handles column
detection itself.
