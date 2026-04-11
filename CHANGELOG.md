# Changelog

All notable changes to `@bigdatacloudapi/mcp-server` will be documented here.

This project follows [Semantic Versioning](https://semver.org/).

---

## [1.1.0] - 2026-04-12

### Added — 11 new tools (now 26 total, matching full SDK coverage)

**IP Geolocation package:**
- `country-info` — detailed country information by ISO code
- `all-countries` — full list of all countries with details
- `user-risk` — risk assessment (Low/Medium/High) for e-commerce and sign-up flows
- `timezone-by-iana-id` — timezone details by IANA ID (e.g. "Australia/Sydney")
- `phone-number-validate-by-ip` — phone validation using caller IP for country detection

**Network Engineering package:**
- `asn-info-full` — extended ASN info with upstream providers, transit peers, and service area
- `asn-receiving-from` — paginated upstream providers for an ASN
- `asn-transit-to` — paginated downstream peers for an ASN
- `bgp-prefixes` — active BGP prefixes announced by an ASN (IPv4 or IPv6)
- `networks-by-cidr` — all BGP networks within a given CIDR range
- `asn-rank-list` — ranked list of all ASNs by IPv4 address space

---

## [1.0.0] - 2026-04-10

### Initial Release
- 15 tools covering IP Geolocation, Reverse Geocoding, Network, Timezone, Phone & Email, User Agent, Security
