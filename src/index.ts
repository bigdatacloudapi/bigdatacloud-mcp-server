#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const API_BASE = "https://api-bdc.net/data";
const API_KEY = process.env.BIGDATACLOUD_API_KEY || "";

const PACKAGE_VERSION = "1.1.0";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface ApiCallOptions {
  endpoint: string;
  params: Record<string, string | number | boolean | undefined>;
  requiresKey?: boolean;
}

async function callApi({ endpoint, params, requiresKey }: ApiCallOptions): Promise<string> {
  if (requiresKey && !API_KEY) {
    return JSON.stringify({
      error: "API key required",
      message:
        "This endpoint requires a BigDataCloud API key. " +
        "Get a free key at https://www.bigdatacloud.com/login — " +
        "then set the BIGDATACLOUD_API_KEY environment variable.",
      signUpUrl: "https://www.bigdatacloud.com/login",
    });
  }

  const url = new URL(`${API_BASE}/${endpoint}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  if (API_KEY) {
    url.searchParams.set("key", API_KEY);
  }

  const res = await fetch(url.toString(), {
    headers: { Accept: "application/json" },
    redirect: "follow",
  });

  if (!res.ok) {
    const body = await res.text();
    return JSON.stringify({
      error: `API returned ${res.status}`,
      statusCode: res.status,
      details: body,
      ...(res.status === 402 && {
        message:
          "Quota exceeded or subscription required. " +
          "Upgrade at https://www.bigdatacloud.com/api-packages",
      }),
    });
  }

  return await res.text();
}

function ok(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "bigdatacloud",
  version: PACKAGE_VERSION,
});

// ========================
// IP Geolocation
// ========================

server.tool(
  "ip-geolocation",
  "Get detailed geolocation for an IP address — city, region, country, coordinates, ISP, network type. Requires API key (free tier available).",
  {
    ip: z.string().describe("IPv4 or IPv6 address to geolocate"),
    localityLanguage: z.string().optional().describe("Language for results (e.g. 'en'). Default: en"),
  },
  async ({ ip, localityLanguage }) => {
    const text = await callApi({
      endpoint: "ip-geolocation",
      params: { ip, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

server.tool(
  "ip-geolocation-full",
  "Get comprehensive geolocation for an IP including confidence area, hazard report, and security assessment. Premium endpoint.",
  {
    ip: z.string().describe("IPv4 or IPv6 address to geolocate"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ ip, localityLanguage }) => {
    const text = await callApi({
      endpoint: "ip-geolocation-full",
      params: { ip, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

server.tool(
  "ip-geolocation-with-confidence",
  "Get geolocation with confidence score and estimated area boundary for an IP address. Shows how reliable the geolocation is.",
  {
    ip: z.string().describe("IPv4 or IPv6 address to geolocate"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ ip, localityLanguage }) => {
    const text = await callApi({
      endpoint: "ip-geolocation-with-confidence",
      params: { ip, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

// ========================
// API KEY TOOLS — Reverse Geocoding
// ========================

server.tool(
  "reverse-geocode",
  "Convert latitude/longitude to detailed address information — locality, city, region, country, postcode. Requires API key.",
  {
    latitude: z.number().min(-90).max(90).describe("Latitude (-90 to 90)"),
    longitude: z.number().min(-180).max(180).describe("Longitude (-180 to 180)"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ latitude, longitude, localityLanguage }) => {
    const text = await callApi({
      endpoint: "reverse-geocode",
      params: { latitude, longitude, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

server.tool(
  "reverse-geocode-with-timezone",
  "Convert coordinates to address plus full timezone details (offset, DST, local time).",
  {
    latitude: z.number().min(-90).max(90).describe("Latitude"),
    longitude: z.number().min(-180).max(180).describe("Longitude"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ latitude, longitude, localityLanguage }) => {
    const text = await callApi({
      endpoint: "reverse-geocode-with-timezone",
      params: { latitude, longitude, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

// ========================
// API KEY TOOLS — Network & ASN
// ========================

server.tool(
  "asn-info",
  "Get information about an Autonomous System — name, organisation, country, IPv4/IPv6 prefixes announced.",
  {
    asn: z.string().describe("AS number (e.g. 'AS13335' or '13335')"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ asn, localityLanguage }) => {
    const text = await callApi({
      endpoint: "asn-info",
      params: { asn, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

server.tool(
  "network-by-ip",
  "Get detailed network information for an IP — the BGP-announced prefix, AS, carrier, network type.",
  {
    ip: z.string().describe("IPv4 or IPv6 address"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ ip, localityLanguage }) => {
    const text = await callApi({
      endpoint: "network-by-ip",
      params: { ip, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

server.tool(
  "country-by-ip",
  "Detect which country an IP address is located in, with detailed country information.",
  {
    ip: z.string().describe("IPv4 or IPv6 address"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ ip, localityLanguage }) => {
    const text = await callApi({
      endpoint: "country-by-ip",
      params: { ip, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

// ========================
// API KEY TOOLS — Timezone
// ========================

server.tool(
  "timezone-by-ip",
  "Get timezone details for an IP address — timezone name, offset, DST status, current local time.",
  {
    ip: z.string().describe("IPv4 or IPv6 address"),
    utcReference: z.string().optional().describe("UTC reference time for conversion (ISO 8601)"),
  },
  async ({ ip, utcReference }) => {
    const text = await callApi({
      endpoint: "timezone-by-ip",
      params: { ip, utcReference },
      requiresKey: true,
    });
    return ok(text);
  }
);

server.tool(
  "timezone-by-location",
  "Get timezone details for GPS coordinates — timezone name, offset, DST status, current local time.",
  {
    latitude: z.number().min(-90).max(90).describe("Latitude"),
    longitude: z.number().min(-180).max(180).describe("Longitude"),
    utcReference: z.string().optional().describe("UTC reference time for conversion (ISO 8601)"),
  },
  async ({ latitude, longitude, utcReference }) => {
    const text = await callApi({
      endpoint: "timezone-by-location",
      params: { latitude, longitude, utcReference },
      requiresKey: true,
    });
    return ok(text);
  }
);

// ========================
// API KEY TOOLS — Phone & Email
// ========================

server.tool(
  "phone-number-validate",
  "Validate and format a phone number — returns country, carrier, line type, formatted number.",
  {
    number: z.string().describe("Phone number to validate (any format)"),
    countryCode: z.string().optional().describe("ISO country code hint (e.g. 'US', 'AU')"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ number, countryCode, localityLanguage }) => {
    const text = await callApi({
      endpoint: "phone-number-validate",
      params: { number, countryCode, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

server.tool(
  "email-verify",
  "Validate an email address — checks format, domain, MX records, disposable status.",
  {
    emailAddress: z.string().describe("Email address to verify"),
  },
  async ({ emailAddress }) => {
    const text = await callApi({
      endpoint: "email-verify",
      params: { emailAddress },
      requiresKey: true,
    });
    return ok(text);
  }
);

// ========================
// API KEY TOOLS — User Agent
// ========================

server.tool(
  "user-agent-info",
  "Parse a User-Agent string — extract browser, OS, device type, bot detection.",
  {
    userAgentRaw: z.string().describe("Raw User-Agent string to parse"),
  },
  async ({ userAgentRaw }) => {
    const text = await callApi({
      endpoint: "user-agent-info",
      params: { userAgentRaw },
      requiresKey: true,
    });
    return ok(text);
  }
);

// ========================
// API KEY TOOLS — Security
// ========================

server.tool(
  "ip-hazard-report",
  "Get a hazard/threat assessment for an IP address — VPN, proxy, Tor, bot, spam detection.",
  {
    ip: z.string().describe("IPv4 or IPv6 address to assess"),
  },
  async ({ ip }) => {
    const text = await callApi({
      endpoint: "hazard-report",
      params: { ip },
      requiresKey: true,
    });
    return ok(text);
  }
);

server.tool(
  "tor-exit-nodes",
  "Get the list of active Tor exit nodes with geolocation and carrier info.",
  {
    batchSize: z.number().optional().describe("Number of results (default 50)"),
    offset: z.number().optional().describe("Pagination offset"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ batchSize, offset, localityLanguage }) => {
    const text = await callApi({
      endpoint: "tor-exit-nodes-list",
      params: { batchSize, offset, localityLanguage },
      requiresKey: true,
    });
    return ok(text);
  }
);

// ========================
// IP Geolocation — additional
// ========================

server.tool(
  "country-info",
  "Get detailed information about a country by ISO code — name, currency, calling code, languages, World Bank region and income level.",
  {
    code: z.string().describe("ISO 3166-1 alpha-2 country code (e.g. 'AU', 'US', 'GB')"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ code, localityLanguage }) => {
    const text = await callApi({ endpoint: "country-info", params: { code, localityLanguage }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "all-countries",
  "Get a full list of all countries with detailed information — names, currencies, calling codes, languages, regions.",
  {
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ localityLanguage }) => {
    const text = await callApi({ endpoint: "countries", params: { localityLanguage }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "user-risk",
  "Get a risk assessment for an IP address suitable for e-commerce and sign-up flows — returns a risk level (Low/Medium/High) and description.",
  {
    ip: z.string().describe("IPv4 or IPv6 address to assess"),
  },
  async ({ ip }) => {
    const text = await callApi({ endpoint: "user-risk", params: { ip }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "timezone-by-iana-id",
  "Get timezone details for a given IANA timezone ID — offset, DST status, display name, and current local time.",
  {
    timeZoneId: z.string().describe("IANA timezone ID (e.g. 'Australia/Sydney', 'America/New_York')"),
    utcReference: z.string().optional().describe("UTC reference time for conversion (ISO 8601)"),
  },
  async ({ timeZoneId, utcReference }) => {
    const text = await callApi({ endpoint: "timezone-info", params: { timeZoneId, utcReference }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "phone-number-validate-by-ip",
  "Validate a phone number using the caller's IP address for country detection. Use when you know the user's IP but not their country code.",
  {
    number: z.string().describe("Phone number to validate"),
    ip: z.string().describe("End user's IP address for country detection"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ number, ip, localityLanguage }) => {
    const text = await callApi({ endpoint: "phone-number-validate-by-ip", params: { number, ip, localityLanguage }, requiresKey: true });
    return ok(text);
  }
);

// ========================
// Network Engineering — additional
// ========================

server.tool(
  "asn-info-full",
  "Get extended ASN information including upstream providers (receiving-from), downstream peers (transit-to), prefix counts, rank, and service area polygon.",
  {
    asn: z.string().describe("AS number (e.g. 'AS13335' or '13335')"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ asn, localityLanguage }) => {
    const text = await callApi({ endpoint: "asn-info-full", params: { asn, localityLanguage }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "asn-receiving-from",
  "Get paginated list of upstream providers for an ASN — the networks this ASN receives traffic from (peering/transit relationships).",
  {
    asn: z.string().describe("AS number (e.g. 'AS13335')"),
    batchSize: z.number().optional().describe("Number of results per page (default 25)"),
    offset: z.number().optional().describe("Pagination offset"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ asn, batchSize, offset, localityLanguage }) => {
    const text = await callApi({ endpoint: "asn-info-receiving-from", params: { asn, batchSize, offset, localityLanguage }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "asn-transit-to",
  "Get paginated list of downstream peers for an ASN — the networks this ASN provides transit to.",
  {
    asn: z.string().describe("AS number (e.g. 'AS13335')"),
    batchSize: z.number().optional().describe("Number of results per page (default 25)"),
    offset: z.number().optional().describe("Pagination offset"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ asn, batchSize, offset, localityLanguage }) => {
    const text = await callApi({ endpoint: "asn-info-transit-to", params: { asn, batchSize, offset, localityLanguage }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "bgp-prefixes",
  "Get paginated list of active BGP prefixes announced by an ASN. Use isIPv4=true for IPv4 prefixes, false for IPv6.",
  {
    asn: z.string().describe("AS number (e.g. 'AS13335')"),
    isIPv4: z.boolean().optional().describe("true for IPv4 prefixes (default), false for IPv6"),
    batchSize: z.number().optional().describe("Number of results per page (default 25)"),
    offset: z.number().optional().describe("Pagination offset"),
  },
  async ({ asn, isIPv4, batchSize, offset }) => {
    const isv4 = isIPv4 === false ? "false" : "true";
    const text = await callApi({ endpoint: "prefixes-list", params: { asn, isv4, batchSize, offset }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "networks-by-cidr",
  "Get all networks announced on BGP within a given CIDR range — useful for finding what networks overlap with a specific IP block.",
  {
    cidr: z.string().describe("CIDR notation (e.g. '1.1.1.0/24', '8.8.8.0/24')"),
    localityLanguage: z.string().optional().describe("Language for results. Default: en"),
  },
  async ({ cidr, localityLanguage }) => {
    const text = await callApi({ endpoint: "network-by-cidr", params: { cidr, localityLanguage }, requiresKey: true });
    return ok(text);
  }
);

server.tool(
  "asn-rank-list",
  "Get a paginated ranked list of all ASNs sorted by IPv4 address space. Useful for identifying the largest networks on the internet.",
  {
    batchSize: z.number().optional().describe("Number of results per page (default 15)"),
    offset: z.number().optional().describe("Pagination offset"),
  },
  async ({ batchSize, offset }) => {
    const text = await callApi({ endpoint: "asn-rank-list", params: { batchSize, offset }, requiresKey: true });
    return ok(text);
  }
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
