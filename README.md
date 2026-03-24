# BigDataCloud MCP Server

[![bigdatacloudapi/bigdatacloud-mcp-server MCP server](https://glama.ai/mcp/servers/bigdatacloudapi/bigdatacloud-mcp-server/badges/score.svg)](https://glama.ai/mcp/servers/bigdatacloudapi/bigdatacloud-mcp-server)


An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that gives AI assistants access to [BigDataCloud](https://www.bigdatacloud.com) APIs — IP geolocation, reverse geocoding, network intelligence, timezone, phone/email validation and more.

## Why?

Ask your AI assistant to geolocate an IP address, reverse-geocode GPS coordinates, or validate a phone number — and get real, accurate results powered by BigDataCloud's [patented IP geolocation technology](https://www.bigdatacloud.com/insights/ip-geolocation-accuracy-report).

## Quick Start

### Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "bigdatacloud": {
      "command": "npx",
      "args": ["-y", "@bigdatacloudapi/mcp-server"],
      "env": {
        "BIGDATACLOUD_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "bigdatacloud": {
      "command": "npx",
      "args": ["-y", "@bigdatacloudapi/mcp-server"],
      "env": {
        "BIGDATACLOUD_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to your VS Code settings or `.vscode/mcp.json`:

```json
{
  "mcp": {
    "servers": {
      "bigdatacloud": {
        "command": "npx",
        "args": ["-y", "@bigdatacloudapi/mcp-server"],
        "env": {
          "BIGDATACLOUD_API_KEY": "your-api-key-here"
        }
      }
    }
  }
}
```

## API Key

**Free tier available** — most tools work with a free API key:

1. Sign up at [bigdatacloud.com/login](https://www.bigdatacloud.com/login)
2. Get your API key from the dashboard
3. Set the `BIGDATACLOUD_API_KEY` environment variable

All tools require an API key. The free tier gives you access to every endpoint with generous volume limits.

## Available Tools

### All Tools (free API key — all endpoints, volume-limited)

| Tool | Description |
|------|-------------|
| `ip-geolocation` | IP address → city, region, country, coordinates, ISP |
| `ip-geolocation-full` | Full geolocation + confidence area + hazard report |
| `ip-geolocation-with-confidence` | Geolocation + confidence score + area boundary |
| `reverse-geocode` | Coordinates → detailed address information |
| `reverse-geocode-with-timezone` | Coordinates → address + timezone details |
| `asn-info` | AS number → organisation, country, prefixes |
| `network-by-ip` | IP → BGP prefix, carrier, network type |
| `country-by-ip` | IP → country with detailed country info |
| `timezone-by-ip` | IP → timezone, offset, DST, local time |
| `timezone-by-location` | Coordinates → timezone details |
| `phone-number-validate` | Phone number → country, carrier, line type |
| `email-verify` | Email → format check, domain, MX, disposable status |
| `user-agent-info` | UA string → browser, OS, device, bot detection |
| `ip-hazard-report` | VPN, proxy, Tor, bot, spam threat assessment |
| `tor-exit-nodes` | List active Tor exit nodes with geolocation |

Need more volume? [Upgrade your plan](https://www.bigdatacloud.com/api-packages).

## Example Prompts

Once configured, try asking your AI assistant:

- *"Where is IP address 8.8.8.8 located?"*
- *"What's the address at coordinates -34.9285, 138.6007?"*
- *"What timezone is 203.0.113.50 in?"*
- *"Validate this phone number: +61 4 1234 5678"*
- *"Is this email address valid: test@example.com?"*
- *"What AS number does 1.1.1.1 belong to?"*
- *"Show me the current Tor exit nodes"*

## About BigDataCloud

[BigDataCloud](https://www.bigdatacloud.com) provides next-generation IP geolocation powered by patented technology. Our system continuously collects ground-truth location data and uses proprietary algorithms to deliver industry-leading accuracy — verified daily in our [public accuracy report](https://www.bigdatacloud.com/insights/ip-geolocation-accuracy-report).

- 🏆 **Patented technology** — US Patent 11,792,110 B2
- 📊 **Transparent accuracy** — public daily benchmark vs. competitors
- 🌍 **Global coverage** — IPv4 and IPv6
- ⚡ **Ultra-fast** — edge-deployed flat-file architecture

## License

MIT
