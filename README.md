# Nethergaze

*A grizzled sysadmin's scrying pool for VPS network traffic.*

Nethergaze is a real-time TUI dashboard that correlates active TCP connections with HTTP access logs — something no single existing tool does. See who's connected, what they're requesting, and where they're from, all in one terminal.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

## What It Does

![Nethergaze in action — catching a SYN flood botnet](public/nethergaze.png)

- **Left panel** — Sortable table of connected IPs with country, org name (GeoIP + whois), connection count, request count, bytes served
- **Right panel** — Color-coded streaming HTTP log (green=2xx, yellow=4xx, red=5xx) with live filtering
- **IP drill-down** — Press Enter on any IP for full detail: connections, recent requests, whois info
- **Auto-enrichment** — GeoIP and whois/RDAP lookups run automatically in background threads for every new IP

## Why It Matters

During initial deployment, Nethergaze revealed a **SYN flood attack** — 254 half-open connections from a Brazilian botnet (~30 IPs across two /24 blocks) hammering port 443. The connections showed up in the table with country/org data but zero completed requests, which made the pattern immediately obvious. Without this kind of correlation between TCP state and HTTP logs, the attack would have gone unnoticed until performance degraded.

This is the gap Nethergaze fills: `ss` shows connections but not what they're requesting. Access logs show requests but not the underlying TCP state. Nethergaze joins them by IP in real time so anomalies — botnets, scanners, misbehaving clients — stand out at a glance.

## Install

```bash
git clone https://github.com/OuttaMyDepth/NetherGaze.git
cd nethergaze
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

### GeoIP Databases (Recommended)

For country, city, and ASN resolution, install free [DB-IP Lite](https://db-ip.com/db/lite.php) databases (MMDB format, no account required):

```bash
sudo mkdir -p /usr/share/GeoIP
cd /tmp
wget -q "https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz"
wget -q "https://download.db-ip.com/free/dbip-asn-lite-$(date +%Y-%m).mmdb.gz"
gunzip dbip-city-lite-*.mmdb.gz dbip-asn-lite-*.mmdb.gz
sudo mv dbip-city-lite-*.mmdb /usr/share/GeoIP/GeoLite2-City.mmdb
sudo mv dbip-asn-lite-*.mmdb /usr/share/GeoIP/GeoLite2-ASN.mmdb
```

DB-IP Lite updates monthly. [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) databases are also supported (same MMDB format). Without GeoIP databases, Nethergaze falls back to whois for org names, but country codes will be unavailable.

## Usage

```bash
# Basic — auto-discovers per-vhost nginx logs via glob
nethergaze

# Custom log path (single file or glob pattern)
nethergaze --log-path "/var/log/nginx/mysite.access.log"
nethergaze --log-path "/var/log/nginx/*.access.log"

# Specify log format (auto-detected by default)
nethergaze --log-format json

# Custom interface, disable enrichment
nethergaze --interface ens3 --no-whois --no-geoip

# Use a config file
nethergaze --config ~/.config/nethergaze/config.toml
```

### Log Format Support

Nethergaze auto-detects the log format per line. Explicitly set it with `--log-format` if needed:

| Format | Description | Example Server |
|--------|-------------|----------------|
| `auto` | Tries each format in order (default) | Any |
| `combined` | nginx combined / Apache combined (CLF + referrer + user-agent) | nginx, Apache |
| `common` | Common Log Format (CLF) | Apache, minimal configs |
| `json` | JSON lines with nested or flat keys | Caddy |

### Key Bindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `Tab` / `Shift+Tab` | Switch focus between panels |
| `Enter` | Drill down into selected IP |
| `s` | Cycle sort column (connections / requests / bytes / IP) |
| `w` | Trigger whois lookup for selected IP |
| `r` | Force refresh all data |
| `/` | Filter log entries |
| `?` | Show key bindings |

## Configuration

Copy `config.example.toml` to `~/.config/nethergaze/config.toml`:

```toml
# Glob pattern to watch multiple vhost logs at once
log_path = "/var/log/nginx/*.access.log"

# Log format: auto, combined, common, json
log_format = "auto"

interface = "ens3"
show_private_ips = false

[refresh]
connections_interval = 1.0
log_interval = 0.5

[geoip]
enabled = true
city_db = "/usr/share/GeoIP/GeoLite2-City.mmdb"
asn_db = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

[whois]
enabled = true
cache_ttl = 86400
max_workers = 3
```

Config resolution: CLI flags > environment variables (`NETHERGAZE_*`) > config file > defaults.

## How It Works

Nethergaze reads `/proc/net/tcp` directly (faster than shelling out to `ss` or `netstat`), tails HTTP access logs with inode-based rotation detection, and joins the data by IP address in a thread-safe correlation engine. Whois lookups run in background daemon threads with RDAP-to-legacy-whois fallback and 24-hour disk-cached results. GeoIP lookups are synchronous and memory-cached.

```
/proc/net/tcp (1s poll) -->                  --> Connections Table
HTTP access logs (0.5s) --> Correlation      --> HTTP Activity Log
vnstat (30s)            -->   Engine         --> Header Bar
whois/RDAP (async)      --> (IPProfile dict) --> Stats Bar
GeoIP (sync, cached)    -->
```

Key implementation details:

- **Multi-file log watching** — `log_path` accepts glob patterns (e.g., `/var/log/nginx/*.access.log`) to tail all vhost logs simultaneously, with periodic rescan for new files
- **Private IP filtering** — Docker bridge / internal traffic (172.x, 10.x, etc.) is filtered from the log panel by default
- **Whois resilience** — RDAP is tried first; on failure (e.g., LACNIC 403s), falls back to legacy whois protocol. Failed lookups are not cached so they retry on next encounter
- **Stale profile cleanup** — IPs that drop all connections and have no request history are automatically pruned from the display

## Requirements

- Python 3.11+
- Linux (reads `/proc/net/tcp`)
- HTTP server with combined, common, or JSON log format (nginx, Apache, Caddy)
- Optional: `vnstat` for bandwidth stats
- Optional: MMDB GeoIP databases (DB-IP Lite or MaxMind GeoLite2) for country/city/ASN

## License

MIT
