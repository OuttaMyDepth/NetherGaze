# Nethergaze

*A grizzled sysadmin's scrying pool for VPS network traffic.*

Nethergaze is a real-time TUI dashboard that correlates active TCP connections with nginx access logs — something no single existing tool does. See who's connected, what they're requesting, and where they're from, all in one terminal.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

## What It Does

```
┌─────────────────────────────────────────────────────────────────────────┐
│ VPSTracker | vps-2bae6cbe | Up: 47d 3h | BW: ↓12.4 GiB ↑8.2 GiB     │
├──────────────────────────────────┬──────────────────────────────────────┤
│ IP Address     CC Org       Conns│ 14:23:01 93.184.216.34  200 GET /   │
│ 93.184.216.34  ?  EDGECAST  2   │ 14:23:02 198.51.100.1   404 GET /wp │
│ 198.51.100.1   ?  CLOUDFLAR 1   │ 14:23:03 203.0.113.50   200 POST /a │
│ 203.0.113.50   ?  HETZNER   3   │ 14:23:04 93.184.216.34  200 GET /st │
│                                  │ 14:23:05 170.106.107.87 403 GET /.. │
├──────────────────────────────────┴──────────────────────────────────────┤
│ Conns: 14 (6 EST) | IPs: 4 | Req/min: 23 | Sent: 4.2 MiB             │
└─────────────────────────────────────────────────────────────────────────┘
```

- **Left panel** — Sortable table of connected IPs with org name (via whois RDAP), connection count, request count, bytes served
- **Right panel** — Color-coded streaming HTTP log (green=2xx, yellow=4xx, red=5xx)
- **IP drill-down** — Press Enter on any IP for full detail: connections, recent requests, whois info
- **Auto-enrichment** — Whois/RDAP lookups run automatically in background threads for every new IP

## Install

```bash
git clone https://github.com/YOURUSER/nethergaze.git
cd nethergaze
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Basic — reads /var/log/nginx/access.log, monitors eth0
vpstracker

# Custom log path and interface
vpstracker --log-path /var/log/nginx/mysite.log --interface ens3

# Disable whois lookups (faster startup, less noise)
vpstracker --no-whois

# Use a config file
vpstracker --config ~/.config/vpstracker/config.toml
```

### Key Bindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `Tab` / `Shift+Tab` | Switch focus between panels |
| `Enter` | Drill down into selected IP |
| `s` | Cycle sort column (connections → requests → bytes → IP) |
| `w` | Trigger whois lookup for selected IP |
| `r` | Force refresh all data |
| `?` | Show key bindings |

## Configuration

Copy `config.example.toml` to `~/.config/vpstracker/config.toml`:

```toml
log_path = "/var/log/nginx/access.log"
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

Config resolution: CLI flags → environment variables (`VPSTRACKER_*`) → config file → defaults.

## Optional: GeoIP

For country/city/ASN resolution, install [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) databases. Without them, Nethergaze falls back to whois for org names.

## How It Works

Nethergaze reads `/proc/net/tcp` directly (faster than shelling out to `ss` or `netstat`), tails your nginx access log with inode-based rotation detection, and joins the data by IP address in a thread-safe correlation engine. Whois lookups run in a background thread pool with 24-hour disk-cached results.

```
/proc/net/tcp (1s poll) ──→                  ──→ Connections Table
nginx access.log (0.5s) ──→ Correlation      ──→ HTTP Activity Log
vnstat (30s)            ──→   Engine          ──→ Header Bar
whois/RDAP (async)      ──→ (IPProfile dict) ──→ Stats Bar
GeoIP (sync, cached)    ──→
```

## Requirements

- Python 3.11+
- Linux (reads `/proc/net/tcp`)
- nginx with combined log format
- Optional: `vnstat` for bandwidth stats, MaxMind GeoLite2 `.mmdb` files for GeoIP

## License

MIT
