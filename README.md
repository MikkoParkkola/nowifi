# nowifi

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

### No WiFi? Now WiFi.

**Author: Mikko Parkkola**

One command. 27 techniques. Browser works immediately.

```bash
sudo ./nowifi
```

Stuck behind a hotel/airport/cafe WiFi login page? `nowifi` detects the captive portal, probes for weaknesses, and tries 19 bypass techniques automatically -- most powerful first, stops on the first one that works. Your browser works immediately. `Ctrl+C` restores everything.

Need the actual WiFi password instead? `nowifi crack` runs a multi-step WPA cracking pipeline with 4 more techniques.

---

## Installation

### Download Binary (Recommended)

```bash
# macOS (Apple Silicon)
curl -sL https://github.com/MikkoParkkola/nowifi/releases/latest/download/nowifi-darwin-arm64 -o nowifi
chmod +x nowifi

# macOS (Intel)
curl -sL https://github.com/MikkoParkkola/nowifi/releases/latest/download/nowifi-darwin-amd64 -o nowifi
chmod +x nowifi

# Linux (amd64)
curl -sL https://github.com/MikkoParkkola/nowifi/releases/latest/download/nowifi-linux-amd64 -o nowifi
chmod +x nowifi
```

### Build from Source

```bash
git clone https://github.com/MikkoParkkola/nowifi.git
cd nowifi/go
go build -o nowifi ./cmd/nowifi
```

### Homebrew

```bash
brew install MikkoParkkola/tap/nowifi
```

---

## Quick Start

```bash
# Full audit: detect portal, probe leaks, try all bypasses
sudo ./nowifi

# Read-only assessment (no changes to network)
./nowifi diagnose

# WPA password cracking
sudo ./nowifi crack

# Check system health
./nowifi doctor
```

---

## All 21 Commands

| Command | What it does |
|---------|-------------|
| `sudo nowifi` | Full audit: detect, probe, bypass, report |
| `sudo nowifi -p` | Probe only -- find leaks without exploiting them |
| `sudo nowifi --fast` | Skip stealth timing (faster but more detectable) |
| `sudo nowifi -t URL` | Use a specific chisel tunnel server |
| `sudo nowifi -i en1` | Use a different WiFi interface (default: `en0`) |
| `nowifi diagnose` | Read-only security assessment (no changes to network) |
| `nowifi diagnose -r json -o report.json` | Save diagnosis as JSON file |
| `nowifi crack` | WPA/WPA2 cracking (PMKID + handshake + hashcat) |
| `nowifi crack --scan-only` | Scan for WiFi networks without attacking |
| `nowifi scan` | Scan nearby WiFi networks with signal/security info |
| `nowifi watch` | Maintain access -- auto-reconnect on session expiry |
| `nowifi history` | Show past audit sessions |
| `nowifi tools` | Show which external tools are installed/missing |
| `nowifi tools -d` | Auto-download missing tools (chisel, hysteria, cloudflared) |
| `nowifi server create` | Create a tunnel server (CF Worker or VPS) |
| `nowifi server list` | List active tunnel servers |
| `nowifi server destroy` | Destroy a tunnel server |
| `nowifi server info` | Show which techniques need a server |
| `nowifi ecosystem` | Show complementary tools (bettercap, wifiphisher, etc.) |
| `nowifi setup` | Interactive first-time setup wizard |
| `nowifi doctor` | System health check |
| `sudo nowifi reset` | Emergency network reset after crash/kill |

---

## 27 Techniques

### Portal Bypass (19 techniques)

These work when you're connected to WiFi but stuck behind a captive portal login page.

| # | Technique | How it works | Severity |
|---|-----------|-------------|----------|
| 1 | **IPv6 bypass** | Portal only filters IPv4; IPv6 passes unfiltered | Critical |
| 2 | **HTTPS/WS tunnel** | Chisel WebSocket tunnel through HTTPS to your server | Critical |
| 3 | **CNA User-Agent spoof** | Portal auto-approves Apple CNA/Wispr User-Agent requests | High |
| 4 | **JS-only bypass** | Portal enforces auth only in JavaScript, not server-side | High |
| 5 | **HTTP CONNECT abuse** | Tunnel through the portal's transparent proxy via CONNECT | High |
| 6 | **MAC clone (idle)** | Clone an inactive authenticated device's MAC address | Critical |
| 7 | **MAC clone (any)** | Clone any authenticated device's MAC from ARP table | Critical |
| 8 | **DNS tunnel** | IP-over-DNS via iodine (50-500 Kbps) | High |
| 9 | **ICMP tunnel** | IP-over-ping via hans (100-300 Kbps) | High |
| 10 | **VPN on port 53** | WireGuard/OpenVPN on DNS port, usually allowed | High |
| 11 | **Whitelist domain** | Tunnel via whitelisted CDN domain | Medium |
| 12 | **Session cookie replay** | Sniff and replay portal auth cookies (HTTP portals) | High |
| 13 | **Portal default creds** | Try default admin passwords on portal management | Critical |
| 14 | **MAC rotate** | Fresh random MAC for new session/quota/time limit | High |
| 15 | **DHCP rotate** | New IP via DHCP release/renew cycle | Medium |
| 16 | **QUIC tunnel** | Hysteria2 over UDP/443 (looks like HTTP/3 to DPI) | Critical |
| 17 | **CF Workers proxy** | Serverless proxy via Cloudflare Workers (no server needed) | Critical |
| 18 | **NTP tunnel** | Data encoded in NTP extension fields on UDP/123 | High |
| 19 | **DoH tunnel** | DNS-over-HTTPS to Cloudflare/Google (whitelisted endpoints) | High |

### WPA Cracking (4 techniques)

These crack the actual WiFi password when you don't have it.

| # | Technique | How it works |
|---|-----------|-------------|
| 20 | **PMKID capture** | Extract PMKID from AP's first message -- no clients needed (~60% of APs) |
| 21 | **WPS Pixie-Dust** | Exploit weak RNG in WPS (~30% of WPS-enabled APs, 5-30s) |
| 22 | **Handshake capture + hashcat** | Deauth a client, capture 4-way handshake, GPU crack |
| 23 | **WPS PIN brute force** | Brute force 11,000 PIN combinations (2-10 hours, last resort) |

### Smart Cracking (4 additional strategies)

| # | Technique | How it works |
|---|-----------|-------------|
| 24 | **Smart common passwords** | Top 1000 WiFi passwords (embedded, no wordlist needed) |
| 25 | **Numeric mask attack** | 8-digit patterns common in ISP-issued routers |
| 26 | **Word+number rules** | Hashcat rules combining dictionary words with numbers |
| 27 | **Online brute force** | wpa_supplicant PSK attempts (no monitor mode needed) |

---

## External Tools

nowifi works out of the box for many techniques. External tools unlock tunnel and cracking capabilities.

```bash
# Check what's installed
nowifi tools

# Auto-download supported tools
nowifi tools -d
```

| Tool | Unlocks | Install |
|------|---------|---------|
| chisel | HTTPS/WS tunnel (#2) | `nowifi tools -d` |
| hysteria | QUIC tunnel (#16) | `nowifi tools -d` |
| cloudflared | DoH tunnel (#19) | `nowifi tools -d` |
| iodine | DNS tunnel (#8) | `brew install iodine` |
| hans | ICMP tunnel (#9) | `brew install hans` |
| hashcat | WPA cracking (GPU) | `brew install hashcat` |
| aircrack-ng | WPA cracking (CPU) | `brew install aircrack-ng` |
| hcxdumptool | PMKID/handshake capture | `brew install hcxdumptool` |
| hcxpcapngtool | Convert captures for hashcat | `brew install hcxtools` |
| reaver | WPS Pixie-Dust/PIN attacks | `brew install reaver` |

---

## Tunnel Server Setup

Many techniques work without any server (MAC clone, IPv6, CNA spoof, etc.). Tunnel-based bypasses need a server you control outside the portal's network.

### Quickest: Cloudflare Workers (Free)

```bash
nowifi server create
# Deploys a free Cloudflare Worker as HTTPS proxy (100K req/day)
```

### VPS (DigitalOcean / Hetzner)

```bash
nowifi server create -p digitalocean -t do_xxx_token
# Creates $0.007/hr droplet with chisel+iodine+hans pre-installed
```

### Your Own Server

```bash
# On your server:
chisel server --reverse --port 443

# On your laptop (behind portal):
sudo nowifi -t https://your-server.example.com
```

---

## Architecture (Go)

```
cmd/nowifi/main.go         Entry point
internal/
  cli/                     Cobra commands (audit, diagnose, crack, tools, ...)
  detect/                  Portal detection: canary URLs, DNS hijack, vendor fingerprinting
  probe/                   Leak enumeration: DNS, ICMP, IPv6, HTTPS, QUIC, NTP, DoH, ports
  bypass/                  19 bypass techniques, ordered most-powerful-first
  crack/                   WPA cracking: PMKID, handshake, hashcat, WPS, smart crack
  tunnel/                  Tunnel management: chisel, iodine, hans, hysteria
  platform/                OS abstraction: macOS (darwin.go) / Linux (linux.go)
  report/                  Terminal, markdown, and JSON report generation
  toolchain/               External tool discovery, auto-download, version management
  server/                  Cloudflare Workers + VPS provisioning (DO, Hetzner)
  config/                  Persistent config (~/.nowifi/config.json)
  capture/                 Audit trail storage (~/.nowifi/captures/)
  guard/                   State restoration on exit (MAC, proxy, DNS)
  monitor/                 WiFi monitor mode management
  discover/                WiFi network scanning
  portal/                  Auto-login to known portal types
  clone/                   MAC address cloning
  inflight/                Airline portal intelligence: 7 provider profiles, 50+ airlines
  ui/                      Web dashboard + menubar app
```

---

## Responsible Use

This tool is for **authorized security assessments** of captive portal implementations.

- **Only test networks you own or have explicit written authorization to test.** Unauthorized access to computer networks is illegal in most jurisdictions (e.g., CFAA in the US, Computer Misuse Act in the UK, Rikoslaki 38:8 in Finland).
- **Deauthentication attacks** (technique #22, WPA handshake capture) actively interfere with other users' connections. This may violate telecommunications regulations even on networks you own, if it affects third parties.
- **MAC cloning** another device's address takes over their authenticated session, disconnecting them. Only use this in controlled lab environments or with explicit consent.
- **Session cookie replay** involves capturing other users' network traffic. This may violate wiretapping laws in your jurisdiction.

The authors accept no liability for misuse. This tool is published for defensive research, security assessment, and education.

---

## License

[AGPL-3.0](LICENSE) -- Copyright (C) 2026 Mikko Parkkola
