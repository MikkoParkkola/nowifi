# nowifi -- Setup for AI Assistants

> `nowifi` is a standalone CLI tool, NOT an MCP server. There are no MCP tools to register.

## What To Do

You are setting up `nowifi` -- a captive portal bypass tool. One command, 27 techniques, browser works immediately.

### Step 1: Install

```bash
brew install MikkoParkkola/tap/nowifi
```

Pre-built binary, no toolchain needed. If Homebrew is not available:

```bash
# macOS Apple Silicon
curl -L https://github.com/MikkoParkkola/nowifi/releases/latest/download/nowifi-darwin-arm64.tar.gz | tar xz
sudo install -m 0755 nowifi-darwin-arm64 /usr/local/bin/nowifi
```

### Step 2: Run

```bash
# Full bypass -- detect portal, probe, bypass, maintain, restore on exit
sudo nowifi

# Read-only assessment (no changes to network)
nowifi diagnose

# Check what external tools are installed
nowifi tools
```

That is it. `nowifi` auto-detects the captive portal, probes for weaknesses, tries 19 bypass techniques (most powerful first), stops on the first one that works, and maintains your connection until `Ctrl+C`. All network changes are restored on exit.

---

## Commands

| Command | What it does |
|---------|-------------|
| `sudo nowifi` | Full bypass: detect, probe, bypass, maintain, restore on exit |
| `sudo nowifi -p` | Probe only -- find leaks without exploiting them |
| `sudo nowifi --fast` | Skip stealth timing (faster but more detectable) |
| `sudo nowifi -t URL` | Use a specific chisel tunnel server |
| `nowifi diagnose` | Read-only security assessment |
| `nowifi diagnose -r json` | Assessment as JSON |
| `nowifi crack` | WPA/WPA2 password cracking (8 techniques) |
| `nowifi scan` | Scan nearby WiFi networks |
| `nowifi watch` | Maintain access -- auto-reconnect on session expiry |
| `nowifi score` | Grade nearby networks A-F |
| `nowifi tools` | Show installed/missing external tools |
| `nowifi tools -d` | Auto-download missing tools (chisel, hysteria, cloudflared) |
| `nowifi server create` | Create a tunnel server (CF Worker or VPS) |
| `nowifi doctor` | System health check |
| `nowifi ui` | Launch web dashboard |
| `sudo nowifi reset` | Emergency network reset after crash |

## 27 Techniques

**Portal Bypass (19)**: IPv6 bypass, HTTPS/WS tunnel, CNA User-Agent spoof, JS-only bypass, HTTP CONNECT abuse, MAC clone (idle), MAC clone (any), DNS tunnel, ICMP tunnel, VPN on port 53, whitelist domain, session cookie replay, portal default creds, MAC rotate, DHCP rotate, QUIC tunnel, CF Workers proxy, NTP tunnel, DoH tunnel.

**WPA Cracking (4)**: PMKID capture, WPS Pixie-Dust, handshake capture + hashcat, WPS PIN brute force.

**Smart Cracking (4)**: Common passwords, numeric mask, word+number rules, online brute force.

Techniques run in order of power. The tool stops on the first success.

## Optional External Tools

Most techniques work out of the box. Tunnel and cracking techniques need external tools:

| Tool | Unlocks | Install |
|------|---------|---------|
| chisel | HTTPS/WS tunnel | `nowifi tools -d` |
| hysteria | QUIC tunnel | `nowifi tools -d` |
| cloudflared | DoH tunnel | `nowifi tools -d` |
| iodine | DNS tunnel | `brew install iodine` |
| hashcat | WPA cracking (GPU) | `brew install hashcat` |
| aircrack-ng | WPA cracking (CPU) | `brew install aircrack-ng` |

## Important Notes

- Requires `sudo` for bypass and crack commands (network changes need root).
- `Ctrl+C` always restores original MAC, proxy, DNS, TTL, and PF rules.
- Inflight WiFi profiles for 7 providers (Panasonic, Gogo, Viasat, etc.) covering 40+ airlines.
- This is for authorized security assessments only.

## Source

- GitHub: https://github.com/MikkoParkkola/nowifi
- License: AGPL-3.0
