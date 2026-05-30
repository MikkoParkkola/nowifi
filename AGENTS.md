# nowifi -- Setup for AI Assistants

> `nowifi` is a standalone CLI tool, NOT an MCP server. There are no MCP tools to register.

## What To Do

You are setting up `nowifi` -- a captive portal bypass tool. One command, 43 techniques, browser works immediately.

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

That is it. `nowifi` auto-detects the captive portal, probes for weaknesses, tries 35 bypass techniques (most powerful first), stops on the first one that works, and maintains your connection until `Ctrl+C`. All network changes are restored on exit.

---

## Commands

| Command | What it does |
|---------|-------------|
| `sudo nowifi` | Full bypass: detect, probe, bypass, maintain, restore on exit |
| `sudo nowifi -p` | Probe only -- find leaks without exploiting them |
| `sudo nowifi --fast` | Skip stealth timing (faster but more detectable) |
| `sudo nowifi -t URL` | Use a specific chisel tunnel server |
| `sudo nowifi --masque-server URL` | MASQUE tunnel via HTTP/3 Extended CONNECT |
| `sudo nowifi --grpc-server URL` | gRPC bidi streaming tunnel |
| `sudo nowifi --connectip-server URL` | CONNECT-IP full IP tunnel (TUN device) |
| `nowifi diagnose` | Read-only security assessment |
| `nowifi diagnose -r json` | Assessment as JSON |
| `nowifi forensics` | Capture a portable forensic package of which egress channels survive enforcement (read-only, no sudo, local-only) |
| `nowifi report` | Review/submit queued reports from environments nowifi could not bypass (consent-gated GitHub issue) |
| `nowifi crack` | WPA/WPA2 password cracking (8 techniques) |
| `nowifi scan` | Scan nearby WiFi networks |
| `nowifi watch` | Maintain access -- auto-reconnect on session expiry |
| `nowifi score` | Grade nearby networks A-F |
| `nowifi tools` | Show installed/missing external tools |
| `nowifi tools -d` | Auto-download missing tools (chisel, hysteria, cloudflared) |
| `nowifi server listen` | Run a tunnel server (6 modes: quic/h3/h2/sse/grpc/connectip) |
| `nowifi doctor` | System health check |
| `nowifi ui` | Launch web dashboard |
| `sudo nowifi reset` | Emergency network reset after crash |

## 43 Techniques

**Portal Bypass (35)**: IPv6 bypass, HTTPS/WS tunnel, CNA User-Agent spoof, JS-only bypass, HTTP CONNECT abuse, MAC clone (idle), MAC clone (any), DNS tunnel, ICMP tunnel, VPN on port 53, whitelist domain, session cookie replay, portal default creds, MAC rotate, DHCP rotate, QUIC tunnel, CF Workers proxy, NTP tunnel, DoH tunnel, CAPPORT session extend, DoQ tunnel, HTTP/3 tunnel, DHCP route bypass, ECH domain fronting, WireGuard-over-WebSocket, secondary interface bypass, MASQUE tunnel, WebTransport tunnel, HTTP/2 CONNECT tunnel, SSE streaming tunnel, gRPC bidi streaming tunnel, CONNECT-IP tunnel, Cloudflare WARP tunnel, portal self-relay, TURN relay.

**WPA Cracking (4)**: PMKID capture, WPS Pixie-Dust, handshake capture + hashcat, WPS PIN brute force.

**Smart Cracking (4)**: Common passwords, numeric mask, word+number rules, online brute force.

Techniques run in order of power. The tool stops on the first success.

## Server Modes

`nowifi server listen --mode <mode>` runs a tunnel server:

| Mode | Protocol | Looks like |
|------|----------|------------|
| `quic` | Raw QUIC bidi streams | Generic QUIC |
| `h3` | MASQUE + WebTransport | Google Meet / Apple Private Relay |
| `h2` | HTTP/2 CONNECT proxy | gRPC / Cloud API |
| `sse` | Server-Sent Events relay | News feed / chat stream |
| `grpc` | gRPC bidi streaming | Kubernetes API / microservices |
| `connectip` | CONNECT-IP (RFC 9484) | Apple Private Relay / iCloud+ |

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
