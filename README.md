# nowifi -- No WiFi? Now WiFi.

WiFi security assessment tool. One command, 19 bypass techniques, browser works immediately.

## Quick Start

```bash
pip install -e .
sudo nowifi
```

That's it. Detects the portal, probes for leaks, tries every bypass technique from most powerful to least. Stops on the first one that works. Browser works immediately. Ctrl+C restores everything.

## What It Does

Four phases, fully automatic:

1. **Detect** -- Identifies the captive portal type (HTTP redirect, DNS hijack, firewall block, transparent proxy, walled garden) and fingerprints the vendor (Cisco Meraki, Aruba, Ruckus, UniFi, MikroTik, Fortinet, pfSense, OpenNDS, CoovaChilli, Nomadix). Detects auth methods (email, password, social login, voucher, terms-only).

2. **Probe** -- Enumerates every leak in the portal's pre-auth firewall. Tests DNS (Cloudflare, Google, Quad9), ICMP, IPv6, HTTPS, QUIC (UDP/443), NTP (UDP/123), DNS-over-HTTPS, 10 commonly whitelisted domains, and 25+ TCP ports. Stealth mode uses randomized order, jitter between probes, and small parallel batches to avoid IDS detection. Also stealth-scans your tunnel server to find which ports pass through.

3. **Bypass** -- Tries all 19 techniques in order (most powerful first), stops on the first success. Tunnel-based bypasses auto-configure the system SOCKS proxy so the browser works without any manual steps. Non-tunnel bypasses (MAC clone, IPv6) work directly.

4. **Report** -- Produces a rich terminal report with probe results, bypass outcomes, severity ratings, impact descriptions, and remediation advice. Also supports markdown and JSON output for pentest reports.

## 19 Bypass Techniques

| # | Technique | How it works | Severity |
|---|-----------|-------------|----------|
| 1 | **IPv6 bypass** | Portal only filters IPv4; IPv6 passes unfiltered | Critical |
| 2 | **HTTPS/WS tunnel** | Chisel WebSocket tunnel through Cloudflare to your server | Critical |
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

## GUI

**Web dashboard** (cross-platform):

```bash
nowifi ui
```

Opens a NiceGUI web dashboard at `http://127.0.0.1:8321` with live probe results, bypass status, and a log console. Run Audit, Probe Only, or Reset Network with one click.

**macOS menubar app**:

```bash
nowifi menubar
```

Adds a menubar icon with Run Audit, Probe Only, Open Dashboard, and Reset Network. Runs audits in the background with macOS notifications on completion.

## Server Setup

For tunnel-based bypasses (chisel, DNS tunnel, ICMP tunnel, QUIC, NTP), you need a server outside the captive portal's network.

**Chisel** (recommended -- works with HTTPS/WebSocket, highest bandwidth):

```bash
# On your server:
chisel server --reverse --port 443

# nowifi connects automatically using --tunnel-server (defaults to https://spark.raxor.ai)
sudo nowifi --tunnel-server https://your-server.example.com
```

**DNS tunnel** (iodine -- works when only DNS passes through):

```bash
# On your server:
iodined -f 10.0.0.1 t.example.com

# On your laptop:
sudo nowifi --dns-domain t.example.com
```

**ICMP tunnel** (hans -- works when only ping passes through):

```bash
# On your server:
hans -s 10.0.0.1 -f

# On your laptop:
sudo nowifi --icmp-server YOUR_SERVER_IP
```

**QUIC tunnel** (Hysteria2 -- works when UDP/443 passes through):

```bash
# On your server:
hysteria server --listen :443

# On your laptop:
sudo nowifi --quic-server your-server:443
```

**NTP tunnel** (ntpescape -- works when UDP/123 passes through):

```bash
# On your server:
ntpescape server

# On your laptop:
sudo nowifi --ntp-server YOUR_SERVER_IP
```

## Commands

```
sudo nowifi                Run full audit (detect, probe, bypass, report)
sudo nowifi -p             Probe only -- enumerate leaks without exploiting
sudo nowifi --fast         Skip stealth timing (faster, but more detectable)
sudo nowifi -t URL         Use a specific chisel tunnel server
sudo nowifi -d DOMAIN      Set DNS tunnel domain for iodine
nowifi ui                  Launch web dashboard in browser
nowifi menubar             Launch macOS menubar app
sudo nowifi reset          Reset network to clean state after crash/kill
nowifi --version           Show version
```

## Cleanup Guarantee

**StateGuard** ensures the system returns to its pre-nowifi state on exit, no matter what:

- **Normal exit** -- restores MAC address, removes SOCKS proxy, stops tunnels, flushes DNS
- **Ctrl+C** -- signal handler triggers full restoration before exit
- **SIGTERM** -- same as Ctrl+C
- **Exceptions** -- context manager `__exit__` restores everything
- **atexit** -- registered as a last-resort fallback

If nowifi was killed hard (`kill -9`, power loss, crash), run:

```bash
sudo nowifi reset
```

This kills orphaned tunnel processes (chisel, iodine, hans, hysteria, ntpescape, dnscrypt-proxy), removes the system SOCKS proxy, restores the hardware MAC, flushes DNS, power-cycles WiFi, and renews DHCP.

## For Security Researchers

This tool is designed for **authorized security assessments** of captive portal implementations. Use it to:

- Audit your organization's guest WiFi for bypass vulnerabilities
- Verify that captive portal ACLs cover IPv6, UDP, ICMP, and DNS
- Test whether MAC-based auth is resilient to clone attacks
- Check for default credentials on portal admin interfaces
- Validate that session cookies use HTTPS and Secure flag
- Confirm that DPI catches WebSocket, QUIC, and DNS tunnel traffic

**Responsible use**: Only test networks you own or have explicit written authorization to test. Unauthorized access to computer networks is illegal in most jurisdictions. The bypass techniques in this tool exploit real vulnerabilities -- report findings to the network operator and give them time to remediate before any public disclosure.

## Architecture

```
cli.py          Entry point, Click commands, orchestrates the 4 phases
  |
  +-- detect.py       Portal detection: canary URLs, DNS hijack check, vendor fingerprinting
  +-- probe.py        Leak enumeration: DNS, ICMP, IPv6, HTTPS, QUIC, NTP, DoH, ports, whitelists
  +-- bypass.py       19 bypass techniques, ordered most-powerful-first
  |     +-- tunnel.py       Tunnel management: chisel, iodine, hans, hysteria, ntpescape, cloudflared
  |     +-- platform_mac.py MAC spoofing, WiFi control, ARP table, StateGuard
  +-- report.py       Terminal (rich), markdown, and JSON report generation
  +-- gui_web.py      NiceGUI web dashboard (cross-platform)
  +-- gui_menubar.py  macOS menubar app (rumps)
```

## Requirements

- **macOS 12+** (uses `networksetup`, `system_profiler`, `ifconfig`)
- **Python 3.11+**
- **Core dependencies**: click, requests, rich, dnspython

**Optional tools** (for tunnel bypasses):

| Tool | Bypass | Install |
|------|--------|---------|
| chisel | HTTPS/WS tunnel | `brew install chisel` or `go install github.com/jpillora/chisel@latest` |
| iodine | DNS tunnel | `brew install iodine` |
| hans | ICMP tunnel | `brew install hans` |
| hysteria | QUIC tunnel | `brew install hysteria` |
| ntpescape | NTP tunnel | Build from https://github.com/evallen/ntpescape |
| cloudflared | DoH tunnel | `brew install cloudflared` |
| wg-quick | VPN port 53 | `brew install wireguard-tools` |

**Optional Python packages** (for GUI and advanced features):

```bash
pip install -e ".[gui]"    # NiceGUI dashboard + macOS menubar
pip install -e ".[full]"   # All optional deps (scapy, beautifulsoup4, pysocks)
```

## License

TBD
