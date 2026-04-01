# nowifi

### No WiFi? Now WiFi.

One command. 23 bypass techniques. Browser works immediately.

```bash
pip install -e .
sudo nowifi
```

Stuck behind a hotel/airport/cafe WiFi login page? `nowifi` detects the captive portal, probes for weaknesses, and tries 19 bypass techniques automatically -- most powerful first, stops on the first one that works. Your browser works immediately. `Ctrl+C` restores everything.

Need the actual WiFi password instead? `nowifi crack` runs a 4-step WPA cracking pipeline with 4 more techniques.

---

## 30-Second Quickstart

```bash
# Install
git clone https://github.com/yourusername/nowifi.git
cd nowifi
pip install -e .

# Run (needs sudo for MAC address and proxy changes)
sudo nowifi
```

That's it. nowifi will:
1. Detect the captive portal type and vendor
2. Probe every protocol for leaks (DNS, ICMP, IPv6, HTTPS, QUIC, NTP, DoH, 25+ ports)
3. Try all 19 bypass techniques, stop on the first success
4. Auto-configure your system so the browser works with zero manual steps
5. Print a security report with findings and remediation advice

---

## What It Does

```
              You're stuck behind a captive portal
                            |
                    +-------v-------+
                    |   1. DETECT   |  Identify portal type + vendor
                    +-------+-------+  (Meraki, Aruba, UniFi, etc.)
                            |
                    +-------v-------+
                    |   2. PROBE    |  Test every protocol for leaks
                    +-------+-------+  (DNS, ICMP, IPv6, QUIC, NTP, DoH,
                            |          whitelisted domains, 25+ TCP ports)
                    +-------v-------+
                    |   3. BYPASS   |  Try 19 techniques, most powerful first
                    +-------+-------+  Stop on first success
                            |
                    +-------v-------+
                    |   4. REPORT   |  Security findings + remediation advice
                    +---------------+  (terminal, markdown, or JSON)
```

**Detect** identifies the captive portal type (HTTP redirect, DNS hijack, firewall block, transparent proxy, walled garden) and fingerprints the vendor (Cisco Meraki, Aruba, Ruckus, UniFi, MikroTik, Fortinet, pfSense, OpenNDS, CoovaChilli, Nomadix). It also detects authentication methods (email, password, social login, voucher, terms-only).

**Probe** enumerates every leak in the portal's pre-auth firewall with stealth: randomized order, jitter between probes, and small parallel batches to avoid IDS detection. It also stealth-scans your tunnel server to find which ports pass through.

**Bypass** tries all 19 techniques in order. Tunnel-based bypasses auto-configure the system SOCKS proxy so your browser works without any manual steps. Non-tunnel bypasses (MAC clone, IPv6) work directly.

**Report** produces a terminal report with probe results, bypass outcomes, severity ratings, impact descriptions, and remediation advice. Also supports markdown (`-r markdown`) and JSON (`-r json`) for pentest reports.

---

## All Commands

| Command | What it does |
|---------|-------------|
| `sudo nowifi` | Run full audit: detect, probe, bypass, report |
| `sudo nowifi -p` | Probe only -- find leaks without exploiting them |
| `sudo nowifi --fast` | Skip stealth timing (faster but more detectable) |
| `sudo nowifi -t URL` | Use a specific chisel tunnel server |
| `sudo nowifi -i en1` | Use a different WiFi interface (default: `en0`) |
| `nowifi diagnose` | Read-only security assessment (no changes to network) |
| `nowifi diagnose -r json -o report.json` | Save diagnosis as JSON file |
| `nowifi crack` | WPA/WPA2 cracking (PMKID + handshake + hashcat) |
| `nowifi crack --scan-only` | Scan for WiFi networks without attacking |
| `nowifi tools` | Show which external tools are installed/missing |
| `nowifi tools -d` | Auto-download missing tools (chisel, hysteria, cloudflared) |
| `nowifi ui` | Launch web dashboard in browser |
| `nowifi menubar` | Launch macOS menubar app |
| `nowifi ecosystem` | Show complementary tools (bettercap, wifiphisher, etc.) |
| `sudo nowifi reset` | Emergency network reset after crash/kill |
| `nowifi --version` | Show version |

### Full Option Reference

```
sudo nowifi [OPTIONS]

Options:
  -i, --interface TEXT       WiFi interface (default: en0)
  -t, --tunnel-server TEXT   Chisel tunnel endpoint (default: https://spark.raxor.ai)
  -d, --dns-domain TEXT      DNS tunnel domain (for iodine)
  --icmp-server TEXT         ICMP tunnel server IP (for hans)
  --cf-workers TEXT          Cloudflare Workers proxy URL
  --quic-server TEXT         QUIC/Hysteria2 server address
  --ntp-server TEXT          NTP tunnel server IP
  --stealth / --fast         Stealth timing vs fast (default: stealth)
  -p, --probe-only           Probe only, don't exploit
  --version                  Show version
```

---

## Bypass Techniques

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

| # | Technique | How it works | Severity |
|---|-----------|-------------|----------|
| 20 | **PMKID capture** | Extract PMKID from AP's first message -- no clients needed (~60% of APs) | High |
| 21 | **WPS Pixie-Dust** | Exploit weak RNG in WPS (~30% of WPS-enabled APs, 5-30s) | High |
| 22 | **Handshake capture + hashcat** | Deauth a client, capture 4-way handshake, GPU crack | High |
| 23 | **WPS PIN brute force** | Brute force 11,000 PIN combinations (2-10 hours, last resort) | Medium |

---

## Installation

### macOS

```bash
# Python 3.11+ required
brew install python@3.12   # if you don't have Python 3.11+

# Install nowifi
git clone https://github.com/yourusername/nowifi.git
cd nowifi
pip install -e .
```

### Linux (Ubuntu/Kali)

```bash
# Python 3.11+ required
sudo apt update
sudo apt install python3 python3-pip python3-venv

# Install nowifi
git clone https://github.com/yourusername/nowifi.git
cd nowifi
pip install -e .
```

The default WiFi interface on Linux is `wlan0` instead of `en0`:

```bash
sudo nowifi -i wlan0
```

### Optional Dependencies

For the GUI dashboard and menubar app:

```bash
pip install -e ".[gui]"     # NiceGUI dashboard + macOS menubar
```

For all optional features (GUI + packet inspection + SOCKS):

```bash
pip install -e ".[full]"    # Adds scapy, beautifulsoup4, pysocks
```

### External Tools (Optional)

External tools unlock additional bypass and cracking techniques. Without them, nowifi still works -- it just skips the techniques that need them.

Check what's installed:

```bash
nowifi tools
```

Auto-download tools that support it (chisel, hysteria, cloudflared):

```bash
nowifi tools -d
```

This downloads binaries to `~/.nowifi/bin/`.

**Full tool list:**

| Tool | Unlocks | Install |
|------|---------|---------|
| chisel | HTTPS/WS tunnel (#2) | `nowifi tools -d` or `brew install chisel` |
| iodine | DNS tunnel (#8) | `brew install iodine` |
| hans | ICMP tunnel (#9) | `brew install hans` |
| wg-quick | VPN on port 53 (#10) | `brew install wireguard-tools` |
| hysteria | QUIC tunnel (#16) | `nowifi tools -d` or `brew install hysteria` |
| ntpescape | NTP tunnel (#18) | Build from [github.com/evallen/ntpescape](https://github.com/evallen/ntpescape) |
| cloudflared | DoH tunnel (#19) | `nowifi tools -d` or `brew install cloudflared` |
| dnscrypt-proxy | DoH tunnel (#19) | `brew install dnscrypt-proxy` |
| hashcat | WPA cracking (GPU) | `brew install hashcat` |
| hcxdumptool | PMKID/handshake capture | `brew install hcxdumptool` |
| hcxpcapngtool | Convert captures for hashcat | `brew install hcxtools` |
| aircrack-ng | WPA cracking (CPU fallback) | `brew install aircrack-ng` |
| reaver | WPS Pixie-Dust/PIN attacks | `brew install reaver` |

On Linux (Ubuntu/Kali), replace `brew install` with `sudo apt install` for most tools.

---

## Setup (For Tunnel Bypass)

Many bypass techniques (MAC clone, IPv6, CNA spoof, JS bypass, MAC rotate, DHCP rotate) work without any server. They run entirely locally.

Tunnel-based bypasses (techniques #2, #8, #9, #10, #16, #18, #19) need a server you control outside the captive portal's network. Here's how to set up the most common one:

### Chisel (Recommended)

Chisel creates a WebSocket tunnel over HTTPS -- the highest bandwidth option and the hardest for portals to detect.

**On your server** (a VPS, cloud VM, or home server with a public IP):

```bash
# Install chisel
curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > /usr/local/bin/chisel
chmod +x /usr/local/bin/chisel

# Run it (port 443 works best -- looks like normal HTTPS)
chisel server --reverse --port 443
```

**On your laptop** (behind the captive portal):

```bash
# nowifi auto-connects to the tunnel server
sudo nowifi -t https://your-server.example.com
```

That's it. nowifi will try the chisel tunnel as technique #2 and auto-configure your system SOCKS proxy if it works.

### Other Tunnel Servers

**DNS tunnel** (iodine -- works when only DNS passes through):

```bash
# Server: iodined -f 10.0.0.1 t.example.com
# Laptop:
sudo nowifi -d t.example.com
```

**ICMP tunnel** (hans -- works when only ping passes through):

```bash
# Server: hans -s 10.0.0.1 -f
# Laptop:
sudo nowifi --icmp-server YOUR_SERVER_IP
```

**QUIC tunnel** (Hysteria2 -- works when UDP/443 passes through):

```bash
# Server: hysteria server --listen :443
# Laptop:
sudo nowifi --quic-server your-server:443
```

**NTP tunnel** (ntpescape -- works when UDP/123 passes through):

```bash
# Server: ntpescape server
# Laptop:
sudo nowifi --ntp-server YOUR_SERVER_IP
```

---

## GUI

### Web Dashboard (Cross-Platform)

```bash
nowifi ui
```

Opens a dark-themed web dashboard at `http://127.0.0.1:8321` with:
- Live probe results as they come in
- Bypass status and active tunnel monitoring
- One-click Run Audit, Probe Only, and Reset Network buttons
- Log console showing everything nowifi is doing

Specify a different port with `--port`:

```bash
nowifi ui --port 9000
```

### macOS Menubar App

```bash
nowifi menubar
```

Adds a "NW" icon to your macOS menu bar with:
- **Run Audit** -- full audit in the background
- **Probe Only** -- enumerate leaks without exploiting
- **Open Dashboard** -- opens the web UI in your browser
- **Reset Network** -- emergency cleanup

Audits run in the background with macOS notifications on completion.

---

## Diagnosis Mode (Read-Only)

```bash
nowifi diagnose
```

Scans everything but changes nothing. No MAC spoofing, no tunnels, no proxy changes. Pure read-only assessment that tells you which of the 23 bypass methods *would* work on this network.

Use this when you want to assess a network's security without actually exploiting anything.

```bash
# Terminal output (default)
nowifi diagnose

# Save as markdown report
nowifi diagnose -r markdown -o report.md

# Save as JSON (for automated processing)
nowifi diagnose -r json -o findings.json
```

The diagnosis shows:
- Portal detection results (type, vendor, auth methods)
- Protocol analysis (which protocols are open/closed)
- Feasibility assessment for all 23 methods with confidence levels
- Which external tools are installed vs missing
- A summary verdict ("12/23 methods feasible" or "Secure -- no methods feasible")

---

## WPA Cracking

```bash
sudo nowifi crack
```

When you don't have the WiFi password at all, `nowifi crack` runs a 4-step pipeline:

1. **Scan** -- find nearby WiFi networks, show signal strength and security
2. **PMKID capture** -- try to extract PMKID from the AP (works on ~60% of APs, no clients needed)
3. **Handshake capture** -- deauth a connected client to capture the 4-way handshake
4. **Crack** -- run hashcat (GPU) or aircrack-ng (CPU fallback) against the capture

```bash
# Scan networks without attacking
sudo nowifi crack --scan-only

# Target a specific network
sudo nowifi crack -t "CoffeeShop_WiFi"

# Use a specific wordlist
sudo nowifi crack -w ~/wordlists/rockyou.txt

# Set capture timeout (default: 300 seconds)
sudo nowifi crack --timeout 600
```

**Important: macOS users need an external USB WiFi adapter** for WPA cracking. The built-in card does not support monitor mode, which is required for packet capture. Recommended: Alfa AWUS036ACH with RTL8812AU chipset.

On Linux (Kali), the built-in card usually works.

---

## Complementary Tools

```bash
nowifi ecosystem
```

Shows tools that complement nowifi for deeper assessments:

| Tool | What it does | When to use |
|------|-------------|-------------|
| bettercap | MITM, ARP spoofing, network topology | After nowifi gets you on the network |
| wifiphisher | Evil twin, rogue AP, credential phishing | When you need to clone a portal (Linux) |
| eaphammer | WPA2-Enterprise, 802.1X, GTC downgrade | Enterprise WiFi with RADIUS/EAP |
| kismet | Passive WiFi/BT/Zigbee reconnaissance | Full spectrum passive monitoring |
| Wireshark | Deep packet capture and analysis | Analyzing traffic after getting access |
| Responder | LLMNR/NBT-NS poisoning, NTLMv2 capture | Harvesting Windows credentials on WiFi |
| mitm6 | IPv6 RA attacks, DHCPv6 poisoning | When IPv6 is enabled on the network |
| Nmap | Network scanning, service detection | Mapping the network after gaining access |

Typical workflow: `nowifi` (get access) -> `nmap` (map network) -> `bettercap` (MITM) -> `Wireshark` (analyze).

---

## Troubleshooting

### "Not connected on en0"

Make sure WiFi is turned on and you're connected to a network. Check your interface name:

```bash
# macOS: list interfaces
networksetup -listallhardwareports

# Linux: list interfaces
ip link show
```

Your WiFi might be `en1` or `wlan0` instead of `en0`:

```bash
sudo nowifi -i en1       # macOS alternate interface
sudo nowifi -i wlan0     # Linux
```

### "Need sudo" / "Operation not permitted"

MAC address changes, proxy configuration, and tunnel setup require root privileges:

```bash
sudo nowifi              # Full audit
```

Probe-only mode and diagnosis work without sudo for most checks, but some probes (ICMP) may need it:

```bash
nowifi diagnose          # Works without sudo
sudo nowifi -p           # Full probe accuracy with sudo
```

### "Tool not found: chisel" (or iodine, hans, etc.)

Auto-download supported tools:

```bash
nowifi tools -d
```

This downloads chisel, hysteria, and cloudflared to `~/.nowifi/bin/`. For tools that need system packages (iodine, hans, hashcat):

```bash
# macOS
brew install iodine hans hashcat

# Linux
sudo apt install iodine hashcat
```

### "Monitor mode not supported"

macOS's built-in WiFi card (en0) does not support monitor mode. For WPA cracking (`nowifi crack`), you need an external USB WiFi adapter.

Recommended adapters:
- **Alfa AWUS036ACH** (RTL8812AU) -- dual-band, best Linux/macOS support
- **Alfa AWUS036ACHM** (RTL8812AU) -- smaller form factor
- **Panda PAU09** (RT5572) -- budget option, good Linux support

On Linux (Kali), the built-in card usually supports monitor mode.

### "Portal detected but no bypass worked"

Try these in order:

1. **Run with `--fast`** to try all techniques quickly:
   ```bash
   sudo nowifi --fast
   ```

2. **Check what's open** with diagnosis mode:
   ```bash
   nowifi diagnose
   ```

3. **Set up a tunnel server** (see [Setup](#setup-for-tunnel-bypass) above) -- most bypasses need a server you control.

4. **Install missing tools** -- some techniques are skipped when tools aren't installed:
   ```bash
   nowifi tools -d
   ```

5. **Try a specific tunnel type** if you know which protocol is open:
   ```bash
   sudo nowifi -d t.example.com           # DNS tunnel
   sudo nowifi --icmp-server 1.2.3.4      # ICMP tunnel
   sudo nowifi --quic-server srv:443      # QUIC tunnel
   ```

### Browser still not working after bypass

1. **Check system proxy settings.** nowifi auto-configures SOCKS proxy for tunnel bypasses. If something went wrong:
   ```bash
   # macOS: check proxy
   networksetup -getsocksfirewallproxy Wi-Fi
   ```

2. **Reset and retry:**
   ```bash
   sudo nowifi reset
   sudo nowifi
   ```

3. **Try a different browser.** Some browsers (especially Firefox) use their own proxy settings instead of the system proxy.

4. **Flush DNS** if pages aren't loading even though the tunnel is active:
   ```bash
   # macOS
   sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
   # Linux
   sudo systemd-resolve --flush-caches
   ```

---

## Cleanup & Uninstall

### Emergency Reset

If nowifi was killed hard (`kill -9`, power loss, laptop lid close) and your network is broken:

```bash
sudo nowifi reset
```

This will:
- Kill orphaned tunnel processes (chisel, iodine, hans, hysteria, ntpescape, dnscrypt-proxy)
- Remove the system SOCKS proxy
- Restore your hardware MAC address
- Flush DNS cache
- Power-cycle WiFi (off and back on)
- Renew DHCP lease

### Cleanup Guarantee

Under normal circumstances, you never need `reset`. **StateGuard** ensures the system returns to its pre-nowifi state on exit, no matter what:

- **Normal exit** -- restores MAC, removes proxy, stops tunnels, flushes DNS
- **Ctrl+C** -- signal handler triggers full restoration
- **SIGTERM** -- same as Ctrl+C
- **Unhandled exceptions** -- context manager `__exit__` cleans up
- **atexit** -- registered as a last-resort fallback

### Full Uninstall

```bash
pip uninstall nowifi
rm -rf ~/.nowifi            # Remove downloaded tools
```

---

## For Security Researchers

This tool is designed for **authorized security assessments** of captive portal implementations. Use it to:

- Audit your organization's guest WiFi for bypass vulnerabilities
- Verify that captive portal ACLs cover IPv6, UDP, ICMP, and DNS
- Test whether MAC-based auth is resilient to clone attacks
- Check for default credentials on portal admin interfaces
- Validate that session cookies use HTTPS and Secure flag
- Confirm that DPI catches WebSocket, QUIC, and DNS tunnel traffic

**Responsible use:** Only test networks you own or have explicit written authorization to test. Unauthorized access to computer networks is illegal in most jurisdictions. The bypass techniques in this tool exploit real vulnerabilities -- report findings to the network operator and give them time to remediate before any public disclosure.

---

## Architecture

```
cli.py              Entry point, Click commands, orchestrates the 4 phases
  |
  +-- detect.py         Portal detection: canary URLs, DNS hijack, vendor fingerprinting
  +-- probe.py          Leak enumeration: DNS, ICMP, IPv6, HTTPS, QUIC, NTP, DoH, ports
  +-- bypass.py         19 bypass techniques, ordered most-powerful-first
  |     +-- tunnel.py       Tunnel management: chisel, iodine, hans, hysteria, ntpescape
  |     +-- platform.py     OS abstraction (auto-selects mac/linux)
  |       +-- platform_mac.py    MAC spoofing, WiFi control, ARP table, StateGuard (macOS)
  |       +-- platform_linux.py  Same operations via ip/iw/nmcli (Linux)
  +-- crack.py          WPA cracking: PMKID, handshake, hashcat, aircrack-ng, WPS
  +-- monitor.py        Monitor mode management (enable/disable, guard context manager)
  +-- diagnose.py       Read-only assessment: feasibility of all 23 methods
  +-- report.py         Terminal (rich), markdown, and JSON report generation
  +-- toolchain.py      External tool discovery, auto-download, version management
  +-- gui_web.py        NiceGUI web dashboard (cross-platform)
  +-- gui_menubar.py    macOS menubar app (rumps)
```

---

## License

MIT
