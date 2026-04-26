# nowifi Go Rewrite -- Architecture Design Document

> Historical design note: this document captures the original Go rewrite plan.
> Current command behavior and technique counts are maintained in
> [README.md](../README.md) and `internal/techniques`.

**Status:** Draft
**Date:** 2026-03-29
**Author:** Mikko Parkkola
**Python baseline:** v0.1.0 (15 modules, 23 techniques, ~3200 LOC)

---

## 1. Why Go

### 1.1 Distribution Problem

The Python version requires users to have Python 3.11+, pip, venv, and potentially system-level dependencies (dnspython, requests, rich, nicegui, rumps). On a fresh macOS or Linux install, the install path is:

```
brew install python@3.12    # or apt install python3.12
pip install nowifi
nowifi tools -d             # download external binaries
```

This is three commands, assumes Homebrew/apt, and breaks when the system Python is wrong or pip is externally managed (PEP 668). Many security tools are used infrequently and in hostile environments (hotel WiFi, airport, conference) where the user cannot easily debug dependency issues.

### 1.2 Go Solves This

| Property | Python | Go |
|----------|--------|----|
| Install | pip + venv + Python 3.11+ | Single binary, zero deps |
| Startup | ~500ms (interpreter + imports) | ~5ms |
| Cross-compile | PyInstaller (fragile, 50MB+) | `GOOS=linux GOARCH=arm64 go build` |
| Networking | requests + dnspython + socket | net/http + net + miekg/dns (stdlib-quality) |
| Concurrency | threading/asyncio (GIL) | goroutines (native, lightweight) |
| Binary size | N/A (needs interpreter) | ~15-20MB (single static binary) |

### 1.3 Precedent

Every external tool nowifi depends on is already written in Go:
- **chisel** -- HTTPS/WebSocket tunnel (Go)
- **cloudflared** -- Cloudflare tunnel/DoH proxy (Go)
- **hysteria** -- QUIC tunnel (Go)
- **bettercap** -- Network MITM framework (Go)

nowifi should be a peer to these tools, not a Python wrapper that shells out to them.

### 1.4 What Go Cannot Do

- **NiceGUI dashboard** -- No equivalent. Replaced by embedded web UI (Go `embed` + htmx).
- **rumps menubar** -- macOS-only. Replaced by `getlantern/systray` (cross-platform).
- **Rich terminal formatting** -- Replaced by `charmbracelet/lipgloss` + `fatih/color`.

These are acceptable tradeoffs. The functionality is preserved; only the implementation library changes.

---

## 2. Project Structure

```
nowifi/
├── cmd/
│   └── nowifi/
│       └── main.go                 # CLI entry point (cobra root command)
│
├── internal/
│   ├── detect/
│   │   ├── detect.go               # Portal detection (canary checks, consensus)
│   │   ├── fingerprint.go          # Vendor signature database + matching
│   │   ├── auth.go                 # Auth method detection from HTML
│   │   └── detect_test.go
│   │
│   ├── probe/
│   │   ├── probe.go                # ProbeAll orchestrator (stealth jitter, batching)
│   │   ├── dns.go                  # DNS resolver reachability (miekg/dns)
│   │   ├── icmp.go                 # ICMP ping probes
│   │   ├── ipv6.go                 # IPv6 connectivity test
│   │   ├── https.go                # HTTPS reachability (Cloudflare, whitelists)
│   │   ├── quic.go                 # UDP/443 QUIC probe (raw UDP)
│   │   ├── ntp.go                  # UDP/123 NTP probe
│   │   ├── doh.go                  # DNS-over-HTTPS endpoint reachability
│   │   ├── ports.go                # Stealth TCP port scanner (randomized, batched)
│   │   ├── whitelist.go            # Whitelisted domain enumeration
│   │   ├── tunnel_server.go        # DNS beacon + smart scan of user's server
│   │   └── probe_test.go
│   │
│   ├── bypass/
│   │   ├── bypass.go               # Run all 23 techniques in order, stop on success
│   │   ├── types.go                # BypassMethod, Severity, BypassResult, AuditConfig
│   │   ├── ipv6.go                 # Technique 1: IPv6 bypass
│   │   ├── chisel.go               # Technique 2: HTTPS/WS tunnel (chisel)
│   │   ├── cna.go                  # Technique 3: CNA User-Agent spoof
│   │   ├── js.go                   # Technique 4: JS-only enforcement bypass
│   │   ├── connect.go              # Technique 5: HTTP CONNECT abuse
│   │   ├── mac_clone.go            # Techniques 6-7: MAC clone (idle/any)
│   │   ├── dns_tunnel.go           # Technique 8: DNS tunnel (iodine)
│   │   ├── icmp_tunnel.go          # Technique 9: ICMP tunnel (hans)
│   │   ├── vpn53.go                # Technique 10: VPN on port 53
│   │   ├── whitelist.go            # Technique 11: Whitelist domain abuse
│   │   ├── session.go              # Technique 12: Session cookie replay
│   │   ├── default_creds.go        # Technique 13: Portal default credentials
│   │   ├── mac_rotate.go           # Technique 14: MAC rotate (fresh identity)
│   │   ├── dhcp.go                 # Technique 15: DHCP rotate
│   │   ├── quic_tunnel.go          # Technique 16: QUIC tunnel (Hysteria2)
│   │   ├── cf_workers.go           # Technique 17: Cloudflare Workers proxy
│   │   ├── ntp_tunnel.go           # Technique 18: NTP tunnel
│   │   ├── doh_tunnel.go           # Technique 19: DoH tunnel
│   │   ├── pmkid.go                # Technique 20: WPA PMKID capture
│   │   ├── wps_pixie.go            # Technique 21: WPS Pixie-Dust
│   │   ├── handshake.go            # Technique 22: WPA handshake capture + crack
│   │   ├── wps_pin.go              # Technique 23: WPS PIN brute force
│   │   ├── proxy.go                # System SOCKS proxy management
│   │   └── bypass_test.go
│   │
│   ├── crack/
│   │   ├── crack.go                # Full cracking pipeline (run_crack)
│   │   ├── scan.go                 # WiFi network scanning (macOS + Linux)
│   │   ├── pmkid.go                # PMKID capture via hcxdumptool
│   │   ├── handshake.go            # Handshake capture (hcx / aircrack-ng)
│   │   ├── hashcat.go              # GPU-accelerated cracking
│   │   ├── aircrack.go             # CPU fallback cracking
│   │   ├── wps.go                  # WPS Pixie-Dust + PIN brute force
│   │   ├── wordlist.go             # Wordlist discovery
│   │   └── crack_test.go
│   │
│   ├── tunnel/
│   │   ├── tunnel.go               # TunnelHandle, start/stop/verify
│   │   ├── chisel.go               # Chisel client management
│   │   ├── dns.go                  # iodine DNS tunnel
│   │   ├── icmp.go                 # hans ICMP tunnel
│   │   ├── quic.go                 # Hysteria2 QUIC tunnel
│   │   ├── ntp.go                  # ntpescape NTP tunnel
│   │   ├── doh.go                  # cloudflared / dnscrypt-proxy DoH
│   │   ├── cf_workers.go           # Cloudflare Workers proxy verification
│   │   └── tunnel_test.go
│   │
│   ├── monitor/
│   │   ├── monitor.go              # Enable/disable monitor mode
│   │   ├── guard.go                # MonitorGuard (context-manager equivalent)
│   │   ├── monitor_linux.go        # Linux: airmon-ng / iw
│   │   ├── monitor_darwin.go       # macOS: external adapter only
│   │   └── monitor_test.go
│   │
│   ├── platform/
│   │   ├── platform.go             # Interface (WifiInfo, ArpEntry, etc.)
│   │   ├── platform_darwin.go      # macOS: networksetup, system_profiler, ifconfig
│   │   ├── platform_linux.go       # Linux: nmcli, iw, ip, dhclient
│   │   ├── mac.go                  # MAC address operations (get, set, generate)
│   │   ├── validate.go             # Input validation (MAC, interface, IP, domain)
│   │   └── platform_test.go
│   │
│   ├── guard/
│   │   ├── guard.go                # StateGuard: saves + restores MAC, proxy, DNS, tunnels
│   │   └── guard_test.go           # Signal handling (SIGINT, SIGTERM), atexit equivalent
│   │
│   ├── server/
│   │   ├── server.go               # VPS/CF Worker provisioning commands
│   │   └── server_test.go
│   │
│   ├── report/
│   │   ├── terminal.go             # Rich terminal output (lipgloss + fatih/color)
│   │   ├── markdown.go             # Markdown pentest report
│   │   ├── json.go                 # JSON/NDJSON report
│   │   └── report_test.go
│   │
│   ├── toolchain/
│   │   ├── toolchain.go            # Tool registry, find, download, ensure
│   │   ├── download.go             # HTTP download + gunzip + chmod
│   │   └── toolchain_test.go
│   │
│   ├── diagnose/
│   │   ├── diagnose.go             # Read-only feasibility assessment (23 methods)
│   │   ├── tools.go                # External tool presence check
│   │   └── diagnose_test.go
│   │
│   └── ui/
│       ├── web/
│       │   ├── server.go           # HTTP server (net/http)
│       │   ├── handlers.go         # API endpoints (/api/probe, /api/bypass, etc.)
│       │   ├── sse.go              # Server-Sent Events for live updates
│       │   └── static/             # Embedded via //go:embed
│       │       ├── index.html      # Single-page dashboard (htmx + Alpine.js)
│       │       ├── style.css       # Dark theme (matches NiceGUI dashboard aesthetics)
│       │       └── app.js          # Client-side logic
│       └── systray/
│           ├── systray.go          # Cross-platform system tray (getlantern/systray)
│           ├── systray_darwin.go   # macOS-specific icon handling
│           └── systray_linux.go    # Linux-specific tray integration
│
├── go.mod
├── go.sum
├── Makefile                        # Build targets for all platforms
├── .goreleaser.yml                 # GitHub Releases automation
└── docs/
    └── GO-REWRITE-DESIGN.md        # This document
```

### 2.1 Why `internal/`

All packages are under `internal/` to prevent external import. nowifi is an end-user tool, not a library. This keeps the API surface at zero and allows aggressive refactoring without semver concerns.

### 2.2 Build Tags for Platform Abstraction

The Python version uses `platform.py` with runtime `sys.platform` checks to import `platform_mac.py` or `platform_linux.py`. Go replaces this with build tags:

```go
// platform_darwin.go
//go:build darwin

package platform

func GetWifiInfo(iface string) (*WifiInfo, error) {
    // system_profiler SPAirPortDataType -json
}
```

```go
// platform_linux.go
//go:build linux

package platform

func GetWifiInfo(iface string) (*WifiInfo, error) {
    // nmcli / iw dev link / iwgetid
}
```

Both files implement the same exported functions. The compiler selects one at build time. No runtime branching, no dead code in the binary.

---

## 3. Module-by-Module Mapping

### 3.1 detect (Python: detect.py, 294 lines)

**Current behavior:**
- 4 canary URLs (Apple CNA, Google 204, Firefox, Microsoft NCSI)
- Consensus algorithm: redirect to different domain = instant captive; majority failure = transparent/firewall
- DNS hijack detection (resolve 4 known domains, check if all return same IP)
- 10-vendor fingerprint database (Cisco Meraki, Aruba, Ruckus, UniFi, Mikrotik, Fortinet, pfSense, OpenNDS, CoovaChilli, Nomadix)
- Auth method detection from HTML (email, password, phone, social, voucher, terms-only)

**Go approach:**
- `net/http` for canary checks (replace `requests`)
- `net` stdlib for DNS hijack (replace `socket.gethostbyname`)
- Vendor signatures as `map[string]VendorSignature` (compile-time constant)
- HTML auth detection via `regexp` (no need for BeautifulSoup)

**Key type:**
```go
type PortalInfo struct {
    IsCaptive   bool
    PortalType  PortalType  // enum: HTTPRedirect, DNSHijack, FirewallBlock, Transparent, WalledGarden, None
    PortalURL   string
    RedirectURL string
    Vendor      string
    VendorScore int
    AuthMethods []string
    PortalIP    string
    SSID        string
    Gateway     string
}
```

### 3.2 probe (Python: probe.py, 679 lines)

**Current behavior:**
- DNS probe: test 3 external resolvers (Cloudflare, Google, Quad9) via dnspython
- ICMP probe: subprocess `ping -c 1`
- IPv6 probe: raw socket connect to Google/Cloudflare IPv6 addresses
- HTTPS probe: requests.get to Cloudflare
- Whitelist probe: 10 commonly whitelisted domains
- Port scan: 27 candidate ports, randomized order, parallel batches of 4-8 with jitter
- QUIC probe: raw UDP/443 with QUIC Initial packet
- NTP probe: raw UDP/123 with NTP client request
- DoH probe: HTTPS GET to Cloudflare/Google DNS-over-HTTPS endpoints
- DNS beacon: TXT query for server's port list
- Tunnel server scan: tiered priority ports with early exit

**Go approach:**
- `github.com/miekg/dns` for DNS probes (replaces dnspython)
- `golang.org/x/net/icmp` for native ICMP (no subprocess, no `ping` dependency)
- `net` stdlib for TCP/UDP probes
- `net/http` for HTTPS/DoH/whitelist probes
- Goroutines for parallel probes (replaces `concurrent.futures.ThreadPoolExecutor`)
- `time.Sleep` with `crypto/rand` for stealth jitter
- Context with timeout for all probes

**Performance improvement:** Goroutines are ~8KB stack vs Python thread at ~1MB. The batch-of-4 limitation in Python was partly due to GIL contention. In Go, we can safely run all 27 port probes concurrently with a `sync.WaitGroup` while still controlling timing via a token semaphore.

### 3.3 bypass (Python: bypass.py, 726 lines)

**Current behavior:**
- 19 bypass techniques in fixed order, stop on first success
- Each technique returns `BypassResult` with success, severity, impact, details, remediation
- On tunnel success: auto-configure system SOCKS proxy via `networksetup` (macOS) or env vars (Linux)
- System proxy management: set/clear SOCKS via `networksetup -setsocksfirewallproxy`

**Go approach:**
- Same ordered pipeline with early exit
- Each technique in its own file (maintainability)
- Technique interface:

```go
type Technique interface {
    Name() string
    Method() BypassMethod
    Try(probes *probe.Results, config *AuditConfig) *BypassResult
}
```

- Techniques registered in a slice (preserves ordering)
- System proxy: `os/exec` calling `networksetup` (darwin) or `gsettings` (linux)

### 3.4 crack (Python: crack.py, ~1500 lines)

**Current behavior:**
- WiFi scanning: `system_profiler SPAirPortDataType -json` (macOS), `iw dev scan` (Linux), fallback to `airport -s`
- PMKID capture: hcxdumptool + hcxpcapngtool
- Handshake capture: hcxdumptool (with deauth) or airodump-ng + aireplay-ng
- WPS scan: wash or reaver --wash
- WPS Pixie-Dust: reaver -K 1
- WPS PIN brute: reaver (full brute)
- Hashcat crack: mode 22000 (PMKID+EAPOL), dictionary/brute/rule modes
- Aircrack-ng: CPU fallback
- Wordlist discovery: search 10+ common paths

**Go approach:**
- All external tool invocation via `os/exec` (same as Python's `subprocess`)
- JSON parsing of `system_profiler` output via `encoding/json`
- Reaver output parsing via `regexp`
- Hashcat output parsing via `regexp`
- `os.Stat` for wordlist discovery
- Pipeline pattern: each step returns early on success

### 3.5 tunnel (Python: tunnel.py, 433 lines)

**Current behavior:**
- TunnelHandle: wraps subprocess.Popen, tracks local_port + active state
- 6 tunnel types: chisel, iodine (DNS), hans (ICMP), hysteria (QUIC), ntpescape (NTP), cloudflared/dnscrypt (DoH)
- Verification: requests.get through SOCKS proxy or direct
- Port listening check: TCP connect to 127.0.0.1:port
- CF Workers verification: proxy GET through worker URL

**Go approach:**
- `os/exec.Cmd` replaces `subprocess.Popen`
- `TunnelHandle` struct with `Stop()` method (same lifecycle)
- Verification via `net/http` with SOCKS proxy transport:

```go
transport := &http.Transport{
    DialContext: socks5Dialer.DialContext,
}
client := &http.Client{Transport: transport}
```

This is cleaner than Python's `requests` + `pysocks` combination.

### 3.6 monitor (Python: monitor.py, 317 lines)

**Current behavior:**
- Check monitor support (macOS: en0 never supports; Linux: check iw phy)
- Find monitor interfaces (macOS: skip standard interfaces; Linux: iw dev)
- Enable: airmon-ng start (preferred) or iw dev set type monitor
- Disable: airmon-ng stop (restart NetworkManager) or iw dev set type managed
- MonitorGuard: context manager for automatic revert

**Go approach:**
- Build tags: `monitor_darwin.go` (always returns "not supported for en0"), `monitor_linux.go` (airmon-ng / iw)
- Guard pattern using `defer`:

```go
mon, err := monitor.Enable(iface)
if err != nil { return err }
defer mon.Disable()
```

### 3.7 platform (Python: platform_mac.py 394 lines, platform_linux.py 640 lines)

**Current behavior:**

Both platforms implement the same interface:
- `get_wifi_info()` -- current connection SSID, BSSID, channel, security, RSSI
- `get_current_mac()` / `set_mac()` -- MAC address read/write
- `get_gateway()` / `get_local_ip()` / `get_ipv6_address()` -- network info
- `get_arp_table()` -- ARP neighbor cache
- `generate_random_mac()` -- locally-administered unicast MAC
- `disconnect_wifi()` / `connect_wifi()` / `rejoin_wifi()` -- WiFi state
- `renew_dhcp()` -- DHCP lease renewal
- `flush_dns()` -- DNS cache flush
- `StateGuard` -- save/restore all state (MAC, proxy, DNS, tunnels, signals)

**macOS tools used:** `system_profiler`, `airport`, `networksetup`, `ifconfig`, `route`, `arp`, `dscacheutil`, `killall`
**Linux tools used:** `nmcli`, `iw`, `iwgetid`, `iwconfig`, `ip`, `dhclient`, `dhcpcd`, `resolvectl`, `systemd-resolve`, `nscd`, `gsettings`, `arp`

**Go approach:**
- Same `os/exec` invocation pattern
- Input validation in `validate.go` using `regexp` (same patterns: MAC `^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`, interface `^[a-zA-Z][a-zA-Z0-9]{0,15}$`)
- Random MAC generation: `crypto/rand` for security (Python uses `random` which is not cryptographic, but for MAC generation this is acceptable)

### 3.8 guard (Python: StateGuard in platform_mac.py / platform_linux.py)

**Current behavior:**
- Context manager (`__enter__`/`__exit__`)
- Saves original MAC on entry
- On exit: stops tunnels, clears SOCKS proxy, restores MAC, renews DHCP, flushes DNS
- Signal handlers for SIGINT and SIGTERM
- `atexit.register()` for crash recovery

**Go approach:**
- `defer guard.Restore()` replaces `__exit__`
- `signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)` in a goroutine
- No `atexit` equivalent needed -- `defer` in `main()` covers normal exit, signal handler covers interrupt

```go
func main() {
    g := guard.New("en0")
    defer g.Restore()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigCh
        g.Restore()
        os.Exit(1)
    }()

    // ... run audit ...
}
```

### 3.9 report (Python: report.py, 257 lines)

**Current behavior:**
- Terminal: Rich Console, Panel, Table with color-coded severity
- Markdown: pentest report with tables
- JSON: structured NDJSON

**Go approach:**
- Terminal: `charmbracelet/lipgloss` for styled panels/borders, `fatih/color` for inline colors, `olekukonko/tablewriter` for ASCII tables
- Markdown: `fmt.Sprintf` / `strings.Builder` (same string concatenation approach)
- JSON: `encoding/json` with `json.MarshalIndent`

### 3.10 toolchain (Python: toolchain.py, 190 lines)

**Current behavior:**
- Tool registry: 3 downloadable (chisel, hysteria, cloudflared) with GitHub release URLs
- System tools: 8 entries with install hints
- Find: PATH + ~/.nowifi/bin/ + ~/bin/ + /usr/local/bin/
- Download: HTTP GET, gunzip if needed, chmod +x
- Platform resolution: darwin/linux + arm64/amd64

**Go approach:**
- Same registry pattern as Go `map[string]ToolInfo`
- `os/exec.LookPath()` replaces `shutil.which()`
- `net/http` for download, `compress/gzip` for decompression
- `os.Chmod` for making executable
- `runtime.GOOS` / `runtime.GOARCH` for platform detection (no parsing needed)

### 3.11 diagnose (Python: diagnose.py, 407 lines)

**Current behavior:**
- 23 method assessments based on probe results + tool availability
- Each method gets: name, number, feasible (bool), confidence (HIGH/MEDIUM/LOW), reason, prerequisites, risk
- Tool presence check: shutil.which for 15 tools
- Terminal output: Rich Panel + Table

**Go approach:**
- Same assessment logic, same output structure
- `os/exec.LookPath` for tool checks
- Terminal output via lipgloss

### 3.12 UI (Python: gui_web.py ~900 lines, gui_menubar.py 83 lines)

**Current NiceGUI dashboard:**
- Real-time dark-themed dashboard
- Live probe status with incremental updates
- Background task runners (probe, diagnose, full audit, WiFi scan)
- Mutable AppState shared between UI timer and background threads
- Quasar/Vue components via NiceGUI

**Go web dashboard approach:**
- `net/http` server on localhost:8321
- Static files embedded via `//go:embed static/*`
- htmx for dynamic updates (no JavaScript framework needed, ~14KB)
- Alpine.js for minimal client-side state (~17KB)
- Server-Sent Events (SSE) for live probe/bypass status streaming
- Same dark theme CSS (ported from NiceGUI styles)

```go
//go:embed static/*
var staticFS embed.FS

func StartDashboard(port int) error {
    mux := http.NewServeMux()
    mux.Handle("/", http.FileServer(http.FS(staticFS)))
    mux.HandleFunc("/api/probe", handleProbe)
    mux.HandleFunc("/api/bypass", handleBypass)
    mux.HandleFunc("/api/events", handleSSE)  // Server-Sent Events
    return http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}
```

**htmx example (probe panel):**
```html
<div hx-get="/api/probe/status" hx-trigger="every 1s" hx-swap="innerHTML">
    <!-- Probe badges update in-place -->
</div>
```

**macOS menubar (Python: rumps) --> Go: getlantern/systray:**
- Same menu items: Run Audit, Probe Only, Open Dashboard, Reset Network, Quit
- Title "NW" / "NW*" during operation
- Native macOS notifications via `os/exec` calling `osascript`

### 3.13 CLI (Python: cli.py, 924 lines)

**Current commands:**
| Command | Description |
|---------|-------------|
| `nowifi` (default) | Full audit: detect + probe + bypass (19 techniques) |
| `nowifi audit` | Same as default |
| `nowifi diagnose` | Read-only assessment, no exploitation |
| `nowifi ui` | Launch web dashboard |
| `nowifi menubar` | Launch macOS menubar app |
| `nowifi reset` | Emergency network restore |
| `nowifi tools [-d]` | List/download external tools |
| `nowifi ecosystem` | Show complementary tool recommendations |
| `nowifi crack` | WPA cracking pipeline |
| `nowifi setup` | First-time setup wizard |
| `nowifi doctor` | System health check |
| `nowifi uninstall` | Remove nowifi data |

**Go approach using cobra:**

```go
var rootCmd = &cobra.Command{
    Use:   "nowifi",
    Short: "No WiFi? Now WiFi.",
    Long:  "Automated captive portal bypass + WiFi cracking. Just run: sudo nowifi",
    RunE:  runFullAudit,  // default action
}

func init() {
    rootCmd.AddCommand(auditCmd)
    rootCmd.AddCommand(diagnoseCmd)
    rootCmd.AddCommand(uiCmd)
    rootCmd.AddCommand(menubarCmd)
    rootCmd.AddCommand(resetCmd)
    rootCmd.AddCommand(toolsCmd)
    rootCmd.AddCommand(ecosystemCmd)
    rootCmd.AddCommand(crackCmd)
    rootCmd.AddCommand(setupCmd)
    rootCmd.AddCommand(doctorCmd)
    rootCmd.AddCommand(uninstallCmd)
    rootCmd.AddCommand(versionCmd)

    // Persistent flags (available to all commands)
    rootCmd.PersistentFlags().StringVarP(&flagInterface, "interface", "i", defaultInterface(), "WiFi interface")
    rootCmd.PersistentFlags().BoolVar(&flagStealth, "stealth", true, "Stealth mode (randomized timing)")
    rootCmd.PersistentFlags().BoolVar(&flagFast, "fast", false, "Fast mode (no stealth)")
}
```

Flag parity with Python version:
- `--interface / -i` (default: en0 on macOS, wlan0 on Linux)
- `--tunnel-server / -t`
- `--dns-domain / -d`
- `--icmp-server`
- `--cf-workers`
- `--quic-server`
- `--ntp-server`
- `--stealth / --fast`
- `--probe-only / -p`
- `--report / -r` (terminal, markdown, json)
- `--output / -o`
- `--wordlist / -w`
- `--scan-only`
- `--target / -t` (for crack command)

---

## 4. Key Go Libraries

| Purpose | Library | Why |
|---------|---------|-----|
| CLI framework | `github.com/spf13/cobra` | Widely used (kubectl, gh, hugo) |
| CLI flags | `github.com/spf13/pflag` | POSIX flags (comes with cobra) |
| Terminal styling | `github.com/charmbracelet/lipgloss` | Declarative styling, panels, borders |
| Terminal color | `github.com/fatih/color` | Lightweight inline color |
| Terminal tables | `github.com/olekukonko/tablewriter` | ASCII table rendering |
| DNS client | `github.com/miekg/dns` | Full DNS protocol, TXT/A/AAAA queries |
| ICMP | `golang.org/x/net/icmp` | Raw ICMP without subprocess |
| HTTP client | `net/http` (stdlib) | Sufficient for all HTTP operations |
| SOCKS proxy | `golang.org/x/net/proxy` | SOCKS5 dialer for tunnel verification |
| WebSocket | `github.com/gorilla/websocket` | For potential embedded chisel client |
| System tray | `github.com/getlantern/systray` | Cross-platform menubar (macOS + Linux) |
| Embed files | `embed` (stdlib) | Embed static web UI in binary |
| JSON | `encoding/json` (stdlib) | Report output |
| Regex | `regexp` (stdlib) | Output parsing (reaver, hashcat, etc.) |

**Total dependencies:** ~10 external packages. Go's module system pins exact versions; no venv, no virtualenv, no pip conflicts.

---

## 5. Distribution Strategy

### 5.1 Build

```makefile
# Makefile
VERSION := $(shell git describe --tags --always)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o nowifi ./cmd/nowifi

.PHONY: build-all
build-all:
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/nowifi-darwin-arm64  ./cmd/nowifi
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/nowifi-darwin-amd64  ./cmd/nowifi
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/nowifi-linux-arm64   ./cmd/nowifi
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/nowifi-linux-amd64   ./cmd/nowifi

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: install
install: build
	sudo cp nowifi /usr/local/bin/nowifi
```

### 5.2 goreleaser

```yaml
# .goreleaser.yml
version: 2

project_name: nowifi

before:
  hooks:
    - go mod tidy
    - go test ./...

builds:
  - main: ./cmd/nowifi
    binary: nowifi
    env:
      - CGO_ENABLED=0
    goos:
      - darwin
      - linux
    goarch:
      - amd64
      - arm64
    ldflags:
      - -s -w -X main.version={{.Version}}

archives:
  - format: tar.gz
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

brews:
  - repository:
      owner: MikkoParkkola
      name: homebrew-tap
    homepage: "https://github.com/MikkoParkkola/nowifi"
    description: "WiFi security tool -- 23 automated bypass techniques"
    install: |
      bin.install "nowifi"

checksum:
  name_template: "checksums.txt"

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"
```

### 5.3 Installation Methods (User Experience)

**Homebrew (macOS + Linux):**
```bash
brew install MikkoParkkola/tap/nowifi
```

**Direct download:**
```bash
curl -fsSL https://install.nowifi.dev | sh
```

The install script detects OS/arch, downloads the correct binary from GitHub Releases, and copies to `/usr/local/bin/`. No Python, no pip, no venv.

**Manual:**
```bash
# Download from GitHub Releases
wget https://github.com/MikkoParkkola/nowifi/releases/latest/download/nowifi_0.2.0_darwin_arm64.tar.gz
tar xzf nowifi_*.tar.gz
sudo mv nowifi /usr/local/bin/
```

**From source:**
```bash
go install github.com/MikkoParkkola/nowifi/cmd/nowifi@latest
```

### 5.4 Binary Size Budget

| Component | Estimated Size |
|-----------|---------------|
| Core logic | ~3 MB |
| cobra/pflag | ~1 MB |
| lipgloss/tablewriter | ~1 MB |
| miekg/dns | ~1 MB |
| Embedded web UI | ~500 KB |
| systray | ~2 MB |
| Go runtime | ~5 MB |
| **Total (stripped)** | **~13-15 MB** |

This is comparable to chisel (11MB) and cloudflared (25MB). With UPX compression, it can be reduced to ~5-7MB.

---

## 6. Migration Plan

### Phase 1: Core Detection + Probing (week 1-2)

Port the read-only functionality first. This can be tested without sudo and without external tools.

**Files to implement:**
- `cmd/nowifi/main.go` -- cobra CLI skeleton with `diagnose` and `doctor` commands
- `internal/detect/` -- portal detection + vendor fingerprinting
- `internal/probe/` -- all 10 probe types
- `internal/platform/` -- WiFi info, MAC read, gateway, ARP table (read-only ops)
- `internal/report/` -- terminal output
- `internal/diagnose/` -- method feasibility assessment
- `internal/toolchain/` -- tool discovery (no download yet)

**Validation:** `nowifi diagnose` produces identical output to the Python version on the same network.

### Phase 2: Bypass Techniques 1-10 + StateGuard (week 3-4)

Port the first 10 bypass techniques plus the cleanup infrastructure.

**Files to implement:**
- `internal/bypass/` -- techniques 1-10 (IPv6, chisel, CNA, JS, CONNECT, MAC clone x2, DNS tunnel, ICMP tunnel, VPN 53)
- `internal/tunnel/` -- chisel, iodine, hans tunnel management
- `internal/guard/` -- StateGuard (MAC restore, proxy cleanup, signal handling)
- `internal/platform/` -- MAC write, DHCP renew, DNS flush, WiFi power cycle

**Validation:** `sudo nowifi` runs full audit with bypass attempts, StateGuard restores state on Ctrl+C.

### Phase 3: Bypass Techniques 11-19 + WPA Cracking (week 5-6)

Complete the bypass suite and add the cracking pipeline.

**Files to implement:**
- `internal/bypass/` -- techniques 11-19 (whitelist, session, default creds, MAC rotate, DHCP, QUIC, CF Workers, NTP, DoH)
- `internal/tunnel/` -- hysteria, ntpescape, cloudflared tunnel types
- `internal/crack/` -- full cracking pipeline
- `internal/monitor/` -- monitor mode management
- `internal/toolchain/` -- auto-download functionality

**Validation:** `nowifi crack --scan-only` scans WiFi, `sudo nowifi crack` runs full pipeline.

### Phase 4: Web Dashboard + Menubar + CLI Polish (week 7-8)

Port the GUI components and complete the CLI.

**Files to implement:**
- `internal/ui/web/` -- embedded web dashboard (htmx + SSE)
- `internal/ui/systray/` -- menubar app
- `internal/server/` -- VPS/CF Worker provisioning
- CLI commands: `setup`, `reset`, `tools -d`, `ecosystem`, `uninstall`
- Terminal output polish (match Python Rich formatting)

**Validation:** `nowifi ui` opens dashboard in browser, `nowifi menubar` shows tray icon.

### Phase 5: Distribution + Testing + Release (week 9-10)

Build pipeline, cross-platform testing, first release.

**Tasks:**
- goreleaser configuration + GitHub Actions CI
- Homebrew tap formula
- Install script (`install.nowifi.dev`)
- Cross-platform testing: macOS arm64, macOS amd64, Ubuntu arm64, Ubuntu amd64
- Integration tests (mock network environments)
- Documentation: README update, man page
- Tag v0.2.0 and release

---

## 7. What Changes From Python

### 7.1 Dependencies Eliminated

| Python Dependency | Replaced By |
|-------------------|-------------|
| `click` | `spf13/cobra` |
| `requests` | `net/http` (stdlib) |
| `rich` | `charmbracelet/lipgloss` + `fatih/color` |
| `dnspython` | `miekg/dns` |
| `nicegui` | `embed` + htmx + SSE |
| `rumps` | `getlantern/systray` |
| `pysocks` | `golang.org/x/net/proxy` |
| `scapy` | Not needed (was optional) |
| `beautifulsoup4` | `regexp` (portal pages are simple) |

### 7.2 Runtime Eliminated

- No Python interpreter (saves ~50MB disk, ~500ms startup)
- No pip / venv / virtualenv
- No PEP 668 "externally managed" issues
- No Python version matrix (3.11 vs 3.12 vs 3.13)
- No `__pycache__` directories

### 7.3 Behavioral Changes

**Identical behavior:**
- 23 technique ordering and logic
- Stealth probing (randomized order, jitter, small batches)
- StateGuard cleanup guarantee (MAC, proxy, DNS, tunnels)
- CLI command structure and flag names
- Report formats (terminal, markdown, JSON)
- Tool auto-download for chisel, hysteria, cloudflared

**Improved behavior:**
- ICMP probes use raw ICMP sockets instead of `subprocess.Popen(["ping"])` -- no fork overhead, no parsing ping output
- DNS probes use `miekg/dns` directly instead of subprocess or dnspython -- lower latency, better error handling
- Concurrent probes use goroutines (8KB stack) instead of Python threads (1MB stack) -- can probe all ports simultaneously
- Web dashboard uses SSE for real-time updates instead of NiceGUI timer polling -- lower latency, less bandwidth
- Startup is ~100x faster (~5ms vs ~500ms) -- critical for `nowifi reset` (emergency restore)

**Removed:**
- `nowifi setup` wizard asking about Python version -- irrelevant with single binary
- pip/venv install path -- replaced by brew/curl/go-install
- `[project.optional-dependencies]` system -- single binary includes everything

---

## 8. What Stays the Same

These are the core invariants that MUST be preserved in the Go rewrite:

1. **`sudo nowifi` just works** -- one command, auto-detects everything, tries 23 techniques, browser works immediately on success
2. **Technique ordering** -- most powerful first (IPv6 > chisel > CNA > ... > DoH)
3. **Stealth by default** -- randomized timing, small batches, short timeouts; `--fast` disables
4. **StateGuard guarantee** -- MAC, proxy, DNS, tunnels restored on ANY exit (normal, Ctrl+C, SIGTERM, crash via atexit equivalent)
5. **Zero manual config for bypass** -- system SOCKS proxy auto-configured so browser works without user touching settings
6. **Read-only `diagnose` mode** -- no network changes, no MAC changes, no tunnels; pure assessment
7. **Report format parity** -- terminal, markdown, JSON output must contain the same data
8. **External tool wrapping** -- nowifi orchestrates proven tools (chisel, iodine, hashcat, etc.), does not reimplement crypto or tunneling
9. **Input validation** -- MAC addresses, interface names, IPs, domains, URLs validated before any privileged operation
10. **Vendor fingerprinting** -- same 10-vendor signature database with scoring

---

## 9. Testing Strategy

### 9.1 Unit Tests

Go table-driven tests for each package:

```go
func TestDetectPortal(t *testing.T) {
    tests := []struct {
        name     string
        canaries []CanaryResult
        want     PortalType
    }{
        {
            name:     "all canaries pass",
            canaries: allPass(),
            want:     PortalTypeNone,
        },
        {
            name:     "redirect to different domain",
            canaries: redirectToDifferentDomain(),
            want:     PortalTypeHTTPRedirect,
        },
        {
            name:     "majority fail consensus",
            canaries: majorityFail(),
            want:     PortalTypeTransparent,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := classifyPortal(tt.canaries)
            if got != tt.want {
                t.Errorf("classifyPortal() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### 9.2 Integration Tests

- **Mock HTTP server** for portal detection (serve canary responses, redirect responses, vendor HTML)
- **Mock DNS server** (`miekg/dns` server) for DNS probe tests
- **Mock tunnel server** for tunnel establishment tests
- **Build tag `//go:build integration`** to separate from unit tests

### 9.3 Cross-Platform CI

```yaml
# .github/workflows/ci.yml
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        arch: [amd64, arm64]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - run: go test ./...
      - run: go build ./cmd/nowifi
```

### 9.4 Test Parity

The Python test suite has 14 test files covering all modules. The Go test suite should achieve equivalent coverage:

| Python Test | Go Test Package | Key Tests |
|-------------|-----------------|-----------|
| test_detect.py | internal/detect/ | Canary consensus, vendor fingerprint, DNS hijack |
| test_probe.py | internal/probe/ | DNS/ICMP/IPv6/QUIC/NTP/DoH/ports, stealth timing |
| test_bypass.py | internal/bypass/ | All 23 techniques (mocked), proxy setup/teardown |
| test_tunnel.py | internal/tunnel/ | Start/stop/verify for each tunnel type |
| test_crack.py | internal/crack/ | Scan, PMKID, handshake, hashcat, reaver output parsing |
| test_monitor.py | internal/monitor/ | Enable/disable, guard lifecycle |
| test_platform_mac.py | internal/platform/ | WiFi info, MAC ops, ARP table, validation |
| test_diagnose.py | internal/diagnose/ | 23 method assessments, tool checks |
| test_report.py | internal/report/ | Terminal, markdown, JSON output |
| test_toolchain.py | internal/toolchain/ | Find, download, platform resolution |
| test_cli.py | cmd/nowifi/ | Command routing, flag parsing, help text |

---

## 10. Risk Analysis

| Risk | Mitigation |
|------|------------|
| macOS `system_profiler` JSON format changes | Pin expected keys, add fallback to `airport` command |
| Linux tool diversity (nmcli vs iw vs iwconfig) | Cascading fallbacks, same as Python version |
| goroutine leak in long-running tunnels | Context cancellation, explicit `cmd.Process.Kill()` |
| Raw ICMP requires root on Linux | Same as Python (needs sudo anyway for MAC ops) |
| systray library stability on Wayland | Graceful degradation: skip tray if init fails |
| htmx/Alpine.js learning curve for contributors | Template components, clear separation of concerns |
| External tool version breakage | Pin tool versions in registry, verify output format |
| Binary size exceeds 20MB | UPX compression, strip debug symbols, audit deps |

---

## 11. Non-Goals

The Go rewrite will NOT:

1. **Embed chisel/cloudflared/hysteria** -- They remain external binaries. Embedding would increase binary size by 50MB+ and create update coupling.
2. **Implement WPA cracking in Go** -- hashcat/aircrack-ng/reaver are established tools with decades of optimization. We wrap them.
3. **Support Windows** -- Both macOS and Linux are POSIX systems with similar networking tools. Windows would require an entirely different platform layer. Not worth the effort.
4. **Provide a REST API** -- The web dashboard is localhost-only. No authentication, no remote access, no API stability contract.
5. **Replace the existing Python version** -- Both versions can coexist. The Go version is the recommended distribution for end users; the Python version remains for contributors who prefer Python.

---

## 12. Success Criteria

The Go rewrite is complete when:

1. `sudo nowifi` on macOS arm64 produces identical bypass results to the Python version on the same network
2. `nowifi diagnose` on Linux amd64 produces the same 23-method assessment
3. `nowifi crack --scan-only` finds the same WiFi networks
4. `nowifi ui` opens a functional web dashboard with live probe updates
5. `brew install MikkoParkkola/tap/nowifi` installs a working binary on macOS
6. `curl -fsSL install.nowifi.dev | sh` installs a working binary on Linux
7. Binary size is under 20MB (uncompressed)
8. Startup time is under 10ms
9. All Go tests pass on macOS (arm64, amd64) and Linux (arm64, amd64)
10. StateGuard correctly restores state after SIGINT, SIGTERM, and normal exit
