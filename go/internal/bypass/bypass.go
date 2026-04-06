// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package bypass implements 19 ordered captive portal bypass techniques.
//
// After a successful bypass, internet works system-wide (including browser)
// with zero manual steps. All changes are temporary and restored when nowifi
// exits via the guard package.
//
// Techniques ordered most-powerful-first:
//
//  1. IPv6 bypass          - portal only filters IPv4
//  2. HTTPS/WS tunnel      - chisel through Cloudflare to your server
//  3. CNA User-Agent spoof - portal auto-approves Apple CNA requests
//  4. JS-only bypass       - portal enforces auth only in JavaScript
//  5. HTTP CONNECT abuse   - tunnel through portal's transparent proxy
//  6. MAC clone (idle)     - steal an inactive authenticated device's session
//  7. MAC clone (any)      - steal any authenticated device's session
//  8. DNS tunnel           - IP-over-DNS through your server
//  9. ICMP tunnel          - IP-over-ping through your server
//  10. VPN on port 53       - WireGuard/OpenVPN on DNS port
//  11. Whitelist domain     - tunnel via whitelisted CDN domain
//  12. Session cookie replay- sniff and replay portal auth cookies
//  13. Portal default creds - try default admin passwords on portal
//  14. MAC rotate           - fresh random MAC for new session/quota
//  15. DHCP rotate          - new IP via DHCP release/renew cycle
//  16. QUIC tunnel          - Hysteria2 over UDP/443 (looks like HTTP/3)
//  17. CF Workers proxy     - serverless proxy via Cloudflare Workers
//  18. NTP tunnel           - data over UDP/123 (almost never blocked)
//  19. DoH tunnel           - DNS-over-HTTPS to bypass DNS interception
package bypass

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

// Method identifies a specific bypass technique.
type Method string

const (
	IPv6Bypass      Method = "ipv6_bypass"
	ChiselTunnel    Method = "chisel_tunnel"
	CNASpoof        Method = "cna_useragent_spoof"
	JSBypass        Method = "js_only_bypass" //nolint:gosec // descriptive method name, not a secret
	HTTPConnect     Method = "http_connect_abuse"
	MACCloneIdle    Method = "mac_clone_idle"
	MACClone        Method = "mac_clone"
	DNSTunnel       Method = "dns_tunnel"
	ICMPTunnel      Method = "icmp_tunnel"
	VPNPort53       Method = "vpn_port_53"
	WhitelistDomain Method = "whitelist_domain"
	SessionReplay   Method = "session_cookie_replay"
	PortalCreds     Method = "portal_default_creds"
	MACRotate       Method = "mac_rotate"
	DHCPRotate      Method = "dhcp_rotate"
	QUICTunnel      Method = "quic_tunnel"
	CFWorkers       Method = "cf_workers_proxy"
	NTPTunnel       Method = "ntp_tunnel"
	DoHTunnel       Method = "doh_tunnel"
)

// Config holds user-specified settings for the bypass engine.
type Config struct {
	Interface    string
	TunnelServer string
	DNSDomain    string
	ICMPServer   string
	QUICServer   string
	NTPServer    string
	CFWorkersURL string
	VPNServer    string
	Stealth      bool
}

// Result records the outcome of a single bypass attempt.
type Result struct {
	Method      Method
	Success     bool
	Severity    string // critical, high, medium, low, info
	Impact      string
	Details     string
	Remediation string
	Tunnel      *tunnel.Handle
}

// ---------------------------------------------------------------------------
// Probe result interfaces -- minimal types needed from the probe package.
// The actual probe package implements these; we define them here so bypass
// can compile independently.
// ---------------------------------------------------------------------------

// ProbeResult holds the status of a single protocol probe.
type ProbeResult struct {
	IsOpen  bool
	Details string
}

// WhitelistResult holds a probed whitelisted domain.
type WhitelistResult struct {
	Domain  string
	IsOpen  bool
	Details string
}

// PortResult holds a probed TCP port.
type PortResult struct {
	Port    int
	Service string
	IsOpen  bool
}

// ProbeResults is the full set of probe outcomes consumed by the bypass engine.
// This mirrors the probe.Results struct; the caller maps from probe.Results to this.
type ProbeResults struct {
	DNS        ProbeResult
	ICMP       ProbeResult
	IPv6       ProbeResult
	Cloudflare ProbeResult
	QUIC       ProbeResult
	NTP        ProbeResult
	DoH        ProbeResult

	Whitelists        []WhitelistResult
	OpenPorts         []PortResult
	TunnelServerPorts []PortResult
}

// PlatformOps abstracts the platform-specific operations needed by bypass
// techniques. This allows testing with mocks and decouples from the concrete
// platform package's build-tag-gated functions.
type PlatformOps interface {
	GetGateway(iface string) string
	GetCurrentMAC(iface string) string
	GetArpTable() []platform.ArpEntry
	SetMAC(iface, mac string) bool
	RenewDHCP(iface string)
	GenerateRandomMAC() string
}

// RunBypasses tries all 19 bypass techniques in order, stopping on the
// first success. Returns the list of all attempted results.
func RunBypasses(probes *ProbeResults, config *Config, plat PlatformOps) []Result {
	if plat == nil {
		plat = &defaultPlatformOps{}
	}

	hasServer := config.TunnelServer != ""
	if !hasServer {
		logStatus("No tunnel server configured -- trying serverless techniques first.")
		logStatus("Tip: `nowifi server create` deploys a free Cloudflare Worker (~30s).")
	}

	type technique struct {
		name string
		fn   func() Result
	}

	techniques := []technique{
		{"IPv6 bypass", func() Result { return tryIPv6(probes) }},
		{"HTTPS tunnel (chisel)", func() Result { return tryChisel(config, probes) }},
		{"CNA User-Agent spoof", func() Result { return tryCNASpoof() }},
		{"JS-only bypass", func() Result { return tryJSBypass() }},
		{"HTTP CONNECT abuse", func() Result { return tryHTTPConnect(probes, config, plat) }},
		{"MAC clone (idle)", func() Result { return tryMACClone(config.Interface, true, plat) }},
		{"MAC clone (any)", func() Result { return tryMACClone(config.Interface, false, plat) }},
		{"DNS tunnel", func() Result { return tryDNSTunnel(config, probes) }},
		{"ICMP tunnel", func() Result { return tryICMPTunnel(config, probes) }},
		{"VPN port 53", func() Result { return tryVPNPort53(config, probes) }},
		{"Whitelist tunnel", func() Result { return tryWhitelist(probes) }},
		{"Session cookie replay", func() Result { return trySessionReplay(config.Interface, plat) }},
		{"Portal default creds", func() Result { return tryDefaultCreds(config.Interface, plat) }},
		{"MAC rotate", func() Result { return tryMACRotate(config.Interface, plat) }},
		{"DHCP rotate", func() Result { return tryDHCPRotate(config.Interface, plat) }},
		{"QUIC tunnel (Hysteria2)", func() Result { return tryQUICTunnel(config, probes) }},
		{"Cloudflare Workers proxy", func() Result { return tryCFWorkers(config, probes) }},
		{"NTP tunnel", func() Result { return tryNTPTunnel(config, probes) }},
		{"DoH tunnel", func() Result { return tryDoHTunnel(probes) }},
	}

	var results []Result
	for _, t := range techniques {
		tName := t.name // capture for panic recovery
		logStatus("Trying: %s...", tName)
		r := func() (result Result) {
			defer func() {
				if rec := recover(); rec != nil {
					result = Result{Success: false, Details: fmt.Sprintf("panic in %s: %v", tName, rec)}
				}
			}()
			return t.fn()
		}()

		results = append(results, r)
		if r.Success {
			logStatus("SUCCESS: %s", t.name)
			// For tunnel-based methods, set system SOCKS proxy so browser works.
			if r.Tunnel != nil && r.Tunnel.Active && r.Tunnel.LocalPort > 0 {
				setSystemSOCKSProxy(config.Interface, r.Tunnel.LocalPort)
			}
			return results
		}
		logStatus("Failed: %s", t.name)
	}

	return results
}

// ClearSystemSOCKSProxy removes the system-wide SOCKS proxy.
// Called by the guard package on cleanup.
func ClearSystemSOCKSProxy(iface string) {
	service := getNetworkService(iface)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxystate", service, "off").Run()
}

// ---------------------------------------------------------------------------
// System proxy management
// ---------------------------------------------------------------------------

func setSystemSOCKSProxy(iface string, port int) {
	service := getNetworkService(iface)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxy", service, "127.0.0.1", fmt.Sprintf("%d", port)).Run()
	_ = exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxystate", service, "on").Run()
}

var networkServiceRE = regexp.MustCompile(`Hardware Port:\s*(.+)`)

// serviceNameRE ensures a network service name contains only safe characters.
// macOS service names like "Wi-Fi", "Ethernet", "USB 10/100/1000 LAN" etc.
var serviceNameRE = regexp.MustCompile(`^[a-zA-Z0-9 ./_-]+$`)

func getNetworkService(iface string) string {
	// Validate interface before using in output comparison.
	if _, err := platform.ValidateInterface(iface); err != nil {
		return "Wi-Fi"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "networksetup", "-listallhardwareports").Output()
	if err != nil {
		return "Wi-Fi" // fallback
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Device: "+iface) && i > 0 {
			m := networkServiceRE.FindStringSubmatch(lines[i-1])
			if len(m) > 1 {
				service := strings.TrimSpace(m[1])
				// Validate the parsed service name to prevent injection.
				if serviceNameRE.MatchString(service) {
					return service
				}
			}
		}
	}
	return "Wi-Fi" // fallback
}

// ---------------------------------------------------------------------------
// Internet connectivity check
// ---------------------------------------------------------------------------

// internetCheckURL is the URL used by HasInternet(). Tests override this
// to point at httptest servers so no real network call is made.
var internetCheckURL = "http://connectivitycheck.gstatic.com/generate_204"

// HasInternet checks if we have real internet connectivity by hitting
// Google's connectivity check URL (HTTP 204 = connected).
func HasInternet() bool {
	// Use 10s timeout to accommodate satellite links (RTT 500-2500ms).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", internetCheckURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 204
}

// ---------------------------------------------------------------------------
// Default platform ops -- delegates to the platform package.
// The actual implementations are in platform_darwin.go / platform_linux.go.
// These stubs allow bypass to compile on any platform; the caller should
// inject a real PlatformOps at runtime.
// ---------------------------------------------------------------------------

type defaultPlatformOps struct{}

func (d *defaultPlatformOps) GetGateway(iface string) string    { return "" }
func (d *defaultPlatformOps) GetCurrentMAC(iface string) string { return "" }
func (d *defaultPlatformOps) GetArpTable() []platform.ArpEntry  { return nil }
func (d *defaultPlatformOps) SetMAC(iface, mac string) bool     { return false }
func (d *defaultPlatformOps) RenewDHCP(iface string)            {}
func (d *defaultPlatformOps) GenerateRandomMAC() string         { return platform.GenerateRandomMAC() }

// suppressLog controls whether bypass log output is suppressed (TUI mode).
var suppressLog atomic.Bool

// SetSuppressLog sets whether bypass log output is suppressed.
func SetSuppressLog(v bool) { suppressLog.Store(v) }

func logStatus(format string, args ...any) {
	if !suppressLog.Load() {
		log.Printf("  "+format, args...)
	}
}
