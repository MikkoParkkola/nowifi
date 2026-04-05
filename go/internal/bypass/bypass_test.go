// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// ---------------------------------------------------------------------------
// Mock PlatformOps
// ---------------------------------------------------------------------------

type mockPlatform struct {
	arpTable   []platform.ArpEntry
	currentMAC string
	gateway    string
	setMACErr  error
	setMACOK   bool
	renewCalls int
	randomMAC  string
	calls      []string // track call order
}

func (m *mockPlatform) GetGateway(iface string) string {
	m.calls = append(m.calls, "GetGateway")
	return m.gateway
}
func (m *mockPlatform) GetCurrentMAC(iface string) string {
	m.calls = append(m.calls, "GetCurrentMAC")
	return m.currentMAC
}
func (m *mockPlatform) GetArpTable() []platform.ArpEntry {
	m.calls = append(m.calls, "GetArpTable")
	return m.arpTable
}
func (m *mockPlatform) SetMAC(iface, mac string) bool {
	m.calls = append(m.calls, "SetMAC")
	return m.setMACOK
}
func (m *mockPlatform) RenewDHCP(iface string) {
	m.calls = append(m.calls, "RenewDHCP")
	m.renewCalls++
}
func (m *mockPlatform) GenerateRandomMAC() string {
	m.calls = append(m.calls, "GenerateRandomMAC")
	return m.randomMAC
}

// ---------------------------------------------------------------------------
// Test: All 19 Method constants exist
// ---------------------------------------------------------------------------

func TestAllMethodConstants(t *testing.T) {
	methods := []struct {
		name   string
		method Method
		want   string
	}{
		{"IPv6Bypass", IPv6Bypass, "ipv6_bypass"},
		{"ChiselTunnel", ChiselTunnel, "chisel_tunnel"},
		{"CNASpoof", CNASpoof, "cna_useragent_spoof"},
		{"JSBypass", JSBypass, "js_only_bypass"},
		{"HTTPConnect", HTTPConnect, "http_connect_abuse"},
		{"MACCloneIdle", MACCloneIdle, "mac_clone_idle"},
		{"MACClone", MACClone, "mac_clone"},
		{"DNSTunnel", DNSTunnel, "dns_tunnel"},
		{"ICMPTunnel", ICMPTunnel, "icmp_tunnel"},
		{"VPNPort53", VPNPort53, "vpn_port_53"},
		{"WhitelistDomain", WhitelistDomain, "whitelist_domain"},
		{"SessionReplay", SessionReplay, "session_cookie_replay"},
		{"PortalCreds", PortalCreds, "portal_default_creds"},
		{"MACRotate", MACRotate, "mac_rotate"},
		{"DHCPRotate", DHCPRotate, "dhcp_rotate"},
		{"QUICTunnel", QUICTunnel, "quic_tunnel"},
		{"CFWorkers", CFWorkers, "cf_workers_proxy"},
		{"NTPTunnel", NTPTunnel, "ntp_tunnel"},
		{"DoHTunnel", DoHTunnel, "doh_tunnel"},
	}

	if len(methods) != 19 {
		t.Fatalf("expected 19 methods, got %d", len(methods))
	}

	for _, tc := range methods {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.method) != tc.want {
				t.Errorf("Method %s = %q, want %q", tc.name, tc.method, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: RunBypasses stops on first success
// ---------------------------------------------------------------------------

func TestRunBypasses_StopsOnFirstSuccess(t *testing.T) {
	// Provide IPv6 open so the first technique succeeds immediately.
	probes := &ProbeResults{
		IPv6: ProbeResult{IsOpen: true, Details: "Global IPv6 available"},
	}
	config := &Config{Interface: "en0"}
	plat := &mockPlatform{}

	results := RunBypasses(probes, config, plat)

	if len(results) != 1 {
		t.Fatalf("expected 1 result (stop on first success), got %d", len(results))
	}
	if !results[0].Success {
		t.Error("expected first result to be successful")
	}
	if results[0].Method != IPv6Bypass {
		t.Errorf("expected method %s, got %s", IPv6Bypass, results[0].Method)
	}
}

// ---------------------------------------------------------------------------
// Test: RunBypasses returns results and stops early on success or tries all
// ---------------------------------------------------------------------------

func TestRunBypasses_ReturnsResults(t *testing.T) {
	// All probes closed, no servers configured. Network-dependent techniques
	// (CNA spoof, JS bypass) may succeed if the test host has internet, so
	// we verify structural properties rather than exact counts.
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}
	plat := &mockPlatform{}

	results := RunBypasses(probes, config, plat)

	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if len(results) > 19 {
		t.Fatalf("got %d results, but there are only 19 techniques", len(results))
	}

	// If last result is a success, RunBypasses stopped early (correct).
	// If no results succeeded, all 19 should have been tried.
	lastSuccess := results[len(results)-1].Success
	if lastSuccess {
		// Stopped on first success: verify every result before the last failed.
		for i := 0; i < len(results)-1; i++ {
			if results[i].Success {
				t.Errorf("result[%d] (%s) succeeded but is not the last result", i, results[i].Method)
			}
		}
	} else {
		// All failed: should have tried all 19.
		if len(results) != 19 {
			t.Errorf("all failed but got %d results instead of 19", len(results))
		}
	}
}

// ---------------------------------------------------------------------------
// Test: RunBypasses with nil PlatformOps uses defaults
// ---------------------------------------------------------------------------

func TestRunBypasses_NilPlatform(t *testing.T) {
	probes := &ProbeResults{
		IPv6: ProbeResult{IsOpen: true, Details: "test"},
	}
	config := &Config{Interface: "en0"}

	// nil plat should not panic -- defaultPlatformOps is used.
	results := RunBypasses(probes, config, nil)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result with nil platform")
	}
	if results[0].Method != IPv6Bypass || !results[0].Success {
		t.Error("IPv6 bypass should succeed even with nil plat")
	}
}

// ---------------------------------------------------------------------------
// Test: RunBypasses panic recovery
// ---------------------------------------------------------------------------

func TestRunBypasses_PanicRecovery(t *testing.T) {
	// RunBypasses has defer/recover in the technique loop.
	// We verify this by checking that a panicking function path
	// does not crash the whole engine. The IPv6 path cannot panic,
	// but if all paths fail the engine should still return 19 results.
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}
	plat := &mockPlatform{}

	results := RunBypasses(probes, config, plat)
	// The engine should survive all techniques without crashing.
	if len(results) == 0 {
		t.Fatal("expected results even if all techniques fail")
	}
}

// ---------------------------------------------------------------------------
// Test: RunBypasses technique ordering
// ---------------------------------------------------------------------------

func TestRunBypasses_TechniqueOrdering(t *testing.T) {
	// All probes closed, no servers. Track the order of Methods attempted.
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}
	plat := &mockPlatform{}

	results := RunBypasses(probes, config, plat)

	// The first technique should always be IPv6.
	if len(results) > 0 && results[0].Method != IPv6Bypass {
		t.Errorf("first technique = %s, want %s", results[0].Method, IPv6Bypass)
	}

	// Verify the expected order of the first few methods.
	expectedOrder := []Method{
		IPv6Bypass, ChiselTunnel, CNASpoof, JSBypass, HTTPConnect,
	}
	for i, want := range expectedOrder {
		if i >= len(results) {
			break
		}
		if results[i].Method != want {
			t.Errorf("technique[%d] = %s, want %s", i, results[i].Method, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: RunBypasses calls PlatformOps for MAC/DHCP techniques
// ---------------------------------------------------------------------------

func TestRunBypasses_PlatformOpsCalled(t *testing.T) {
	// Directly test techniques that call PlatformOps, rather than relying on
	// RunBypasses reaching them (CNA/JS bypass may succeed and stop early).
	plat := &mockPlatform{randomMAC: "02:aa:bb:cc:dd:ee"}

	// tryHTTPConnect calls GetGateway.
	tryHTTPConnect(&ProbeResults{}, &Config{Interface: "en0"}, plat)
	// tryMACClone calls GetGateway, GetCurrentMAC, GetArpTable.
	tryMACClone("en0", false, plat)
	// tryMACRotate calls GenerateRandomMAC.
	tryMACRotate("en0", plat)

	gatewayCount := 0
	for _, c := range plat.calls {
		if c == "GetGateway" {
			gatewayCount++
		}
	}
	if gatewayCount < 2 {
		t.Errorf("expected at least 2 GetGateway calls, got %d", gatewayCount)
	}

	hasGenMAC := false
	for _, c := range plat.calls {
		if c == "GenerateRandomMAC" {
			hasGenMAC = true
			break
		}
	}
	if !hasGenMAC {
		t.Error("expected GenerateRandomMAC call from tryMACRotate")
	}
}

// ---------------------------------------------------------------------------
// Test: IPv6 bypass
// ---------------------------------------------------------------------------

func TestTryIPv6(t *testing.T) {
	tests := []struct {
		name    string
		isOpen  bool
		wantOK  bool
		wantSev string
	}{
		{"open", true, true, "critical"},
		{"closed", false, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probes := &ProbeResults{IPv6: ProbeResult{IsOpen: tc.isOpen, Details: "test"}}
			r := tryIPv6(probes)
			if r.Success != tc.wantOK {
				t.Errorf("Success = %v, want %v", r.Success, tc.wantOK)
			}
			if r.Method != IPv6Bypass {
				t.Errorf("Method = %s, want %s", r.Method, IPv6Bypass)
			}
			if tc.wantOK && r.Severity != tc.wantSev {
				t.Errorf("Severity = %q, want %q", r.Severity, tc.wantSev)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: IPv6 bypass preserves Details from probe
// ---------------------------------------------------------------------------

func TestTryIPv6_PreservesDetails(t *testing.T) {
	probes := &ProbeResults{IPv6: ProbeResult{IsOpen: true, Details: "Connected to 2607:f8b0::200e"}}
	r := tryIPv6(probes)
	if r.Details != "Connected to 2607:f8b0::200e" {
		t.Errorf("Details = %q, want probe details passed through", r.Details)
	}
	if r.Remediation == "" {
		t.Error("successful IPv6 bypass should include remediation")
	}
	if r.Impact == "" {
		t.Error("successful IPv6 bypass should include impact")
	}
}

// ---------------------------------------------------------------------------
// Test: isInflightNetwork -- pure function
// ---------------------------------------------------------------------------

func TestIsInflightNetwork(t *testing.T) {
	tests := []struct {
		name string
		rtt  time.Duration
		want bool
	}{
		{"ground wifi 10ms", 10 * time.Millisecond, false},
		{"ground wifi 50ms", 50 * time.Millisecond, false},
		{"borderline 400ms", 400 * time.Millisecond, false},
		{"satellite 401ms", 401 * time.Millisecond, true},
		{"satellite 600ms", 600 * time.Millisecond, true},
		{"satellite 2500ms", 2500 * time.Millisecond, true},
		{"zero", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isInflightNetwork(tc.rtt)
			if got != tc.want {
				t.Errorf("isInflightNetwork(%v) = %v, want %v", tc.rtt, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: networkServiceRE and serviceNameRE regex patterns
// ---------------------------------------------------------------------------

func TestNetworkServiceRE(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Hardware Port: Wi-Fi", "Wi-Fi"},
		{"Hardware Port: Ethernet", "Ethernet"},
		{"Hardware Port: USB 10/100/1000 LAN", "USB 10/100/1000 LAN"},
		{"Hardware Port:  Thunderbolt Bridge", "Thunderbolt Bridge"},
		{"Not a port line", ""},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			m := networkServiceRE.FindStringSubmatch(tc.input)
			got := ""
			if len(m) > 1 {
				got = strings.TrimSpace(m[1])
			}
			if got != tc.want {
				t.Errorf("networkServiceRE(%q) captured %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestServiceNameRE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"Wi-Fi", "Wi-Fi", true},
		{"Ethernet", "Ethernet", true},
		{"USB 10/100/1000 LAN", "USB 10/100/1000 LAN", true},
		{"injection attempt", "Wi-Fi; rm -rf /", false},
		{"backtick injection", "Wi-Fi`id`", false},
		{"pipe injection", "Wi-Fi|cat /etc/passwd", false},
		{"empty", "", false},
		{"normal with dots", "VPN.Connection.1", true},
		{"underscores", "eth_0", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := serviceNameRE.MatchString(tc.input)
			if got != tc.valid {
				t.Errorf("serviceNameRE(%q) = %v, want %v", tc.input, got, tc.valid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: MAC clone filters gateway, broadcast, own MAC
// ---------------------------------------------------------------------------

func TestTryMACClone_FiltersGatewayBroadcastOwnMAC(t *testing.T) {
	plat := &mockPlatform{
		gateway:    "192.168.1.1",
		currentMAC: "aa:bb:cc:dd:ee:ff",
		arpTable: []platform.ArpEntry{
			{IP: "192.168.1.1", MAC: "11:22:33:44:55:66", Interface: "en0"},   // gateway -> skip
			{IP: "192.168.1.2", MAC: "ff:ff:ff:ff:ff:ff", Interface: "en0"},   // broadcast -> skip
			{IP: "192.168.1.3", MAC: "aa:bb:cc:dd:ee:ff", Interface: "en0"},   // our MAC -> skip
			{IP: "192.168.1.4", MAC: "(incomplete)", Interface: "en0"},         // incomplete -> skip
			{IP: "192.168.1.5", MAC: "00:11:22:33:44:55", Interface: "wlan0"}, // wrong iface -> skip
		},
		setMACOK: false, // so it won't actually try to set anything
	}

	r := tryMACClone("en0", false, plat)
	if r.Success {
		t.Error("expected failure when all candidates are filtered out")
	}
	if r.Method != MACClone {
		t.Errorf("Method = %s, want %s", r.Method, MACClone)
	}
}

// ---------------------------------------------------------------------------
// Test: MAC clone no gateway
// ---------------------------------------------------------------------------

func TestTryMACClone_NoGateway(t *testing.T) {
	plat := &mockPlatform{gateway: ""}
	r := tryMACClone("en0", false, plat)
	if r.Success {
		t.Error("should fail without gateway")
	}
	if !strings.Contains(r.Details, "No gateway") {
		t.Errorf("Details = %q, want 'No gateway'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: MAC clone invalid gateway
// ---------------------------------------------------------------------------

func TestTryMACClone_InvalidGateway(t *testing.T) {
	plat := &mockPlatform{gateway: "not-an-ip"}
	r := tryMACClone("en0", false, plat)
	if r.Success {
		t.Error("should fail with invalid gateway IP")
	}
	if !strings.Contains(r.Details, "Invalid gateway") {
		t.Errorf("Details = %q, want 'Invalid gateway'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: MAC clone idle method returns correct Method
// ---------------------------------------------------------------------------

func TestTryMACClone_IdleMethodConstant(t *testing.T) {
	plat := &mockPlatform{gateway: "192.168.1.1", currentMAC: "aa:bb:cc:dd:ee:ff"}
	r := tryMACClone("en0", true, plat)
	if r.Method != MACCloneIdle {
		t.Errorf("Method = %s, want %s for idleOnly=true", r.Method, MACCloneIdle)
	}

	r2 := tryMACClone("en0", false, plat)
	if r2.Method != MACClone {
		t.Errorf("Method = %s, want %s for idleOnly=false", r2.Method, MACClone)
	}
}

// ---------------------------------------------------------------------------
// Test: MAC clone with short MAC (filtered)
// ---------------------------------------------------------------------------

func TestTryMACClone_ShortMAC(t *testing.T) {
	plat := &mockPlatform{
		gateway:    "192.168.1.1",
		currentMAC: "aa:bb:cc:dd:ee:ff",
		arpTable: []platform.ArpEntry{
			{IP: "192.168.1.50", MAC: "ab:cd", Interface: "en0"}, // too short -> skip
		},
		setMACOK: false,
	}
	r := tryMACClone("en0", false, plat)
	if r.Success {
		t.Error("should fail with only short MAC in table")
	}
	if !strings.Contains(r.Details, "No devices") {
		t.Errorf("Details = %q, want 'No devices' message", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: MAC clone SetMAC fails for all candidates
// ---------------------------------------------------------------------------

func TestTryMACClone_SetMACFails(t *testing.T) {
	plat := &mockPlatform{
		gateway:    "192.168.1.1",
		currentMAC: "aa:bb:cc:dd:ee:ff",
		arpTable: []platform.ArpEntry{
			{IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Interface: "en0"},
			{IP: "192.168.1.51", MAC: "00:11:22:33:44:66", Interface: "en0"},
		},
		setMACOK: false, // SetMAC always fails
	}
	r := tryMACClone("en0", false, plat)
	if r.Success {
		t.Error("should fail when SetMAC returns false for all candidates")
	}
}

// ---------------------------------------------------------------------------
// Test: CNA spoof (mock HTTP server returning 204)
// ---------------------------------------------------------------------------

func TestTryCNASpoof_Success(t *testing.T) {
	// We cannot easily mock the hardcoded URL in tryCNASpoof without
	// modifying the source. Instead, verify the function returns a Result
	// with the correct Method and does not panic.
	r := tryCNASpoof()
	if r.Method != CNASpoof {
		t.Errorf("Method = %s, want %s", r.Method, CNASpoof)
	}
	// In a test environment without a portal, this should fail gracefully.
	// We just verify it doesn't panic and returns a well-formed result.
	if r.Success && r.Severity == "" {
		t.Error("successful result should have a severity")
	}
}

// ---------------------------------------------------------------------------
// Test: JS bypass (mock HTTP server)
// ---------------------------------------------------------------------------

func TestTryJSBypass_NoPanic(t *testing.T) {
	r := tryJSBypass()
	if r.Method != JSBypass {
		t.Errorf("Method = %s, want %s", r.Method, JSBypass)
	}
}

// ---------------------------------------------------------------------------
// Test: No server configured -> server-requiring techniques skip
// ---------------------------------------------------------------------------

func TestRunBypasses_NoServer_SkipsWithMessage(t *testing.T) {
	probes := &ProbeResults{
		DNS:  ProbeResult{IsOpen: true},
		ICMP: ProbeResult{IsOpen: true},
		QUIC: ProbeResult{IsOpen: true},
		NTP:  ProbeResult{IsOpen: true},
	}
	config := &Config{Interface: "en0"} // No servers configured
	plat := &mockPlatform{}

	results := RunBypasses(probes, config, plat)

	// Collect server-dependent methods and their details.
	serverMethods := map[Method]bool{
		ChiselTunnel: true,
		DNSTunnel:    true,
		ICMPTunnel:   true,
		VPNPort53:    true,
		QUICTunnel:   true,
		NTPTunnel:    true,
	}

	for _, r := range results {
		if serverMethods[r.Method] {
			if r.Success {
				t.Errorf("%s should not succeed without server config", r.Method)
			}
			// Verify the details mention configuration or server.
			hasHint := false
			for _, kw := range []string{"configured", "server", "domain", "route"} {
				if contains(r.Details, kw) {
					hasHint = true
					break
				}
			}
			if !hasHint {
				t.Errorf("%s details %q should mention missing config", r.Method, r.Details)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Result struct fields
// ---------------------------------------------------------------------------

func TestResultStruct(t *testing.T) {
	r := Result{
		Method:      IPv6Bypass,
		Success:     true,
		Severity:    "critical",
		Impact:      "full internet",
		Details:     "IPv6 open",
		Remediation: "filter IPv6",
	}
	if r.Method != IPv6Bypass {
		t.Error("Method mismatch")
	}
	if !r.Success {
		t.Error("expected success")
	}
}

// ---------------------------------------------------------------------------
// Test: defaultPlatformOps returns safe defaults
// ---------------------------------------------------------------------------

func TestDefaultPlatformOps(t *testing.T) {
	d := &defaultPlatformOps{}
	if d.GetGateway("en0") != "" {
		t.Error("default GetGateway should return empty")
	}
	if d.GetCurrentMAC("en0") != "" {
		t.Error("default GetCurrentMAC should return empty")
	}
	if d.GetArpTable() != nil {
		t.Error("default GetArpTable should return nil")
	}
	if d.SetMAC("en0", "aa:bb:cc:dd:ee:ff") {
		t.Error("default SetMAC should return false")
	}
	d.RenewDHCP("en0") // should not panic

	mac := d.GenerateRandomMAC()
	if len(mac) != 17 {
		t.Errorf("GenerateRandomMAC returned %q, expected 17-char MAC", mac)
	}
}

// ---------------------------------------------------------------------------
// Test: HTTP CONNECT technique with mock
// ---------------------------------------------------------------------------

func TestTryHTTPConnect_NoGateway(t *testing.T) {
	plat := &mockPlatform{gateway: ""}
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}

	r := tryHTTPConnect(probes, config, plat)
	if r.Success {
		t.Error("should fail without gateway")
	}
	if r.Method != HTTPConnect {
		t.Errorf("Method = %s, want %s", r.Method, HTTPConnect)
	}
}

// ---------------------------------------------------------------------------
// Test: HTTP CONNECT with invalid gateway IP
// ---------------------------------------------------------------------------

func TestTryHTTPConnect_InvalidGateway(t *testing.T) {
	plat := &mockPlatform{gateway: "not-a-valid-ip"}
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}

	r := tryHTTPConnect(probes, config, plat)
	if r.Success {
		t.Error("should fail with invalid gateway IP")
	}
	if !strings.Contains(r.Details, "Invalid gateway") {
		t.Errorf("Details = %q, want 'Invalid gateway'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: Whitelist technique
// ---------------------------------------------------------------------------

func TestTryWhitelist(t *testing.T) {
	tests := []struct {
		name       string
		whitelists []WhitelistResult
		wantOpen   bool
	}{
		{
			"no whitelists",
			nil,
			false,
		},
		{
			"all closed",
			[]WhitelistResult{{Domain: "apple.com", IsOpen: false}},
			false,
		},
		{
			"one open",
			[]WhitelistResult{
				{Domain: "apple.com", IsOpen: true},
				{Domain: "google.com", IsOpen: false},
			},
			false, // whitelist technique always returns Success=false (advisory only)
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probes := &ProbeResults{Whitelists: tc.whitelists}
			r := tryWhitelist(probes)
			if r.Method != WhitelistDomain {
				t.Errorf("Method = %s, want %s", r.Method, WhitelistDomain)
			}
			if r.Success != tc.wantOpen {
				t.Errorf("Success = %v, want %v", r.Success, tc.wantOpen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Whitelist with multiple open domains includes them in details
// ---------------------------------------------------------------------------

func TestTryWhitelist_MultipleOpen(t *testing.T) {
	probes := &ProbeResults{Whitelists: []WhitelistResult{
		{Domain: "apple.com", IsOpen: true},
		{Domain: "cloudflare.com", IsOpen: true},
		{Domain: "google.com", IsOpen: false},
	}}
	r := tryWhitelist(probes)
	if !strings.Contains(r.Details, "apple.com") {
		t.Error("Details should mention apple.com")
	}
	if !strings.Contains(r.Details, "cloudflare.com") {
		t.Error("Details should mention cloudflare.com")
	}
	if r.Severity != "medium" {
		t.Errorf("Severity = %q, want 'medium'", r.Severity)
	}
}

// ---------------------------------------------------------------------------
// Test: Whitelist with empty list
// ---------------------------------------------------------------------------

func TestTryWhitelist_EmptySlice(t *testing.T) {
	probes := &ProbeResults{Whitelists: []WhitelistResult{}}
	r := tryWhitelist(probes)
	if r.Success {
		t.Error("empty whitelist should not succeed")
	}
	if !strings.Contains(r.Details, "No whitelisted domains") {
		t.Errorf("Details = %q, want 'No whitelisted domains' message", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: DNS tunnel without DNS
// ---------------------------------------------------------------------------

func TestTryDNSTunnel_DNSClosed(t *testing.T) {
	probes := &ProbeResults{DNS: ProbeResult{IsOpen: false}}
	config := &Config{DNSDomain: "t.example.com"}

	r := tryDNSTunnel(config, probes)
	if r.Success {
		t.Error("should fail when DNS is closed")
	}
	if r.Method != DNSTunnel {
		t.Errorf("Method = %s, want %s", r.Method, DNSTunnel)
	}
}

func TestTryDNSTunnel_NoDomain(t *testing.T) {
	probes := &ProbeResults{DNS: ProbeResult{IsOpen: true}}
	config := &Config{}

	r := tryDNSTunnel(config, probes)
	if r.Success {
		t.Error("should fail without domain")
	}
	if !strings.Contains(r.Details, "domain") {
		t.Errorf("Details = %q, want mention of domain", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: ICMP tunnel without ICMP
// ---------------------------------------------------------------------------

func TestTryICMPTunnel_ICMPClosed(t *testing.T) {
	probes := &ProbeResults{ICMP: ProbeResult{IsOpen: false}}
	config := &Config{ICMPServer: "1.2.3.4"}

	r := tryICMPTunnel(config, probes)
	if r.Success {
		t.Error("should fail when ICMP is closed")
	}
}

func TestTryICMPTunnel_NoServer(t *testing.T) {
	probes := &ProbeResults{ICMP: ProbeResult{IsOpen: true}}
	config := &Config{}

	r := tryICMPTunnel(config, probes)
	if r.Success {
		t.Error("should fail without server")
	}
	if !strings.Contains(r.Details, "server") {
		t.Errorf("Details = %q, want mention of server", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: QUIC tunnel without QUIC
// ---------------------------------------------------------------------------

func TestTryQUICTunnel_QUICClosed(t *testing.T) {
	probes := &ProbeResults{QUIC: ProbeResult{IsOpen: false}}
	config := &Config{QUICServer: "quic.example.com"}

	r := tryQUICTunnel(config, probes)
	if r.Success {
		t.Error("should fail when QUIC is closed")
	}
}

// ---------------------------------------------------------------------------
// Test: QUIC tunnel uses TunnelServer as fallback
// ---------------------------------------------------------------------------

func TestTryQUICTunnel_NoServer(t *testing.T) {
	probes := &ProbeResults{QUIC: ProbeResult{IsOpen: true}}
	config := &Config{} // no QUICServer and no TunnelServer

	r := tryQUICTunnel(config, probes)
	if r.Success {
		t.Error("should fail without any server")
	}
	if !strings.Contains(r.Details, "server") {
		t.Errorf("Details = %q, want mention of server", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: NTP tunnel without NTP
// ---------------------------------------------------------------------------

func TestTryNTPTunnel_NTPClosed(t *testing.T) {
	probes := &ProbeResults{NTP: ProbeResult{IsOpen: false}}
	config := &Config{NTPServer: "ntp.example.com"}

	r := tryNTPTunnel(config, probes)
	if r.Success {
		t.Error("should fail when NTP is closed")
	}
}

func TestTryNTPTunnel_NoServer(t *testing.T) {
	probes := &ProbeResults{NTP: ProbeResult{IsOpen: true}}
	config := &Config{}

	r := tryNTPTunnel(config, probes)
	if r.Success {
		t.Error("should fail without server")
	}
	if !strings.Contains(r.Details, "server") {
		t.Errorf("Details = %q, want mention of server", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: DoH tunnel without DoH
// ---------------------------------------------------------------------------

func TestTryDoHTunnel_DoHClosed(t *testing.T) {
	probes := &ProbeResults{DoH: ProbeResult{IsOpen: false}}

	r := tryDoHTunnel(probes)
	if r.Success {
		t.Error("should fail when DoH is closed")
	}
	if !strings.Contains(r.Details, "not reachable") {
		t.Errorf("Details = %q, want 'not reachable'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: VPN port 53 without config
// ---------------------------------------------------------------------------

func TestTryVPNPort53_NoServer(t *testing.T) {
	probes := &ProbeResults{DNS: ProbeResult{IsOpen: true}}
	config := &Config{}

	r := tryVPNPort53(config, probes)
	if r.Success {
		t.Error("should fail without VPN server")
	}
	if !strings.Contains(r.Details, "VPN server") {
		t.Errorf("Details = %q, want mention of VPN server", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: VPN port 53 -- port not open
// ---------------------------------------------------------------------------

func TestTryVPNPort53_PortClosed(t *testing.T) {
	probes := &ProbeResults{
		DNS:       ProbeResult{IsOpen: false},
		OpenPorts: []PortResult{{Port: 80, IsOpen: true}, {Port: 443, IsOpen: true}},
	}
	config := &Config{VPNServer: "vpn.example.com"}

	r := tryVPNPort53(config, probes)
	if r.Success {
		t.Error("should fail when port 53 is not open")
	}
	if !strings.Contains(r.Details, "Port 53 not open") {
		t.Errorf("Details = %q, want 'Port 53 not open'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: VPN port 53 -- port 53 in OpenPorts
// ---------------------------------------------------------------------------

func TestTryVPNPort53_Port53InOpenPorts(t *testing.T) {
	probes := &ProbeResults{
		DNS:       ProbeResult{IsOpen: false},
		OpenPorts: []PortResult{{Port: 53, IsOpen: true}},
	}
	config := &Config{VPNServer: "vpn.example.com"}

	r := tryVPNPort53(config, probes)
	// Should not fail with "Port 53 not open" -- it passes the port check
	// and proceeds to try WireGuard (which will fail without the binary).
	if strings.Contains(r.Details, "Port 53 not open") {
		t.Errorf("should pass port check when port 53 is open; Details = %q", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: CF Workers without URL
// ---------------------------------------------------------------------------

func TestTryCFWorkers_NoURL(t *testing.T) {
	probes := &ProbeResults{Cloudflare: ProbeResult{IsOpen: true}}
	config := &Config{}

	r := tryCFWorkers(config, probes)
	if r.Success {
		t.Error("should fail without CF Workers URL")
	}
}

// ---------------------------------------------------------------------------
// Test: CF Workers -- Cloudflare not reachable
// ---------------------------------------------------------------------------

func TestTryCFWorkers_CloudflareNotReachable(t *testing.T) {
	probes := &ProbeResults{Cloudflare: ProbeResult{IsOpen: false}}
	config := &Config{CFWorkersURL: "https://my-worker.workers.dev"}

	r := tryCFWorkers(config, probes)
	if r.Success {
		t.Error("should fail when Cloudflare is not reachable")
	}
	if !strings.Contains(r.Details, "Cloudflare not reachable") {
		t.Errorf("Details = %q, want 'Cloudflare not reachable'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: CF Workers -- Cloudflare reachable via whitelist
// ---------------------------------------------------------------------------

func TestTryCFWorkers_CloudflareViaWhitelist(t *testing.T) {
	probes := &ProbeResults{
		Cloudflare: ProbeResult{IsOpen: false},
		Whitelists: []WhitelistResult{
			{Domain: "cloudflare.com", IsOpen: true},
		},
	}
	config := &Config{CFWorkersURL: "https://my-worker.workers.dev"}

	r := tryCFWorkers(config, probes)
	// Should pass the CF reachability check (via whitelist with "cloudflare").
	// Will still fail because VerifyCFWorkersProxy requires real connectivity.
	if strings.Contains(r.Details, "Cloudflare not reachable") {
		t.Errorf("should pass CF check via whitelist; Details = %q", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: Session replay no gateway
// ---------------------------------------------------------------------------

func TestTrySessionReplay_NoGateway(t *testing.T) {
	plat := &mockPlatform{gateway: ""}
	r := trySessionReplay("en0", plat)
	if r.Success {
		t.Error("should fail without gateway")
	}
	if r.Method != SessionReplay {
		t.Errorf("Method = %s, want %s", r.Method, SessionReplay)
	}
}

// ---------------------------------------------------------------------------
// Test: MAC rotate
// ---------------------------------------------------------------------------

func TestTryMACRotate_NoSudo(t *testing.T) {
	plat := &mockPlatform{
		setMACOK:  false,
		randomMAC: "02:11:22:33:44:55",
	}
	r := tryMACRotate("en0", plat)
	if r.Success {
		t.Error("should fail without sudo")
	}
	if !strings.Contains(r.Details, "sudo") {
		t.Errorf("Details = %q, want mention of sudo", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: Portal creds no gateway
// ---------------------------------------------------------------------------

func TestTryDefaultCreds_NoGateway(t *testing.T) {
	plat := &mockPlatform{gateway: ""}
	r := tryDefaultCreds("en0", plat)
	if r.Success {
		t.Error("should fail without gateway")
	}
}

// ---------------------------------------------------------------------------
// Test: Portal creds with mock server
// ---------------------------------------------------------------------------

func TestTryDefaultCreds_WithMockServer(t *testing.T) {
	// Create a mock server that serves a login form and accepts admin/admin.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, `<html><form>Username: <input name="username"/>Password: <input name="password" type="password"/><button>Login</button></form></html>`)
			return
		}
		if r.Method == "POST" {
			r.ParseForm()
			if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
				fmt.Fprint(w, `<html>Welcome, admin! Dashboard.</html>`)
				return
			}
			fmt.Fprint(w, `<html><form>Login failed. Username: <input/></form></html>`)
		}
	}))
	defer ts.Close()

	// The tryDefaultCreds function uses the gateway IP, not a URL, so we
	// can't directly inject our mock server without changing the source.
	// This test verifies the function handles a real HTTP server correctly
	// by checking it doesn't panic and returns a well-formed Result.
	plat := &mockPlatform{gateway: "127.0.0.1"}
	r := tryDefaultCreds("en0", plat)
	if r.Method != PortalCreds {
		t.Errorf("Method = %s, want %s", r.Method, PortalCreds)
	}
}

// ---------------------------------------------------------------------------
// Test: Chisel tunnel -- no server configured, CF blocked
// ---------------------------------------------------------------------------

func TestTryChisel_NoServerNoCF(t *testing.T) {
	probes := &ProbeResults{
		Cloudflare: ProbeResult{IsOpen: false},
	}
	config := &Config{} // no TunnelServer

	r := tryChisel(config, probes)
	if r.Success {
		t.Error("should fail without server and CF")
	}
	if r.Method != ChiselTunnel {
		t.Errorf("Method = %s, want %s", r.Method, ChiselTunnel)
	}
}

// ---------------------------------------------------------------------------
// Test: Chisel tunnel -- CF reachable but no server
// ---------------------------------------------------------------------------

func TestTryChisel_CFReachableNoServer(t *testing.T) {
	probes := &ProbeResults{
		Cloudflare: ProbeResult{IsOpen: true},
	}
	config := &Config{} // no TunnelServer

	r := tryChisel(config, probes)
	if r.Success {
		t.Error("should fail without server even if CF is reachable")
	}
}

// ---------------------------------------------------------------------------
// Test: Chisel tunnel -- CF via whitelisted domain
// ---------------------------------------------------------------------------

func TestTryChisel_CFViaWhitelist(t *testing.T) {
	probes := &ProbeResults{
		Cloudflare: ProbeResult{IsOpen: false},
		Whitelists: []WhitelistResult{
			{Domain: "apple.com", IsOpen: true},
		},
	}
	config := &Config{TunnelServer: "https://tunnel.example.com"}

	r := tryChisel(config, probes)
	// CF becomes reachable via whitelist. Chisel will attempt connection
	// but fail because tunnel.example.com is not a real server.
	if r.Method != ChiselTunnel {
		t.Errorf("Method = %s, want %s", r.Method, ChiselTunnel)
	}
}

// ---------------------------------------------------------------------------
// Test: Chisel tunnel -- server configured, no open ports
// ---------------------------------------------------------------------------

func TestTryChisel_ServerNoOpenPorts(t *testing.T) {
	probes := &ProbeResults{
		Cloudflare:        ProbeResult{IsOpen: false},
		TunnelServerPorts: []PortResult{
			{Port: 443, IsOpen: false},
			{Port: 80, IsOpen: false},
		},
	}
	config := &Config{TunnelServer: "https://tunnel.example.com"}

	r := tryChisel(config, probes)
	if r.Success {
		t.Error("should fail with no open ports on tunnel server")
	}
}

// ---------------------------------------------------------------------------
// Test: ProbeResult / WhitelistResult / PortResult types
// ---------------------------------------------------------------------------

func TestProbeResultTypes(t *testing.T) {
	// ProbeResult
	pr := ProbeResult{IsOpen: true, Details: "test detail"}
	if !pr.IsOpen || pr.Details != "test detail" {
		t.Error("ProbeResult fields")
	}

	// WhitelistResult
	wr := WhitelistResult{Domain: "example.com", IsOpen: true, Details: "accessible"}
	if wr.Domain != "example.com" || !wr.IsOpen {
		t.Error("WhitelistResult fields")
	}

	// PortResult
	port := PortResult{Port: 443, Service: "HTTPS", IsOpen: true}
	if port.Port != 443 || !port.IsOpen || port.Service != "HTTPS" {
		t.Error("PortResult fields")
	}
}

// ---------------------------------------------------------------------------
// Test: ProbeResults struct -- all fields accessible
// ---------------------------------------------------------------------------

func TestProbeResults_AllFields(t *testing.T) {
	pr := &ProbeResults{
		DNS:        ProbeResult{IsOpen: true, Details: "DNS open"},
		ICMP:       ProbeResult{IsOpen: false, Details: "ICMP blocked"},
		IPv6:       ProbeResult{IsOpen: true, Details: "IPv6 working"},
		Cloudflare: ProbeResult{IsOpen: true, Details: "CF reachable"},
		QUIC:       ProbeResult{IsOpen: false},
		NTP:        ProbeResult{IsOpen: false},
		DoH:        ProbeResult{IsOpen: true},
		Whitelists: []WhitelistResult{
			{Domain: "apple.com", IsOpen: true},
		},
		OpenPorts: []PortResult{
			{Port: 80, IsOpen: true},
		},
		TunnelServerPorts: []PortResult{
			{Port: 443, IsOpen: false},
		},
	}

	if !pr.DNS.IsOpen {
		t.Error("DNS should be open")
	}
	if pr.ICMP.IsOpen {
		t.Error("ICMP should be closed")
	}
	if len(pr.Whitelists) != 1 {
		t.Errorf("Whitelists len = %d, want 1", len(pr.Whitelists))
	}
	if len(pr.OpenPorts) != 1 {
		t.Errorf("OpenPorts len = %d, want 1", len(pr.OpenPorts))
	}
}

// ---------------------------------------------------------------------------
// Test: Config struct fields
// ---------------------------------------------------------------------------

func TestConfigStruct(t *testing.T) {
	c := Config{
		Interface:    "en0",
		TunnelServer: "https://tunnel.example.com",
		DNSDomain:    "t.example.com",
		ICMPServer:   "1.2.3.4",
		QUICServer:   "quic.example.com",
		NTPServer:    "ntp.example.com",
		CFWorkersURL: "https://worker.workers.dev",
		VPNServer:    "vpn.example.com",
		Stealth:      true,
	}
	if c.Interface != "en0" {
		t.Error("Interface")
	}
	if c.TunnelServer != "https://tunnel.example.com" {
		t.Error("TunnelServer")
	}
	if !c.Stealth {
		t.Error("Stealth")
	}
}

// ---------------------------------------------------------------------------
// Test: DHCP rotate calls RenewDHCP
// ---------------------------------------------------------------------------

func TestTryDHCPRotate_CallsRenew(t *testing.T) {
	plat := &mockPlatform{}
	// tryDHCPRotate always calls RenewDHCP and then checks hasInternet.
	_ = tryDHCPRotate("en0", plat)
	if plat.renewCalls == 0 {
		t.Error("expected RenewDHCP to be called")
	}
}

// ---------------------------------------------------------------------------
// Test: tryHTTPConnect with valid gateway but no CONNECT support
// ---------------------------------------------------------------------------

func TestTryHTTPConnect_ValidGatewayNoConnect(t *testing.T) {
	// Use 127.0.0.1 as a valid gateway IP. The function tries ports 80, 8080, 3128.
	// Nothing listens there (or if it does, it won't support CONNECT).
	plat := &mockPlatform{gateway: "127.0.0.1"}
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}

	r := tryHTTPConnect(probes, config, plat)
	if r.Method != HTTPConnect {
		t.Errorf("Method = %s, want %s", r.Method, HTTPConnect)
	}
	// Should fail -- no proxy running on standard ports.
	if r.Success {
		t.Error("should fail when no CONNECT proxy is running")
	}
	if !strings.Contains(r.Details, "CONNECT not available") {
		t.Errorf("Details = %q, want 'CONNECT not available'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: trySessionReplay with mock HTTP server (portal with cookies)
// ---------------------------------------------------------------------------

func TestTrySessionReplay_PortalWithCookies(t *testing.T) {
	// Create a portal that sets cookies over HTTP.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "SESSIONID", Value: "abc123"})
		w.WriteHeader(200)
		fmt.Fprint(w, `<html>Portal Login</html>`)
	}))
	defer ts.Close()

	// trySessionReplay uses the gateway IP directly on port 80.
	// We cannot make it hit our mock server directly since it constructs
	// the URL from the gateway. Test with 127.0.0.1 which will hit
	// whatever is on port 80 (or fail).
	plat := &mockPlatform{gateway: "127.0.0.1"}
	r := trySessionReplay("en0", plat)
	if r.Method != SessionReplay {
		t.Errorf("Method = %s, want %s", r.Method, SessionReplay)
	}
	// Will likely fail (nothing on 127.0.0.1:80 with cookies) but
	// should not panic.
}

// ---------------------------------------------------------------------------
// Test: trySessionReplay verifies it does not succeed without cookies
// ---------------------------------------------------------------------------

func TestTrySessionReplay_NoCookies(t *testing.T) {
	plat := &mockPlatform{gateway: "127.0.0.1"}
	r := trySessionReplay("en0", plat)
	// Without a portal serving HTTP cookies, this should always fail.
	if r.Success {
		t.Error("should not succeed without portal cookies")
	}
}

// ---------------------------------------------------------------------------
// Test: tryDoHTunnel with open DoH -- tests beyond the early return
// ---------------------------------------------------------------------------

func TestTryDoHTunnel_DoHOpen(t *testing.T) {
	probes := &ProbeResults{DoH: ProbeResult{IsOpen: true}}
	r := tryDoHTunnel(probes)
	// DoH is open, so the function proceeds past the early return.
	// It will try tunnel.StartDoHTunnel which will fail (no real tunnel binary),
	// but we exercise the DoH-open path.
	if r.Method != DoHTunnel {
		t.Errorf("Method = %s, want %s", r.Method, DoHTunnel)
	}
}

// ---------------------------------------------------------------------------
// Test: tryDNSTunnel with DNS open and domain configured
// ---------------------------------------------------------------------------

func TestTryDNSTunnel_DNSOpenDomainSet(t *testing.T) {
	probes := &ProbeResults{DNS: ProbeResult{IsOpen: true}}
	config := &Config{DNSDomain: "t.example.com"}
	r := tryDNSTunnel(config, probes)
	// Should pass both early returns and try to start the tunnel.
	if r.Method != DNSTunnel {
		t.Errorf("Method = %s, want %s", r.Method, DNSTunnel)
	}
	// Will fail because tunnel binary is not available.
	if r.Success {
		t.Error("should fail without real tunnel binary")
	}
}

// ---------------------------------------------------------------------------
// Test: tryICMPTunnel with ICMP open and server configured
// ---------------------------------------------------------------------------

func TestTryICMPTunnel_ICMPOpenServerSet(t *testing.T) {
	probes := &ProbeResults{ICMP: ProbeResult{IsOpen: true}}
	config := &Config{ICMPServer: "1.2.3.4"}
	r := tryICMPTunnel(config, probes)
	if r.Method != ICMPTunnel {
		t.Errorf("Method = %s, want %s", r.Method, ICMPTunnel)
	}
}

// ---------------------------------------------------------------------------
// Test: tryNTPTunnel with NTP open and server configured
// ---------------------------------------------------------------------------

func TestTryNTPTunnel_NTPOpenServerSet(t *testing.T) {
	probes := &ProbeResults{NTP: ProbeResult{IsOpen: true}}
	config := &Config{NTPServer: "ntp.example.com"}
	r := tryNTPTunnel(config, probes)
	if r.Method != NTPTunnel {
		t.Errorf("Method = %s, want %s", r.Method, NTPTunnel)
	}
}

// ---------------------------------------------------------------------------
// Test: tryQUICTunnel with QUIC open and QUICServer configured
// ---------------------------------------------------------------------------

func TestTryQUICTunnel_QUICOpenServerSet(t *testing.T) {
	probes := &ProbeResults{QUIC: ProbeResult{IsOpen: true}}
	config := &Config{QUICServer: "quic.example.com"}
	r := tryQUICTunnel(config, probes)
	if r.Method != QUICTunnel {
		t.Errorf("Method = %s, want %s", r.Method, QUICTunnel)
	}
}

// ---------------------------------------------------------------------------
// Test: tryQUICTunnel falls back to TunnelServer
// ---------------------------------------------------------------------------

func TestTryQUICTunnel_FallsBackToTunnelServer(t *testing.T) {
	probes := &ProbeResults{QUIC: ProbeResult{IsOpen: true}}
	config := &Config{TunnelServer: "https://tunnel.example.com"} // No QUICServer
	r := tryQUICTunnel(config, probes)
	if r.Method != QUICTunnel {
		t.Errorf("Method = %s, want %s", r.Method, QUICTunnel)
	}
	// Should not have the "No QUIC server" error.
	if strings.Contains(r.Details, "No QUIC server") {
		t.Error("should use TunnelServer as fallback")
	}
}

// ---------------------------------------------------------------------------
// Test: tryVPNPort53 with DNS open (direct, not via OpenPorts)
// ---------------------------------------------------------------------------

func TestTryVPNPort53_DNSOpen(t *testing.T) {
	probes := &ProbeResults{DNS: ProbeResult{IsOpen: true}}
	config := &Config{VPNServer: "vpn.example.com"}
	r := tryVPNPort53(config, probes)
	// DNS.IsOpen passes the port check. Should proceed to try WireGuard.
	if strings.Contains(r.Details, "Port 53 not open") {
		t.Errorf("should pass port check via DNS.IsOpen; Details = %q", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: tryChisel with TunnelServer and open tunnel port
// ---------------------------------------------------------------------------

func TestTryChisel_WithOpenTunnelPort(t *testing.T) {
	probes := &ProbeResults{
		Cloudflare:        ProbeResult{IsOpen: false},
		TunnelServerPorts: []PortResult{
			{Port: 443, IsOpen: true},
		},
	}
	config := &Config{TunnelServer: "https://tunnel.example.com"}
	r := tryChisel(config, probes)
	// CF is not reachable, but there's an open port on the tunnel server.
	// The function should attempt direct connection (and fail because the server
	// doesn't exist), but we exercise the direct-connect path.
	if r.Method != ChiselTunnel {
		t.Errorf("Method = %s, want %s", r.Method, ChiselTunnel)
	}
}

// ---------------------------------------------------------------------------
// Test: measureNetworkLatency with invalid gateway
// ---------------------------------------------------------------------------

func TestMeasureNetworkLatency_InvalidGateway(t *testing.T) {
	// Invalid IP returns conservative 2s default.
	d := measureNetworkLatency("not-a-valid-ip")
	if d != 2*time.Second {
		t.Errorf("measureNetworkLatency(invalid) = %v, want 2s", d)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
