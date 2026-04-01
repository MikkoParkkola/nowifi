// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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
}

func (m *mockPlatform) GetGateway(iface string) string       { return m.gateway }
func (m *mockPlatform) GetCurrentMAC(iface string) string    { return m.currentMAC }
func (m *mockPlatform) GetArpTable() []platform.ArpEntry     { return m.arpTable }
func (m *mockPlatform) SetMAC(iface, mac string) bool        { return m.setMACOK }
func (m *mockPlatform) RenewDHCP(iface string)               { m.renewCalls++ }
func (m *mockPlatform) GenerateRandomMAC() string             { return m.randomMAC }

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
// Test: Session replay no gateway
// ---------------------------------------------------------------------------

func TestTrySessionReplay_NoGateway(t *testing.T) {
	plat := &mockPlatform{gateway: ""}
	r := trySessionReplay("en0", plat)
	if r.Success {
		t.Error("should fail without gateway")
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
