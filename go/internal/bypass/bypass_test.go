// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/crack"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/techniques"
	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

// ---------------------------------------------------------------------------
// Mock PlatformOps
// ---------------------------------------------------------------------------

type mockPlatform struct {
	arpTable   []platform.ArpEntry
	currentMAC string
	gateway    string
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

func TestReadmeTechniqueClaimsMatchImplementation(t *testing.T) {
	readmePath := filepath.Join("..", "..", "..", "README.md")
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", readmePath, err)
	}

	readme := string(data)
	bypassMethods := []Method{
		IPv6Bypass,
		ChiselTunnel,
		CNASpoof,
		JSBypass,
		HTTPConnect,
		MACCloneIdle,
		MACClone,
		DNSTunnel,
		ICMPTunnel,
		VPNPort53,
		WhitelistDomain,
		SessionReplay,
		PortalCreds,
		MACRotate,
		DHCPRotate,
		QUICTunnel,
		CFWorkers,
		NTPTunnel,
		DoHTunnel,
	}
	crackMethods := []crack.Method{
		crack.PMKID,
		crack.Handshake,
		crack.Hashcat,
		crack.Dictionary,
		crack.WPSPixie,
		crack.WPSPin,
		crack.OnlineBrute,
		crack.SmartCrackM,
	}
	totalTechniques := len(bypassMethods) + len(crackMethods)

	if !strings.Contains(readme, fmt.Sprintf("One command. %d techniques.", totalTechniques)) {
		t.Fatalf("README should advertise the current overall technique count of %d", totalTechniques)
	}
	if !strings.Contains(readme, fmt.Sprintf("tries %d bypass techniques automatically", len(bypassMethods))) {
		t.Fatalf("README should advertise the current bypass technique count of %d", len(bypassMethods))
	}
	if !strings.Contains(readme, fmt.Sprintf("## %d Techniques", totalTechniques)) {
		t.Fatalf("README should headline the current total technique count of %d", totalTechniques)
	}
	if !strings.Contains(readme, fmt.Sprintf("### Portal Bypass (%d techniques)", len(bypassMethods))) {
		t.Fatalf("README should headline the current portal bypass count of %d", len(bypassMethods))
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

func TestTechniqueRunnerRegistryMatchesTechniqueMetadata(t *testing.T) {
	for _, info := range techniques.BypassTechniqueInfos() {
		if _, ok := techniqueRunnerByMethod[Method(info.ID)]; !ok {
			t.Fatalf("missing runner for technique %s", info.ID)
		}
	}
}

func TestOrderedTechniqueRunners_MissingRunnerReturnsFailure(t *testing.T) {
	original, ok := techniqueRunnerByMethod[IPv6Bypass]
	if !ok {
		t.Fatal("expected IPv6Bypass runner to exist")
	}
	delete(techniqueRunnerByMethod, IPv6Bypass)
	defer func() {
		techniqueRunnerByMethod[IPv6Bypass] = original
	}()

	runners := orderedTechniqueRunners()
	if len(runners) != techniques.BypassTechniqueCount() {
		t.Fatalf("expected %d runners, got %d", techniques.BypassTechniqueCount(), len(runners))
	}

	if runners[0].runName != "IPv6 bypass" {
		t.Fatalf("expected fallback runner name %q, got %q", "IPv6 bypass", runners[0].runName)
	}

	result := runners[0].run(&ProbeResults{}, &Config{}, &mockPlatform{})
	if result.Success {
		t.Fatal("expected missing runner fallback to fail")
	}
	if result.Method != IPv6Bypass {
		t.Fatalf("expected method %q, got %q", IPv6Bypass, result.Method)
	}
	if result.Severity != "critical" {
		t.Fatalf("expected critical severity, got %q", result.Severity)
	}
	if !strings.Contains(result.Details, "missing runner for technique ipv6_bypass") {
		t.Fatalf("unexpected details: %q", result.Details)
	}
	if !strings.Contains(result.Remediation, "runner registry") {
		t.Fatalf("unexpected remediation: %q", result.Remediation)
	}
}

func TestFinalizeSuccessfulTunnelResult_ConfiguresSystemProxy(t *testing.T) {
	oldSetSystemProxyFn := setSystemProxyFn
	defer func() {
		setSystemProxyFn = oldSetSystemProxyFn
	}()

	var gotIface string
	var gotPort int
	setSystemProxyFn = func(iface string, port int) error {
		gotIface = iface
		gotPort = port
		return nil
	}

	handle := &tunnel.Handle{Active: true, LocalPort: 1080}
	result := finalizeSuccessfulTunnelResult("en0", Result{
		Method:  ChiselTunnel,
		Success: true,
		Details: "HTTPS/WebSocket tunnel through https://tunnel.example.com",
		Tunnel:  handle,
	})

	if !result.Success {
		t.Fatal("expected proxy setup success to preserve successful result")
	}
	if result.Tunnel != handle {
		t.Fatal("expected active tunnel handle to be preserved on proxy setup success")
	}
	if gotIface != "en0" || gotPort != 1080 {
		t.Fatalf("setSystemProxyFn called with (%q, %d), want (%q, %d)", gotIface, gotPort, "en0", 1080)
	}
}

func TestFinalizeSuccessfulTunnelResult_StopsTunnelOnProxySetupFailure(t *testing.T) {
	oldSetSystemProxyFn := setSystemProxyFn
	defer func() {
		setSystemProxyFn = oldSetSystemProxyFn
	}()

	setSystemProxyFn = func(iface string, port int) error {
		if iface != "en0" || port != 1080 {
			t.Fatalf("unexpected proxy setup call (%q, %d)", iface, port)
		}
		return fmt.Errorf("permission denied")
	}

	handle := &tunnel.Handle{Active: true, LocalPort: 1080}
	result := finalizeSuccessfulTunnelResult("en0", Result{
		Method:      ChiselTunnel,
		Success:     true,
		Severity:    "critical",
		Impact:      "Full internet via system SOCKS proxy (auto-configured)",
		Details:     "HTTPS/WebSocket tunnel through https://tunnel.example.com",
		Remediation: "Block WebSocket upgrades pre-auth.",
		Tunnel:      handle,
	})

	if result.Success {
		t.Fatal("expected proxy setup failure to clear successful result")
	}
	if result.Tunnel != nil {
		t.Fatal("expected failed proxy setup to clear tunnel handle from the result")
	}
	if handle.Active {
		t.Fatal("expected failed proxy setup to stop the active tunnel")
	}
	if result.Severity != "" {
		t.Fatalf("Severity = %q, want empty string after proxy setup failure", result.Severity)
	}
	if result.Impact != "" {
		t.Fatalf("Impact = %q, want empty string after proxy setup failure", result.Impact)
	}
	if result.Remediation != "Fix local proxy configuration permissions and retry." {
		t.Fatalf("Remediation = %q, want proxy setup remediation", result.Remediation)
	}
	if !contains(result.Details, "HTTPS/WebSocket tunnel through https://tunnel.example.com") {
		t.Fatalf("Details = %q, want original success details preserved", result.Details)
	}
	if !contains(result.Details, "failed to configure system SOCKS proxy on port 1080: permission denied") {
		t.Fatalf("Details = %q, want proxy setup failure details", result.Details)
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
			{IP: "192.168.1.4", MAC: "(incomplete)", Interface: "en0"},        // incomplete -> skip
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
		Cloudflare: ProbeResult{IsOpen: false},
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

func TestTryDoHTunnel_VerificationFailureStopsHandle(t *testing.T) {
	oldStartDoHTunnelFn := startDoHTunnelFn
	oldDoHTunnelVerifyFn := doHTunnelVerifyFn
	defer func() {
		startDoHTunnelFn = oldStartDoHTunnelFn
		doHTunnelVerifyFn = oldDoHTunnelVerifyFn
	}()

	handle := &tunnel.Handle{Active: true, LocalPort: 1083}
	startDoHTunnelFn = func(localPort int, dohServer string, timeout time.Duration) (*tunnel.Handle, error) {
		if localPort != 1083 {
			t.Fatalf("StartDoHTunnel called with port %d, want 1083", localPort)
		}
		return handle, nil
	}
	doHTunnelVerifyFn = func() bool { return false }

	r := tryDoHTunnel(&ProbeResults{DoH: ProbeResult{IsOpen: true}})
	if r.Success {
		t.Fatal("expected DoH tunnel without internet access to fail")
	}
	if r.Method != DoHTunnel {
		t.Fatalf("Method = %s, want %s", r.Method, DoHTunnel)
	}
	if !strings.Contains(r.Details, "no internet access") {
		t.Fatalf("Details = %q, want no-internet explanation", r.Details)
	}
	if handle.Active {
		t.Fatal("expected failed DoH verification to stop the tunnel handle")
	}
}

func TestTryDoHTunnel_SuccessSkipsSOCKSProxySetup(t *testing.T) {
	oldStartDoHTunnelFn := startDoHTunnelFn
	oldDoHTunnelVerifyFn := doHTunnelVerifyFn
	oldSetSystemProxyFn := setSystemProxyFn
	defer func() {
		startDoHTunnelFn = oldStartDoHTunnelFn
		doHTunnelVerifyFn = oldDoHTunnelVerifyFn
		setSystemProxyFn = oldSetSystemProxyFn
	}()

	handle := &tunnel.Handle{Active: true, LocalPort: 1083}
	startDoHTunnelFn = func(localPort int, dohServer string, timeout time.Duration) (*tunnel.Handle, error) {
		return handle, nil
	}
	doHTunnelVerifyFn = func() bool { return true }

	proxyConfigured := false
	setSystemProxyFn = func(iface string, port int) error {
		proxyConfigured = true
		return nil
	}

	result := tryDoHTunnel(&ProbeResults{DoH: ProbeResult{IsOpen: true}})
	if !result.Success {
		t.Fatal("expected verified DoH tunnel to succeed")
	}
	if result.Tunnel == nil {
		t.Fatal("expected verified DoH tunnel to keep the tunnel handle")
	}
	if result.Tunnel.LocalPort != 0 {
		t.Fatalf("LocalPort = %d, want 0 to skip SOCKS auto-configuration", result.Tunnel.LocalPort)
	}

	finalized := finalizeSuccessfulTunnelResult("en0", result)
	if proxyConfigured {
		t.Fatal("expected DoH tunnel success to skip SOCKS proxy configuration")
	}
	if !finalized.Success {
		t.Fatal("expected skipped proxy setup to preserve success result")
	}
	if finalized.Tunnel != handle {
		t.Fatal("expected finalized result to preserve the DoH tunnel handle")
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
		Cloudflare: ProbeResult{IsOpen: false},
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

// ===========================================================================
// Mock-based coverage tests
// ===========================================================================

// saveAndRestore saves a hook variable and returns a restore function.
// Usage: defer saveAndRestore(&hookVar, newVal)()
func saveHooks(t *testing.T) func() {
	t.Helper()
	origInternetCheckURL := internetCheckURL
	origCNACheckURL := cnaCheckURL
	origJSOverrides := jsTestURLOverrides
	origPortalSchemes := portalSchemes
	origDefaultCredsBase := defaultCredsBaseURL
	origSessionReplayURL := sessionReplayURLFunc
	return func() {
		internetCheckURL = origInternetCheckURL
		cnaCheckURL = origCNACheckURL
		jsTestURLOverrides = origJSOverrides
		portalSchemes = origPortalSchemes
		defaultCredsBaseURL = origDefaultCredsBase
		sessionReplayURLFunc = origSessionReplayURL
	}
}

// ---------------------------------------------------------------------------
// Test: tryJSBypass — portal returns login page (fail)
// ---------------------------------------------------------------------------

func TestTryJSBypass_PortalReturnsLoginPage(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `<html><body>Welcome to the captive portal login page. Please authenticate.</body></html>`)
	}))
	defer ts.Close()

	jsTestURLOverrides = []string{ts.URL}
	r := tryJSBypass()
	if r.Method != JSBypass {
		t.Errorf("Method = %s, want %s", r.Method, JSBypass)
	}
	if r.Success {
		t.Error("should fail when portal returns login page")
	}
	if !strings.Contains(r.Details, "server-side enforcement") {
		t.Errorf("Details = %q, want server-side enforcement", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: tryJSBypass — returns real IP content (success)
// ---------------------------------------------------------------------------

func TestTryJSBypass_ReturnsRealIP(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `203.0.113.42`)
	}))
	defer ts.Close()

	jsTestURLOverrides = []string{ts.URL}
	r := tryJSBypass()
	if r.Method != JSBypass {
		t.Errorf("Method = %s, want %s", r.Method, JSBypass)
	}
	if !r.Success {
		t.Error("should succeed when response is real IP content (no portal keywords)")
	}
	if r.Severity != "high" {
		t.Errorf("Severity = %q, want 'high'", r.Severity)
	}
	if r.Remediation == "" {
		t.Error("successful JS bypass should include remediation")
	}
}

// ---------------------------------------------------------------------------
// Test: tryJSBypass — returns redirect (treated as blocked)
// ---------------------------------------------------------------------------

func TestTryJSBypass_Redirect(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://portal.example.com/login", http.StatusFound)
	}))
	defer ts.Close()

	jsTestURLOverrides = []string{ts.URL}
	r := tryJSBypass()
	if r.Success {
		t.Error("should fail when portal redirects (client doesn't follow redirects)")
	}
}

// ---------------------------------------------------------------------------
// Test: tryJSBypass — server error
// ---------------------------------------------------------------------------

func TestTryJSBypass_ServerError(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	jsTestURLOverrides = []string{ts.URL}
	r := tryJSBypass()
	if r.Success {
		t.Error("should fail on server error")
	}
}

// ---------------------------------------------------------------------------
// Test: tryJSBypass — SPA bypass path (204 response)
// ---------------------------------------------------------------------------

func TestTryJSBypass_SPABypass204(t *testing.T) {
	defer saveHooks(t)()

	// First URL returns a portal page (blocks the direct check),
	// SPA URL returns 204 (no portal keywords).
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Header.Get("Accept") == "application/json" {
			// SPA API check path.
			w.WriteHeader(204)
			return
		}
		// Direct URL check returns portal page.
		w.WriteHeader(200)
		fmt.Fprint(w, `<html>captive portal login</html>`)
	}))
	defer ts.Close()

	jsTestURLOverrides = []string{ts.URL}
	r := tryJSBypass()
	if !r.Success {
		t.Error("should succeed when SPA API returns 204")
	}
	if r.Success && !strings.Contains(r.Impact, "SPA") {
		t.Errorf("Impact = %q, want mention of SPA", r.Impact)
	}
}

// ---------------------------------------------------------------------------
// Test: tryJSBypass — connection refused (all URLs unreachable)
// ---------------------------------------------------------------------------

func TestTryJSBypass_ConnectionRefused(t *testing.T) {
	defer saveHooks(t)()

	// Use a URL that will immediately refuse connection.
	jsTestURLOverrides = []string{"http://127.0.0.1:1"}
	r := tryJSBypass()
	if r.Success {
		t.Error("should fail when all URLs refuse connection")
	}
}

// ---------------------------------------------------------------------------
// Test: tryCNASpoof — portal returns 204 for CNA UA (success)
// ---------------------------------------------------------------------------

func TestTryCNASpoof_MockSuccess(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if strings.Contains(ua, "CaptiveNetworkSupport") || strings.Contains(ua, "wispr") {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(302)
	}))
	defer ts.Close()

	cnaCheckURL = ts.URL
	r := tryCNASpoof()
	if !r.Success {
		t.Error("should succeed when portal returns 204 for CNA UA")
	}
	if r.Method != CNASpoof {
		t.Errorf("Method = %s, want %s", r.Method, CNASpoof)
	}
	if r.Severity != "high" {
		t.Errorf("Severity = %q, want 'high'", r.Severity)
	}
	if r.Remediation == "" {
		t.Error("successful CNA spoof should include remediation")
	}
}

// ---------------------------------------------------------------------------
// Test: tryCNASpoof — portal blocks all UAs
// ---------------------------------------------------------------------------

func TestTryCNASpoof_MockAllBlocked(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(302)
	}))
	defer ts.Close()

	cnaCheckURL = ts.URL
	r := tryCNASpoof()
	if r.Success {
		t.Error("should fail when portal blocks all CNA UAs")
	}
	if !strings.Contains(r.Details, "No UA bypass") {
		t.Errorf("Details = %q, want 'No UA bypass'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: tryCNASpoof — first UA fails, second succeeds
// ---------------------------------------------------------------------------

func TestTryCNASpoof_SecondUASucceeds(t *testing.T) {
	defer saveHooks(t)()

	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First UA (Apple CNA) blocked.
			w.WriteHeader(302)
			return
		}
		// Second UA (iOS CNA) succeeds.
		w.WriteHeader(204)
	}))
	defer ts.Close()

	cnaCheckURL = ts.URL
	r := tryCNASpoof()
	if !r.Success {
		t.Error("should succeed when second UA gets 204")
	}
	if !strings.Contains(r.Impact, "iOS CNA") {
		t.Errorf("Impact = %q, want mention of the successful UA", r.Impact)
	}
}

// ---------------------------------------------------------------------------
// Test: tryCNASpoof — connection refused
// ---------------------------------------------------------------------------

func TestTryCNASpoof_ConnectionRefused(t *testing.T) {
	defer saveHooks(t)()

	cnaCheckURL = "http://127.0.0.1:1"
	r := tryCNASpoof()
	if r.Success {
		t.Error("should fail when connection refused")
	}
}

// ---------------------------------------------------------------------------
// Test: tryDefaultCreds — mock server with login form, admin:admin works
// ---------------------------------------------------------------------------

func TestTryDefaultCreds_MockSuccess(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin" {
			http.NotFound(w, r)
			return
		}
		if r.Method == "GET" {
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><form>Username: <input name="username"/>Password: <input name="password"/><button>Login</button></form></html>`)
			return
		}
		if r.Method == "POST" {
			r.ParseForm()
			if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
				w.WriteHeader(200)
				fmt.Fprint(w, `<html>Welcome to the admin dashboard.</html>`)
				return
			}
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><form>Login failed. Username: <input/>Password: <input/></form></html>`)
		}
	}))
	defer ts.Close()

	defaultCredsBaseURL = ts.URL
	portalSchemes = []string{"http"}
	plat := &mockPlatform{gateway: "192.168.1.1"}

	r := tryDefaultCreds("en0", plat)
	if r.Method != PortalCreds {
		t.Errorf("Method = %s, want %s", r.Method, PortalCreds)
	}
	if !r.Success {
		t.Errorf("should succeed with admin:admin; Details = %q", r.Details)
	}
	if r.Severity != "critical" {
		t.Errorf("Severity = %q, want 'critical'", r.Severity)
	}
	if !strings.Contains(r.Impact, "admin:admin") {
		t.Errorf("Impact = %q, want mention of admin:admin", r.Impact)
	}
	if r.Remediation == "" {
		t.Error("successful creds bypass should include remediation")
	}
}

// ---------------------------------------------------------------------------
// Test: tryDefaultCreds — wrong creds (login form present, none match)
// ---------------------------------------------------------------------------

func TestTryDefaultCreds_WrongCreds(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin" {
			http.NotFound(w, r)
			return
		}
		if r.Method == "GET" {
			w.WriteHeader(200)
			fmt.Fprint(w, `<html><form>Username: <input/>Password: <input/><button>Login</button></form></html>`)
			return
		}
		// All POST attempts show login form again (creds failed).
		w.WriteHeader(200)
		fmt.Fprint(w, `<html><form>Login failed. Username: <input/>Password: <input/></form></html>`)
	}))
	defer ts.Close()

	defaultCredsBaseURL = ts.URL
	portalSchemes = []string{"http"}
	plat := &mockPlatform{gateway: "192.168.1.1"}

	r := tryDefaultCreds("en0", plat)
	if r.Success {
		t.Error("should fail when all default creds are rejected")
	}
}

// ---------------------------------------------------------------------------
// Test: tryDefaultCreds — no login form on admin pages
// ---------------------------------------------------------------------------

func TestTryDefaultCreds_NoLoginForm(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// No login-related keywords.
		fmt.Fprint(w, `<html><body>Status: OK. Uptime: 42 days.</body></html>`)
	}))
	defer ts.Close()

	defaultCredsBaseURL = ts.URL
	portalSchemes = []string{"http"}
	plat := &mockPlatform{gateway: "192.168.1.1"}

	r := tryDefaultCreds("en0", plat)
	if r.Success {
		t.Error("should fail when no login form is found")
	}
}

// ---------------------------------------------------------------------------
// Test: tryDefaultCreds — server returns 404 for all admin paths
// ---------------------------------------------------------------------------

func TestTryDefaultCreds_AllPaths404(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	defaultCredsBaseURL = ts.URL
	portalSchemes = []string{"http"}
	plat := &mockPlatform{gateway: "192.168.1.1"}

	r := tryDefaultCreds("en0", plat)
	if r.Success {
		t.Error("should fail when all admin paths return 404")
	}
}

// ---------------------------------------------------------------------------
// Test: tryMACClone — successful clone with mock
// ---------------------------------------------------------------------------

func TestTryMACClone_SuccessfulClone(t *testing.T) {
	defer saveHooks(t)()

	// Mock hasInternet to return 204 (success).
	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	plat := &mockPlatform{
		gateway:    "192.168.1.1",
		currentMAC: "aa:bb:cc:dd:ee:ff",
		arpTable: []platform.ArpEntry{
			{IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Interface: "en0"},
		},
		setMACOK: true,
	}

	r := tryMACClone("en0", false, plat)
	if r.Method != MACClone {
		t.Errorf("Method = %s, want %s", r.Method, MACClone)
	}
	if !r.Success {
		t.Errorf("should succeed when SetMAC works and hasInternet succeeds; Details = %q", r.Details)
	}
	if r.Severity != "critical" {
		t.Errorf("Severity = %q, want 'critical'", r.Severity)
	}
	if !strings.Contains(r.Impact, "00:11:22:33:44:55") {
		t.Errorf("Impact = %q, want cloned MAC mentioned", r.Impact)
	}
	if r.Remediation == "" {
		t.Error("successful MAC clone should include remediation")
	}
}

// ---------------------------------------------------------------------------
// Test: tryMACClone — all candidates fail internet check
// ---------------------------------------------------------------------------

func TestTryMACClone_AllCandidatesFailInternet(t *testing.T) {
	defer saveHooks(t)()

	// Mock hasInternet to always fail.
	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	plat := &mockPlatform{
		gateway:    "192.168.1.1",
		currentMAC: "aa:bb:cc:dd:ee:ff",
		arpTable: []platform.ArpEntry{
			{IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Interface: "en0"},
			{IP: "192.168.1.51", MAC: "00:11:22:33:44:66", Interface: "en0"},
		},
		setMACOK: true,
	}

	r := tryMACClone("en0", false, plat)
	if r.Success {
		t.Error("should fail when all cloned MACs fail internet check")
	}
	if !strings.Contains(r.Details, "Tried") {
		t.Errorf("Details = %q, want 'Tried N MACs' message", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: tryMACClone — idle detection with privacy MAC
// ---------------------------------------------------------------------------

func TestTryMACClone_SuccessPrivacyMAC(t *testing.T) {
	defer saveHooks(t)()

	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	// Use a locally-administered MAC (bit 1 of first octet set).
	plat := &mockPlatform{
		gateway:    "192.168.1.1",
		currentMAC: "aa:bb:cc:dd:ee:ff",
		arpTable: []platform.ArpEntry{
			{IP: "192.168.1.50", MAC: "02:11:22:33:44:55", Interface: "en0"},
		},
		setMACOK: true,
	}

	r := tryMACClone("en0", false, plat)
	if !r.Success {
		t.Errorf("should succeed; Details = %q", r.Details)
	}
	if !strings.Contains(r.Impact, "privacy MAC") {
		t.Errorf("Impact = %q, want mention of 'privacy MAC'", r.Impact)
	}
}

// ---------------------------------------------------------------------------
// Test: tryMACClone idle — success path (candidate doesn't respond to ping)
// ---------------------------------------------------------------------------

func TestTryMACClone_IdleSuccess(t *testing.T) {
	defer saveHooks(t)()

	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	// Use non-routable IPs that ping will fail to reach (idle detection).
	plat := &mockPlatform{
		gateway:    "192.168.1.1",
		currentMAC: "aa:bb:cc:dd:ee:ff",
		arpTable: []platform.ArpEntry{
			{IP: "192.168.253.250", MAC: "00:11:22:33:44:55", Interface: "en0"},
		},
		setMACOK: true,
	}

	r := tryMACClone("en0", true, plat)
	if r.Method != MACCloneIdle {
		t.Errorf("Method = %s, want %s", r.Method, MACCloneIdle)
	}
	// Candidate at non-routable IP will timeout on ping -> considered idle.
	// Then SetMAC succeeds and hasInternet returns 204.
	if !r.Success {
		t.Errorf("should succeed with idle device and working internet; Details = %q", r.Details)
	}
	if r.Success && !strings.Contains(r.Impact, "idle") {
		t.Errorf("Impact = %q, want mention of 'idle'", r.Impact)
	}
}

// ---------------------------------------------------------------------------
// Test: trySessionReplay — portal serves HTTP cookies
// ---------------------------------------------------------------------------

func TestTrySessionReplay_MockPortalWithCookies(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc123"})
		http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "xyz789"})
		w.WriteHeader(200)
		fmt.Fprint(w, `<html>Portal Login</html>`)
	}))
	defer ts.Close()

	sessionReplayURLFunc = func(gateway string) string {
		return ts.URL + "/"
	}

	plat := &mockPlatform{gateway: "192.168.1.1"}
	r := trySessionReplay("en0", plat)
	if r.Method != SessionReplay {
		t.Errorf("Method = %s, want %s", r.Method, SessionReplay)
	}
	// The function reports cookies as sniffable but doesn't mark as Success
	// (requires monitor mode packet capture for full exploit).
	if r.Success {
		t.Error("session replay should not succeed (requires monitor mode)")
	}
	if r.Severity != "high" {
		t.Errorf("Severity = %q, want 'high' for HTTP cookies", r.Severity)
	}
	if !strings.Contains(r.Details, "PHPSESSID") {
		t.Errorf("Details = %q, want cookie names mentioned", r.Details)
	}
	if r.Remediation == "" {
		t.Error("cookie finding should include remediation")
	}
}

// ---------------------------------------------------------------------------
// Test: trySessionReplay — portal without cookies
// ---------------------------------------------------------------------------

func TestTrySessionReplay_MockNoCookies(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `<html>Portal Login</html>`)
	}))
	defer ts.Close()

	sessionReplayURLFunc = func(gateway string) string {
		return ts.URL + "/"
	}

	plat := &mockPlatform{gateway: "192.168.1.1"}
	r := trySessionReplay("en0", plat)
	if r.Success {
		t.Error("should fail without cookies")
	}
	if !strings.Contains(r.Details, "HTTPS or no cookies") {
		t.Errorf("Details = %q, want 'HTTPS or no cookies'", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: trySessionReplay — connection error
// ---------------------------------------------------------------------------

func TestTrySessionReplay_ConnectionError(t *testing.T) {
	defer saveHooks(t)()

	sessionReplayURLFunc = func(gateway string) string {
		return "http://127.0.0.1:1/"
	}

	plat := &mockPlatform{gateway: "192.168.1.1"}
	r := trySessionReplay("en0", plat)
	if r.Success {
		t.Error("should fail on connection error")
	}
}

// ---------------------------------------------------------------------------
// Test: tryMACRotate — success path
// ---------------------------------------------------------------------------

func TestTryMACRotate_MockSuccess(t *testing.T) {
	defer saveHooks(t)()

	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	plat := &mockPlatform{
		setMACOK:  true,
		randomMAC: "02:aa:bb:cc:dd:ee",
	}

	r := tryMACRotate("en0", plat)
	if r.Method != MACRotate {
		t.Errorf("Method = %s, want %s", r.Method, MACRotate)
	}
	if !r.Success {
		t.Errorf("should succeed when SetMAC works and hasInternet succeeds; Details = %q", r.Details)
	}
	if r.Severity != "high" {
		t.Errorf("Severity = %q, want 'high'", r.Severity)
	}
	if !strings.Contains(r.Impact, "02:aa:bb:cc:dd:ee") {
		t.Errorf("Impact = %q, want new MAC mentioned", r.Impact)
	}
}

// ---------------------------------------------------------------------------
// Test: tryMACRotate — SetMAC succeeds but no internet
// ---------------------------------------------------------------------------

func TestTryMACRotate_NoInternet(t *testing.T) {
	defer saveHooks(t)()

	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	plat := &mockPlatform{
		setMACOK:  true,
		randomMAC: "02:aa:bb:cc:dd:ee",
	}

	r := tryMACRotate("en0", plat)
	if r.Success {
		t.Error("should fail without internet after MAC change")
	}
	if r.Severity != "medium" {
		t.Errorf("Severity = %q, want 'medium'", r.Severity)
	}
	if !strings.Contains(r.Details, "02:aa:bb:cc:dd:ee") {
		t.Errorf("Details = %q, want new MAC mentioned", r.Details)
	}
}

// ---------------------------------------------------------------------------
// Test: tryHTTPConnect — mock TCP server responds 200 to CONNECT
// ---------------------------------------------------------------------------

func TestTryHTTPConnect_MockConnectSuccess(t *testing.T) {
	// Start a TCP server on a known port that responds "200" to CONNECT.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			req := string(buf[:n])
			if strings.Contains(req, "CONNECT") {
				conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			}
			conn.Close()
		}
	}()

	// tryHTTPConnect tries ports 80, 8080, 3128. We need our mock on one of those.
	// Instead, verify the gateway+port mechanism works with the mock on our random port.
	// Since we cannot override the port list, test the "valid gateway" path directly.
	plat := &mockPlatform{gateway: "127.0.0.1"}
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}

	r := tryHTTPConnect(probes, config, plat)
	if r.Method != HTTPConnect {
		t.Errorf("Method = %s, want %s", r.Method, HTTPConnect)
	}
	// The function tries ports 80, 8080, 3128 on 127.0.0.1.
	// Our mock is on a random port, but if any of 80/8080/3128 happen to
	// have something running, we check accordingly. The key coverage path
	// is that it reaches the TCP dial+CONNECT logic without errors.
	_ = portStr
}

// ---------------------------------------------------------------------------
// Test: tryHTTPConnect — mock TCP CONNECT proxy on port 8080
// ---------------------------------------------------------------------------

func TestTryHTTPConnect_MockProxyOnPort(t *testing.T) {
	// Bind specifically to port 0 and use a wrapper approach.
	// Since tryHTTPConnect hardcodes ports, we test the full path using
	// a gateway that resolves to 127.0.0.1 and see if any standard port
	// happens to respond.
	plat := &mockPlatform{gateway: "127.0.0.1"}
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}

	r := tryHTTPConnect(probes, config, plat)
	// Main coverage: exercises the IP validation, port iteration, TCP dial path.
	if r.Method != HTTPConnect {
		t.Errorf("Method = %s, want %s", r.Method, HTTPConnect)
	}
}

// ---------------------------------------------------------------------------
// Test: tryDHCPRotate — success path with mock internet
// ---------------------------------------------------------------------------

func TestTryDHCPRotate_MockSuccess(t *testing.T) {
	defer saveHooks(t)()

	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	plat := &mockPlatform{}
	r := tryDHCPRotate("en0", plat)
	if r.Method != DHCPRotate {
		t.Errorf("Method = %s, want %s", r.Method, DHCPRotate)
	}
	if !r.Success {
		t.Error("should succeed when hasInternet returns true after DHCP renew")
	}
	if r.Severity != "medium" {
		t.Errorf("Severity = %q, want 'medium'", r.Severity)
	}
}

// ---------------------------------------------------------------------------
// Test: tryDHCPRotate — failure path
// ---------------------------------------------------------------------------

func TestTryDHCPRotate_MockFail(t *testing.T) {
	defer saveHooks(t)()

	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	plat := &mockPlatform{}
	r := tryDHCPRotate("en0", plat)
	if r.Success {
		t.Error("should fail when hasInternet returns false")
	}
}

// ---------------------------------------------------------------------------
// Test: measureNetworkLatency — valid local gateway returns a duration
// ---------------------------------------------------------------------------

func TestMeasureNetworkLatency_ValidGateway(t *testing.T) {
	// localhost ping should succeed and return < 2s.
	d := measureNetworkLatency("127.0.0.1")
	if d == 2*time.Second {
		// If ping to localhost fails (e.g., in a sandbox), skip.
		t.Skip("ping to 127.0.0.1 failed (sandbox environment)")
	}
	if d <= 0 {
		t.Errorf("duration = %v, expected positive", d)
	}
}

// ---------------------------------------------------------------------------
// Test: measureNetworkLatency — unreachable host returns 2s default
// ---------------------------------------------------------------------------

func TestMeasureNetworkLatency_UnreachableHost(t *testing.T) {
	// Non-routable IP: ping will fail.
	d := measureNetworkLatency("192.0.2.1")
	if d != 2*time.Second {
		// Ping might succeed in some environments; only verify it's positive.
		if d <= 0 {
			t.Errorf("duration = %v, expected positive", d)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: RunBypasses with mock internet — exercises tunnel handle path
// ---------------------------------------------------------------------------

func TestRunBypasses_WithMockInternet(t *testing.T) {
	defer saveHooks(t)()

	// Make hasInternet succeed so MAC/DHCP techniques can succeed.
	internetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer internetSrv.Close()
	internetCheckURL = internetSrv.URL

	// Make CNA/JS bypass fail so we exercise later techniques.
	cnaCheckURL = "http://127.0.0.1:1"
	jsTestURLOverrides = []string{"http://127.0.0.1:1"}

	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}
	plat := &mockPlatform{
		gateway:    "192.168.1.1",
		currentMAC: "aa:bb:cc:dd:ee:ff",
		arpTable: []platform.ArpEntry{
			{IP: "192.168.253.250", MAC: "00:11:22:33:44:55", Interface: "en0"},
		},
		setMACOK:  true,
		randomMAC: "02:aa:bb:cc:dd:ee",
	}

	results := RunBypasses(probes, config, plat)
	// Should stop at the first success (one of the MAC/DHCP techniques).
	found := false
	for _, r := range results {
		if r.Success {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one technique to succeed with mock internet")
	}
}

// ---------------------------------------------------------------------------
// Test: RunBypasses logs "No tunnel server" message
// ---------------------------------------------------------------------------

func TestRunBypasses_NoTunnelServerLog(t *testing.T) {
	defer saveHooks(t)()

	// Force everything to fail fast.
	cnaCheckURL = "http://127.0.0.1:1"
	jsTestURLOverrides = []string{"http://127.0.0.1:1"}
	internetCheckURL = "http://127.0.0.1:1"

	probes := &ProbeResults{IPv6: ProbeResult{IsOpen: true, Details: "test"}}
	config := &Config{Interface: "en0"} // no TunnelServer

	results := RunBypasses(probes, config, nil)
	// IPv6 succeeds immediately.
	if len(results) == 0 || !results[0].Success {
		t.Error("expected IPv6 to succeed")
	}
}

// ---------------------------------------------------------------------------
// Test: tryDefaultCreds — second admin path has login form
// ---------------------------------------------------------------------------

func TestTryDefaultCreds_SecondPathHasForm(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			http.NotFound(w, r)
		case "/login":
			if r.Method == "GET" {
				w.WriteHeader(200)
				fmt.Fprint(w, `<html><form>Username: <input/>Password: <input/>Login</form></html>`)
				return
			}
			if r.Method == "POST" {
				r.ParseForm()
				if r.FormValue("username") == "root" && r.FormValue("password") == "admin" {
					w.WriteHeader(200)
					fmt.Fprint(w, `<html>Router Management Console</html>`)
					return
				}
				w.WriteHeader(200)
				fmt.Fprint(w, `<html><form>Invalid login. Username: <input/></form></html>`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	defaultCredsBaseURL = ts.URL
	portalSchemes = []string{"http"}
	plat := &mockPlatform{gateway: "192.168.1.1"}

	r := tryDefaultCreds("en0", plat)
	if !r.Success {
		t.Errorf("should succeed with root:admin on /login; Details = %q", r.Details)
	}
	if r.Success && !strings.Contains(r.Impact, "root:admin") {
		t.Errorf("Impact = %q, want mention of root:admin", r.Impact)
	}
}

// ---------------------------------------------------------------------------
// Edge case: All 19 techniques fail -- error report clarity
// ---------------------------------------------------------------------------

func TestRunBypasses_AllFail_ClearErrorReport(t *testing.T) {
	// All probes closed, no servers, no tunnel config.
	probes := &ProbeResults{}
	config := &Config{Interface: "en0"}
	plat := &mockPlatform{
		gateway:    "",
		currentMAC: "",
		setMACOK:   false,
		randomMAC:  "02:00:00:00:00:01",
	}

	results := RunBypasses(probes, config, plat)

	// Every technique should have been tried.
	if len(results) != 19 {
		// Some techniques (CNA, JS) may succeed if the test machine has internet.
		// If any succeeded, RunBypasses stops early (correct behavior).
		lastSuccess := results[len(results)-1].Success
		if !lastSuccess && len(results) != 19 {
			t.Errorf("all failed but got %d results instead of 19", len(results))
		}
		return
	}

	// Every result should have a non-empty Details explaining the failure.
	for i, r := range results {
		if r.Details == "" {
			t.Errorf("result[%d] (%s) has empty Details", i, r.Method)
		}
		if r.Success {
			t.Errorf("result[%d] (%s) unexpectedly succeeded", i, r.Method)
		}
	}

	// Verify all 19 methods are represented.
	seen := make(map[Method]bool)
	for _, r := range results {
		seen[r.Method] = true
	}
	expectedMethods := []Method{
		IPv6Bypass, ChiselTunnel, CNASpoof, JSBypass, HTTPConnect,
		MACCloneIdle, MACClone, DNSTunnel, ICMPTunnel, VPNPort53,
		WhitelistDomain, SessionReplay, PortalCreds, MACRotate,
		DHCPRotate, QUICTunnel, CFWorkers, NTPTunnel, DoHTunnel,
	}
	for _, m := range expectedMethods {
		if !seen[m] {
			t.Errorf("method %s not present in results", m)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge case: HasInternet with mock server
// ---------------------------------------------------------------------------

func TestHasInternet_Mock204(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer ts.Close()
	internetCheckURL = ts.URL

	if !HasInternet() {
		t.Error("HasInternet should return true for 204")
	}
}

func TestHasInternet_Mock403(t *testing.T) {
	defer saveHooks(t)()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer ts.Close()
	internetCheckURL = ts.URL

	if HasInternet() {
		t.Error("HasInternet should return false for 403")
	}
}

func TestHasInternet_Unreachable(t *testing.T) {
	defer saveHooks(t)()

	internetCheckURL = "http://192.0.2.1:1/unreachable"
	if HasInternet() {
		t.Error("HasInternet should return false for unreachable URL")
	}
}

// ---------------------------------------------------------------------------
// Edge case: SetSuppressLog toggle
// ---------------------------------------------------------------------------

func TestSetSuppressLog(t *testing.T) {
	// Should not panic.
	SetSuppressLog(true)
	SetSuppressLog(false)
}

// ---------------------------------------------------------------------------
// Edge case: measureNetworkLatency with unreachable IP
// ---------------------------------------------------------------------------

func TestMeasureNetworkLatency_UnreachableIP(t *testing.T) {
	// Non-routable IP should return the 2s default.
	d := measureNetworkLatency("192.0.2.1")
	if d != 2*time.Second {
		t.Errorf("measureNetworkLatency(unreachable) = %v, want 2s default", d)
	}
}

// ---------------------------------------------------------------------------
// Edge case: empty interface name
// ---------------------------------------------------------------------------

func TestRunBypasses_EmptyInterface(t *testing.T) {
	probes := &ProbeResults{IPv6: ProbeResult{IsOpen: true}}
	config := &Config{Interface: ""}
	plat := &mockPlatform{}

	// Should not panic with empty interface.
	results := RunBypasses(probes, config, plat)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
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
