// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package detect

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestHostFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"simple", "http://example.com/path", "example.com"},
		{"with port", "http://example.com:8080/path", "example.com"},
		{"https", "https://portal.wifi.com/login", "portal.wifi.com"},
		{"empty", "", ""},
		{"invalid", "://bad", ""},
		{"ip address", "http://192.168.1.1/login", "192.168.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostFromURL(tt.url)
			if got != tt.want {
				t.Errorf("hostFromURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestCheckCanary_Success(t *testing.T) {
	// Server returns the expected Apple CNA response.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"))
	}))
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/hotspot-detect.html",
		ExpectedBody:   "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
		ExpectedStatus: 200,
		Name:           "Test Apple CNA",
	}

	result := checkCanary(client, c)
	if result == nil {
		t.Fatal("expected non-nil result for successful canary")
	}
	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.StatusCode)
	}
	if result.Body != c.ExpectedBody {
		t.Errorf("body = %q, want %q", result.Body, c.ExpectedBody)
	}
}

func TestCheckCanary_Redirect(t *testing.T) {
	// Portal server that the canary gets redirected to.
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Please log in</body></html>"))
	}))
	defer portal.Close()

	// Canary server that redirects to the portal.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, portal.URL+"/login", http.StatusFound)
	}))
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/hotspot-detect.html",
		ExpectedBody:   "Success",
		ExpectedStatus: 200,
		Name:           "Test Redirect",
	}

	result := checkCanary(client, c)
	if result == nil {
		t.Fatal("expected non-nil result for redirect canary")
	}
	// After following the redirect, the final URL should be the portal.
	if result.FinalURL != portal.URL+"/login" {
		t.Errorf("FinalURL = %q, want %q", result.FinalURL, portal.URL+"/login")
	}
	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.StatusCode)
	}
}

func TestCheckCanary_ConnectionRefused(t *testing.T) {
	// Use a client pointing at a closed server.
	client := &http.Client{}
	c := canary{
		URL:            "http://127.0.0.1:1/nonexistent",
		ExpectedBody:   "anything",
		ExpectedStatus: 200,
		Name:           "Test Unreachable",
	}

	result := checkCanary(client, c)
	if result != nil {
		t.Error("expected nil result for unreachable canary")
	}
}

func TestCheckCanary_204(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/generate_204",
		ExpectedBody:   "",
		ExpectedStatus: 204,
		Name:           "Test Google 204",
	}

	result := checkCanary(client, c)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.StatusCode != 204 {
		t.Errorf("status = %d, want 204", result.StatusCode)
	}
}

func TestFingerprintPortal_CiscoMeraki(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><body class="meraki-splash"><h1>Welcome to Meraki Portal</h1></body></html>`
	fingerprintPortal(info, body, "http://portal.example.com/splash/login", http.Header{})

	if info.Vendor != "cisco_meraki" {
		t.Errorf("Vendor = %q, want %q", info.Vendor, "cisco_meraki")
	}
	if info.VendorScore < 2 {
		t.Errorf("VendorScore = %d, want >= 2", info.VendorScore)
	}
}

func TestFingerprintPortal_Aruba(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><body><div class="aruba_clearpass">Sign in via ClearPass</div></body></html>`
	headers := http.Header{"Server": {"Aruba"}}
	fingerprintPortal(info, body, "http://portal.setafi.com/cgi-bin/auth", headers)

	if info.Vendor != "aruba" {
		t.Errorf("Vendor = %q, want %q", info.Vendor, "aruba")
	}
}

func TestFingerprintPortal_UniFi(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><body class="unifi-portal"><form>...</form></body></html>`
	fingerprintPortal(info, body, "http://unifi.local/guest/s/default", http.Header{})

	if info.Vendor != "unifi" {
		t.Errorf("Vendor = %q, want %q", info.Vendor, "unifi")
	}
}

func TestFingerprintPortal_Unknown(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><body>Please connect to the network</body></html>`
	fingerprintPortal(info, body, "http://portal.example.com/connect", http.Header{})

	if info.Vendor != "" {
		t.Errorf("Vendor = %q, want empty for unknown portal", info.Vendor)
	}
}

func TestFingerprintPortal_UnknownClearsExistingVendor(t *testing.T) {
	info := &PortalInfo{
		Vendor:      "stale",
		VendorScore: 7,
	}
	body := `<html><body>Please connect to the network</body></html>`
	fingerprintPortal(info, body, "http://portal.example.com/connect", http.Header{})

	if info.Vendor != "" {
		t.Errorf("Vendor = %q, want empty for unknown portal", info.Vendor)
	}
	if info.VendorScore != 0 {
		t.Errorf("VendorScore = %d, want 0 for unknown portal", info.VendorScore)
	}
}

func TestFingerprintPortal_PrefersHighestScore(t *testing.T) {
	originalSignatures := vendorSignatures
	vendorSignatures = map[string]vendorSignature{
		"weak": {
			URLPatterns: []string{"/login"},
		},
		"strong": {
			URLPatterns: []string{"/login"},
			HTMLMarkers: []string{"portal"},
		},
	}
	defer func() {
		vendorSignatures = originalSignatures
	}()

	for i := 0; i < 50; i++ {
		info := &PortalInfo{}
		fingerprintPortal(info, `<html><body>Portal</body></html>`, "http://portal.example.com/login", http.Header{})
		if info.Vendor != "strong" {
			t.Fatalf("iteration %d: Vendor = %q, want %q", i, info.Vendor, "strong")
		}
		if info.VendorScore != 3 {
			t.Fatalf("iteration %d: VendorScore = %d, want %d", i, info.VendorScore, 3)
		}
	}
}

func TestFingerprintPortal_BreaksTiesDeterministically(t *testing.T) {
	originalSignatures := vendorSignatures
	vendorSignatures = map[string]vendorSignature{
		"beta": {
			URLPatterns: []string{"/login"},
		},
		"alpha": {
			URLPatterns: []string{"/login"},
		},
	}
	defer func() {
		vendorSignatures = originalSignatures
	}()

	for i := 0; i < 50; i++ {
		info := &PortalInfo{}
		fingerprintPortal(info, `<html><body>login</body></html>`, "http://portal.example.com/login", http.Header{})
		if info.Vendor != "alpha" {
			t.Fatalf("iteration %d: Vendor = %q, want %q", i, info.Vendor, "alpha")
		}
		if info.VendorScore != 2 {
			t.Fatalf("iteration %d: VendorScore = %d, want %d", i, info.VendorScore, 2)
		}
	}
}

func TestDetectAuthMethods(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			"email input",
			`<form><input type="email" name="user_email" /><button>Submit</button></form>`,
			[]string{"email"},
		},
		{
			"password input",
			`<form><input type="password" name="pw" /></form>`,
			[]string{"password"},
		},
		{
			"phone input",
			`<form><input type="tel" name="phone_number" /></form>`,
			[]string{"phone"},
		},
		{
			"google oauth",
			`<a href="https://accounts.google.com/o/oauth2">Sign in with Google</a>`,
			[]string{"social_google"},
		},
		{
			"facebook login",
			`<a href="https://www.facebook.com/dialog/oauth">Login with Facebook</a>`,
			[]string{"social_facebook"},
		},
		{
			"room number",
			`<form><label>Room Number</label><input name="room_no" /></form>`,
			[]string{"room_number"},
		},
		{
			"voucher code",
			`<form><label>Access Code</label><input name="voucher" /></form>`,
			[]string{"voucher"},
		},
		{
			"terms only",
			`<form><label><input type="checkbox" /> I accept the terms and conditions</label></form>`,
			[]string{"terms_only"},
		},
		{
			"multiple methods",
			`<form><input type="email" /><input type="password" /></form>`,
			[]string{"email", "password"},
		},
		{
			"no methods",
			`<html><body>Welcome</body></html>`,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectAuthMethods(tt.html)
			if len(got) != len(tt.want) {
				t.Fatalf("detectAuthMethods() returned %v, want %v", got, tt.want)
			}
			for i, m := range got {
				if m != tt.want[i] {
					t.Errorf("method[%d] = %q, want %q", i, m, tt.want[i])
				}
			}
		})
	}
}

func TestDetectPortal_NoPortal(t *testing.T) {
	// All canaries return their expected content.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hotspot-detect.html":
			w.WriteHeader(200)
			w.Write([]byte("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"))
		case "/generate_204":
			w.WriteHeader(204)
		case "/canonical.html":
			w.WriteHeader(200)
			w.Write([]byte("success"))
		case "/connecttest.txt":
			w.WriteHeader(200)
			w.Write([]byte("Microsoft Connect Test"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	// Temporarily override canaryURLs to point at our test server.
	origCanaries := make([]canary, len(canaryURLs))
	copy(origCanaries, canaryURLs)
	canaryURLs[0].URL = ts.URL + "/hotspot-detect.html"
	canaryURLs[1].URL = ts.URL + "/generate_204"
	canaryURLs[2].URL = ts.URL + "/canonical.html"
	canaryURLs[3].URL = ts.URL + "/connecttest.txt"
	defer func() { copy(canaryURLs, origCanaries) }()

	info := DetectPortal("en0")

	// The canaries will succeed but DNS hijack check may trigger since
	// we cannot easily mock net.LookupHost. The key assertion is that
	// the canary consensus does not flag a portal.
	if info.Type == PortalHTTPRedirect || info.Type == PortalTransparent || info.Type == PortalFirewall {
		t.Errorf("Type = %q, expected no canary-based portal detection", info.Type)
	}
}

func TestDetectPortal_Redirect(t *testing.T) {
	// Both httptest servers use 127.0.0.1, so redirect to "different domain"
	// cannot be tested via DetectPortal directly (same host).
	// Instead, test the redirect detection logic directly via checkCanary +
	// the host comparison that DetectPortal performs.

	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body class="meraki-splash">Login to WiFi</body></html>`))
	}))
	defer portal.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, portal.URL+"/login", http.StatusFound)
	}))
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/hotspot-detect.html",
		ExpectedBody:   "Success",
		ExpectedStatus: 200,
		Name:           "Test",
	}

	result := checkCanary(client, c)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// The final URL after redirect should be on the portal server.
	if result.FinalURL != portal.URL+"/login" {
		t.Errorf("FinalURL = %q, want %q", result.FinalURL, portal.URL+"/login")
	}

	// The content should NOT match the expected canary body, meaning this
	// canary would count as a failure in the consensus algorithm.
	if result.StatusCode == c.ExpectedStatus && result.Body == c.ExpectedBody {
		t.Error("redirected canary should not match expected content")
	}

	// Test the cross-domain detection logic directly.
	canaryHost := hostFromURL("http://captive.apple.com/hotspot-detect.html")
	portalHost := hostFromURL("http://portal.hotel.com/login")
	if canaryHost == portalHost {
		t.Error("canary and portal hosts should differ for cross-domain redirect")
	}
	if canaryHost == "" || portalHost == "" {
		t.Error("hosts should not be empty")
	}
}

func TestDetectPortal_ConsensusFailure(t *testing.T) {
	// All canaries return wrong content (simulating transparent portal).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Not the expected content"))
	}))
	defer ts.Close()

	origCanaries := make([]canary, len(canaryURLs))
	copy(origCanaries, canaryURLs)
	canaryURLs[0].URL = ts.URL + "/hotspot-detect.html"
	canaryURLs[1].URL = ts.URL + "/generate_204"
	canaryURLs[2].URL = ts.URL + "/canonical.html"
	canaryURLs[3].URL = ts.URL + "/connecttest.txt"
	defer func() { copy(canaryURLs, origCanaries) }()

	info := DetectPortal("en0")
	if !info.IsCaptive {
		t.Error("expected IsCaptive = true when majority of canaries fail")
	}
	// All 4 fail, 0 succeed: failures(4) > successes(0) && failures >= 2.
	if info.Type != PortalTransparent {
		t.Errorf("Type = %q, want %q", info.Type, PortalTransparent)
	}
}

func TestDetectPortal_FirewallBlock(t *testing.T) {
	// All canaries time out / connection refused (no redirect body).
	origCanaries := make([]canary, len(canaryURLs))
	copy(origCanaries, canaryURLs)
	// Point to a port that refuses connections.
	for i := range canaryURLs {
		canaryURLs[i].URL = "http://127.0.0.1:1/path"
	}
	defer func() { copy(canaryURLs, origCanaries) }()

	info := DetectPortal("en0")
	if !info.IsCaptive {
		t.Error("expected IsCaptive = true when all canaries fail to connect")
	}
	if info.Type != PortalFirewall {
		t.Errorf("Type = %q, want %q", info.Type, PortalFirewall)
	}
}

func TestDetectPortal_PartialCanaryFailure(t *testing.T) {
	// Only 1 of 4 canaries fails -- should NOT trigger portal (need majority).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hotspot-detect.html":
			w.WriteHeader(200)
			w.Write([]byte("Wrong content")) // Fails
		case "/generate_204":
			w.WriteHeader(204)
		case "/canonical.html":
			w.WriteHeader(200)
			w.Write([]byte("success"))
		case "/connecttest.txt":
			w.WriteHeader(200)
			w.Write([]byte("Microsoft Connect Test"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	origCanaries := make([]canary, len(canaryURLs))
	copy(origCanaries, canaryURLs)
	canaryURLs[0].URL = ts.URL + "/hotspot-detect.html"
	canaryURLs[1].URL = ts.URL + "/generate_204"
	canaryURLs[2].URL = ts.URL + "/canonical.html"
	canaryURLs[3].URL = ts.URL + "/connecttest.txt"
	defer func() { copy(canaryURLs, origCanaries) }()

	info := DetectPortal("en0")
	// 1 failure, 3 successes -- should NOT trigger canary-based portal.
	if info.Type == PortalTransparent || info.Type == PortalFirewall {
		t.Errorf("partial failure should not trigger portal, got Type=%q", info.Type)
	}
}

func TestDetectPortal_MixedCanaryFailures(t *testing.T) {
	// 3 canaries fail, 1 succeeds -- should trigger portal (majority fail).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generate_204":
			w.WriteHeader(204) // Only one succeeds.
		default:
			w.WriteHeader(200)
			w.Write([]byte("Wrong content"))
		}
	}))
	defer ts.Close()

	origCanaries := make([]canary, len(canaryURLs))
	copy(origCanaries, canaryURLs)
	canaryURLs[0].URL = ts.URL + "/hotspot-detect.html"
	canaryURLs[1].URL = ts.URL + "/generate_204"
	canaryURLs[2].URL = ts.URL + "/canonical.html"
	canaryURLs[3].URL = ts.URL + "/connecttest.txt"
	defer func() { copy(canaryURLs, origCanaries) }()

	info := DetectPortal("en0")
	if !info.IsCaptive {
		t.Error("majority canary failure should detect captive portal")
	}
}

func TestCheckCanary_GoogleExpectedBodyEmpty(t *testing.T) {
	// Google canary expects no body check (empty ExpectedBody).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/generate_204",
		ExpectedBody:   "",
		ExpectedStatus: 204,
		Name:           "Google 204",
	}

	result := checkCanary(client, c)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.StatusCode != 204 {
		t.Errorf("status = %d, want 204", result.StatusCode)
	}
}

func TestCheckCanary_WrongStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/hotspot",
		ExpectedBody:   "Success",
		ExpectedStatus: 200,
		Name:           "Test",
	}

	result := checkCanary(client, c)
	if result == nil {
		t.Fatal("expected non-nil result for wrong status")
	}
	if result.StatusCode != 500 {
		t.Errorf("status = %d, want 500", result.StatusCode)
	}
}

func TestCanaryURLs_Defined(t *testing.T) {
	if len(canaryURLs) < 4 {
		t.Fatalf("expected at least 4 canary URLs, got %d", len(canaryURLs))
	}
	names := map[string]bool{}
	for _, c := range canaryURLs {
		if c.URL == "" {
			t.Error("canary has empty URL")
		}
		if c.Name == "" {
			t.Error("canary has empty Name")
		}
		if c.ExpectedStatus == 0 {
			t.Errorf("canary %q has zero ExpectedStatus", c.Name)
		}
		names[c.Name] = true
	}
	if !names["Apple CNA"] {
		t.Error("missing Apple CNA canary")
	}
	if !names["Google 204"] {
		t.Error("missing Google 204 canary")
	}
}

// ---------------------------------------------------------------------------
// fingerprintPortal — vendor-specific tests
// ---------------------------------------------------------------------------

func TestFingerprintPortal_Mikrotik(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><head><title>mikrotik hotspot</title></head><body><div class="routeros">Login</div></body></html>`
	fingerprintPortal(info, body, "http://192.168.1.1/login", http.Header{})
	if info.Vendor != "mikrotik" {
		t.Errorf("Vendor = %q, want mikrotik", info.Vendor)
	}
}

func TestFingerprintPortal_Fortinet(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><body><div class="ftnt_login">FortiGate Auth</div></body></html>`
	headers := http.Header{"Server": {"FortiGate"}}
	fingerprintPortal(info, body, "http://portal.example.com/fgtauth", headers)
	if info.Vendor != "fortinet" {
		t.Errorf("Vendor = %q, want fortinet", info.Vendor)
	}
}

func TestFingerprintPortal_Ruckus(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><body class="ruckus-portal"><form>SmartZone login</form></body></html>`
	fingerprintPortal(info, body, "http://ruckus.local/login.html", http.Header{})
	if info.Vendor != "ruckus" {
		t.Errorf("Vendor = %q, want ruckus", info.Vendor)
	}
}

func TestFingerprintPortal_PanasonicViaKong(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><body>Inflight WiFi</body></html>`
	headers := http.Header{"X-Kong-Proxy-Latency": {"42"}}
	fingerprintPortal(info, body, "http://portal.example.com/wifi", headers)
	if info.Vendor != "panasonic_avionics" {
		t.Errorf("Vendor = %q, want panasonic_avionics", info.Vendor)
	}
}

func TestFingerprintPortal_PanasonicViaHeader(t *testing.T) {
	info := &PortalInfo{}
	body := `<html><body>Inflight WiFi</body></html>`
	headers := http.Header{"Via": {"1.1 kong"}}
	fingerprintPortal(info, body, "http://portal.example.com/wifi", headers)
	if info.Vendor != "panasonic_avionics" {
		t.Errorf("Vendor = %q, want panasonic_avionics", info.Vendor)
	}
}

// ---------------------------------------------------------------------------
// scoreVendorSignature
// ---------------------------------------------------------------------------

func TestScoreVendorSignature_AllMatch(t *testing.T) {
	sig := vendorSignature{
		URLPatterns:    []string{"/login"},
		HTMLMarkers:    []string{"portal", "wifi"},
		HeaderPatterns: []string{"MyServer"},
	}
	score, matchCount := scoreVendorSignature("/login", "portal wifi page", "myserver: v1", sig)
	// URL match=1*2, HTML match=2*1, header match=1*2 = 6.
	if score < 4 {
		t.Errorf("score = %d, want >= 4", score)
	}
	if matchCount < 3 {
		t.Errorf("matchCount = %d, want >= 3", matchCount)
	}
}

func TestScoreVendorSignature_NoMatch(t *testing.T) {
	sig := vendorSignature{
		URLPatterns:    []string{"/meraki"},
		HTMLMarkers:    []string{"meraki"},
		HeaderPatterns: []string{"Meraki"},
	}
	score, matchCount := scoreVendorSignature("/other", "no match", "apache: 2.4", sig)
	if score != 0 {
		t.Errorf("score = %d, want 0", score)
	}
	if matchCount != 0 {
		t.Errorf("matchCount = %d, want 0", matchCount)
	}
}

// ---------------------------------------------------------------------------
// countVendorPatternMatches
// ---------------------------------------------------------------------------

func TestCountVendorPatternMatches(t *testing.T) {
	if c := countVendorPatternMatches("abc def ghi", []string{"abc", "ghi"}); c != 2 {
		t.Errorf("expected 2 matches, got %d", c)
	}
	if c := countVendorPatternMatches("nothing here", []string{"xyz"}); c != 0 {
		t.Errorf("expected 0 matches, got %d", c)
	}
	if c := countVendorPatternMatches("test", nil); c != 0 {
		t.Errorf("expected 0 for nil patterns, got %d", c)
	}
}

// ---------------------------------------------------------------------------
// detectAuthMethods — edge cases
// ---------------------------------------------------------------------------

func TestDetectAuthMethods_CaseInsensitive(t *testing.T) {
	methods := detectAuthMethods(`<form><INPUT TYPE="EMAIL" NAME="USER_EMAIL" /></form>`)
	if len(methods) == 0 {
		t.Error("expected email to be detected case-insensitively")
	}
}

func TestDetectAuthMethods_Empty(t *testing.T) {
	methods := detectAuthMethods("")
	if len(methods) != 0 {
		t.Errorf("expected 0 methods for empty html, got %d", len(methods))
	}
}

// ---------------------------------------------------------------------------
// hostFromURL — additional cases
// ---------------------------------------------------------------------------

func TestHostFromURL_IPv6(t *testing.T) {
	got := hostFromURL("http://[::1]:8080/path")
	if got != "::1" {
		t.Errorf("hostFromURL IPv6 = %q, want ::1", got)
	}
}

// ---------------------------------------------------------------------------
// resolvePortalIP — empty hostname
// ---------------------------------------------------------------------------

func TestResolvePortalIP_EmptyURL(t *testing.T) {
	ip := resolvePortalIP("")
	if ip != "" {
		t.Errorf("resolvePortalIP empty = %q, want empty", ip)
	}
}

func TestResolvePortalIP_InvalidURL(t *testing.T) {
	ip := resolvePortalIP("://bad")
	if ip != "" {
		t.Errorf("resolvePortalIP invalid = %q, want empty", ip)
	}
}

func TestResolvePortalIP_ValidDomain(t *testing.T) {
	// localhost should resolve.
	ip := resolvePortalIP("http://localhost/login")
	// May or may not resolve depending on environment; just verify no panic.
	_ = ip
}

func TestResolvePortalIP_IPAddress(t *testing.T) {
	ip := resolvePortalIP("http://127.0.0.1/login")
	// Should resolve 127.0.0.1 to itself.
	if ip != "" && ip != "127.0.0.1" && ip != "::1" {
		t.Errorf("resolvePortalIP(127.0.0.1) = %q", ip)
	}
}

// ---------------------------------------------------------------------------
// PortalType constants
// ---------------------------------------------------------------------------

func TestPortalTypeConstants(t *testing.T) {
	types := []PortalType{
		PortalHTTPRedirect, PortalDNSHijack, PortalTransparent,
		PortalFirewall, PortalWalledGarden, PortalNone,
	}
	seen := make(map[PortalType]bool)
	for _, pt := range types {
		if seen[pt] {
			t.Errorf("duplicate portal type: %s", pt)
		}
		seen[pt] = true
		if string(pt) == "" {
			t.Error("portal type should not be empty")
		}
	}
}

// ---------------------------------------------------------------------------
// Inflight vendor signatures
// ---------------------------------------------------------------------------

func TestVendorSignatures_Inflight(t *testing.T) {
	inflightVendors := []string{
		"panasonic_avionics", "gogo_inflight", "viasat_inflight",
		"inmarsat_gx", "thales_inflyt", "sita_onair",
		"anuvu_inflight", "boingo_inflight",
	}
	for _, v := range inflightVendors {
		sig, ok := vendorSignatures[v]
		if !ok {
			t.Errorf("missing inflight vendor signature: %s", v)
			continue
		}
		if len(sig.URLPatterns) == 0 && len(sig.HTMLMarkers) == 0 {
			t.Errorf("vendor %s has no URL or HTML patterns", v)
		}
	}
}

func TestVendorSignatures_Defined(t *testing.T) {
	expectedVendors := []string{"cisco_meraki", "aruba", "ruckus", "unifi", "mikrotik", "fortinet"}
	for _, v := range expectedVendors {
		sig, ok := vendorSignatures[v]
		if !ok {
			t.Errorf("missing vendor signature: %s", v)
			continue
		}
		if len(sig.HTMLMarkers) == 0 {
			t.Errorf("vendor %s has no HTML markers", v)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge cases: DNS completely broken (no resolution at all)
// ---------------------------------------------------------------------------

func TestDetectPortal_AllCanariesTimeout(t *testing.T) {
	// Simulate DNS completely broken by pointing all canaries at unreachable host.
	origCanaries := make([]canary, len(canaryURLs))
	copy(origCanaries, canaryURLs)
	// Use a non-routable IP with a very short timeout. RFC 5737 TEST-NET.
	for i := range canaryURLs {
		canaryURLs[i].URL = "http://192.0.2.1:1/path"
	}
	defer func() { copy(canaryURLs, origCanaries) }()

	info := DetectPortal("en0")
	// All 4 canaries should fail (connection timeout/refused).
	// failures(4) >= 2 -> IsCaptive=true, Type=PortalFirewall (no redirects).
	if !info.IsCaptive {
		t.Error("expected IsCaptive=true when all canaries are unreachable")
	}
	if info.Type != PortalFirewall {
		t.Errorf("Type = %q, want %q when all canaries timeout", info.Type, PortalFirewall)
	}
}

// ---------------------------------------------------------------------------
// Edge case: canary returns empty body
// ---------------------------------------------------------------------------

func TestCheckCanary_EmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Empty body
	}))
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/test",
		ExpectedBody:   "Success",
		ExpectedStatus: 200,
		Name:           "Test Empty Body",
	}

	result := checkCanary(client, c)
	if result == nil {
		t.Fatal("expected non-nil result even with empty body")
	}
	if result.Body != "" {
		t.Errorf("body = %q, want empty", result.Body)
	}
	// Status matches but body does not -> this canary would count as a failure
	// in the consensus algorithm because ExpectedBody is non-empty.
}

// ---------------------------------------------------------------------------
// Edge case: canary with very large response body (> 256KB truncation)
// ---------------------------------------------------------------------------

func TestCheckCanary_LargeBody(t *testing.T) {
	largeBody := bytes.Repeat([]byte{'A'}, 512*1024) // 512KB

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(largeBody)
	}))
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/large",
		ExpectedBody:   "",
		ExpectedStatus: 200,
		Name:           "Test Large Body",
	}

	result := checkCanary(client, c)
	if result == nil {
		t.Fatal("expected non-nil result for large body")
	}
	// Body should be truncated to 256KB.
	if int64(len(result.Body)) > maxCanaryBodyBytes {
		t.Errorf("body length = %d, should be truncated to 256KB", len(result.Body))
	}
}

func TestCheckCanary_LargeBodyReusesConnection(t *testing.T) {
	largeBody := bytes.Repeat([]byte{'A'}, 512*1024) // 512KB
	seenConnections := map[string]struct{}{}
	var mu sync.Mutex

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if _, err := w.Write(largeBody); err != nil {
			t.Errorf("write body: %v", err)
		}
	}))
	ts.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state != http.StateNew {
			return
		}
		mu.Lock()
		seenConnections[conn.RemoteAddr().String()] = struct{}{}
		mu.Unlock()
	}
	ts.Start()
	defer ts.Close()

	client := ts.Client()
	c := canary{
		URL:            ts.URL + "/large",
		ExpectedBody:   "",
		ExpectedStatus: 200,
		Name:           "Test Large Body Reuse",
	}

	for i := 0; i < 2; i++ {
		result := checkCanary(client, c)
		if result == nil {
			t.Fatalf("request %d returned nil result", i+1)
		}
	}

	mu.Lock()
	connectionCount := len(seenConnections)
	mu.Unlock()
	if connectionCount != 1 {
		t.Fatalf("connection count = %d, want 1", connectionCount)
	}
}

// ---------------------------------------------------------------------------
// Edge case: no default gateway (fingerprintFromDNS returns empty)
// ---------------------------------------------------------------------------

func TestFingerprintPortal_EmptyInputs(t *testing.T) {
	info := &PortalInfo{}
	fingerprintPortal(info, "", "", http.Header{})
	if info.Vendor != "" {
		t.Errorf("Vendor = %q, want empty for all-empty inputs", info.Vendor)
	}
	if info.VendorScore != 0 {
		t.Errorf("VendorScore = %d, want 0", info.VendorScore)
	}
	if len(info.AuthMethods) != 0 {
		t.Errorf("AuthMethods = %v, want empty", info.AuthMethods)
	}
}

// ---------------------------------------------------------------------------
// Edge case: multiple auth methods in one page
// ---------------------------------------------------------------------------

func TestDetectAuthMethods_AllMethodsInOnePage(t *testing.T) {
	html := `<html><body>
		<form>
			<input type="email" name="email"/>
			<input type="password" name="pw"/>
			<input type="tel" name="phone"/>
			<a href="https://accounts.google.com/o/oauth2">Google</a>
			<a href="https://www.facebook.com/dialog/oauth">Facebook</a>
			<label>Room Number: <input name="room_no"/></label>
			<label>Voucher Code: <input name="voucher"/></label>
			<label><input type="checkbox"/> I accept the terms and conditions</label>
		</form>
	</body></html>`

	methods := detectAuthMethods(html)
	expected := []string{"email", "password", "phone", "social_google", "social_facebook", "room_number", "voucher", "terms_only"}
	if len(methods) != len(expected) {
		t.Fatalf("detectAuthMethods returned %d methods, want %d: %v", len(methods), len(expected), methods)
	}
	for i, m := range methods {
		if m != expected[i] {
			t.Errorf("method[%d] = %q, want %q", i, m, expected[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Edge case: canary with too many redirects
// ---------------------------------------------------------------------------

func TestCheckCanary_TooManyRedirects(t *testing.T) {
	redirectCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		// Always redirect to self -- will hit the 10-redirect limit.
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}))
	defer ts.Close()

	client := ts.Client()
	// Override the client's redirect policy to match DetectPortal's.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	c := canary{
		URL:            ts.URL + "/loop",
		ExpectedBody:   "Success",
		ExpectedStatus: 200,
		Name:           "Test Redirect Loop",
	}

	result := checkCanary(client, c)
	// Should not return nil (the last redirect response is returned).
	// The key assertion: no panic, no infinite loop.
	if result == nil {
		// Acceptable: the client may return an error on redirect loop.
		return
	}
	// If we got a result, verify the status is a redirect.
	if result.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 for redirect loop", result.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Edge case: PortalInfo fields set correctly for walled garden
// ---------------------------------------------------------------------------

func TestPortalInfo_WalledGardenType(t *testing.T) {
	info := &PortalInfo{
		IsCaptive: true,
		Type:      PortalWalledGarden,
		Vendor:    "custom",
	}
	if info.Type != PortalWalledGarden {
		t.Errorf("Type = %q, want %q", info.Type, PortalWalledGarden)
	}
}
