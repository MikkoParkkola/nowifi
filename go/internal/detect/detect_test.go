// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package detect

import (
	"net/http"
	"net/http/httptest"
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
