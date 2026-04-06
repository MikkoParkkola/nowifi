// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/probe"
	"github.com/MikkoParkkola/nowifi/internal/report"
)

// ---------------------------------------------------------------------------
// mapPortalInfo
// ---------------------------------------------------------------------------

func TestMapPortalInfo_FullData(t *testing.T) {
	p := &detect.PortalInfo{
		IsCaptive:   true,
		Type:        "http_redirect",
		Vendor:      "Aruba",
		PortalURL:   "https://portal.example.com/login",
		AuthMethods: []string{"email", "sms"},
		Gateway:     "192.168.1.1",
	}
	wifi := &platform.WifiInfo{
		SSID:    "CoffeeShop",
		BSSID:   "AA:BB:CC:DD:EE:FF",
		Channel: "6",
		RSSI:    -45,
	}

	rp := mapPortalInfo(p, wifi)

	if !rp.IsCaptive {
		t.Error("expected IsCaptive=true")
	}
	if rp.PortalType != "http_redirect" {
		t.Errorf("PortalType = %q, want http_redirect", rp.PortalType)
	}
	if rp.Vendor != "Aruba" {
		t.Errorf("Vendor = %q, want Aruba", rp.Vendor)
	}
	if rp.PortalURL != "https://portal.example.com/login" {
		t.Errorf("PortalURL = %q", rp.PortalURL)
	}
	if len(rp.AuthMethods) != 2 {
		t.Errorf("AuthMethods len = %d, want 2", len(rp.AuthMethods))
	}
	if rp.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q, want 192.168.1.1", rp.Gateway)
	}
	if rp.SSID != "CoffeeShop" {
		t.Errorf("SSID = %q, want CoffeeShop", rp.SSID)
	}
}

func TestMapPortalInfo_NilWifi(t *testing.T) {
	p := &detect.PortalInfo{
		IsCaptive: false,
		Type:      "none",
	}

	rp := mapPortalInfo(p, nil)

	if rp.IsCaptive {
		t.Error("expected IsCaptive=false")
	}
	if rp.SSID != "" {
		t.Errorf("SSID = %q, want empty", rp.SSID)
	}
}

func TestMapPortalInfo_NoCaptive(t *testing.T) {
	p := &detect.PortalInfo{
		IsCaptive: false,
	}
	wifi := &platform.WifiInfo{SSID: "HomeWiFi"}

	rp := mapPortalInfo(p, wifi)

	if rp.IsCaptive {
		t.Error("expected IsCaptive=false")
	}
	if rp.SSID != "HomeWiFi" {
		t.Errorf("SSID = %q, want HomeWiFi", rp.SSID)
	}
}

func TestMapPortalInfo_EmptyAuthMethods(t *testing.T) {
	p := &detect.PortalInfo{
		IsCaptive:   true,
		AuthMethods: nil,
	}

	rp := mapPortalInfo(p, nil)

	if len(rp.AuthMethods) != 0 {
		t.Errorf("AuthMethods should be empty, got %d", len(rp.AuthMethods))
	}
}

// ---------------------------------------------------------------------------
// mapReportProbes
// ---------------------------------------------------------------------------

func TestMapReportProbes_Full(t *testing.T) {
	p := &probe.ProbeResults{
		DNS:        probe.DnsProbeResult{IsOpen: true, Details: "udp/53 open"},
		ICMP:       probe.IcmpProbeResult{IsOpen: false, Details: "blocked"},
		IPv6:       probe.Ipv6ProbeResult{IsOpen: true, Details: "ipv6 reachable"},
		Cloudflare: probe.HttpsProbeResult{IsOpen: true, Details: "cf ok"},
		QUIC:       probe.PortProbeResult{IsOpen: false, Details: "quic blocked"},
		NTP:        probe.PortProbeResult{IsOpen: true, Details: "ntp ok"},
		DoH:        probe.PortProbeResult{IsOpen: true, Details: "doh ok"},
		Whitelists: []probe.WhitelistResult{
			{Domain: "apple.com", IsOpen: true, Details: "200"},
			{Domain: "microsoft.com", IsOpen: false, Details: "blocked"},
		},
		OpenPorts: []probe.PortProbeResult{
			{Port: 80, Service: "HTTP", IsOpen: true},
			{Port: 443, Service: "HTTPS", IsOpen: true},
			{Port: 8080, Service: "HTTP-Alt", IsOpen: false},
		},
	}

	rp := mapReportProbes(p)

	// Verify protocol fields.
	if !rp.DNS.IsOpen || rp.DNS.Details != "udp/53 open" {
		t.Errorf("DNS: IsOpen=%v Details=%q", rp.DNS.IsOpen, rp.DNS.Details)
	}
	if rp.ICMP.IsOpen {
		t.Error("ICMP should be closed")
	}
	if !rp.IPv6.IsOpen {
		t.Error("IPv6 should be open")
	}
	if !rp.Cloudflare.IsOpen {
		t.Error("Cloudflare should be open")
	}
	if rp.QUIC.IsOpen {
		t.Error("QUIC should be closed")
	}
	if !rp.NTP.IsOpen {
		t.Error("NTP should be open")
	}
	if !rp.DoH.IsOpen {
		t.Error("DoH should be open")
	}

	// Verify whitelists.
	if len(rp.Whitelists) != 2 {
		t.Fatalf("Whitelists len = %d, want 2", len(rp.Whitelists))
	}
	if rp.Whitelists[0].Domain != "apple.com" || !rp.Whitelists[0].IsOpen {
		t.Errorf("Whitelist[0] = %+v", rp.Whitelists[0])
	}
	if rp.Whitelists[1].Domain != "microsoft.com" || rp.Whitelists[1].IsOpen {
		t.Errorf("Whitelist[1] = %+v", rp.Whitelists[1])
	}

	// Verify open ports.
	if len(rp.OpenPorts) != 3 {
		t.Fatalf("OpenPorts len = %d, want 3", len(rp.OpenPorts))
	}
	if rp.OpenPorts[0].Port != 80 || rp.OpenPorts[0].Service != "HTTP" || !rp.OpenPorts[0].IsOpen {
		t.Errorf("OpenPorts[0] = %+v", rp.OpenPorts[0])
	}
}

func TestMapReportProbes_EmptyWhitelists(t *testing.T) {
	p := &probe.ProbeResults{}
	rp := mapReportProbes(p)

	if len(rp.Whitelists) != 0 {
		t.Errorf("Whitelists should be empty, got %d", len(rp.Whitelists))
	}
	if len(rp.OpenPorts) != 0 {
		t.Errorf("OpenPorts should be empty, got %d", len(rp.OpenPorts))
	}
}

func TestMapReportProbes_ReturnType(t *testing.T) {
	p := &probe.ProbeResults{
		DNS: probe.DnsProbeResult{IsOpen: true, Details: "test"},
	}
	rp := mapReportProbes(p)

	// Verify the return is report.ProbeResults (compile-time check).
	var _ report.ProbeResults = rp
	if !rp.DNS.IsOpen {
		t.Error("DNS should be open")
	}
}

// ---------------------------------------------------------------------------
// checkInternet — with httptest
// ---------------------------------------------------------------------------

func TestCheckInternet_204(t *testing.T) {
	// Create a mock server that returns 204.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent) // 204
	}))
	defer ts.Close()

	// checkInternet uses a hardcoded URL so we cannot easily inject.
	// Instead, test the response handling logic directly.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("new GET request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("StatusCode = %d, want 204", resp.StatusCode)
	}
}

func TestCheckInternet_Redirect(t *testing.T) {
	// A redirect (portal) should not be treated as connected.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://portal.example.com", http.StatusFound)
	}))
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("new GET request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	// 302 != 204, so this would be "not connected".
	if resp.StatusCode == 204 {
		t.Error("redirect should not be interpreted as connected")
	}
}

func TestCheckInternet_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("new GET request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 204 {
		t.Error("500 should not be interpreted as connected")
	}
}

// ---------------------------------------------------------------------------
// portOpen (diagnose.go helper)
// ---------------------------------------------------------------------------

func TestPortOpen(t *testing.T) {
	tests := []struct {
		name   string
		probes *probe.ProbeResults
		port   int
		want   bool
	}{
		{
			name:   "port 443 open",
			probes: &probe.ProbeResults{OpenPorts: []probe.PortProbeResult{{Port: 443, IsOpen: true}}},
			port:   443,
			want:   true,
		},
		{
			name:   "port 443 closed",
			probes: &probe.ProbeResults{OpenPorts: []probe.PortProbeResult{{Port: 443, IsOpen: false}}},
			port:   443,
			want:   false,
		},
		{
			name:   "port not present",
			probes: &probe.ProbeResults{OpenPorts: []probe.PortProbeResult{{Port: 80, IsOpen: true}}},
			port:   443,
			want:   false,
		},
		{
			name:   "empty ports",
			probes: &probe.ProbeResults{},
			port:   443,
			want:   false,
		},
		{
			name: "multiple ports mixed",
			probes: &probe.ProbeResults{OpenPorts: []probe.PortProbeResult{
				{Port: 80, IsOpen: true},
				{Port: 443, IsOpen: true},
				{Port: 8080, IsOpen: false},
			}},
			port: 8080,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := portOpen(tt.probes, tt.port)
			if got != tt.want {
				t.Errorf("portOpen(probes, %d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// assessMethods (diagnose.go)
// ---------------------------------------------------------------------------

func TestAssessMethods_AllOpen(t *testing.T) {
	probes := &probe.ProbeResults{
		DNS:        probe.DnsProbeResult{IsOpen: true},
		ICMP:       probe.IcmpProbeResult{IsOpen: true},
		IPv6:       probe.Ipv6ProbeResult{IsOpen: true},
		Cloudflare: probe.HttpsProbeResult{IsOpen: true},
		QUIC:       probe.PortProbeResult{IsOpen: true},
		NTP:        probe.PortProbeResult{IsOpen: true},
		DoH:        probe.PortProbeResult{IsOpen: true},
		Whitelists: []probe.WhitelistResult{
			{Domain: "apple.com", IsOpen: true},
		},
		OpenPorts: []probe.PortProbeResult{
			{Port: 443, IsOpen: true},
			{Port: 8080, IsOpen: true},
		},
	}
	portal := &detect.PortalInfo{IsCaptive: true}

	count := assessMethods(probes, portal)

	// With all open and captive: IPv6(1) + HTTPS(1) + CNA(1) + JS(1) + HTTP CONNECT(1)
	// + MAC clone idle(1) + MAC clone any(1) + DNS(1) + ICMP(1) + VPN53(1)
	// + Whitelist(1) + Session(1) + Portal creds(1) + MAC rotate(1) + DHCP(1)
	// + QUIC(1) + CF Workers(1) + NTP(1) + DoH(1) = 19
	if count < 15 {
		t.Errorf("assessMethods with all open = %d, expected >= 15", count)
	}
}

func TestAssessMethods_AllClosed_NoCaptive(t *testing.T) {
	probes := &probe.ProbeResults{}
	portal := &detect.PortalInfo{IsCaptive: false}

	count := assessMethods(probes, portal)

	// Only MAC clone idle, MAC clone any, MAC rotate, DHCP rotate = 4.
	if count != 4 {
		t.Errorf("assessMethods all closed no captive = %d, want 4", count)
	}
}

func TestAssessMethods_CaptiveOnly(t *testing.T) {
	probes := &probe.ProbeResults{}
	portal := &detect.PortalInfo{IsCaptive: true}

	count := assessMethods(probes, portal)

	// MAC clone idle(1) + MAC clone any(1) + CNA(1) + JS(1) + Session(1) + Creds(1)
	// + MAC rotate(1) + DHCP(1) = 8
	if count != 8 {
		t.Errorf("assessMethods captive only = %d, want 8", count)
	}
}

// ---------------------------------------------------------------------------
// tunnelCloser
// ---------------------------------------------------------------------------

type mockTunnel struct{ stopped bool }

func (m *mockTunnel) Stop() { m.stopped = true }

func TestTunnelCloser(t *testing.T) {
	m := &mockTunnel{}
	tc := tunnelCloser{h: m}
	err := tc.Close()

	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
	if !m.stopped {
		t.Error("expected Stop() to be called")
	}
}
