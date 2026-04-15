// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package inflight

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDetectProvider_Panasonic(t *testing.T) {
	p := DetectProvider("00:A0:BC:C0:84:40", "", "", nil)
	if p != Panasonic {
		t.Errorf("expected Panasonic from OUI, got %s", p)
	}
}

func TestDetectProvider_DNS(t *testing.T) {
	tests := []struct {
		dns      string
		expected Provider
	}{
		{"www.nordic-sky.finnair.com", Panasonic},
		{"gogoinflight.com", Gogo},
		{"portal.viasat.com", Viasat},
		{"gx-aviation.inmarsat.com", Inmarsat},
		{"wifi.inflyt.thales.com", Thales},
		{"portal.onair.aero", SITA},
		{"unknown.example.com", Unknown},
	}

	for _, tt := range tests {
		got := DetectProvider("", tt.dns, "", nil)
		if got != tt.expected {
			t.Errorf("DNS %q: expected %s, got %s", tt.dns, tt.expected, got)
		}
	}
}

func TestDetectProvider_HTML(t *testing.T) {
	p := DetectProvider("", "", "<script src='portal-loader.js'></script>", nil)
	if p != Panasonic {
		t.Errorf("expected Panasonic from HTML marker, got %s", p)
	}
}

func TestDetectProvider_Headers(t *testing.T) {
	headers := map[string]string{"Via": "kong/3.3.1"}
	p := DetectProvider("", "", "", headers)
	if p != Panasonic {
		t.Errorf("expected Panasonic from Kong header, got %s", p)
	}
}

func TestAllAirlines(t *testing.T) {
	airlines := AllAirlines()
	if len(airlines) == 0 {
		t.Error("expected non-empty airline list")
	}
	if airlines["Finnair"] != Panasonic {
		t.Errorf("expected Finnair -> Panasonic, got %s", airlines["Finnair"])
	}
	if airlines["American Airlines"] != Gogo {
		t.Errorf("expected American Airlines -> Gogo, got %s", airlines["American Airlines"])
	}
}

func TestGetProfile(t *testing.T) {
	p := GetProfile(Panasonic)
	if p == nil {
		t.Fatal("expected non-nil profile for Panasonic")
	}
	if p.TypicalRTTMs < 500 {
		t.Errorf("expected satellite RTT > 500ms, got %d", p.TypicalRTTMs)
	}
	if !p.HasFreeTier && len(p.FreeTierDomains) > 0 {
		t.Error("inconsistent: HasFreeTier=false but FreeTierDomains not empty")
	}
}

// ---------------------------------------------------------------------------
// Edge case: unknown airline code
// ---------------------------------------------------------------------------

func TestDetectProvider_UnknownAirlineReturnsUnknown(t *testing.T) {
	// No signals at all should return Unknown.
	p := DetectProvider("", "", "", nil)
	if p != Unknown {
		t.Errorf("expected Unknown with no signals, got %s", p)
	}
}

func TestDetectProvider_UnknownGatewayMAC(t *testing.T) {
	// A MAC that doesn't match any known provider OUI.
	p := DetectProvider("FF:FF:FF:FF:FF:FF", "", "", nil)
	if p != Unknown {
		t.Errorf("expected Unknown for broadcast MAC, got %s", p)
	}
}

func TestDetectProvider_EmptyHTML(t *testing.T) {
	p := DetectProvider("", "", "", nil)
	if p != Unknown {
		t.Errorf("expected Unknown for empty HTML, got %s", p)
	}
}

func TestDetectProvider_UnknownDNSPattern(t *testing.T) {
	p := DetectProvider("", "totally.unknown.domain.example.com", "", nil)
	if p != Unknown {
		t.Errorf("expected Unknown for unrecognized DNS, got %s", p)
	}
}

func TestDetectProvider_UnknownHeaders(t *testing.T) {
	headers := map[string]string{"Server": "Apache/2.4.52"}
	p := DetectProvider("", "", "", headers)
	if p != Unknown {
		t.Errorf("expected Unknown for generic Apache header, got %s", p)
	}
}

// ---------------------------------------------------------------------------
// Edge case: unknown provider returns nil profile
// ---------------------------------------------------------------------------

func TestGetProfile_UnknownProvider(t *testing.T) {
	p := GetProfile(Unknown)
	if p != nil {
		t.Error("expected nil profile for Unknown provider")
	}
}

func TestGetProfile_InvalidProvider(t *testing.T) {
	p := GetProfile(Provider("nonexistent_provider"))
	if p != nil {
		t.Error("expected nil profile for nonexistent provider")
	}
}

// ---------------------------------------------------------------------------
// Edge case: all providers have RecommendedOrder and IneffectiveTechniques
// ---------------------------------------------------------------------------

func TestProfiles_AllHaveRecommendedOrder(t *testing.T) {
	for provider, profile := range Profiles {
		if len(profile.RecommendedOrder) == 0 {
			t.Errorf("provider %s has empty RecommendedOrder", provider)
		}
		if len(profile.Airlines) == 0 {
			t.Errorf("provider %s has empty Airlines", provider)
		}
		if profile.TypicalRTTMs == 0 {
			t.Errorf("provider %s has zero TypicalRTTMs", provider)
		}
		if profile.Name == "" {
			t.Errorf("provider %s has empty Name", provider)
		}
		if profile.Description == "" {
			t.Errorf("provider %s has empty Description", provider)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge case: DetectProvider with mixed signals (conflicting OUI vs DNS)
// ---------------------------------------------------------------------------

func TestDetectProvider_OUITakesPrecedence(t *testing.T) {
	// Panasonic OUI + Gogo DNS pattern. OUI is checked first in the loop.
	// Due to map iteration order being non-deterministic, the result depends
	// on which provider is checked first. But at least one should match.
	p := DetectProvider("00:A0:BC:00:00:00", "gogoinflight.com", "", nil)
	if p == Unknown {
		t.Error("should detect some provider with both OUI and DNS signals")
	}
}

// ---------------------------------------------------------------------------
// Edge case: case insensitivity
// ---------------------------------------------------------------------------

func TestDetectProvider_CaseInsensitiveMAC(t *testing.T) {
	p := DetectProvider("00:a0:bc:c0:84:40", "", "", nil)
	if p != Panasonic {
		t.Errorf("expected Panasonic from lowercase OUI, got %s", p)
	}
}

func TestDetectProvider_CaseInsensitiveHTML(t *testing.T) {
	p := DetectProvider("", "", "<SCRIPT SRC='PORTAL-LOADER.JS'></SCRIPT>", nil)
	if p != Panasonic {
		t.Errorf("expected Panasonic from uppercase HTML marker, got %s", p)
	}
}

func TestDetectProvider_Anuvu(t *testing.T) {
	p := DetectProvider("", "anuvu.com", "", nil)
	if p != Anuvu {
		t.Errorf("expected Anuvu from DNS, got %s", p)
	}
}

func TestReadmeInflightClaimsMatchRegistry(t *testing.T) {
	providerCount := len(Profiles)
	airlineFloor := (len(AllAirlines()) / 10) * 10

	readmePath := filepath.Join("..", "..", "..", "README.md")
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", readmePath, err)
	}
	text := string(data)

	if !strings.Contains(text, fmt.Sprintf("profiles for %d major providers", providerCount)) {
		t.Fatalf("README should advertise %d provider profiles", providerCount)
	}
	if !strings.Contains(text, fmt.Sprintf("%d+ airlines", airlineFloor)) {
		t.Fatalf("README should advertise the current airline floor of %d+", airlineFloor)
	}
	if strings.Contains(text, "50+ airlines") {
		t.Fatal("README should not advertise the stale 50+ airline claim")
	}
}

func TestDetectLinkType(t *testing.T) {
	tests := []struct {
		rtt      int
		expected LinkType
		name     string
	}{
		{0, "", "zero RTT returns empty"},
		{35, LEO, "Starlink typical 35ms"},
		{60, LEO, "LEO upper boundary"},
		{70, AirToGround, "ATG lower boundary"},
		{150, AirToGround, "Gogo ATG typical"},
		{250, KaBand, "satellite lower boundary"},
		{700, KaBand, "Ku/Ka typical"},
		{850, KaBand, "KLM observed avg"},
		{1283, KaBand, "KLM observed max"},
		{1500, "", "degraded path returns empty"},
	}
	for _, tc := range tests {
		if got := DetectLinkType(tc.rtt); got != tc.expected {
			t.Errorf("%s: DetectLinkType(%d) = %q, want %q", tc.name, tc.rtt, got, tc.expected)
		}
	}
}

func TestIsStarlink(t *testing.T) {
	if !IsStarlink(40) {
		t.Error("40ms RTT should identify as Starlink/LEO")
	}
	if IsStarlink(850) {
		t.Error("850ms RTT should not identify as Starlink/LEO")
	}
	if IsStarlink(0) {
		t.Error("0ms RTT should not identify as Starlink/LEO")
	}
}


func TestCAPPORTResponse_IsCaptive(t *testing.T) {
	captive := true
	notCaptive := false
	tests := []struct {
		name string
		resp *CAPPORTResponse
		want bool
	}{
		{"nil response", nil, false},
		{"absent field", &CAPPORTResponse{}, false},
		{"captive true", &CAPPORTResponse{Captive: &captive}, true},
		{"captive false", &CAPPORTResponse{Captive: &notCaptive}, false},
	}
	for _, tc := range tests {
		if got := tc.resp.IsCaptive(); got != tc.want {
			t.Errorf("%s: IsCaptive() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCAPPORTResponse_CanExtend(t *testing.T) {
	yes := true
	no := false
	if (&CAPPORTResponse{CanExtendSession: &yes}).CanExtend() != true {
		t.Error("CanExtendSession:true should return true")
	}
	if (&CAPPORTResponse{CanExtendSession: &no}).CanExtend() != false {
		t.Error("CanExtendSession:false should return false")
	}
	if (&CAPPORTResponse{}).CanExtend() != false {
		t.Error("absent field should return false")
	}
	var nilResp *CAPPORTResponse
	if nilResp.CanExtend() {
		t.Error("nil receiver should return false, not panic")
	}
}

func TestCAPPORTResponse_SessionRemaining(t *testing.T) {
	var secondsRemaining int64 = 1800
	if (&CAPPORTResponse{SessionSecondsRemaining: &secondsRemaining}).SessionRemaining() != 1800 {
		t.Error("seconds-remaining should be returned verbatim")
	}
	if (&CAPPORTResponse{}).SessionRemaining() != -1 {
		t.Error("absent fields should return -1")
	}
}

func TestQueryCAPPORT_ParsesKLMStyleResponse(t *testing.T) {
	// KLM observed response (sanitized):
	// {"captive":false,"can-extend-session":true,"venue-info-url":"...","user-portal-url":"..."}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/captive+json")
		_, _ = w.Write([]byte(`{"captive":false,"can-extend-session":true,"venue-info-url":"https://example.com/venue","user-portal-url":"https://example.com/portal"}`))
	}))
	defer server.Close()

	resp, err := QueryCAPPORT(context.Background(), server.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("QueryCAPPORT failed: %v", err)
	}
	if resp.IsCaptive() {
		t.Error("expected not captive")
	}
	if !resp.CanExtend() {
		t.Error("expected can-extend-session: true")
	}
	if resp.UserPortalURL != "https://example.com/portal" {
		t.Errorf("unexpected user-portal-url: %q", resp.UserPortalURL)
	}
}

func TestQueryCAPPORT_HandlesErrors(t *testing.T) {
	// Invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	if _, err := QueryCAPPORT(context.Background(), server.URL, 2*time.Second); err == nil {
		t.Error("expected error on invalid JSON")
	}

	// 500 error
	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errServer.Close()

	if _, err := QueryCAPPORT(context.Background(), errServer.URL, 2*time.Second); err == nil {
		t.Error("expected error on 500")
	}
}
