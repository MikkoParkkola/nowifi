// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package inflight

import "testing"

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
