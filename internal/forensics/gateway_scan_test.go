// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package forensics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeKongAdmin_ExposedAndClosed(t *testing.T) {
	// A test server standing in for an EXPOSED Kong admin API (HTTP 200).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Empty gateway -> nil (no probe).
	if probeKongAdmin(srv.Client(), "") != nil {
		t.Error("empty gateway should yield nil")
	}

	// Unreachable gateway -> probes present but not exposed.
	got := probeKongAdmin(&http.Client{}, "203.0.113.255")
	if len(got) != len(kongAdminPorts) {
		t.Fatalf("want %d probes, got %d", len(kongAdminPorts), len(got))
	}
	for _, kp := range got {
		if kp.Exposed {
			t.Errorf("unreachable gateway must not be Exposed: %+v", kp)
		}
	}
}

func TestMapHoles_KongAdminExposed(t *testing.T) {
	raw := &RawSections{
		KongAdmin: []KongProbe{
			{Port: 8001, StatusCode: 200, Exposed: true},
			{Port: 8444, StatusCode: 0, Exposed: false},
		},
	}
	holes := MapHoles(raw)
	var found bool
	for _, h := range holes {
		if h.Technique == "kong_admin_exposed" {
			found = true
			if h.Severity != SeverityHigh {
				t.Errorf("kong_admin_exposed must be HIGH, got %s", h.Severity)
			}
			if !strings.Contains(h.Detail, "8001") {
				t.Errorf("detail should name the exposed port: %s", h.Detail)
			}
		}
	}
	if !found {
		t.Error("an exposed Kong admin port must produce a kong_admin_exposed hole")
	}

	// A closed Kong admin must NOT produce the hole.
	closed := MapHoles(&RawSections{KongAdmin: []KongProbe{{Port: 8001, Exposed: false}}})
	for _, h := range closed {
		if h.Technique == "kong_admin_exposed" {
			t.Error("closed Kong admin must not produce a hole")
		}
	}
}

// TestRunNmapGateway_NoGateway verifies the empty-gateway guard (no nmap run).
func TestRunNmapGateway_NoGateway(t *testing.T) {
	out, ran := runNmapGateway("")
	if ran || out != "" {
		t.Errorf("empty gateway must not run nmap; got ran=%v out=%q", ran, out)
	}
}
