// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// TestDHCPRouteBypass_NoRoutes verifies the technique reports failure when
// DHCP option 121 is not advertised, without touching the routing table.
func TestDHCPRouteBypass_NoRoutes(t *testing.T) {
	var addCalled, delCalled int32
	platformAddRoute = func(string, string) error { atomic.AddInt32(&addCalled, 1); return nil }
	platformDeleteRoute = func(string) error { atomic.AddInt32(&delCalled, 1); return nil }
	defer resetDHCPRouteStubs()

	r := tryDHCPRouteBypass(&Config{}, nil)
	if r.Success {
		t.Fatalf("expected failure when no routes; got success: %+v", r)
	}
	if atomic.LoadInt32(&addCalled) != 0 || atomic.LoadInt32(&delCalled) != 0 {
		t.Errorf("unexpected route mutation: add=%d del=%d", addCalled, delCalled)
	}
	if !strings.Contains(r.Details, "not advertised") {
		t.Errorf("details should mention not advertised, got %q", r.Details)
	}
}

// TestDHCPRouteBypass_OnlyDefaultRoute verifies we do NOT attempt to install
// a 0.0.0.0/0 route (the system already has one; installing another would be
// dangerous and provides no bypass primitive).
func TestDHCPRouteBypass_OnlyDefaultRoute(t *testing.T) {
	var addCalled int32
	platformAddRoute = func(string, string) error { atomic.AddInt32(&addCalled, 1); return nil }
	platformDeleteRoute = func(string) error { return nil }
	defer resetDHCPRouteStubs()

	cfg := &Config{
		DHCPClasslessRoutes: []platform.DHCPRoute{
			{CIDR: "0.0.0.0/0", Gateway: "192.168.1.1"},
		},
	}
	r := tryDHCPRouteBypass(cfg, nil)
	if r.Success {
		t.Fatal("expected failure with only default route")
	}
	if atomic.LoadInt32(&addCalled) != 0 {
		t.Errorf("must not AddRoute for default route; got %d calls", addCalled)
	}
	if !strings.Contains(r.Details, "only default route") {
		t.Errorf("details should mention only default route, got %q", r.Details)
	}
}

// TestDHCPRouteBypass_Success exercises the full happy path: a non-default
// route is advertised, AddRoute succeeds, the verify HTTP check returns 204,
// and the technique reports success. DeleteRoute must NOT be called.
func TestDHCPRouteBypass_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	origURL := dhcpRouteVerifyURL
	dhcpRouteVerifyURL = srv.URL
	defer func() { dhcpRouteVerifyURL = origURL }()

	var addArgs, delArgs []string
	platformAddRoute = func(cidr, gw string) error {
		addArgs = append(addArgs, cidr+"|"+gw)
		return nil
	}
	platformDeleteRoute = func(cidr string) error {
		delArgs = append(delArgs, cidr)
		return nil
	}
	defer resetDHCPRouteStubs()

	cfg := &Config{
		DHCPClasslessRoutes: []platform.DHCPRoute{
			{CIDR: "0.0.0.0/0", Gateway: "192.168.1.1"}, // must be skipped
			{CIDR: "8.8.8.8/32", Gateway: "192.168.1.2"},
		},
	}
	r := tryDHCPRouteBypass(cfg, nil)
	if !r.Success {
		t.Fatalf("expected success; got %+v", r)
	}
	if len(addArgs) != 1 || addArgs[0] != "8.8.8.8/32|192.168.1.2" {
		t.Errorf("expected single AddRoute(8.8.8.8/32, 192.168.1.2); got %v", addArgs)
	}
	if len(delArgs) != 0 {
		t.Errorf("must not DeleteRoute on success; got %v", delArgs)
	}
}

// TestDHCPRouteBypass_RollbackOnNoInternet verifies that when AddRoute
// succeeds but the verify check does NOT return 204, the route is deleted.
func TestDHCPRouteBypass_RollbackOnNoInternet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // portal-style 500
	}))
	defer srv.Close()

	origURL := dhcpRouteVerifyURL
	dhcpRouteVerifyURL = srv.URL
	defer func() { dhcpRouteVerifyURL = origURL }()

	var addCalled, delCalled int32
	platformAddRoute = func(string, string) error { atomic.AddInt32(&addCalled, 1); return nil }
	platformDeleteRoute = func(string) error { atomic.AddInt32(&delCalled, 1); return nil }
	defer resetDHCPRouteStubs()

	cfg := &Config{
		DHCPClasslessRoutes: []platform.DHCPRoute{
			{CIDR: "10.0.0.0/8", Gateway: "192.168.1.9"},
		},
	}
	r := tryDHCPRouteBypass(cfg, nil)
	if r.Success {
		t.Fatal("expected failure when verify URL returns 500")
	}
	if atomic.LoadInt32(&addCalled) != 1 {
		t.Errorf("expected one AddRoute; got %d", addCalled)
	}
	if atomic.LoadInt32(&delCalled) != 1 {
		t.Errorf("expected rollback DeleteRoute; got %d", delCalled)
	}
}

// TestDHCPRouteBypass_PrefersNarrowestRoute verifies that narrower routes
// are attempted first — they're safer: a /32 affects one host, a /8 many.
func TestDHCPRouteBypass_PrefersNarrowestRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	origURL := dhcpRouteVerifyURL
	dhcpRouteVerifyURL = srv.URL
	defer func() { dhcpRouteVerifyURL = origURL }()

	var firstAdded string
	platformAddRoute = func(cidr, _ string) error {
		if firstAdded == "" {
			firstAdded = cidr
		}
		return nil
	}
	platformDeleteRoute = func(string) error { return nil }
	defer resetDHCPRouteStubs()

	cfg := &Config{
		DHCPClasslessRoutes: []platform.DHCPRoute{
			{CIDR: "10.0.0.0/8", Gateway: "192.168.1.9"},
			{CIDR: "8.8.8.8/32", Gateway: "192.168.1.9"},
			{CIDR: "172.16.0.0/12", Gateway: "192.168.1.9"},
		},
	}
	if r := tryDHCPRouteBypass(cfg, nil); !r.Success {
		t.Fatalf("expected success; got %+v", r)
	}
	if firstAdded != "8.8.8.8/32" {
		t.Errorf("expected narrowest route first; got %q", firstAdded)
	}
}

// TestFilterNonDefaultRoutes verifies input sanitation: malformed CIDRs or
// gateways are dropped before we ever touch the kernel routing table.
func TestFilterNonDefaultRoutes(t *testing.T) {
	in := []platform.DHCPRoute{
		{CIDR: "0.0.0.0/0", Gateway: "1.1.1.1"},      // default -- drop
		{CIDR: "10.0.0.0/8", Gateway: ""},            // empty gw -- drop
		{CIDR: "", Gateway: "1.1.1.1"},               // empty cidr -- drop
		{CIDR: "not-a-cidr", Gateway: "1.1.1.1"},     // bad cidr -- drop
		{CIDR: "10.0.0.0/8", Gateway: "not-an-ip"},   // bad gw -- drop
		{CIDR: "10.0.0.0/8", Gateway: "192.168.1.1"}, // keep
	}
	out := filterNonDefaultRoutes(in)
	if len(out) != 1 || out[0].CIDR != "10.0.0.0/8" {
		t.Errorf("filter returned %v, want single 10.0.0.0/8", out)
	}
}

func resetDHCPRouteStubs() {
	platformAddRoute = platform.AddRoute
	platformDeleteRoute = platform.DeleteRoute
}
