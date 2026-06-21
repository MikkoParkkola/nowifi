//go:build linux

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package platform

import "testing"

func TestParseLinuxClasslessRoutes_Dhcpcd(t *testing.T) {
	in := "new_classless_static_routes='10.0.0.0/8 192.168.1.1 0.0.0.0/0 192.168.1.1'\n"
	got := parseLinuxClasslessRoutes(in)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2; got %v", len(got), got)
	}
	if got[0].CIDR != "10.0.0.0/8" || got[0].Gateway != "192.168.1.1" {
		t.Errorf("[0] = %+v", got[0])
	}
	if got[1].CIDR != "0.0.0.0/0" || got[1].Gateway != "192.168.1.1" {
		t.Errorf("[1] = %+v", got[1])
	}
}

func TestParseLinuxClasslessRoutes_Systemd(t *testing.T) {
	in := "ADDRESS=192.168.1.55\nCLASSLESS_STATIC_ROUTES=172.16.0.0/12 10.0.0.1\n"
	got := parseLinuxClasslessRoutes(in)
	if len(got) != 1 || got[0].CIDR != "172.16.0.0/12" || got[0].Gateway != "10.0.0.1" {
		t.Errorf("got %v", got)
	}
}

func TestParseLinuxClasslessRoutes_DhclientHex(t *testing.T) {
	// prefix=8 dest=10 gw=192.168.1.1 → "8:a:c0:a8:1:1"
	// prefix=0 gw=192.168.1.1 → "0:c0:a8:1:1"
	in := "option rfc3442-classless-static-routes 8:a:c0:a8:1:1, 0:c0:a8:1:1;\n"
	got := parseLinuxClasslessRoutes(in)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2; got %v", len(got), got)
	}
	if got[0].CIDR != "10.0.0.0/8" || got[0].Gateway != "192.168.1.1" {
		t.Errorf("[0] = %+v, want 10.0.0.0/8 via 192.168.1.1", got[0])
	}
	if got[1].CIDR != "0.0.0.0/0" || got[1].Gateway != "192.168.1.1" {
		t.Errorf("[1] = %+v, want 0.0.0.0/0 via 192.168.1.1", got[1])
	}
}

func TestParseLinuxClasslessRoutes_NoOption(t *testing.T) {
	got := parseLinuxClasslessRoutes("ADDRESS=192.168.1.55\nROUTER=192.168.1.1\n")
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}
