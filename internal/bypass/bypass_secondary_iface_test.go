// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import "testing"

func TestIsVirtualInterface(t *testing.T) {
	virtual := []string{"lo0", "br0", "docker0", "veth123abc", "virbr0", "utun3", "awdl0", "llw0", "anpi0", "ap1"}
	for _, name := range virtual {
		if !isVirtualInterface(name) {
			t.Errorf("isVirtualInterface(%q) = false, want true", name)
		}
	}
	physical := []string{"en0", "en1", "eth0", "wlan0", "pdp_ip0", "rmnet0", "usb0"}
	for _, name := range physical {
		if isVirtualInterface(name) {
			t.Errorf("isVirtualInterface(%q) = true, want false", name)
		}
	}
}

func TestClassifyInterface(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"pdp_ip0", "cellular modem"},
		{"rmnet0", "cellular modem"},
		{"wwan0", "cellular modem"},
		{"en1", "secondary Ethernet/WiFi adapter"},
		{"eth0", "Ethernet"},
		{"usb0", "USB network adapter"},
		{"bnep0", "Bluetooth PAN tethering"},
		{"mystery0", "secondary interface"},
	}
	for _, tc := range tests {
		got := classifyInterface(tc.name)
		if got != tc.want {
			t.Errorf("classifyInterface(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTrySecondaryIfaceBypass_NilConfig(t *testing.T) {
	r := trySecondaryIfaceBypass(nil, nil)
	if r.Success {
		t.Fatal("expected failure with nil config")
	}
}

func TestFindSecondaryInterfaces_ExcludesPrimary(t *testing.T) {
	// This test runs on real hardware; it should at least not panic.
	// On CI, loopback is the only non-WiFi interface — expect 0 or more.
	candidates := findSecondaryInterfaces("en0")
	for _, c := range candidates {
		if c.Name == "en0" {
			t.Errorf("findSecondaryInterfaces should exclude primary interface en0; got %+v", c)
		}
	}
}
