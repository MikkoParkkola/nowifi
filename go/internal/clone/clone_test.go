// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package clone

import (
	"testing"
)

// ---------------------------------------------------------------------------
// DetectTargetOS
// ---------------------------------------------------------------------------

func TestDetectTargetOS(t *testing.T) {
	tests := []struct {
		name string
		mac  string
		want string
	}{
		// Apple OUIs -> ios
		{"apple A4:B1:97", "A4:B1:97:01:02:03", "ios"},
		{"apple F0:D1:A9", "F0:D1:A9:AA:BB:CC", "ios"},
		{"apple 3C:06:A7", "3C:06:A7:00:00:00", "ios"},
		{"apple 28:CF:51", "28:CF:51:12:34:56", "ios"},
		{"apple 88:66:A5", "88:66:A5:FF:FF:FF", "ios"},
		{"apple DC:56:E7", "DC:56:E7:AB:CD:EF", "ios"},

		// Android OUIs
		{"android B4:7C:9C", "B4:7C:9C:01:02:03", "android"},
		{"android CC:07:AB", "CC:07:AB:AA:BB:CC", "android"},
		{"android 84:38:35", "84:38:35:00:00:00", "android"},
		{"android F8:D0:BD", "F8:D0:BD:12:34:56", "android"},
		{"android 94:63:D1", "94:63:D1:FF:FF:FF", "android"},

		// Windows OUIs
		{"windows F4:8E:38", "F4:8E:38:01:02:03", "windows"},
		{"windows 3C:2E:FF", "3C:2E:FF:AA:BB:CC", "windows"},
		{"windows B4:99:BA", "B4:99:BA:00:00:00", "windows"},
		{"windows 1C:69:7A", "1C:69:7A:12:34:56", "windows"},
		{"windows 50:9A:4C", "50:9A:4C:FF:FF:FF", "windows"},

		// Unknown OUI -> linux default
		{"unknown OUI", "00:11:22:33:44:55", "linux"},
		{"another unknown", "DE:AD:BE:EF:CA:FE", "linux"},

		// Case insensitivity
		{"lowercase apple", "a4:b1:97:01:02:03", "ios"},
		{"mixed case apple", "a4:B1:97:01:02:03", "ios"},

		// Edge cases
		{"too short", "AA:BB", "linux"},
		{"empty", "", "linux"},
		{"five octets", "AA:BB:CC:DD:EE", "linux"},
		{"no colons short", "AABB", "linux"},

		// MAC with colons stripped internally -> still works for 6+ hex chars
		{"no colons full", "A4B197010203", "ios"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectTargetOS(tt.mac)
			if got != tt.want {
				t.Errorf("DetectTargetOS(%q) = %q, want %q", tt.mac, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ProfileForOS
// ---------------------------------------------------------------------------

func TestProfileForOS(t *testing.T) {
	tests := []struct {
		name    string
		os      string
		wantOS  string
		wantTTL int
	}{
		{"macos", "macos", "macos", 64},
		{"ios", "ios", "ios", 64},
		{"windows", "windows", "windows", 128},
		{"android", "android", "android", 64},
		{"linux", "linux", "linux", 64},
		{"unknown defaults to linux", "freebsd", "linux", 64},
		{"empty defaults to linux", "", "linux", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ProfileForOS(tt.os)
			if p.OS != tt.wantOS {
				t.Errorf("ProfileForOS(%q).OS = %q, want %q", tt.os, p.OS, tt.wantOS)
			}
			if p.TTL != tt.wantTTL {
				t.Errorf("ProfileForOS(%q).TTL = %d, want %d", tt.os, p.TTL, tt.wantTTL)
			}
		})
	}
}

func TestProfileForOS_Hostname(t *testing.T) {
	tests := []struct {
		os       string
		wantHost string
	}{
		{"macos", "MacBook-Pro"},
		{"ios", "iPhone"},
		{"windows", "DESKTOP-NOWIFI"},
		{"android", "android-nowifi"},
		{"linux", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.os, func(t *testing.T) {
			p := ProfileForOS(tt.os)
			if p.Hostname != tt.wantHost {
				t.Errorf("ProfileForOS(%q).Hostname = %q, want %q", tt.os, p.Hostname, tt.wantHost)
			}
		})
	}
}

func TestProfileForOS_DHCPOptions(t *testing.T) {
	// Windows and Android have vendor class identifiers; others don't.
	t.Run("windows has option60", func(t *testing.T) {
		p := ProfileForOS("windows")
		if p.DHCPOption60 != "MSFT 5.0" {
			t.Errorf("windows DHCPOption60 = %q, want %q", p.DHCPOption60, "MSFT 5.0")
		}
	})

	t.Run("android has option60", func(t *testing.T) {
		p := ProfileForOS("android")
		if p.DHCPOption60 != "android-dhcp-14" {
			t.Errorf("android DHCPOption60 = %q, want %q", p.DHCPOption60, "android-dhcp-14")
		}
	})

	t.Run("macos no option60", func(t *testing.T) {
		p := ProfileForOS("macos")
		if p.DHCPOption60 != "" {
			t.Errorf("macos DHCPOption60 = %q, want empty", p.DHCPOption60)
		}
	})

	t.Run("ios no option60", func(t *testing.T) {
		p := ProfileForOS("ios")
		if p.DHCPOption60 != "" {
			t.Errorf("ios DHCPOption60 = %q, want empty", p.DHCPOption60)
		}
	})

	// All profiles must have DHCPOptions55.
	for _, os := range []string{"macos", "ios", "windows", "android", "linux"} {
		t.Run(os+"_has_options55", func(t *testing.T) {
			p := ProfileForOS(os)
			if p.DHCPOptions55 == "" {
				t.Errorf("ProfileForOS(%q).DHCPOptions55 is empty", os)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pre-built profiles sanity
// ---------------------------------------------------------------------------

func TestPreBuiltProfiles(t *testing.T) {
	profiles := []DeviceProfile{
		ProfileMacOS, ProfileiOS, ProfileWindows, ProfileAndroid, ProfileLinux,
	}

	for _, p := range profiles {
		t.Run(p.OS, func(t *testing.T) {
			if p.OS == "" {
				t.Error("profile OS is empty")
			}
			if p.Hostname == "" {
				t.Error("profile Hostname is empty")
			}
			if p.DHCPOptions55 == "" {
				t.Error("profile DHCPOptions55 is empty")
			}
			if p.TTL <= 0 {
				t.Errorf("profile TTL = %d, want > 0", p.TTL)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DetectTargetOS -> ProfileForOS round-trip
// ---------------------------------------------------------------------------

func TestDetectAndProfile_RoundTrip(t *testing.T) {
	tests := []struct {
		mac    string
		wantOS string
	}{
		{"A4:B1:97:01:02:03", "ios"},
		{"B4:7C:9C:01:02:03", "android"},
		{"F4:8E:38:01:02:03", "windows"},
		{"00:11:22:33:44:55", "linux"},
	}

	for _, tt := range tests {
		t.Run(tt.wantOS, func(t *testing.T) {
			os := DetectTargetOS(tt.mac)
			if os != tt.wantOS {
				t.Fatalf("DetectTargetOS(%q) = %q, want %q", tt.mac, os, tt.wantOS)
			}
			p := ProfileForOS(os)
			if p.OS != tt.wantOS {
				t.Errorf("ProfileForOS(%q).OS = %q, want %q", os, p.OS, tt.wantOS)
			}
		})
	}
}
