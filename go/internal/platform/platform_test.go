//go:build darwin

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package platform

import (
	"regexp"
	"strings"
	"testing"
)

func TestGenerateRandomMAC(t *testing.T) {
	for i := 0; i < 100; i++ {
		mac := GenerateRandomMAC()

		// Check format: xx:xx:xx:xx:xx:xx.
		if !macRE.MatchString(mac) {
			t.Fatalf("GenerateRandomMAC() = %q, does not match MAC format", mac)
		}

		// Parse first octet.
		parts := strings.Split(mac, ":")
		if len(parts) != 6 {
			t.Fatalf("GenerateRandomMAC() = %q, expected 6 octets", mac)
		}

		firstByte := hexToByte(parts[0])

		// Locally administered bit (bit 1 of first octet) must be set.
		if firstByte&0x02 == 0 {
			t.Errorf("GenerateRandomMAC() = %q, first octet %02x not locally administered", mac, firstByte)
		}

		// Unicast bit (bit 0 of first octet) must be clear.
		if firstByte&0x01 != 0 {
			t.Errorf("GenerateRandomMAC() = %q, first octet %02x is multicast", mac, firstByte)
		}

		// All lowercase.
		if mac != strings.ToLower(mac) {
			t.Errorf("GenerateRandomMAC() = %q, expected all lowercase", mac)
		}
	}
}

func TestGenerateRandomMAC_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		mac := GenerateRandomMAC()
		if seen[mac] {
			t.Errorf("duplicate MAC generated: %s", mac)
		}
		seen[mac] = true
	}
}

func hexToByte(s string) byte {
	var b byte
	for _, c := range s {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			b |= byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			b |= byte(c - 'A' + 10)
		}
	}
	return b
}

func TestValidateMAC(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid lowercase", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", false},
		{"valid uppercase", "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff", false},
		{"valid mixed", "aA:bB:cC:dD:eE:fF", "aa:bb:cc:dd:ee:ff", false},
		{"valid zeros", "00:00:00:00:00:00", "00:00:00:00:00:00", false},
		{"too short", "aa:bb:cc:dd:ee", "", true},
		{"too long", "aa:bb:cc:dd:ee:ff:00", "", true},
		{"wrong delimiter", "aa-bb-cc-dd-ee-ff", "", true},
		{"no delimiter", "aabbccddeeff", "", true},
		{"invalid chars", "gg:hh:ii:jj:kk:ll", "", true},
		{"empty", "", "", true},
		{"injection attempt", "aa:bb:cc:dd:ee:ff; rm -rf /", "", true},
		{"spaces", "aa:bb:cc: dd:ee:ff", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateMAC(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMAC(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateMAC(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateInterface(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid en0", "en0", "en0", false},
		{"valid en1", "en1", "en1", false},
		{"valid wlan0", "wlan0", "wlan0", false},
		{"valid long", "abcdef0123456789", "abcdef0123456789", false},
		{"empty", "", "", true},
		{"starts with number", "0en", "", true},
		{"special chars", "en0;", "", true},
		{"injection", "en0; rm -rf /", "", true},
		{"too long", "a1234567890123456", "", true},
		{"spaces", "en 0", "", true},
		{"dots", "en0.1", "", true},
		{"slashes", "/dev/en0", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateInterface(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInterface(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateInterface(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetARPTable(t *testing.T) {
	// This calls the real arp command; skip in environments where it may not work.
	entries, err := GetARPTable()
	if err != nil {
		t.Skipf("GetARPTable() failed (likely no arp available): %v", err)
	}

	// On a running macOS system there should be at least one ARP entry.
	if len(entries) == 0 {
		t.Skip("no ARP entries found (may be normal in CI)")
	}

	for _, e := range entries {
		if e.IP == "" {
			t.Error("ARP entry has empty IP")
		}
		if e.MAC == "" {
			t.Error("ARP entry has empty MAC")
		}
		if e.Interface == "" {
			t.Error("ARP entry has empty Interface")
		}
		// MAC should look valid.
		if !regexp.MustCompile(`^[0-9a-f:]+$`).MatchString(e.MAC) {
			t.Errorf("ARP entry MAC %q does not look valid", e.MAC)
		}
	}
}

func TestGetCurrentMAC(t *testing.T) {
	// Test with a real interface. "lo0" exists on all macOS systems.
	// However, lo0 may not have an "ether" line in ifconfig.
	// Try en0 which is the primary WiFi interface on macOS.
	mac, err := GetCurrentMAC("en0")
	if err != nil {
		t.Skipf("GetCurrentMAC(en0) failed (may not have WiFi): %v", err)
	}
	if mac == "" {
		t.Error("GetCurrentMAC(en0) returned empty MAC")
	}
	if !macRE.MatchString(mac) {
		t.Errorf("GetCurrentMAC(en0) = %q, does not match MAC format", mac)
	}
}

func TestGetCurrentMAC_InvalidInterface(t *testing.T) {
	_, err := GetCurrentMAC("nonexistent99")
	if err == nil {
		t.Error("expected error for nonexistent interface")
	}
}

func TestParseRSSI(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want int
	}{
		{"float", float64(-64), -64},
		{"string with dBm", "-64 dBm / -96 dBm", -64},
		{"string number", "-72", -72},
		{"empty string", "", -99},
		{"nil", nil, -99},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRSSI(tt.val)
			if got != tt.want {
				t.Errorf("parseRSSI(%v) = %d, want %d", tt.val, got, tt.want)
			}
		})
	}
}

func TestGetGateway(t *testing.T) {
	gw, err := GetGateway("en0")
	if err != nil {
		t.Skipf("GetGateway failed (may not have network): %v", err)
	}
	if gw == "" {
		t.Error("GetGateway returned empty string")
	}
	// Gateway should look like an IP address.
	if !regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(gw) {
		t.Errorf("GetGateway = %q, does not look like an IP", gw)
	}
}

func TestMACRegex(t *testing.T) {
	valid := []string{
		"aa:bb:cc:dd:ee:ff",
		"00:11:22:33:44:55",
		"AA:BB:CC:DD:EE:FF",
		"aA:bB:cC:dD:eE:fF",
	}
	for _, mac := range valid {
		if !macRE.MatchString(mac) {
			t.Errorf("macRE should match %q", mac)
		}
	}

	invalid := []string{
		"aa:bb:cc:dd:ee",
		"aa:bb:cc:dd:ee:ff:00",
		"aabbccddeeff",
		"aa-bb-cc-dd-ee-ff",
		"gg:hh:ii:jj:kk:ll",
	}
	for _, mac := range invalid {
		if macRE.MatchString(mac) {
			t.Errorf("macRE should not match %q", mac)
		}
	}
}

func TestIfaceRegex(t *testing.T) {
	valid := []string{
		"en0", "en1", "wlan0", "eth0", "lo0",
	}
	for _, iface := range valid {
		if !ifaceRE.MatchString(iface) {
			t.Errorf("ifaceRE should match %q", iface)
		}
	}

	invalid := []string{
		"", "0en", "en0;cmd", "/dev/en0", "a b",
	}
	for _, iface := range invalid {
		if ifaceRE.MatchString(iface) {
			t.Errorf("ifaceRE should not match %q", iface)
		}
	}
}
