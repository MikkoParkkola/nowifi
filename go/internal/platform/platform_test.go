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

// ---------------------------------------------------------------------------
// normalizeMAC
// ---------------------------------------------------------------------------

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"trims whitespace", "  aa:bb:cc:dd:ee:ff  ", "aa:bb:cc:dd:ee:ff", false},
		{"trims tabs", "\tAA:BB:CC:DD:EE:FF\t", "aa:bb:cc:dd:ee:ff", false},
		{"trims newline", "aa:bb:cc:dd:ee:ff\n", "aa:bb:cc:dd:ee:ff", false},
		{"already clean", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", false},
		{"invalid after trim", "  not-a-mac  ", "", true},
		{"empty after trim", "   ", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMAC(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeMAC(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("normalizeMAC(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseArpEntries — additional cases
// ---------------------------------------------------------------------------

func TestParseArpEntries_MacOSFormat(t *testing.T) {
	re := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+) on (\w+)`)

	tests := []struct {
		name      string
		output    string
		wantCount int
		wantFirst *ArpEntry
	}{
		{
			"two entries",
			"? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n? (192.168.1.2) at 11:22:33:44:55:66 on en0 ifscope [ethernet]",
			2,
			&ArpEntry{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:ff", Interface: "en0"},
		},
		{
			"empty output",
			"",
			0,
			nil,
		},
		{
			"no matching lines",
			"some random text\nanother line",
			0,
			nil,
		},
		{
			"mixed valid and invalid",
			"? (10.0.0.1) at aa:bb:cc:dd:ee:ff on wlan0 [ethernet]\nskip this line\n? (10.0.0.2) at 11:22:33:44:55:66 on wlan0 [ethernet]",
			2,
			&ArpEntry{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", Interface: "wlan0"},
		},
		{
			"uppercase MAC normalized",
			"? (192.168.0.1) at AA:BB:CC:DD:EE:FF on en1 [ethernet]",
			1,
			&ArpEntry{IP: "192.168.0.1", MAC: "aa:bb:cc:dd:ee:ff", Interface: "en1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := parseArpEntries(tt.output, re, 1, 2, 3)
			if len(entries) != tt.wantCount {
				t.Errorf("parseArpEntries() returned %d entries, want %d", len(entries), tt.wantCount)
				return
			}
			if tt.wantFirst != nil && len(entries) > 0 {
				e := entries[0]
				if e.IP != tt.wantFirst.IP {
					t.Errorf("first entry IP = %q, want %q", e.IP, tt.wantFirst.IP)
				}
				if e.MAC != tt.wantFirst.MAC {
					t.Errorf("first entry MAC = %q, want %q", e.MAC, tt.wantFirst.MAC)
				}
				if e.Interface != tt.wantFirst.Interface {
					t.Errorf("first entry Interface = %q, want %q", e.Interface, tt.wantFirst.Interface)
				}
			}
		})
	}
}

func TestParseArpEntries_SkipsInvalidMAC(t *testing.T) {
	re := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\) at (\S+) on (\w+)`)
	output := "? (10.0.0.1) at not-a-mac on en0 [ethernet]\n? (10.0.0.2) at aa:bb:cc:dd:ee:ff on en0 [ethernet]"
	entries := parseArpEntries(output, re, 1, 2, 3)

	if len(entries) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(entries))
	}
	if len(entries) > 0 && entries[0].IP != "10.0.0.2" {
		t.Errorf("expected entry for 10.0.0.2, got %q", entries[0].IP)
	}
}

// ---------------------------------------------------------------------------
// GenerateRandomMAC — first octet distribution
// ---------------------------------------------------------------------------

func TestGenerateRandomMAC_FirstOctetValues(t *testing.T) {
	validFirst := map[byte]bool{0x02: true, 0x06: true, 0x0A: true, 0x0E: true}
	seen := make(map[byte]int)

	for i := 0; i < 200; i++ {
		mac := GenerateRandomMAC()
		parts := strings.Split(mac, ":")
		b := hexToByte(parts[0])
		if !validFirst[b] {
			t.Fatalf("first octet %02x not in {02, 06, 0a, 0e}", b)
		}
		seen[b]++
	}

	// With 200 iterations and 4 choices, each should appear at least once.
	for b := range validFirst {
		if seen[b] == 0 {
			t.Errorf("first octet %02x never appeared in 200 generations", b)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateMAC — additional boundary cases
// ---------------------------------------------------------------------------

func TestValidateMAC_AllZeros(t *testing.T) {
	mac, err := ValidateMAC("00:00:00:00:00:00")
	if err != nil {
		t.Errorf("all-zeros MAC should be valid: %v", err)
	}
	if mac != "00:00:00:00:00:00" {
		t.Errorf("got %q, want 00:00:00:00:00:00", mac)
	}
}

func TestValidateMAC_AllFs(t *testing.T) {
	mac, err := ValidateMAC("FF:FF:FF:FF:FF:FF")
	if err != nil {
		t.Errorf("all-FF MAC should be valid: %v", err)
	}
	if mac != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("got %q, want ff:ff:ff:ff:ff:ff", mac)
	}
}

func TestValidateMAC_MixedHexDigits(t *testing.T) {
	mac, err := ValidateMAC("0A:1B:2C:3D:4E:5F")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mac != "0a:1b:2c:3d:4e:5f" {
		t.Errorf("got %q, want 0a:1b:2c:3d:4e:5f", mac)
	}
}

// ---------------------------------------------------------------------------
// ValidateInterface — additional edge cases
// ---------------------------------------------------------------------------

func TestValidateInterface_SingleChar(t *testing.T) {
	got, err := ValidateInterface("a")
	if err != nil {
		t.Errorf("single char should be valid: %v", err)
	}
	if got != "a" {
		t.Errorf("got %q, want a", got)
	}
}

func TestValidateInterface_MaxLength(t *testing.T) {
	name := "a123456789012345" // 16 chars: 1 alpha + 15 alnum = max allowed
	got, err := ValidateInterface(name)
	if err != nil {
		t.Errorf("16-char interface should be valid: %v", err)
	}
	if got != name {
		t.Errorf("got %q, want %q", got, name)
	}
}

func TestValidateInterface_OverMaxLength(t *testing.T) {
	name := "a1234567890123456" // 17 chars
	_, err := ValidateInterface(name)
	if err == nil {
		t.Error("17-char interface should be invalid")
	}
}

func TestValidateInterface_Underscore(t *testing.T) {
	_, err := ValidateInterface("wlan_0")
	if err == nil {
		t.Error("underscore in interface name should be invalid")
	}
}

func TestValidateInterface_Hyphen(t *testing.T) {
	_, err := ValidateInterface("wlan-0")
	if err == nil {
		t.Error("hyphen in interface name should be invalid")
	}
}
