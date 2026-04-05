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

// ---------------------------------------------------------------------------
// GenerateRandomMAC — comprehensive batch validation
// ---------------------------------------------------------------------------

func TestGenerateRandomMAC_BatchProperties(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		mac := GenerateRandomMAC()

		// Format: xx:xx:xx:xx:xx:xx with lowercase hex.
		if !macRE.MatchString(mac) {
			t.Fatalf("iteration %d: %q does not match MAC format", i, mac)
		}
		if mac != strings.ToLower(mac) {
			t.Fatalf("iteration %d: %q is not lowercase", i, mac)
		}

		parts := strings.Split(mac, ":")
		if len(parts) != 6 {
			t.Fatalf("iteration %d: %q has %d octets, want 6", i, mac, len(parts))
		}

		first := hexToByte(parts[0])

		// Locally-administered bit (bit 1) must be set.
		if first&0x02 == 0 {
			t.Errorf("iteration %d: %q first octet %02x missing locally-administered bit", i, mac, first)
		}
		// Unicast bit (bit 0) must be clear.
		if first&0x01 != 0 {
			t.Errorf("iteration %d: %q first octet %02x is multicast", i, mac, first)
		}

		// No duplicates in batch.
		if seen[mac] {
			t.Errorf("duplicate MAC in 100 generations: %s", mac)
		}
		seen[mac] = true
	}
}

// ---------------------------------------------------------------------------
// ValidateMAC — additional edge cases
// ---------------------------------------------------------------------------

func TestValidateMAC_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Short-format octets from arp output (e.g. "0:a0:bc:c0:84:40").
		{"short octet from arp", "0:a0:bc:c0:84:40", true},
		{"all single-char octets", "0:0:0:0:0:0", true},
		// Consecutive colons.
		{"consecutive colons", "aa::cc:dd:ee:ff", true},
		{"triple colon", "aa:::dd:ee:ff:00", true},
		// Wrong number of octets.
		{"7 octets", "aa:bb:cc:dd:ee:ff:00", true},
		{"5 octets", "aa:bb:cc:dd:ee", true},
		{"4 octets", "aa:bb:cc:dd", true},
		{"1 octet", "aa", true},
		// Whitespace variants.
		{"leading space", " aa:bb:cc:dd:ee:ff", true},
		{"trailing space", "aa:bb:cc:dd:ee:ff ", true},
		{"tab inside", "aa:bb\t:cc:dd:ee:ff", true},
		// Null byte.
		{"null byte", "aa:bb:cc:dd:ee:\x00f", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateMAC(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMAC(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateInterface — additional edge cases
// ---------------------------------------------------------------------------

func TestValidateInterface_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"starts with digit", "0eth", true},
		{"all digits", "1234", true},
		{"special chars", "en0!", true},
		{"unicode", "en\u00e90", true},
		{"newline", "en0\n", true},
		{"null byte", "en\x000", true},
		{"17 chars (max+1)", "a12345678901234567", true},
		{"16 chars (max)", "a123456789012345", false},
		{"pipe injection", "en0|id", true},
		{"backtick injection", "en0`id`", true},
		{"dollar injection", "en0$HOME", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateInterface(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInterface(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateIP
// ---------------------------------------------------------------------------

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"IPv4 normal", "192.168.1.1", "192.168.1.1", false},
		{"IPv4 loopback", "127.0.0.1", "127.0.0.1", false},
		{"IPv4 broadcast", "255.255.255.255", "255.255.255.255", false},
		{"IPv4 zeros", "0.0.0.0", "0.0.0.0", false},
		{"IPv6 loopback", "::1", "::1", false},
		{"IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334", false},
		{"IPv6 link-local", "fe80::1", "fe80::1", false},
		{"IPv4-mapped IPv6", "::ffff:192.168.1.1", "192.168.1.1", false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"garbage", "not-an-ip", "", true},
		{"hostname", "example.com", "", true},
		{"IPv4 with port", "192.168.1.1:80", "", true},
		{"IPv4 overflow", "256.256.256.256", "", true},
		{"IPv4 leading zeros trimmed", " 10.0.0.1 ", "10.0.0.1", false},
		{"shell injection", "127.0.0.1; rm -rf /", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateIP(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIP(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateURL
// ---------------------------------------------------------------------------

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"http", "http://example.com", "http://example.com", false},
		{"https", "https://example.com", "https://example.com", false},
		{"https with path", "https://example.com/path?q=1", "https://example.com/path?q=1", false},
		{"https with fragment", "https://example.com/page#section", "https://example.com/page#section", false},
		{"https with auth", "https://user:pass@example.com", "https://user:pass@example.com", false},
		{"ftp rejected", "ftp://example.com", "", true},
		{"no scheme", "example.com", "", true},
		{"just hostname", "//example.com", "", true},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"no host", "http://", "", true},
		{"shell injection", "https://example.com; rm -rf /", "", true},
		{"data scheme", "data:text/html,<h1>hi</h1>", "", true},
		{"javascript scheme", "javascript:alert(1)", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ValidateURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateServerAddr
// ---------------------------------------------------------------------------

func TestValidateServerAddr(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"host:port", "example.com:8080", "example.com:8080", false},
		{"IP:port", "192.168.1.1:443", "192.168.1.1:443", false},
		{"IPv6 brackets", "[::1]:8080", "[::1]:8080", false},
		{"hostname only", "example.com", "example.com", false},
		{"IP only", "10.0.0.1", "10.0.0.1", false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"port only", ":8080", ":8080", false},
		{"shell injection semicolon", "host; rm -rf /", "", true},
		{"shell injection pipe", "host | cat /etc/passwd", "", true},
		{"shell injection backtick", "host`id`", "", true},
		{"shell injection dollar", "host$(id)", "", true},
		{"spaces", "host name:80", "", true},
		{"newline", "host\n:80", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateServerAddr(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServerAddr(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateServerAddr(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateDomain
// ---------------------------------------------------------------------------

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"simple", "example.com", "example.com", false},
		{"subdomain", "sub.example.com", "sub.example.com", false},
		{"deep subdomain", "a.b.c.example.com", "a.b.c.example.com", false},
		{"single label", "localhost", "localhost", false},
		{"trailing dot", "example.com.", "", true},
		{"starts with hyphen", "-example.com", "", true},
		{"ends with hyphen", "example-", "", true},
		{"single char", "a", "a", false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"too long (254 chars)", strings.Repeat("a", 254), "", true},
		{"max length (253 chars)", strings.Repeat("a", 253), strings.Repeat("a", 253), false},
		{"underscore", "ex_ample.com", "", true},
		{"space inside", "example .com", "", true},
		{"starts with dot", ".example.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateDomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseArpEntries — Linux format and more edge cases
// ---------------------------------------------------------------------------

func TestParseArpEntries_LinuxFormat(t *testing.T) {
	// Linux arp -a output format: hostname (IP) at MAC [ether] on iface
	re := regexp.MustCompile(`\S+\s+\((\S+)\)\s+at\s+(\S+)\s+\[ether\]\s+on\s+(\S+)`)

	tests := []struct {
		name      string
		output    string
		wantCount int
	}{
		{
			"standard linux entry",
			"gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0",
			1,
		},
		{
			"multiple entries",
			"gw (10.0.0.1) at 11:22:33:44:55:66 [ether] on eth0\nhost (10.0.0.2) at aa:bb:cc:dd:ee:ff [ether] on eth0",
			2,
		},
		{
			"incomplete entry skipped",
			"? (10.0.0.1) at <incomplete> on eth0\ngw (10.0.0.2) at aa:bb:cc:dd:ee:ff [ether] on eth0",
			1,
		},
		{
			"garbage lines mixed in",
			"some header line\ngw (10.0.0.1) at aa:bb:cc:dd:ee:ff [ether] on wlan0\n\nanother junk",
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := parseArpEntries(tt.output, re, 1, 2, 3)
			if len(entries) != tt.wantCount {
				t.Errorf("got %d entries, want %d", len(entries), tt.wantCount)
			}
		})
	}
}

func TestParseArpEntries_MacOSRealRegex(t *testing.T) {
	// Use the same regex as GetARPTable in darwin.go.
	re := regexp.MustCompile(`\S+\s+\((\S+)\)\s+at\s+(\S+)\s+on\s+(\S+)`)

	output := "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n" +
		"? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n" +
		"? (224.0.0.251) at 01:00:5e:00:00:fb on en0 ifscope permanent [ethernet]"

	entries := parseArpEntries(output, re, 1, 2, 3)
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].IP != "192.168.1.1" {
		t.Errorf("first entry IP = %q, want 192.168.1.1", entries[0].IP)
	}
	if entries[1].MAC != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("second entry MAC = %q, want ff:ff:ff:ff:ff:ff", entries[1].MAC)
	}
}

// ---------------------------------------------------------------------------
// normalizeMAC — whitespace edge cases
// ---------------------------------------------------------------------------

func TestNormalizeMAC_WhitespaceVariants(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"carriage return", "aa:bb:cc:dd:ee:ff\r", "aa:bb:cc:dd:ee:ff", false},
		{"CRLF", "aa:bb:cc:dd:ee:ff\r\n", "aa:bb:cc:dd:ee:ff", false},
		{"tab and spaces", "\t  aa:bb:cc:dd:ee:ff  \t", "aa:bb:cc:dd:ee:ff", false},
		{"mixed whitespace", " \t\r\nAA:BB:CC:DD:EE:FF\r\n\t ", "aa:bb:cc:dd:ee:ff", false},
		{"only whitespace", " \t\r\n ", "", true},
		{"embedded newline", "aa:bb:cc\n:dd:ee:ff", "", true},
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
