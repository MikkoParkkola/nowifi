// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package discover

import (
	"testing"
	"time"
)

func TestSignalBars(t *testing.T) {
	tests := []struct {
		dBm  int
		want string
	}{
		{-40, "||||"},
		{-50, "||||"},
		{-55, "|||."},
		{-60, "|||."},
		{-65, "||.."},
		{-70, "||.."},
		{-75, "|..."},
		{-80, "|..."},
		{-85, "...."},
		{-99, "...."},
	}

	for _, tt := range tests {
		got := SignalBars(tt.dBm)
		if got != tt.want {
			t.Errorf("SignalBars(%d) = %q, want %q", tt.dBm, got, tt.want)
		}
	}
}

func TestSignalBars_Boundaries(t *testing.T) {
	// Exact boundary values.
	tests := []struct {
		dBm  int
		want string
	}{
		{0, "||||"},    // very strong
		{-49, "||||"},  // just above -50
		{-51, "|||."},  // just below -50
		{-59, "|||."},  // just above -60
		{-61, "||.."},  // just below -60
		{-69, "||.."},  // just above -70
		{-71, "|..."},  // just below -70
		{-79, "|..."},  // just above -80
		{-81, "...."},  // just below -80
		{-120, "...."}, // very weak
	}

	for _, tt := range tests {
		got := SignalBars(tt.dBm)
		if got != tt.want {
			t.Errorf("SignalBars(%d) = %q, want %q", tt.dBm, got, tt.want)
		}
	}
}

func TestFreqToChannel(t *testing.T) {
	tests := []struct {
		freq int
		want int
	}{
		{2412, 1},
		{2437, 6},
		{2462, 11},
		{2484, 14},
		{5180, 36},
		{5240, 48},
		{5745, 149},
		{5825, 165},
		{1000, 0}, // unknown
	}

	for _, tt := range tests {
		got := freqToChannel(tt.freq)
		if got != tt.want {
			t.Errorf("freqToChannel(%d) = %d, want %d", tt.freq, got, tt.want)
		}
	}
}

func TestFreqToChannel_6GHz(t *testing.T) {
	tests := []struct {
		freq int
		want int
	}{
		{5955, 1},   // 6GHz channel 1
		{5975, 5},   // 6GHz channel 5
		{6115, 33},  // 6GHz channel 33
		{6875, 185}, // 6GHz channel 185
	}

	for _, tt := range tests {
		got := freqToChannel(tt.freq)
		if got != tt.want {
			t.Errorf("freqToChannel(%d) = %d, want %d", tt.freq, got, tt.want)
		}
	}
}

func TestFreqToChannel_EdgeCases(t *testing.T) {
	tests := []struct {
		freq int
		want int
	}{
		{0, 0},
		{2411, 0},  // just below 2.4GHz band
		{2485, 0},  // just above 2.4GHz band
		{5169, 0},  // just below 5GHz band
		{5826, 0},  // just above 5GHz band
		{5954, 0},  // just below 6GHz band
		{7116, 0},  // just above 6GHz band
		{-1, 0},    // negative
		{99999, 0}, // huge
	}

	for _, tt := range tests {
		got := freqToChannel(tt.freq)
		if got != tt.want {
			t.Errorf("freqToChannel(%d) = %d, want %d", tt.freq, got, tt.want)
		}
	}
}

func TestNormalizeSecurity(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"wpa3_personal", "WPA3"},
		{"WPA3-SAE", "WPA3"},
		{"wpa2_personal", "WPA2"},
		{"WPA_WPA2_PERSONAL", "WPA2"},
		{"wpa2_enterprise", "WPA2-Enterprise"},
		{"802.1X", "WPA2-Enterprise"},
		{"wpa_personal", "WPA"},
		{"wep", "WEP"},
		{"none", "Open"},
		{"open", "Open"},
		{"", "Open"},
		{"some_unknown_mode", "some_unknown_mode"},
		{"SAE", "WPA3"},
		{"sae_transition", "WPA3"},
		{"WEP40", "WEP"},
	}

	for _, tt := range tests {
		got := normalizeSecurity(tt.raw)
		if got != tt.want {
			t.Errorf("normalizeSecurity(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestParseBSSBlock(t *testing.T) {
	block := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2437
	signal: -65.00 dBm
	SSID: TestNetwork
	RSN:	 * Version: 1
		 * Group cipher: CCMP
	WPS:	 * Version: 2.0`

	n := parseBSSBlock(block)

	if n.BSSID != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("BSSID = %q, want aa:bb:cc:dd:ee:ff", n.BSSID)
	}
	if n.SSID != "TestNetwork" {
		t.Errorf("SSID = %q, want TestNetwork", n.SSID)
	}
	if n.Channel != 6 {
		t.Errorf("Channel = %d, want 6", n.Channel)
	}
	if n.Signal != -65 {
		t.Errorf("Signal = %d, want -65", n.Signal)
	}
	if n.Security != "WPA2" {
		t.Errorf("Security = %q, want WPA2", n.Security)
	}
	if !n.WPS {
		t.Error("WPS should be true")
	}
}

func TestParseBSSBlock_Open(t *testing.T) {
	block := `BSS 11:22:33:44:55:66(on wlan0)
	freq: 2412
	signal: -45.00 dBm
	SSID: FreeWifi`

	n := parseBSSBlock(block)

	if n.BSSID != "11:22:33:44:55:66" {
		t.Errorf("BSSID = %q", n.BSSID)
	}
	if n.SSID != "FreeWifi" {
		t.Errorf("SSID = %q, want FreeWifi", n.SSID)
	}
	if n.Channel != 1 {
		t.Errorf("Channel = %d, want 1", n.Channel)
	}
	if n.Signal != -45 {
		t.Errorf("Signal = %d, want -45", n.Signal)
	}
	if n.Security != "Open" {
		t.Errorf("Security = %q, want Open", n.Security)
	}
	if n.WPS {
		t.Error("WPS should be false")
	}
}

func TestParseBSSBlock_WPA3(t *testing.T) {
	block := `BSS aa:bb:cc:dd:ee:01(on wlan0)
	freq: 5180
	signal: -55.00 dBm
	SSID: SecureNet
	SAE: supported`

	n := parseBSSBlock(block)

	if n.Security != "WPA3" {
		t.Errorf("Security = %q, want WPA3", n.Security)
	}
	if n.Channel != 36 {
		t.Errorf("Channel = %d, want 36", n.Channel)
	}
}

func TestParseBSSBlock_Enterprise(t *testing.T) {
	block := `BSS aa:bb:cc:dd:ee:02(on wlan0)
	freq: 5240
	signal: -60.00 dBm
	SSID: CorpNet
	RSN:	 * Version: 1
	* Authentication suites: 802.1X`

	n := parseBSSBlock(block)

	if n.Security != "WPA2-Enterprise" {
		t.Errorf("Security = %q, want WPA2-Enterprise", n.Security)
	}
}

func TestParseBSSBlock_WPA1(t *testing.T) {
	// Pure WPA1/TKIP block — no RSN or WPA2 IE, only legacy WPA IE.
	block := `BSS aa:bb:cc:dd:ee:05(on wlan0)
	freq: 2437
	signal: -70.00 dBm
	SSID: LegacyNet
	WPA:	 * Version: 1
		 * Group cipher: TKIP
		 * Pairwise ciphers: TKIP
		 * Authentication suites: PSK`

	n := parseBSSBlock(block)

	if n.Security != "WPA" {
		t.Errorf("Security = %q, want WPA (not WPA2 — this is a legacy TKIP-only network)", n.Security)
	}
	if n.SSID != "LegacyNet" {
		t.Errorf("SSID = %q, want LegacyNet", n.SSID)
	}
}

func TestParseBSSBlock_WPA2NotMistakenForWPA1(t *testing.T) {
	// WPA2/RSN block must not regress to "WPA" after the regex split.
	block := `BSS aa:bb:cc:dd:ee:06(on wlan0)
	freq: 5180
	signal: -55.00 dBm
	SSID: ModernNet
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK`

	n := parseBSSBlock(block)

	if n.Security != "WPA2" {
		t.Errorf("Security = %q, want WPA2 (RSN block should not be downgraded to WPA)", n.Security)
	}
}

func TestParseBSSBlock_NoSSID(t *testing.T) {
	block := `BSS aa:bb:cc:dd:ee:03(on wlan0)
	freq: 2412
	signal: -70.00 dBm`

	n := parseBSSBlock(block)

	if n.SSID != "" {
		t.Errorf("SSID = %q, want empty", n.SSID)
	}
	if n.BSSID != "aa:bb:cc:dd:ee:03" {
		t.Errorf("BSSID = %q", n.BSSID)
	}
}

func TestParseBSSBlock_DefaultSignal(t *testing.T) {
	// Block with no signal line should use default -99.
	block := `BSS aa:bb:cc:dd:ee:04(on wlan0)
	SSID: NoSignal`

	n := parseBSSBlock(block)

	if n.Signal != -99 {
		t.Errorf("Signal = %d, want -99 (default)", n.Signal)
	}
}

func TestSplitBSSBlocks(t *testing.T) {
	output := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
	SSID: Net1
BSS 11:22:33:44:55:66(on wlan0)
	SSID: Net2`

	blocks := splitBSSBlocks(output)
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want 2", len(blocks))
	}
}

func TestSplitBSSBlocks_Empty(t *testing.T) {
	blocks := splitBSSBlocks("")
	// Empty input produces one block (the empty trailing content).
	if len(blocks) != 1 {
		t.Fatalf("got %d blocks, want 1 for empty input", len(blocks))
	}
}

func TestSplitBSSBlocks_SingleNetwork(t *testing.T) {
	output := `BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2437
	SSID: OnlyOne`

	blocks := splitBSSBlocks(output)
	if len(blocks) != 1 {
		t.Fatalf("got %d blocks, want 1", len(blocks))
	}
}

func TestSplitBSSBlocks_ThreeNetworks(t *testing.T) {
	output := `BSS aa:bb:cc:dd:ee:01(on wlan0)
	SSID: Net1
BSS aa:bb:cc:dd:ee:02(on wlan0)
	SSID: Net2
BSS aa:bb:cc:dd:ee:03(on wlan0)
	SSID: Net3`

	blocks := splitBSSBlocks(output)
	if len(blocks) != 3 {
		t.Fatalf("got %d blocks, want 3", len(blocks))
	}
}

func TestSplitBSSBlocks_LeadingText(t *testing.T) {
	// Some iw output may have leading text before the first BSS line.
	output := `scan started
BSS aa:bb:cc:dd:ee:ff(on wlan0)
	SSID: Net1`

	blocks := splitBSSBlocks(output)
	// "scan started\n" then "BSS...\n\tSSID..."
	if len(blocks) != 2 {
		t.Fatalf("got %d blocks, want 2 (leading text + BSS)", len(blocks))
	}
}

func TestParseSPNetwork(t *testing.T) {
	n := parseSPNetwork("Airport Wifi", "aa:bb:cc:dd:ee:ff", float64(6), "wpa2_personal", "-64 dBm / -96 dBm")

	if n.SSID != "Airport Wifi" {
		t.Errorf("SSID = %q", n.SSID)
	}
	if n.BSSID != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("BSSID = %q", n.BSSID)
	}
	if n.Channel != 6 {
		t.Errorf("Channel = %d, want 6", n.Channel)
	}
	if n.Security != "WPA2" {
		t.Errorf("Security = %q, want WPA2", n.Security)
	}
	if n.Signal != -64 {
		t.Errorf("Signal = %d, want -64", n.Signal)
	}
}

func TestParseSPNetwork_FloatSignal(t *testing.T) {
	n := parseSPNetwork("Net", "00:11:22:33:44:55", float64(11), "none", float64(-55))

	if n.Signal != -55 {
		t.Errorf("Signal = %d, want -55", n.Signal)
	}
	if n.Security != "Open" {
		t.Errorf("Security = %q, want Open", n.Security)
	}
}

func TestParseSPNetwork_StringChannel(t *testing.T) {
	n := parseSPNetwork("Net", "00:11:22:33:44:55", "36 (5GHz, 80MHz)", "wpa3_personal", "-50 dBm")

	if n.Channel != 36 {
		t.Errorf("Channel = %d, want 36", n.Channel)
	}
	if n.Security != "WPA3" {
		t.Errorf("Security = %q, want WPA3", n.Security)
	}
}

func TestParseSPNetwork_NilValues(t *testing.T) {
	// nil channel and signal => defaults.
	n := parseSPNetwork("Net", "00:11:22:33:44:55", nil, "", nil)

	if n.Channel != 0 {
		t.Errorf("Channel = %d, want 0", n.Channel)
	}
	if n.Signal != -99 {
		t.Errorf("Signal = %d, want -99 (default)", n.Signal)
	}
	if n.Security != "Open" {
		t.Errorf("Security = %q, want Open", n.Security)
	}
}

func TestParseSPNetwork_UnparseableChannel(t *testing.T) {
	n := parseSPNetwork("Net", "00:11:22:33:44:55", "abc", "wpa2_personal", "-70 dBm")

	if n.Channel != 0 {
		t.Errorf("Channel = %d, want 0 for unparseable", n.Channel)
	}
}

func TestScoreDevice(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		device  *AuthorizedDevice
		wantMin float64
		wantMax float64
	}{
		{
			name: "high activity, long presence, recent",
			device: &AuthorizedDevice{
				ARPCount:  15,
				FirstSeen: now.Add(-10 * time.Minute),
				LastSeen:  now,
			},
			wantMin: 0.9,
			wantMax: 1.0,
		},
		{
			name: "low activity, brief, recent",
			device: &AuthorizedDevice{
				ARPCount:  1,
				FirstSeen: now.Add(-10 * time.Second),
				LastSeen:  now,
			},
			wantMin: 0.3,
			wantMax: 0.7,
		},
		{
			name: "medium activity, medium presence, stale",
			device: &AuthorizedDevice{
				ARPCount:  5,
				FirstSeen: now.Add(-3 * time.Minute),
				LastSeen:  now.Add(-5 * time.Minute),
			},
			wantMin: 0.4,
			wantMax: 0.8,
		},
		{
			name: "very high ARP, very long, very stale",
			device: &AuthorizedDevice{
				ARPCount:  100,
				FirstSeen: now.Add(-1 * time.Hour),
				LastSeen:  now.Add(-10 * time.Minute),
			},
			wantMin: 0.7,
			wantMax: 1.0,
		},
		{
			name: "minimum everything",
			device: &AuthorizedDevice{
				ARPCount:  1,
				FirstSeen: now,
				LastSeen:  now.Add(-3 * time.Minute),
			},
			wantMin: 0.3,
			wantMax: 0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := scoreDevice(tt.device)
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("scoreDevice() = %f, want [%f, %f]", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestScoreDevice_Capped(t *testing.T) {
	// Score should never exceed 1.0.
	now := time.Now()
	d := &AuthorizedDevice{
		ARPCount:  1000,
		FirstSeen: now.Add(-24 * time.Hour),
		LastSeen:  now,
	}
	score := scoreDevice(d)
	if score > 1.0 {
		t.Errorf("scoreDevice() = %f, should be capped at 1.0", score)
	}
}

func TestScoreDevice_ARPThresholds(t *testing.T) {
	now := time.Now()
	base := AuthorizedDevice{
		FirstSeen: now.Add(-10 * time.Minute),
		LastSeen:  now,
	}

	// Test each ARP threshold bracket.
	for _, tc := range []struct {
		arp  int
		want float64 // expected ARP component
	}{
		{1, 0.1},
		{2, 0.2},
		{4, 0.2},
		{5, 0.3},
		{9, 0.3},
		{10, 0.4},
		{50, 0.4},
	} {
		d := base
		d.ARPCount = tc.arp
		score := scoreDevice(&d)
		// Duration >5min = +0.3, recent = +0.3 => total = arp + 0.6
		expected := tc.want + 0.6
		if expected > 1.0 {
			expected = 1.0
		}
		if score != expected {
			t.Errorf("ARPCount=%d: scoreDevice() = %f, want %f", tc.arp, score, expected)
		}
	}
}
