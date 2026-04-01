package discover

import (
	"testing"
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
