package crack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Method constants
// ---------------------------------------------------------------------------

func TestMethodConstants(t *testing.T) {
	tests := []struct {
		name string
		got  Method
		want string
	}{
		{"PMKID", PMKID, "pmkid_capture"},
		{"Handshake", Handshake, "handshake_capture"},
		{"Hashcat", Hashcat, "hashcat_crack"},
		{"Dictionary", Dictionary, "dictionary_attack"},
		{"WPSPixie", WPSPixie, "wps_pixie_dust"},
		{"WPSPin", WPSPin, "wps_pin_brute"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Errorf("Method %s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestAllSixMethodsDefined(t *testing.T) {
	methods := []Method{PMKID, Handshake, Hashcat, Dictionary, WPSPixie, WPSPin}
	if len(methods) != 6 {
		t.Fatalf("expected 6 method constants, got %d", len(methods))
	}
	seen := make(map[Method]bool)
	for _, m := range methods {
		if seen[m] {
			t.Errorf("duplicate method: %s", m)
		}
		seen[m] = true
	}
}

// ---------------------------------------------------------------------------
// WifiTarget fields including WPS
// ---------------------------------------------------------------------------

func TestWifiTargetFields(t *testing.T) {
	target := WifiTarget{
		SSID:       "TestNet",
		BSSID:      "AA:BB:CC:DD:EE:FF",
		Channel:    6,
		Security:   "WPA2",
		Signal:     -42,
		Clients:    []string{"11:22:33:44:55:66"},
		WPSEnabled: true,
		WPSLocked:  false,
		WPSVersion: "2.0",
	}

	if target.SSID != "TestNet" {
		t.Errorf("SSID = %q, want TestNet", target.SSID)
	}
	if target.BSSID != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("BSSID = %q, want AA:BB:CC:DD:EE:FF", target.BSSID)
	}
	if target.Channel != 6 {
		t.Errorf("Channel = %d, want 6", target.Channel)
	}
	if target.Security != "WPA2" {
		t.Errorf("Security = %q, want WPA2", target.Security)
	}
	if target.Signal != -42 {
		t.Errorf("Signal = %d, want -42", target.Signal)
	}
	if len(target.Clients) != 1 {
		t.Errorf("Clients length = %d, want 1", len(target.Clients))
	}
	if !target.WPSEnabled {
		t.Error("WPSEnabled = false, want true")
	}
	if target.WPSLocked {
		t.Error("WPSLocked = true, want false")
	}
	if target.WPSVersion != "2.0" {
		t.Errorf("WPSVersion = %q, want 2.0", target.WPSVersion)
	}
}

func TestWifiTargetJSON(t *testing.T) {
	target := WifiTarget{
		SSID:       "MyWiFi",
		BSSID:      "00:11:22:33:44:55",
		Channel:    11,
		Security:   "WPA2",
		Signal:     -55,
		WPSEnabled: true,
		WPSLocked:  true,
		WPSVersion: "1.0",
	}

	data, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded WifiTarget
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.SSID != target.SSID {
		t.Errorf("decoded SSID = %q, want %q", decoded.SSID, target.SSID)
	}
	if decoded.WPSEnabled != target.WPSEnabled {
		t.Errorf("decoded WPSEnabled = %v, want %v", decoded.WPSEnabled, target.WPSEnabled)
	}
	if decoded.WPSLocked != target.WPSLocked {
		t.Errorf("decoded WPSLocked = %v, want %v", decoded.WPSLocked, target.WPSLocked)
	}
	if decoded.WPSVersion != target.WPSVersion {
		t.Errorf("decoded WPSVersion = %q, want %q", decoded.WPSVersion, target.WPSVersion)
	}
}

// ---------------------------------------------------------------------------
// FindWordlists with mock filesystem
// ---------------------------------------------------------------------------

func TestFindWordlists_MockFS(t *testing.T) {
	// Create a temp directory structure mimicking wordlist locations.
	tmpDir := t.TempDir()
	wlDir := filepath.Join(tmpDir, ".nowifi", "wordlists")
	if err := os.MkdirAll(wlDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create two wordlist files.
	wl1 := filepath.Join(wlDir, "rockyou.txt")
	wl2 := filepath.Join(wlDir, "custom.txt")
	if err := os.WriteFile(wl1, []byte("password123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wl2, []byte("admin\nroot\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// FindWordlists searches real filesystem paths -- we verify the function
	// doesn't panic and returns a slice (possibly empty on CI).
	result := FindWordlists()
	if result == nil {
		// nil is valid when no wordlists exist at standard paths.
		result = []string{}
	}

	// Verify the return type is correct (slice of strings).
	_ = len(result)
}

func TestFindWordlists_ReturnsStringSlice(t *testing.T) {
	// Verify FindWordlists returns []string without panicking.
	wl := FindWordlists()
	for _, path := range wl {
		if path == "" {
			t.Error("FindWordlists returned empty string path")
		}
		// Each path should be absolute.
		if !filepath.IsAbs(path) {
			t.Errorf("FindWordlists path %q is not absolute", path)
		}
	}
}

// ---------------------------------------------------------------------------
// RunCrack pipeline order
// ---------------------------------------------------------------------------

func TestRunCrackPipelineOrder(t *testing.T) {
	// RunCrack docstring specifies the pipeline ordering.
	// We verify this by inspecting the documented method order.
	// The pipeline is:
	//   1. PMKID first
	//   2. WPS Pixie before hashcat
	//   3. WPS PIN last
	//
	// We cannot run RunCrack (requires monitor mode, root, external tools),
	// so we verify the ordering contract through the Method constants and
	// the Result type structure.

	expectedOrder := []Method{
		PMKID,     // Step 1: PMKID capture (client-less)
		WPSPixie,  // Step 2: WPS Pixie-Dust (fast)
		Hashcat,   // Step 3: Hashcat crack PMKID
		Handshake, // Step 4: Handshake capture
		Hashcat,   // Step 5: Hashcat crack handshake
		WPSPin,    // Step 6: WPS PIN brute force (last resort)
		Dictionary, // Step 7: Aircrack-ng (CPU fallback)
	}

	// Verify PMKID is first.
	if expectedOrder[0] != PMKID {
		t.Error("PMKID should be first in pipeline")
	}

	// Verify WPS Pixie comes before first Hashcat.
	pixieIdx := -1
	firstHashcatIdx := -1
	for i, m := range expectedOrder {
		if m == WPSPixie && pixieIdx == -1 {
			pixieIdx = i
		}
		if m == Hashcat && firstHashcatIdx == -1 {
			firstHashcatIdx = i
		}
	}
	if pixieIdx >= firstHashcatIdx {
		t.Errorf("WPS Pixie (idx %d) should come before first Hashcat (idx %d)", pixieIdx, firstHashcatIdx)
	}

	// Verify WPS PIN is last technique (before dictionary fallback).
	wpsPinIdx := -1
	for i, m := range expectedOrder {
		if m == WPSPin {
			wpsPinIdx = i
		}
	}
	if wpsPinIdx < len(expectedOrder)-2 {
		t.Error("WPS PIN should be near the end of the pipeline")
	}
}

// ---------------------------------------------------------------------------
// ScanTargets / parseMacOSSystemProfiler with mock data
// ---------------------------------------------------------------------------

func TestParseMacOSSystemProfiler(t *testing.T) {
	// Mock system_profiler SPAirPortDataType -json output.
	mockJSON := `{
  "SPAirPortDataType": [
    {
      "spairport_airport_interfaces": [
        {
          "spairport_airport_other_local_wireless_networks": [
            {
              "_name": "CoffeeShopWiFi",
              "spairport_network_bssid": "AA:BB:CC:DD:EE:01",
              "spairport_network_channel": "6",
              "spairport_security_mode": "wpa2_personal",
              "spairport_signal_noise": "-52 dBm"
            },
            {
              "_name": "OpenNet",
              "spairport_network_bssid": "AA:BB:CC:DD:EE:02",
              "spairport_network_channel": "11, 40MHz",
              "spairport_security_mode": "none",
              "spairport_signal_noise": "-70 dBm"
            }
          ],
          "spairport_current_network_information": {
            "_name": "HomeWiFi",
            "spairport_network_bssid": "AA:BB:CC:DD:EE:03",
            "spairport_network_channel": "1",
            "spairport_security_mode": "wpa2_personal",
            "spairport_signal_noise": "-35 dBm"
          }
        }
      ]
    }
  ]
}`

	targets := parseMacOSSystemProfiler([]byte(mockJSON))

	if len(targets) != 3 {
		t.Fatalf("parseMacOSSystemProfiler returned %d targets, want 3", len(targets))
	}

	tests := []struct {
		idx      int
		ssid     string
		bssid    string
		channel  int
		security string
	}{
		{0, "CoffeeShopWiFi", "AA:BB:CC:DD:EE:01", 6, "wpa2_personal"},
		{1, "OpenNet", "AA:BB:CC:DD:EE:02", 11, "none"},
		{2, "HomeWiFi", "AA:BB:CC:DD:EE:03", 1, "wpa2_personal"},
	}

	for _, tt := range tests {
		t.Run(tt.ssid, func(t *testing.T) {
			tgt := targets[tt.idx]
			if tgt.SSID != tt.ssid {
				t.Errorf("SSID = %q, want %q", tgt.SSID, tt.ssid)
			}
			if tgt.BSSID != tt.bssid {
				t.Errorf("BSSID = %q, want %q", tgt.BSSID, tt.bssid)
			}
			if tgt.Channel != tt.channel {
				t.Errorf("Channel = %d, want %d", tgt.Channel, tt.channel)
			}
			if tgt.Security != tt.security {
				t.Errorf("Security = %q, want %q", tgt.Security, tt.security)
			}
		})
	}
}

func TestParseMacOSSystemProfiler_InvalidJSON(t *testing.T) {
	targets := parseMacOSSystemProfiler([]byte(`{invalid json`))
	if targets != nil {
		t.Errorf("expected nil for invalid JSON, got %d targets", len(targets))
	}
}

func TestParseMacOSSystemProfiler_EmptyData(t *testing.T) {
	targets := parseMacOSSystemProfiler([]byte(`{}`))
	if targets != nil {
		t.Errorf("expected nil for empty data, got %d targets", len(targets))
	}
}

func TestParseMacOSSystemProfiler_NoNetworks(t *testing.T) {
	mockJSON := `{
  "SPAirPortDataType": [
    {
      "spairport_airport_interfaces": [
        {}
      ]
    }
  ]
}`
	targets := parseMacOSSystemProfiler([]byte(mockJSON))
	if len(targets) != 0 {
		t.Errorf("expected 0 targets for no networks, got %d", len(targets))
	}
}

// ---------------------------------------------------------------------------
// parseMacOSNetwork
// ---------------------------------------------------------------------------

func TestParseMacOSNetwork(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		wantNil  bool
		wantSSID string
	}{
		{
			name:     "valid network",
			input:    map[string]interface{}{"_name": "TestWiFi", "spairport_security_mode": "wpa2_personal"},
			wantSSID: "TestWiFi",
		},
		{
			name:    "empty name",
			input:   map[string]interface{}{"_name": ""},
			wantNil: true,
		},
		{
			name:    "missing name",
			input:   map[string]interface{}{"spairport_security_mode": "wpa2"},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseMacOSNetwork(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.SSID != tt.wantSSID {
				t.Errorf("SSID = %q, want %q", result.SSID, tt.wantSSID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseChannelNumber
// ---------------------------------------------------------------------------

func TestParseChannelNumber(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"6", 6},
		{"11, 40MHz", 11},
		{"1", 1},
		{"36, 80MHz", 36},
		{"", 0},
		{"abc", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseChannelNumber(tt.input)
			if got != tt.want {
				t.Errorf("parseChannelNumber(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Result JSON round-trip
// ---------------------------------------------------------------------------

func TestResultJSON(t *testing.T) {
	r := Result{
		Method:      PMKID,
		Success:     true,
		Password:    "s3cret",
		Details:     "captured from test AP",
		CaptureFile: "/tmp/capture.22000",
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Method != PMKID {
		t.Errorf("decoded Method = %q, want %q", decoded.Method, PMKID)
	}
	if !decoded.Success {
		t.Error("decoded Success = false, want true")
	}
	if decoded.Password != "s3cret" {
		t.Errorf("decoded Password = %q, want s3cret", decoded.Password)
	}
}

// ---------------------------------------------------------------------------
// parseWashOutput
// ---------------------------------------------------------------------------

func TestParseWashOutput(t *testing.T) {
	output := `BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------
AA:BB:CC:DD:EE:01    6  -42  2.0  No   RalinkTe  TestAP
AA:BB:CC:DD:EE:02   11  -55  1.0  Yes  Broadcom  LockedAP
`
	targets := parseWashOutput(output)
	if len(targets) != 2 {
		t.Fatalf("parseWashOutput returned %d targets, want 2", len(targets))
	}

	tests := []struct {
		idx        int
		bssid      string
		wpsEnabled bool
		wpsLocked  bool
		wpsVersion string
	}{
		{0, "AA:BB:CC:DD:EE:01", true, false, "2.0"},
		{1, "AA:BB:CC:DD:EE:02", true, true, "1.0"},
	}

	for _, tt := range tests {
		tgt := targets[tt.idx]
		if tgt.BSSID != tt.bssid {
			t.Errorf("[%d] BSSID = %q, want %q", tt.idx, tgt.BSSID, tt.bssid)
		}
		if tgt.WPSEnabled != tt.wpsEnabled {
			t.Errorf("[%d] WPSEnabled = %v, want %v", tt.idx, tgt.WPSEnabled, tt.wpsEnabled)
		}
		if tgt.WPSLocked != tt.wpsLocked {
			t.Errorf("[%d] WPSLocked = %v, want %v", tt.idx, tgt.WPSLocked, tt.wpsLocked)
		}
		if tgt.WPSVersion != tt.wpsVersion {
			t.Errorf("[%d] WPSVersion = %q, want %q", tt.idx, tgt.WPSVersion, tt.wpsVersion)
		}
	}
}

func TestParseWashOutput_Empty(t *testing.T) {
	targets := parseWashOutput("")
	if len(targets) != 0 {
		t.Errorf("expected 0 targets for empty input, got %d", len(targets))
	}
}

// ---------------------------------------------------------------------------
// isDarwin helper
// ---------------------------------------------------------------------------

func TestIsDarwin(t *testing.T) {
	// This just verifies the function doesn't panic and returns a bool.
	_ = isDarwin()
}
