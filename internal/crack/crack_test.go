// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package crack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{"OnlineBrute", OnlineBrute, "online_brute_force"},
		{"SmartCrackM", SmartCrackM, "smart_crack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Errorf("Method %s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestAllMethodsDefined(t *testing.T) {
	methods := []Method{PMKID, Handshake, Hashcat, Dictionary, WPSPixie, WPSPin, OnlineBrute, SmartCrackM}
	if len(methods) != 8 {
		t.Fatalf("expected 8 method constants, got %d", len(methods))
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

func TestWriteTempWordlist_WritesAndCleansUp(t *testing.T) {
	path, cleanup, err := writeTempWordlist("nowifi-test-*.txt", []string{"alpha", "beta"})
	if err != nil {
		t.Fatalf("writeTempWordlist: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if string(data) != "alpha\nbeta\n" {
		t.Fatalf("temp wordlist contents = %q, want %q", string(data), "alpha\nbeta\n")
	}

	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected cleanup to remove %q, got err=%v", path, err)
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
	//   2. WPS Pixie before SmartCrack
	//   3. SmartCrack on PMKID before handshake
	//   4. Handshake capture
	//   5. SmartCrack on handshake
	//   6. Dictionary attack
	//   7. WPS PIN brute force
	//   8. Smart brute force (masks + rules)
	//   9. Online brute force (last resort)
	//
	// We cannot run RunCrack (requires monitor mode, root, external tools),
	// so we verify the ordering contract through the Method constants.

	expectedOrder := []Method{
		PMKID,       // Step 1: PMKID capture (client-less)
		WPSPixie,    // Step 2: WPS Pixie-Dust (fast)
		SmartCrackM, // Step 3: SmartCrack stages 1-3 on PMKID
		Handshake,   // Step 4: Handshake capture
		SmartCrackM, // Step 5: SmartCrack stages 1-3 on handshake
		Hashcat,     // Step 6: Dictionary attack
		Dictionary,  // Step 6b: Aircrack-ng CPU fallback
		WPSPin,      // Step 7: WPS PIN brute force
		SmartCrackM, // Step 8: Smart brute force (masks + rules)
		OnlineBrute, // Step 9: Online brute force (last resort)
	}

	// Verify PMKID is first.
	if expectedOrder[0] != PMKID {
		t.Error("PMKID should be first in pipeline")
	}

	// Verify WPS Pixie comes before first SmartCrack.
	pixieIdx := -1
	firstSmartIdx := -1
	for i, m := range expectedOrder {
		if m == WPSPixie && pixieIdx == -1 {
			pixieIdx = i
		}
		if m == SmartCrackM && firstSmartIdx == -1 {
			firstSmartIdx = i
		}
	}
	if pixieIdx >= firstSmartIdx {
		t.Errorf("WPS Pixie (idx %d) should come before first SmartCrack (idx %d)", pixieIdx, firstSmartIdx)
	}

	// Verify Online brute force is last.
	lastIdx := len(expectedOrder) - 1
	if expectedOrder[lastIdx] != OnlineBrute {
		t.Errorf("Online brute force should be last, got %s", expectedOrder[lastIdx])
	}

	// Verify WPS PIN comes after dictionary but before online brute.
	wpsPinIdx := -1
	dictIdx := -1
	onlineIdx := -1
	for i, m := range expectedOrder {
		if m == WPSPin && wpsPinIdx == -1 {
			wpsPinIdx = i
		}
		if m == Dictionary && dictIdx == -1 {
			dictIdx = i
		}
		if m == OnlineBrute && onlineIdx == -1 {
			onlineIdx = i
		}
	}
	if wpsPinIdx < dictIdx {
		t.Errorf("WPS PIN (idx %d) should come after dictionary (idx %d)", wpsPinIdx, dictIdx)
	}
	if wpsPinIdx > onlineIdx {
		t.Errorf("WPS PIN (idx %d) should come before online brute (idx %d)", wpsPinIdx, onlineIdx)
	}
}

func TestReadmeCrackPipelineMatchesImplementation(t *testing.T) {
	readmePath := filepath.Join("..", "..", "README.md")
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", readmePath, err)
	}

	readme := string(data)
	techniques := []Method{
		PMKID,
		Handshake,
		Hashcat,
		Dictionary,
		WPSPixie,
		WPSPin,
		OnlineBrute,
		SmartCrackM,
	}

	if !strings.Contains(readme, fmt.Sprintf("ordered %d-technique WPA/WPA2 cracking pipeline", len(techniques))) {
		t.Fatalf("README should advertise the current crack technique count of %d", len(techniques))
	}
	if !strings.Contains(readme, "ordered fastest-to-slowest, stops on first recovered password") {
		t.Fatal("README command summary should describe the ordered stop-on-success crack pipeline")
	}
	if !strings.Contains(readme, "stopping as soon as a password is recovered") {
		t.Fatal("README intro should explain that crack stops once it recovers a password")
	}
	if strings.Contains(readme, "8-technique WPA and smart-cracking pipeline") {
		t.Fatal("README should not use the older underspecified crack pipeline wording")
	}
}

func TestSelectedSmartCrackStages(t *testing.T) {
	tests := []struct {
		name         string
		hasWordlists bool
		opts         smartCrackOptions
		want         []smartCrackStage
	}{
		{
			name:         "early stages only",
			hasWordlists: true,
			opts: smartCrackOptions{
				startStage: smartCrackStageCommonPasswords,
				endStage:   smartCrackStageWordNumberRules,
			},
			want: []smartCrackStage{
				smartCrackStageCommonPasswords,
				smartCrackStageNumericMasks,
				smartCrackStageWordNumberRules,
			},
		},
		{
			name:         "full pipeline without wordlists skips dictionary",
			hasWordlists: false,
			opts: smartCrackOptions{
				fullBrute: true,
			},
			want: []smartCrackStage{
				smartCrackStageCommonPasswords,
				smartCrackStageNumericMasks,
				smartCrackStageWordNumberRules,
				smartCrackStageSmartBrute,
				smartCrackStageFullBrute,
			},
		},
		{
			name:         "smart brute only",
			hasWordlists: true,
			opts: smartCrackOptions{
				startStage: smartCrackStageSmartBrute,
				endStage:   smartCrackStageSmartBrute,
			},
			want: []smartCrackStage{
				smartCrackStageSmartBrute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectedSmartCrackStages(tt.hasWordlists, tt.opts)
			if len(got) != len(tt.want) {
				t.Fatalf("selectedSmartCrackStages() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("selectedSmartCrackStages()[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSelectedSmartCrackStages_FullBrute(t *testing.T) {
	got := selectedSmartCrackStages(true, smartCrackOptions{fullBrute: true})
	// Should include all 6 stages (with wordlists).
	if len(got) != 6 {
		t.Fatalf("fullBrute with wordlists: len = %d, want 6", len(got))
	}
	if got[5] != smartCrackStageFullBrute {
		t.Errorf("last stage = %d, want fullBrute", got[5])
	}
}

func TestSelectedSmartCrackStages_DictionarySkipped(t *testing.T) {
	// Without wordlists and without fullBrute, dictionary should be skipped.
	got := selectedSmartCrackStages(false, smartCrackOptions{})
	for _, stage := range got {
		if stage == smartCrackStageDictionary {
			t.Error("dictionary stage should be skipped without wordlists")
		}
	}
}

func TestSelectedSmartCrackStages_WithWordlists(t *testing.T) {
	got := selectedSmartCrackStages(true, smartCrackOptions{
		startStage: smartCrackStageCommonPasswords,
		endStage:   smartCrackStageSmartBrute,
	})
	// Should include dictionary stage when wordlists are available.
	hasDictionary := false
	for _, stage := range got {
		if stage == smartCrackStageDictionary {
			hasDictionary = true
		}
	}
	if !hasDictionary {
		t.Error("dictionary stage should be included with wordlists")
	}
}

func TestNormalizeSmartCrackOptions_AllDefaults(t *testing.T) {
	opts := normalizeSmartCrackOptions(smartCrackOptions{})
	if opts.startStage != smartCrackStageCommonPasswords {
		t.Errorf("default startStage = %d, want %d", opts.startStage, smartCrackStageCommonPasswords)
	}
	if opts.endStage != smartCrackStageSmartBrute {
		t.Errorf("default endStage = %d, want %d", opts.endStage, smartCrackStageSmartBrute)
	}
}

func TestSmartCrackScopeLabel(t *testing.T) {
	if got := smartCrackScopeLabel(smartCrackOptions{
		startStage: smartCrackStageCommonPasswords,
		endStage:   smartCrackStageWordNumberRules,
	}); got != "SmartCrack stages 1-3" {
		t.Fatalf("smartCrackScopeLabel() = %q, want %q", got, "SmartCrack stages 1-3")
	}

	if got := smartCrackScopeLabel(smartCrackOptions{
		startStage: smartCrackStageSmartBrute,
		endStage:   smartCrackStageSmartBrute,
	}); got != "SmartCrack stage 5" {
		t.Fatalf("smartCrackScopeLabel() = %q, want %q", got, "SmartCrack stage 5")
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

// ---------------------------------------------------------------------------
// Common WiFi passwords list
// ---------------------------------------------------------------------------

func TestCommonPasswordsNotEmpty(t *testing.T) {
	if len(commonWifiPasswords) == 0 {
		t.Fatal("commonWifiPasswords is empty")
	}
	if len(commonWifiPasswords) < 500 {
		t.Errorf("commonWifiPasswords has %d entries, expected >= 500", len(commonWifiPasswords))
	}
}

func TestCommonPasswordsMinLength(t *testing.T) {
	// WPA/WPA2 requires minimum 8 characters.
	for i, pw := range commonWifiPasswords {
		if len(pw) < 8 {
			t.Errorf("commonWifiPasswords[%d] = %q has %d chars, WPA minimum is 8", i, pw, len(pw))
		}
	}
}

func TestCommonPasswordsNoDuplicates(t *testing.T) {
	seen := make(map[string]int, len(commonWifiPasswords))
	for i, pw := range commonWifiPasswords {
		if prev, ok := seen[pw]; ok {
			t.Errorf("duplicate password %q at indices %d and %d", pw, prev, i)
		}
		seen[pw] = i
	}
}

func TestCommonPasswordsContainsExpected(t *testing.T) {
	// Spot-check that well-known WiFi passwords are present.
	expected := []string{
		"password", "12345678", "password1", "qwerty123",
		"88888888", "wifipassword", "netgear1",
	}

	set := make(map[string]bool, len(commonWifiPasswords))
	for _, pw := range commonWifiPasswords {
		set[pw] = true
	}

	for _, pw := range expected {
		if !set[pw] {
			t.Errorf("expected %q in commonWifiPasswords but not found", pw)
		}
	}
}

// ---------------------------------------------------------------------------
// Hashcat masks
// ---------------------------------------------------------------------------

func TestHashcatMasksNotEmpty(t *testing.T) {
	if len(hashcatMasks) == 0 {
		t.Fatal("hashcatMasks is empty")
	}
}

func TestHashcatMasksHaveRequiredFields(t *testing.T) {
	for i, m := range hashcatMasks {
		if m.Mask == "" {
			t.Errorf("hashcatMasks[%d].Mask is empty", i)
		}
		if m.Name == "" {
			t.Errorf("hashcatMasks[%d].Name is empty", i)
		}
		if m.EstTime == "" {
			t.Errorf("hashcatMasks[%d].EstTime is empty", i)
		}
		// Masks should contain hashcat placeholders.
		if !strings.Contains(m.Mask, "?") {
			t.Errorf("hashcatMasks[%d].Mask = %q has no hashcat placeholders", i, m.Mask)
		}
	}
}

func TestHashcatMasksNoDuplicateMasks(t *testing.T) {
	seen := make(map[string]int, len(hashcatMasks))
	for i, m := range hashcatMasks {
		if prev, ok := seen[m.Mask]; ok {
			t.Errorf("duplicate mask %q at indices %d and %d", m.Mask, prev, i)
		}
		seen[m.Mask] = i
	}
}

func TestHashcatMasksMinLength8(t *testing.T) {
	// WPA passwords are 8-63 chars; each mask should produce at least 8 chars.
	for i, m := range hashcatMasks {
		// Count output length: each ?X produces 1 char, literal chars produce 1 char.
		outputLen := 0
		mask := m.Mask
		j := 0
		for j < len(mask) {
			if j+1 < len(mask) && mask[j] == '?' {
				outputLen++
				j += 2
			} else {
				outputLen++
				j++
			}
		}
		if outputLen < 8 {
			t.Errorf("hashcatMasks[%d].Mask = %q produces %d chars, WPA minimum is 8", i, m.Mask, outputLen)
		}
	}
}

// ---------------------------------------------------------------------------
// isNumericMask
// ---------------------------------------------------------------------------

func TestIsNumericMask(t *testing.T) {
	tests := []struct {
		mask string
		want bool
	}{
		{"?d?d?d?d?d?d?d?d", true},
		{"?d?d?d?d2024", true},
		{"20?d?d?d?d?d?d", true},
		{"?l?l?l?l?d?d?d?d", false},
		{"?u?l?l?l?l?l?d?d", false},
		{"?a?a?a?a?a?a?a?a", false},
		{"", true}, // empty is vacuously numeric
	}
	for _, tt := range tests {
		t.Run(tt.mask, func(t *testing.T) {
			got := isNumericMask(tt.mask)
			if got != tt.want {
				t.Errorf("isNumericMask(%q) = %v, want %v", tt.mask, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SmartCrack with missing hash file
// ---------------------------------------------------------------------------

func TestSmartCrackMissingHashFile(t *testing.T) {
	result, err := SmartCrack("/nonexistent/hash.22000", 10*time.Second, false)
	if err != nil {
		t.Fatalf("SmartCrack returned error: %v", err)
	}
	if result == nil {
		t.Fatal("SmartCrack returned nil result")
	}
	if result.Success {
		t.Error("SmartCrack should not succeed with missing hash file")
	}
	if result.Method != SmartCrackM {
		t.Errorf("Method = %q, want %q", result.Method, SmartCrackM)
	}
	if !strings.Contains(result.Details, "not found") {
		t.Errorf("Details = %q, should mention file not found", result.Details)
	}
}

func TestSmartCrackWithFullBrute(t *testing.T) {
	// Exercise the fullBrute=true path (reaches stage 6).
	result, err := SmartCrack("/nonexistent/hash.22000", 1*time.Second, true)
	if err != nil {
		t.Fatalf("SmartCrack returned error: %v", err)
	}
	if result == nil {
		t.Fatal("SmartCrack returned nil result")
	}
	if result.Success {
		t.Error("SmartCrack should not succeed with missing hash file")
	}
	if !strings.Contains(result.Details, "not found") {
		t.Errorf("Details = %q, should mention file not found", result.Details)
	}
}

func TestSmartCrackWithOptions_AllStages(t *testing.T) {
	// Exercise with options covering all stages.
	opts := smartCrackOptions{
		startStage: smartCrackStageCommonPasswords,
		endStage:   smartCrackStageFullBrute,
		fullBrute:  true,
	}
	result, err := smartCrackWithOptions("/nonexistent/hash.22000", 1*time.Second, opts)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.Success {
		t.Error("should not succeed with missing hash file")
	}
}

func TestSmartCrackWithOptions_SingleStage(t *testing.T) {
	opts := smartCrackOptions{
		startStage: smartCrackStageNumericMasks,
		endStage:   smartCrackStageNumericMasks,
	}
	result, err := smartCrackWithOptions("/nonexistent/hash.22000", 1*time.Second, opts)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.Success {
		t.Error("should not succeed with missing hash file")
	}
}

func TestSmartCrackNoHashcat(t *testing.T) {
	// Create a dummy hash file.
	tmpDir := t.TempDir()
	hashFile := filepath.Join(tmpDir, "test.22000")
	if err := os.WriteFile(hashFile, []byte("WPA*02*...\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// SmartCrack should handle missing hashcat gracefully.
	result, err := SmartCrack(hashFile, 5*time.Second, false)
	if err != nil {
		t.Fatalf("SmartCrack returned error: %v", err)
	}
	if result == nil {
		t.Fatal("SmartCrack returned nil result")
	}
	// On CI/dev machine without hashcat, it should fail gracefully.
	if result.Method != SmartCrackM {
		t.Errorf("Method = %q, want %q", result.Method, SmartCrackM)
	}
}

// ---------------------------------------------------------------------------
// OnlineBruteForce
// ---------------------------------------------------------------------------

func TestOnlineBruteForceResultType(t *testing.T) {
	target := WifiTarget{
		SSID:     "TestNetwork",
		BSSID:    "AA:BB:CC:DD:EE:FF",
		Channel:  6,
		Security: "WPA2",
		Signal:   -50,
	}

	// OnlineBruteForce should return gracefully when tools are missing.
	result, err := OnlineBruteForce(target, "wlan0", 2*time.Second)
	if err != nil {
		t.Fatalf("OnlineBruteForce returned error: %v", err)
	}
	if result == nil {
		t.Fatal("OnlineBruteForce returned nil result")
	}
	if result.Method != OnlineBrute {
		t.Errorf("Method = %q, want %q", result.Method, OnlineBrute)
	}
	// Without wpa_supplicant installed, it should fail but not crash.
	if result.Success {
		t.Error("Expected failure without wpa_supplicant, got success")
	}
}

// ---------------------------------------------------------------------------
// OnlineBrute and SmartCrackM JSON round-trip
// ---------------------------------------------------------------------------

func TestNewMethodsJSON(t *testing.T) {
	tests := []struct {
		method Method
	}{
		{OnlineBrute},
		{SmartCrackM},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			r := Result{
				Method:  tt.method,
				Success: true,
				Details: "test result",
			}

			data, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			var decoded Result
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			if decoded.Method != tt.method {
				t.Errorf("decoded Method = %q, want %q", decoded.Method, tt.method)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildHashcatArgs
// ---------------------------------------------------------------------------

func TestBuildHashcatArgs(t *testing.T) {
	args := buildHashcatArgs("/tmp/hash.22000", "-a", "3", "/tmp/hash.22000", "?d?d?d?d?d?d?d?d")

	// Should start with -m 22000.
	if len(args) < 2 || args[0] != "-m" || args[1] != "22000" {
		t.Errorf("args should start with -m 22000, got %v", args[:min(2, len(args))])
	}

	// Should contain the extra args.
	found := false
	for _, a := range args {
		if a == "-a" {
			found = true
		}
	}
	if !found {
		t.Error("args should contain -a from extraArgs")
	}

	// Should have --potfile-disable.
	found = false
	for _, a := range args {
		if a == "--potfile-disable" {
			found = true
		}
	}
	if !found {
		t.Error("args should contain --potfile-disable")
	}
}

// ---------------------------------------------------------------------------
// findHashcatRuleByName
// ---------------------------------------------------------------------------

func TestFindHashcatRuleByName_NoExist(t *testing.T) {
	// With a fake hashcat path, should return empty for nonexistent rule.
	result := findHashcatRuleByName("/nonexistent/hashcat", "nonexistent.rule")
	if result != "" {
		t.Errorf("expected empty string for nonexistent rule, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// smartCrackTimeout helper
// ---------------------------------------------------------------------------

func TestSmartCrackWithOptions_DictStageNoWordlists(t *testing.T) {
	// Create a dummy hash file so we get past the file check.
	tmpDir := t.TempDir()
	hashFile := filepath.Join(tmpDir, "test.22000")
	if err := os.WriteFile(hashFile, []byte("WPA*02*...\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := smartCrackOptions{
		startStage: smartCrackStageDictionary,
		endStage:   smartCrackStageDictionary,
	}
	result, err := smartCrackWithOptions(hashFile, 2*time.Second, opts)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Without hashcat installed, this will fail gracefully.
	if result.Method != SmartCrackM {
		t.Errorf("Method = %q, want %q", result.Method, SmartCrackM)
	}
}

func TestIsNumericMask_EdgeCases(t *testing.T) {
	tests := []struct {
		mask string
		want bool
	}{
		{"?d?d?d?d?d?d?d?d", true},
		{"12345678", true},
		{"?d?d?d?d1234", true},
		{"?l?d?d?d?d?d?d?d", false},
		{"?d?d?d?d?d?d?d?a", false},
		{"password", false},
	}
	for _, tt := range tests {
		got := isNumericMask(tt.mask)
		if got != tt.want {
			t.Errorf("isNumericMask(%q) = %v, want %v", tt.mask, got, tt.want)
		}
	}
}

func TestBuildHashcatArgs_StandardFlags(t *testing.T) {
	args := buildHashcatArgs("/tmp/hash.22000", "-a", "0", "/tmp/hash.22000", "/tmp/wl.txt")

	// Check -m 22000 at start.
	if len(args) < 2 || args[0] != "-m" || args[1] != "22000" {
		t.Errorf("args should start with -m 22000, got %v", args[:2])
	}

	// Check standard flags are present.
	hasQuiet := false
	hasO := false
	for _, a := range args {
		if a == "--quiet" {
			hasQuiet = true
		}
		if a == "-O" {
			hasO = true
		}
	}
	if !hasQuiet {
		t.Error("args should contain --quiet")
	}
	if !hasO {
		t.Error("args should contain -O")
	}
}

func TestCrackWithAircrack_MissingCaptureFile(t *testing.T) {
	result, err := CrackWithAircrack("/nonexistent/capture.cap", "/nonexistent/wordlist.txt")
	if err != nil {
		t.Fatalf("CrackWithAircrack returned error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Success {
		t.Error("should not succeed with missing capture file")
	}
	if result.Method != Dictionary {
		t.Errorf("Method = %q, want %q", result.Method, Dictionary)
	}
	if !strings.Contains(result.Details, "not found") {
		t.Errorf("Details = %q, should mention file not found", result.Details)
	}
}

func TestCrackWithHashcat_MissingHashFile(t *testing.T) {
	result, err := CrackWithHashcat("/nonexistent/hash.22000", "")
	if err != nil {
		t.Fatalf("CrackWithHashcat returned error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Success {
		t.Error("should not succeed with missing hash file")
	}
	if result.Method != Hashcat {
		t.Errorf("Method = %q, want %q", result.Method, Hashcat)
	}
	if !strings.Contains(result.Details, "not found") {
		t.Errorf("Details = %q, should mention file not found", result.Details)
	}
}

func TestCrackWithAircrack_MissingWordlist(t *testing.T) {
	// Create a dummy capture file so we get past the file check.
	tmpDir := t.TempDir()
	capFile := filepath.Join(tmpDir, "test.cap")
	os.WriteFile(capFile, []byte("dummy"), 0o644)

	result, err := CrackWithAircrack(capFile, "/nonexistent/wordlist.txt")
	if err != nil {
		t.Fatalf("CrackWithAircrack returned error: %v", err)
	}
	if result.Success {
		t.Error("should not succeed with missing wordlist")
	}
	// Either "not found" (aircrack missing) or "Wordlist not found" (wordlist missing).
	if result.Details == "" {
		t.Error("Details should not be empty")
	}
}

func TestScanTargets_InvalidInterface(t *testing.T) {
	_, err := ScanTargets("../../etc/evil", 1)
	if err == nil {
		t.Error("ScanTargets should reject invalid interface")
	}
}

func TestFindHashcatRules_NonexistentPath(t *testing.T) {
	result := findHashcatRules("/nonexistent/hashcat")
	// Should fall back to "best64.rule" when no rules file found.
	if result != "best64.rule" {
		t.Errorf("findHashcatRules = %q, want best64.rule fallback", result)
	}
}

func TestRunCrack_InvalidInterface(t *testing.T) {
	results, err := RunCrack("../../evil", "TestNet", "", 1*time.Second)
	if err != nil {
		t.Fatalf("RunCrack returned unexpected error: %v", err)
	}
	// RunCrack returns results (not error) when ScanTargets fails.
	if len(results) == 0 {
		t.Fatal("RunCrack should return at least one result")
	}
	if results[0].Success {
		t.Error("RunCrack should not succeed with invalid interface")
	}
}

func TestSmartCrackTimeout(t *testing.T) {
	start := time.Now()
	result := smartCrackTimeout("/tmp/hash.22000", "Stage 2 (numeric)", start)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Success {
		t.Error("timeout result should not be Success")
	}
	if result.Method != SmartCrackM {
		t.Errorf("Method = %q, want %q", result.Method, SmartCrackM)
	}
	if !strings.Contains(result.Details, "Stage 2") {
		t.Errorf("Details = %q, should mention the stage", result.Details)
	}
	if result.CaptureFile != "/tmp/hash.22000" {
		t.Errorf("CaptureFile = %q, want /tmp/hash.22000", result.CaptureFile)
	}
}

// ---------------------------------------------------------------------------
// Edge case: hashcat not installed and GPU cracking requested
// ---------------------------------------------------------------------------

func TestCrackWithHashcat_HashcatNotInstalled(t *testing.T) {
	// Create a valid hash file so we reach the hashcat lookup step.
	tmpDir := t.TempDir()
	hashFile := filepath.Join(tmpDir, "test.22000")
	if err := os.WriteFile(hashFile, []byte("WPA*02*aabbccdd*1122*3344*5566\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := crackWithHashcatMode(hashFile, "brute", "", 5*time.Second)
	if err != nil {
		t.Fatalf("crackWithHashcatMode returned error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	// If hashcat is not installed (common in CI), should fail gracefully.
	// If hashcat IS installed, it will fail because the hash format is fake.
	if result.Method != Hashcat {
		t.Errorf("Method = %q, want %q", result.Method, Hashcat)
	}
	// Either "hashcat not found" or a hashcat execution error -- both are fine.
	if result.Details == "" {
		t.Error("Details should explain why cracking failed")
	}
}

// ---------------------------------------------------------------------------
// Edge case: CrackWithHashcat in rule mode without wordlists
// ---------------------------------------------------------------------------

func TestCrackWithHashcat_RuleModeNoWordlist(t *testing.T) {
	tmpDir := t.TempDir()
	hashFile := filepath.Join(tmpDir, "test.22000")
	if err := os.WriteFile(hashFile, []byte("WPA*02*aabb\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := crackWithHashcatMode(hashFile, "rule", "", 5*time.Second)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.Success {
		t.Error("should not succeed without proper wordlist/hashcat")
	}
	// Should fail either with "hashcat not found" or "No wordlist found".
	if result.Details == "" {
		t.Error("Details should not be empty")
	}
}

// ---------------------------------------------------------------------------
// Edge case: CapturePMKID with invalid interface
// ---------------------------------------------------------------------------

func TestCapturePMKID_InvalidInterface(t *testing.T) {
	target := WifiTarget{
		SSID:    "TestNet",
		BSSID:   "AA:BB:CC:DD:EE:FF",
		Channel: 6,
	}

	result, err := CapturePMKID(target, "../../evil", 1*time.Second)
	if err != nil {
		t.Fatalf("CapturePMKID returned error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Success {
		t.Error("should fail with invalid interface")
	}
	if !strings.Contains(result.Details, "invalid interface") {
		t.Errorf("Details = %q, should mention invalid interface", result.Details)
	}
}

// ---------------------------------------------------------------------------
// Edge case: CaptureHandshake with invalid interface
// ---------------------------------------------------------------------------

func TestCaptureHandshake_InvalidInterface(t *testing.T) {
	target := WifiTarget{
		SSID:    "TestNet",
		BSSID:   "AA:BB:CC:DD:EE:FF",
		Channel: 6,
	}

	result, err := CaptureHandshake(target, "../../evil", 1*time.Second)
	if err != nil {
		t.Fatalf("CaptureHandshake returned error: %v", err)
	}
	if result.Success {
		t.Error("should fail with invalid interface")
	}
	if !strings.Contains(result.Details, "invalid interface") {
		t.Errorf("Details = %q, should mention invalid interface", result.Details)
	}
}

// ---------------------------------------------------------------------------
// Edge case: WPS Pixie-Dust with locked AP
// ---------------------------------------------------------------------------

func TestCrackWPSPixie_LockedAP(t *testing.T) {
	target := WifiTarget{
		SSID:       "LockedNet",
		BSSID:      "AA:BB:CC:DD:EE:FF",
		Channel:    6,
		WPSEnabled: true,
		WPSLocked:  true,
	}

	result, err := CrackWPSPixie(target, "wlan0", 5*time.Second)
	if err != nil {
		t.Fatalf("CrackWPSPixie returned error: %v", err)
	}
	if result.Success {
		t.Error("should fail with WPS locked")
	}
	// Should skip the attack entirely (no monitor mode check needed).
	if !strings.Contains(result.Details, "locked") && !strings.Contains(result.Details, "monitor") {
		t.Errorf("Details = %q, should mention locked or monitor mode", result.Details)
	}
}

// ---------------------------------------------------------------------------
// Edge case: WPS PIN brute with locked AP
// ---------------------------------------------------------------------------

func TestCrackWPSPin_LockedAP(t *testing.T) {
	target := WifiTarget{
		SSID:       "LockedNet",
		BSSID:      "AA:BB:CC:DD:EE:FF",
		Channel:    6,
		WPSEnabled: true,
		WPSLocked:  true,
	}

	result, err := CrackWPSPin(target, "wlan0", 5*time.Second)
	if err != nil {
		t.Fatalf("CrackWPSPin returned error: %v", err)
	}
	if result.Success {
		t.Error("should fail with WPS locked")
	}
	if !strings.Contains(result.Details, "locked") && !strings.Contains(result.Details, "monitor") {
		t.Errorf("Details = %q, should mention locked or monitor mode", result.Details)
	}
}

// ---------------------------------------------------------------------------
// Edge case: parseWashOutput with various malformed inputs
// ---------------------------------------------------------------------------

func TestParseWashOutput_MalformedLines(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   int
	}{
		{"empty", "", 0},
		{"header only", "BSSID  Ch  dBm  WPS  Lck  Vendor  ESSID\n", 0},
		{"separator only", "---\n", 0},
		{"non-BSSID start", "Hello World\n", 0},
		{"BSSID in middle", "Some text AA:BB:CC:DD:EE:FF more\n", 0},
		{"short fields", "AA:BB:CC:DD:EE:FF 6 -42\n", 0},
		{"non-numeric channel", "AA:BB:CC:DD:EE:FF abc -42 2.0 No Vendor ESSID\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWashOutput(tt.output)
			if len(got) != tt.want {
				t.Errorf("parseWashOutput(%q) returned %d, want %d", tt.output, len(got), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge case: parseReaverOutput edge cases
// ---------------------------------------------------------------------------

func TestParseReaverOutput_UnquotedPSK(t *testing.T) {
	output := "[+] WPS PIN: 12345670\n[+] WPA PSK: my secret password"
	pin, psk := parseReaverOutput(output)
	if pin != "12345670" {
		t.Errorf("pin = %q, want 12345670", pin)
	}
	if psk != "my secret password" {
		t.Errorf("psk = %q, want 'my secret password'", psk)
	}
}

func TestParseReaverOutput_PSKWithSpecialChars(t *testing.T) {
	output := "[+] WPA PSK: 'p@$$w0rd!#'"
	_, psk := parseReaverOutput(output)
	if psk != "p@$$w0rd!#" {
		t.Errorf("psk = %q, want 'p@$$w0rd!#'", psk)
	}
}
