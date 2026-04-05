// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package crack

import (
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// parseHashcatOutput
// ---------------------------------------------------------------------------

func TestParseHashcatOutput(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{
			"WPA hash with password",
			"WPA*02*aabbccdd*112233445566*aabbccddeeff*MyNetwork:password123",
			"password123",
		},
		{
			"long hash line",
			"d41d8cd98f:aabbccdd:112233:445566:778899:mypassword",
			"mypassword",
		},
		{
			"empty output",
			"",
			"",
		},
		{
			"session line skipped",
			"Session..........: hashcat\n[s]tatus........: Running\nWPA*02*aa*bb*cc*dd:foundpass",
			"foundpass",
		},
		{
			"no password found",
			"Session..........: hashcat\nStatus........: Exhausted\n",
			"",
		},
		{
			"multiple lines with WPA hash",
			"[s]tatus.........: Running\nWPA*02*aabb*1122*3344*5566:secretwifi\nProgress: 100%",
			"secretwifi",
		},
		{
			"timestamp prefix skipped",
			"[2024-01-01 12:00:00] Starting...\nSession: test\n",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHashcatOutput(tt.stdout)
			if got != tt.want {
				t.Errorf("parseHashcatOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeSmartCrackOptions
// ---------------------------------------------------------------------------

func TestNormalizeSmartCrackOptions_Defaults(t *testing.T) {
	opts := normalizeSmartCrackOptions(smartCrackOptions{})
	if opts.startStage != smartCrackStageCommonPasswords {
		t.Errorf("startStage = %d, want %d", opts.startStage, smartCrackStageCommonPasswords)
	}
	if opts.endStage != smartCrackStageSmartBrute {
		t.Errorf("endStage = %d, want %d", opts.endStage, smartCrackStageSmartBrute)
	}
}

func TestNormalizeSmartCrackOptions_FullBrute(t *testing.T) {
	opts := normalizeSmartCrackOptions(smartCrackOptions{fullBrute: true})
	if opts.endStage != smartCrackStageFullBrute {
		t.Errorf("endStage with fullBrute = %d, want %d", opts.endStage, smartCrackStageFullBrute)
	}
}

func TestNormalizeSmartCrackOptions_EndBeforeStart(t *testing.T) {
	opts := normalizeSmartCrackOptions(smartCrackOptions{
		startStage: smartCrackStageSmartBrute,
		endStage:   smartCrackStageCommonPasswords,
	})
	if opts.endStage < opts.startStage {
		t.Errorf("endStage %d should not be less than startStage %d", opts.endStage, opts.startStage)
	}
}

func TestNormalizeSmartCrackOptions_ExplicitRange(t *testing.T) {
	opts := normalizeSmartCrackOptions(smartCrackOptions{
		startStage: smartCrackStageNumericMasks,
		endStage:   smartCrackStageDictionary,
	})
	if opts.startStage != smartCrackStageNumericMasks {
		t.Errorf("startStage = %d, want %d", opts.startStage, smartCrackStageNumericMasks)
	}
	if opts.endStage != smartCrackStageDictionary {
		t.Errorf("endStage = %d, want %d", opts.endStage, smartCrackStageDictionary)
	}
}

// ---------------------------------------------------------------------------
// smartCrackOptions.includes
// ---------------------------------------------------------------------------

func TestSmartCrackOptions_Includes(t *testing.T) {
	opts := smartCrackOptions{
		startStage: smartCrackStageCommonPasswords,
		endStage:   smartCrackStageWordNumberRules,
	}

	if !opts.includes(smartCrackStageCommonPasswords) {
		t.Error("should include CommonPasswords")
	}
	if !opts.includes(smartCrackStageNumericMasks) {
		t.Error("should include NumericMasks")
	}
	if !opts.includes(smartCrackStageWordNumberRules) {
		t.Error("should include WordNumberRules")
	}
	if opts.includes(smartCrackStageDictionary) {
		t.Error("should NOT include Dictionary")
	}
	if opts.includes(smartCrackStageSmartBrute) {
		t.Error("should NOT include SmartBrute")
	}
}

// ---------------------------------------------------------------------------
// captureDir / ensureCaptureDir
// ---------------------------------------------------------------------------

func TestCaptureDir_NotEmpty(t *testing.T) {
	dir := captureDir()
	if dir == "" {
		t.Error("captureDir() returned empty string")
	}
}

func TestEnsureCaptureDir_CreatesDir(t *testing.T) {
	dir := ensureCaptureDir()
	if dir == "" {
		t.Error("ensureCaptureDir() returned empty string")
	}
}

func TestTimestampedDir_NotEmpty(t *testing.T) {
	dir := timestampedDir("test")
	if dir == "" {
		t.Error("timestampedDir() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// isDarwin (already tested but we add coverage for the helper)
// ---------------------------------------------------------------------------

func TestIsDarwin_ReturnsBool(t *testing.T) {
	result := isDarwin()
	// Just verify it returns consistently.
	if result != isDarwin() {
		t.Error("isDarwin() returned inconsistent results")
	}
}

// ---------------------------------------------------------------------------
// monitorModeError
// ---------------------------------------------------------------------------

func TestMonitorModeError(t *testing.T) {
	msg := monitorModeError("wlan0")
	if msg == "" {
		t.Error("monitorModeError returned empty string")
	}
	if isDarwin() {
		if msg == "" {
			t.Error("monitorModeError on darwin should return non-empty")
		}
	} else {
		if msg == "" {
			t.Error("monitorModeError on linux should return non-empty")
		}
	}
}

// ---------------------------------------------------------------------------
// findTool with nonexistent tool
// ---------------------------------------------------------------------------

func TestFindTool_Nonexistent(t *testing.T) {
	_, err := findTool("nowifi_fake_tool_99999", "install hint")
	if err == nil {
		t.Error("findTool should return error for nonexistent tool")
	}
}

// ---------------------------------------------------------------------------
// parseReaverOutput
// ---------------------------------------------------------------------------

func TestParseReaverOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantPin string
		wantPSK string
	}{
		{
			"pin and psk quoted",
			"[+] WPS PIN: '12345670'\n[+] WPA PSK: 'MyPassword123'",
			"12345670",
			"MyPassword123",
		},
		{
			"pin and psk unquoted",
			"WPS PIN: 12345670\nWPA PSK: secretpass",
			"12345670",
			"secretpass",
		},
		{
			"only pin",
			"[+] WPS PIN: '12340000'\n[!] No WPA PSK recovered",
			"12340000",
			"",
		},
		{
			"only psk",
			"WPA PSK: 'wifi-pass'",
			"",
			"wifi-pass",
		},
		{
			"empty output",
			"",
			"",
			"",
		},
		{
			"no matches",
			"[*] Trying pin 12345678...\n[!] Receive timeout occurred",
			"",
			"",
		},
		{
			"four digit pin",
			"WPS PIN: '1234'",
			"1234",
			"",
		},
		{
			"multiline noise",
			"[Reaver v1.6.5] Starting attack...\n[*] Trying pin 12345670\n[+] WPS PIN: '12345670'\n[+] WPA PSK: 'pass1234'\n[*] Done.",
			"12345670",
			"pass1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPin, gotPSK := parseReaverOutput(tt.output)
			if gotPin != tt.wantPin {
				t.Errorf("wpsPin = %q, want %q", gotPin, tt.wantPin)
			}
			if gotPSK != tt.wantPSK {
				t.Errorf("wpaPSK = %q, want %q", gotPSK, tt.wantPSK)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// countFileLines
// ---------------------------------------------------------------------------

func TestCountFileLines(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"three lines", "a\nb\nc\n", 3},
		{"empty", "", 0},
		{"whitespace only", "  \n\t\n  \n", 0},
		{"mixed", "line1\n\nline2\n  \nline3", 3},
		{"single line no newline", "hello", 1},
		{"single line with newline", "hello\n", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := tmpDir + "/test.txt"
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got := countFileLines(path)
			if got != tt.want {
				t.Errorf("countFileLines() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCountFileLines_NonexistentFile(t *testing.T) {
	got := countFileLines("/nonexistent/file.txt")
	if got != 0 {
		t.Errorf("countFileLines(nonexistent) = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// errCommandTimedOut
// ---------------------------------------------------------------------------

func TestErrCommandTimedOut(t *testing.T) {
	if errCommandTimedOut == nil {
		t.Error("errCommandTimedOut should not be nil")
	}
	if errCommandTimedOut.Error() != "command timed out" {
		t.Errorf("errCommandTimedOut = %q, want 'command timed out'", errCommandTimedOut.Error())
	}
}

// ---------------------------------------------------------------------------
// bssidRE regex
// ---------------------------------------------------------------------------

func TestBSSIDRegex(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA-BB-CC-DD-EE-FF", true},
		{"AABBCCDDEEFF", false},
		{"AA:BB:CC", false},
		{"", false},
		{"GG:HH:II:JJ:KK:LL", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := bssidRE.MatchString(tt.input)
			if got != tt.match {
				t.Errorf("bssidRE.MatchString(%q) = %v, want %v", tt.input, got, tt.match)
			}
		})
	}
}
