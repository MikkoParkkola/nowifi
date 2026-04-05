// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/score"
)

// ---------------------------------------------------------------------------
// colorGrade
// ---------------------------------------------------------------------------

func TestColorGrade(t *testing.T) {
	tests := []struct {
		grade    score.Grade
		contains string
	}{
		{score.GradeA, "A"},
		{score.GradeB, "B"},
		{score.GradeC, "C"},
		{score.GradeD, "D"},
		{score.GradeF, "F"},
	}

	for _, tt := range tests {
		t.Run(string(tt.grade), func(t *testing.T) {
			result := colorGrade(tt.grade)
			if result == "" {
				t.Error("colorGrade returned empty string")
			}
			if !strings.Contains(result, tt.contains) {
				t.Errorf("colorGrade(%q) = %q, should contain %q", tt.grade, result, tt.contains)
			}
		})
	}
}

func TestColorGrade_Unknown(t *testing.T) {
	result := colorGrade("X")
	if result != "X" {
		t.Errorf("colorGrade unknown = %q, want X", result)
	}
}

// ---------------------------------------------------------------------------
// colorSeverity
// ---------------------------------------------------------------------------

func TestColorSeverity(t *testing.T) {
	tests := []struct {
		severity string
		contains string
	}{
		{"critical", "CRIT"},
		{"high", "HIGH"},
		{"medium", "MED"},
		{"low", "LOW"},
		{"info", "INFO"},
		{"unknown", "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := colorSeverity(tt.severity)
			if result == "" {
				t.Error("colorSeverity returned empty string")
			}
			if !strings.Contains(result, tt.contains) {
				t.Errorf("colorSeverity(%q) = %q, should contain %q", tt.severity, result, tt.contains)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// colorSecurity (scan.go)
// ---------------------------------------------------------------------------

func TestColorSecurity(t *testing.T) {
	tests := []struct {
		security string
		contains string
	}{
		{"Open", "Open"},
		{"WEP", "WEP"},
		{"WPA", "WPA"},
		{"WPA2", "WPA2"},
		{"WPA3", "WPA3"},
		{"WPA2-Enterprise", "WPA2-Enterprise"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.security, func(t *testing.T) {
			result := colorSecurity(tt.security)
			if result == "" {
				t.Error("colorSecurity returned empty string")
			}
			if !strings.Contains(result, tt.contains) {
				t.Errorf("colorSecurity(%q) = %q, should contain %q", tt.security, result, tt.contains)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// writeOrPrint
// ---------------------------------------------------------------------------

func TestWriteOrPrint_ToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "test-output.txt")

	writeOrPrint("test content", outFile)

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "test content" {
		t.Errorf("file content = %q, want %q", string(data), "test content")
	}
}

func TestWriteOrPrint_EmptyPath(t *testing.T) {
	// Empty path -> prints to stdout. Just verify no panic.
	writeOrPrint("test content", "")
}

// ---------------------------------------------------------------------------
// writeOutput (diagnose.go)
// ---------------------------------------------------------------------------

func TestWriteOutput_ToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "diagnose-output.md")

	// Save and restore the global variable.
	origOutput := diagnoseOutput
	defer func() { diagnoseOutput = origOutput }()

	diagnoseOutput = outFile
	writeOutput("# Report\n\nTest content")

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "# Report") {
		t.Errorf("file content = %q, should contain # Report", string(data))
	}
}

func TestWriteOutput_EmptyPath(t *testing.T) {
	origOutput := diagnoseOutput
	defer func() { diagnoseOutput = origOutput }()

	diagnoseOutput = ""
	// Should print to stdout without panicking.
	writeOutput("test")
}

// ---------------------------------------------------------------------------
// generateScoreMarkdown
// ---------------------------------------------------------------------------

func TestGenerateScoreMarkdown_Basic(t *testing.T) {
	report := &score.ScanReport{
		Networks: []score.NetworkScore{
			{
				SSID:     "TestNet",
				Grade:    score.GradeB,
				Score:    75,
				Security: "WPA2",
			},
		},
	}

	md := generateScoreMarkdown(report, nil)

	if !strings.Contains(md, "# WiFi Security Score Report") {
		t.Error("markdown should contain header")
	}
	if !strings.Contains(md, "TestNet") {
		t.Error("markdown should contain SSID")
	}
	if !strings.Contains(md, "B") {
		t.Error("markdown should contain grade")
	}
	if !strings.Contains(md, "nowifi") {
		t.Error("markdown should contain nowifi attribution")
	}
}

func TestGenerateScoreMarkdown_WithConnected(t *testing.T) {
	report := &score.ScanReport{
		Networks: []score.NetworkScore{
			{SSID: "Net1", Grade: score.GradeA, Score: 90, Security: "WPA3"},
		},
	}
	connected := &score.NetworkScore{
		SSID:  "Net1",
		Grade: score.GradeA,
		Score: 90,
		Findings: []score.Finding{
			{Severity: "low", Title: "No issues", Remediation: "None needed"},
		},
	}

	md := generateScoreMarkdown(report, connected)

	if !strings.Contains(md, "Deep Analysis") {
		t.Error("markdown should contain Deep Analysis section")
	}
	if !strings.Contains(md, "No issues") {
		t.Error("markdown should contain finding title")
	}
}

func TestGenerateScoreMarkdown_HiddenSSID(t *testing.T) {
	report := &score.ScanReport{
		Networks: []score.NetworkScore{
			{SSID: "", Grade: score.GradeF, Score: 10, Security: "Open"},
		},
	}

	md := generateScoreMarkdown(report, nil)

	if !strings.Contains(md, "(hidden)") {
		t.Error("markdown should show (hidden) for empty SSID")
	}
}

func TestGenerateScoreMarkdown_WithWPS(t *testing.T) {
	report := &score.ScanReport{
		Networks: []score.NetworkScore{
			{SSID: "WPSNet", Grade: score.GradeD, Score: 40, Security: "WPA2", WPS: true},
		},
	}

	md := generateScoreMarkdown(report, nil)

	if !strings.Contains(md, "YES") {
		t.Error("markdown should show YES for WPS")
	}
}

func TestGenerateScoreMarkdown_Findings(t *testing.T) {
	report := &score.ScanReport{
		Networks: []score.NetworkScore{
			{
				SSID: "Net1", Grade: score.GradeD, Score: 35, Security: "WPA2",
				Findings: []score.Finding{
					{Severity: "critical", Title: "WPS enabled"},
					{Severity: "high", Title: "Weak encryption"},
				},
			},
		},
	}

	md := generateScoreMarkdown(report, nil)

	// Table should show critical and high counts.
	if !strings.Contains(md, "1") {
		t.Error("markdown should contain finding counts")
	}
}

// ---------------------------------------------------------------------------
// Score command flags
// ---------------------------------------------------------------------------

func TestScoreCmd_Flags(t *testing.T) {
	if scoreCmd.Use != "score" {
		t.Errorf("scoreCmd.Use = %q, want score", scoreCmd.Use)
	}

	f := scoreCmd.Flags().Lookup("deep")
	if f == nil {
		t.Fatal("--deep flag not registered on scoreCmd")
	}
	if f.DefValue != "false" {
		t.Errorf("--deep default = %q, want false", f.DefValue)
	}

	f = scoreCmd.Flags().Lookup("format")
	if f == nil {
		t.Fatal("--format flag not registered on scoreCmd")
	}
	if f.DefValue != "terminal" {
		t.Errorf("--format default = %q, want terminal", f.DefValue)
	}

	f = scoreCmd.Flags().Lookup("output")
	if f == nil {
		t.Fatal("--output flag not registered on scoreCmd")
	}
	if f.DefValue != "" {
		t.Errorf("--output default = %q, want empty", f.DefValue)
	}
}
