// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package score

import (
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/discover"
)

// ---------------------------------------------------------------------------
// scoreToGrade
// ---------------------------------------------------------------------------

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score int
		want  Grade
	}{
		{100, GradeA},
		{95, GradeA},
		{90, GradeA},
		{89, GradeB},
		{75, GradeB},
		{74, GradeC},
		{60, GradeC},
		{59, GradeD},
		{40, GradeD},
		{39, GradeF},
		{0, GradeF},
		{-10, GradeF},
	}

	for _, tt := range tests {
		got := scoreToGrade(tt.score)
		if got != tt.want {
			t.Errorf("scoreToGrade(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ScoreNetwork — encryption assessment
// ---------------------------------------------------------------------------

func TestScoreNetwork_OpenNetwork(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "FreeWiFi",
		Security: "Open",
	}
	ns := ScoreNetwork(net)

	if ns.Score > 50 {
		t.Errorf("open network score = %d, want <= 50", ns.Score)
	}
	if ns.Grade == GradeA || ns.Grade == GradeB {
		t.Errorf("open network grade = %q, expected C or worse", ns.Grade)
	}
	assertHasFinding(t, ns.Findings, "critical", "No encryption")
}

func TestScoreNetwork_EmptySecurity(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "NoSec",
		Security: "",
	}
	ns := ScoreNetwork(net)

	if ns.Score > 50 {
		t.Errorf("empty security score = %d, want <= 50", ns.Score)
	}
	assertHasFinding(t, ns.Findings, "critical", "No encryption")
}

func TestScoreNetwork_WEP(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "OldRouter",
		Security: "WEP",
	}
	ns := ScoreNetwork(net)

	if ns.Score > 55 {
		t.Errorf("WEP score = %d, want <= 55", ns.Score)
	}
	assertHasFinding(t, ns.Findings, "critical", "WEP encryption")
}

func TestScoreNetwork_WPA2Personal(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "HomeWiFi",
		Security: "WPA2",
	}
	ns := ScoreNetwork(net)

	if ns.Score != 95 {
		t.Errorf("WPA2 score = %d, want 95", ns.Score)
	}
	if ns.Grade != GradeA {
		t.Errorf("WPA2 grade = %q, want A", ns.Grade)
	}
}

func TestScoreNetwork_WPA3(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "SecureWiFi",
		Security: "WPA3",
	}
	ns := ScoreNetwork(net)

	if ns.Score != 100 {
		t.Errorf("WPA3 score = %d, want 100", ns.Score)
	}
	if ns.Grade != GradeA {
		t.Errorf("WPA3 grade = %q, want A", ns.Grade)
	}
}

func TestScoreNetwork_Enterprise(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "CorpWiFi",
		Security: "WPA2-Enterprise",
	}
	ns := ScoreNetwork(net)

	if ns.Score != 100 {
		t.Errorf("Enterprise score = %d, want 100", ns.Score)
	}
}

// ---------------------------------------------------------------------------
// ScoreNetwork — WPS
// ---------------------------------------------------------------------------

func TestScoreNetwork_WPS(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "WPSRouter",
		Security: "WPA2",
		WPS:      true,
	}
	ns := ScoreNetwork(net)

	// WPA2 (-5) + WPS (-25) = 70.
	if ns.Score != 70 {
		t.Errorf("WPA2+WPS score = %d, want 70", ns.Score)
	}
	assertHasFinding(t, ns.Findings, "high", "WPS enabled")
}

// ---------------------------------------------------------------------------
// ScoreNetwork — portal on open network
// ---------------------------------------------------------------------------

func TestScoreNetwork_OpenWithPortal(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:         "Airport",
		Security:     "Open",
		PortalLikely: true,
	}
	ns := ScoreNetwork(net)

	// Open (-50) + portal on open (-10) = 40.
	if ns.Score != 40 {
		t.Errorf("open+portal score = %d, want 40", ns.Score)
	}
	assertHasFinding(t, ns.Findings, "critical", "No encryption")
	assertHasFinding(t, ns.Findings, "high", "Captive portal on open network")
	assertHasFinding(t, ns.Findings, "medium", "Client isolation unknown")
}

// ---------------------------------------------------------------------------
// ScoreNetwork — hidden SSID
// ---------------------------------------------------------------------------

func TestScoreNetwork_HiddenSSID(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "",
		Security: "WPA3",
	}
	ns := ScoreNetwork(net)

	assertHasFinding(t, ns.Findings, "low", "Hidden SSID")
}

func TestScoreNetwork_HiddenSSIDTag(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "<hidden>",
		Security: "WPA3",
	}
	ns := ScoreNetwork(net)

	assertHasFinding(t, ns.Findings, "low", "Hidden SSID")
}

// ---------------------------------------------------------------------------
// ScoreNetwork — strong signal
// ---------------------------------------------------------------------------

func TestScoreNetwork_StrongSignal(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "CloseBY",
		Security: "WPA3",
		Signal:   -30,
	}
	ns := ScoreNetwork(net)

	assertHasFinding(t, ns.Findings, "info", "Strong signal")
}

func TestScoreNetwork_WeakSignal(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "FarAway",
		Security: "WPA3",
		Signal:   -80,
	}
	ns := ScoreNetwork(net)

	assertNoFinding(t, ns.Findings, "Strong signal")
}

// ---------------------------------------------------------------------------
// ScoreNetwork — score clamping
// ---------------------------------------------------------------------------

func TestScoreNetwork_ScoreFloorZero(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:         "WorstWiFi",
		Security:     "Open",
		WPS:          true,
		PortalLikely: true,
	}
	ns := ScoreNetwork(net)

	if ns.Score < 0 {
		t.Errorf("score should not be negative, got %d", ns.Score)
	}
}

// ---------------------------------------------------------------------------
// ScoreNetwork — metadata passthrough
// ---------------------------------------------------------------------------

func TestScoreNetwork_MetadataPreserved(t *testing.T) {
	net := discover.ScannedNetwork{
		SSID:     "TestNet",
		BSSID:    "aa:bb:cc:dd:ee:ff",
		Channel:  6,
		Signal:   -65,
		Security: "WPA2",
		WPS:      false,
	}
	ns := ScoreNetwork(net)

	if ns.SSID != "TestNet" {
		t.Errorf("SSID = %q, want TestNet", ns.SSID)
	}
	if ns.BSSID != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("BSSID = %q", ns.BSSID)
	}
	if ns.Channel != 6 {
		t.Errorf("Channel = %d, want 6", ns.Channel)
	}
	if ns.Signal != -65 {
		t.Errorf("Signal = %d, want -65", ns.Signal)
	}
	if ns.Security != "WPA2" {
		t.Errorf("Security = %q", ns.Security)
	}
	if ns.WPS != false {
		t.Error("WPS should be false")
	}
	if ns.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

// ---------------------------------------------------------------------------
// buildSummary
// ---------------------------------------------------------------------------

func TestBuildSummary_Empty(t *testing.T) {
	s := buildSummary(nil)
	if s.TotalNetworks != 0 {
		t.Errorf("empty summary TotalNetworks = %d, want 0", s.TotalNetworks)
	}
	if s.CriticalFindings != 0 || s.HighFindings != 0 || s.MediumFindings != 0 {
		t.Error("empty summary should have zero findings")
	}
}

func TestBuildSummary_SingleNetwork(t *testing.T) {
	networks := []NetworkScore{
		{SSID: "Test", Score: 95, Grade: GradeA, Findings: []Finding{
			{Severity: "info", Title: "WPA3"},
		}},
	}
	s := buildSummary(networks)

	if s.TotalNetworks != 1 {
		t.Errorf("TotalNetworks = %d, want 1", s.TotalNetworks)
	}
	if s.GradeA != 1 {
		t.Errorf("GradeA = %d, want 1", s.GradeA)
	}
	if s.BestNetwork != "Test" {
		t.Errorf("BestNetwork = %q, want Test", s.BestNetwork)
	}
	if s.WorstNetwork != "Test" {
		t.Errorf("WorstNetwork = %q, want Test", s.WorstNetwork)
	}
}

func TestBuildSummary_MultipleNetworks(t *testing.T) {
	networks := []NetworkScore{
		{SSID: "Secure", Score: 100, Grade: GradeA, Findings: []Finding{
			{Severity: "info", Title: "WPA3"},
		}},
		{SSID: "OK", Score: 70, Grade: GradeC, Findings: []Finding{
			{Severity: "medium", Title: "test medium"},
		}},
		{SSID: "Bad", Score: 20, Grade: GradeF, Findings: []Finding{
			{Severity: "critical", Title: "no encryption"},
			{Severity: "high", Title: "WPS"},
		}},
		{SSID: "Decent", Score: 80, Grade: GradeB, Findings: nil},
		{SSID: "Poor", Score: 45, Grade: GradeD, Findings: []Finding{
			{Severity: "high", Title: "test high"},
		}},
	}

	s := buildSummary(networks)

	if s.TotalNetworks != 5 {
		t.Errorf("TotalNetworks = %d, want 5", s.TotalNetworks)
	}
	if s.GradeA != 1 {
		t.Errorf("GradeA = %d, want 1", s.GradeA)
	}
	if s.GradeB != 1 {
		t.Errorf("GradeB = %d, want 1", s.GradeB)
	}
	if s.GradeC != 1 {
		t.Errorf("GradeC = %d, want 1", s.GradeC)
	}
	if s.GradeD != 1 {
		t.Errorf("GradeD = %d, want 1", s.GradeD)
	}
	if s.GradeF != 1 {
		t.Errorf("GradeF = %d, want 1", s.GradeF)
	}
	if s.CriticalFindings != 1 {
		t.Errorf("CriticalFindings = %d, want 1", s.CriticalFindings)
	}
	if s.HighFindings != 2 {
		t.Errorf("HighFindings = %d, want 2", s.HighFindings)
	}
	if s.MediumFindings != 1 {
		t.Errorf("MediumFindings = %d, want 1", s.MediumFindings)
	}
	if s.BestNetwork != "Secure" {
		t.Errorf("BestNetwork = %q, want Secure", s.BestNetwork)
	}
	if s.WorstNetwork != "Bad" {
		t.Errorf("WorstNetwork = %q, want Bad", s.WorstNetwork)
	}
}

func TestBuildSummary_AllSameScore(t *testing.T) {
	networks := []NetworkScore{
		{SSID: "Net1", Score: 50, Grade: GradeD},
		{SSID: "Net2", Score: 50, Grade: GradeD},
	}
	s := buildSummary(networks)

	if s.TotalNetworks != 2 {
		t.Errorf("TotalNetworks = %d, want 2", s.TotalNetworks)
	}
	if s.GradeD != 2 {
		t.Errorf("GradeD = %d, want 2", s.GradeD)
	}
}

// ---------------------------------------------------------------------------
// Grade constants
// ---------------------------------------------------------------------------

func TestGradeConstants(t *testing.T) {
	if GradeA != "A" {
		t.Errorf("GradeA = %q", GradeA)
	}
	if GradeB != "B" {
		t.Errorf("GradeB = %q", GradeB)
	}
	if GradeC != "C" {
		t.Errorf("GradeC = %q", GradeC)
	}
	if GradeD != "D" {
		t.Errorf("GradeD = %q", GradeD)
	}
	if GradeF != "F" {
		t.Errorf("GradeF = %q", GradeF)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertHasFinding(t *testing.T, findings []Finding, severity, titleSubstr string) {
	t.Helper()
	for _, f := range findings {
		if f.Severity == severity && containsSubstr(f.Title, titleSubstr) {
			return
		}
	}
	t.Errorf("expected finding with severity=%q title containing %q, got %v", severity, titleSubstr, findingTitles(findings))
}

func assertNoFinding(t *testing.T, findings []Finding, titleSubstr string) {
	t.Helper()
	for _, f := range findings {
		if containsSubstr(f.Title, titleSubstr) {
			t.Errorf("unexpected finding with title containing %q", titleSubstr)
			return
		}
	}
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func findingTitles(findings []Finding) []string {
	titles := make([]string, len(findings))
	for i, f := range findings {
		titles[i] = f.Severity + ": " + f.Title
	}
	return titles
}
