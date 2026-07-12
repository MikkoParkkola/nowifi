// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/inflight"
)

func TestReconReportMarshalsToJSON(t *testing.T) {
	report := &ReconReport{
		Timestamp: "2026-04-15T12:00:00Z",
		Host:      HostInfo{OS: "darwin", Arch: "arm64"},
		Network:   NetworkInfo{Interface: "en0", LocalIP: "172.19.0.55"},
		Latency:   LatencyProbe{TargetHost: "1.1.1.1", AvgMs: 850, DetectedLink: "ka_band"},
		Provider:  ProviderGuess{Provider: "thales_inflyt", Confidence: "high"},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	expected := []string{
		`"interface":"en0"`,
		`"provider":"thales_inflyt"`,
		`"confidence":"high"`,
		`"detected_link_type":"ka_band"`,
	}
	for _, want := range expected {
		if !strings.Contains(string(data), want) {
			t.Errorf("expected JSON to contain %q, got: %s", want, data)
		}
	}
}

func TestInferConfidence(t *testing.T) {
	tests := []struct {
		name     string
		provider inflight.Provider
		report   *ReconReport
		want     string
	}{
		{"unknown returns unknown", inflight.Unknown, &ReconReport{}, "unknown"},
		{
			"known + no evidence is low",
			inflight.Thales,
			&ReconReport{},
			"low",
		},
		{
			"known + server header is medium",
			inflight.Thales,
			&ReconReport{Portal: &PortalProbe{ServerHeader: "AFKLM AIRCON HUB"}},
			"medium",
		},
		{
			"known + 2 signals is high",
			inflight.Thales,
			&ReconReport{
				Portal:  &PortalProbe{ServerHeader: "AFKLM AIRCON HUB"},
				CAPPORT: &CAPPORTProbe{URL: "https://example.com/capport"},
			},
			"high",
		},
	}
	for _, tc := range tests {
		got := inferConfidence(tc.provider, tc.report)
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestReconCmdHasFlags(t *testing.T) {
	// Verify the command is wired up with expected flags.
	if reconCmd.Flag("output") == nil {
		t.Error("reconCmd should have --output flag")
	}
	if reconCmd.Flag("iface") == nil {
		t.Error("reconCmd should have --iface flag")
	}
}

func TestReconCmdHelpMentionsPurpose(t *testing.T) {
	// Check the Long description directly rather than executing --help
	// (cobra's SetArgs on a subcommand can trigger unintended runs).
	long := strings.ToLower(reconCmd.Long)
	for _, expected := range []string{"fingerprint", "capport", "passively"} {
		if !strings.Contains(long, expected) {
			t.Errorf("reconCmd.Long should mention %q; got:\n%s", expected, reconCmd.Long)
		}
	}
}
