// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/forensics"
)

func TestForensicsCmd_Registered(t *testing.T) {
	if forensicsCmd.Use != "forensics" {
		t.Errorf("forensicsCmd.Use = %q, want forensics", forensicsCmd.Use)
	}
	registered := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "forensics" {
			registered = true
			break
		}
	}
	if !registered {
		t.Error("forensics subcommand not registered on rootCmd")
	}
}

func TestForensicsCmd_FlagsDefined(t *testing.T) {
	for _, name := range []string{"output", "format", "baseline", "baseline-file", "timeout", "portal-base"} {
		if forensicsCmd.Flags().Lookup(name) == nil {
			t.Errorf("forensics flag %q not defined", name)
		}
	}
	// -o and -f shorthands.
	if forensicsCmd.Flags().ShorthandLookup("o") == nil {
		t.Error("forensics -o shorthand not defined")
	}
	if forensicsCmd.Flags().ShorthandLookup("f") == nil {
		t.Error("forensics -f shorthand not defined")
	}
}

func TestForensicsCmd_LongMentionsGuarantees(t *testing.T) {
	long := forensicsCmd.Long
	for _, want := range []string{"READ-ONLY", "NO SUDO", "LOCAL-ONLY"} {
		if !strings.Contains(long, want) {
			t.Errorf("forensics Long help missing guarantee %q", want)
		}
	}
}

// TestWriteForensicsPackage_FormatSelection verifies the --format wiring writes
// the right files, without any network access (package is built in-memory).
func TestWriteForensicsPackage_FormatSelection(t *testing.T) {
	tests := []struct {
		format   string
		wantTxt  bool
		wantJSON bool
	}{
		{"both", true, true},
		{"json", false, true},
		{"txt", true, false},
		{"", true, true}, // default treated as both
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			dir := t.TempDir()
			// Set the package-level flags the helper reads.
			forensicsOutput = dir
			forensicsFormat = tt.format
			forensicsBaseline = false
			defer func() { forensicsOutput, forensicsFormat = "", "both" }()

			pkg := &forensics.Package{TS: "20260530T120000Z", Iface: "en0", GW: "10.0.0.1", Provider: "test"}
			res, err := writeForensicsPackage(pkg)
			if err != nil {
				t.Fatalf("writeForensicsPackage error: %v", err)
			}

			txtExists := res.TextPath != "" && fileExists(t, res.TextPath)
			jsonExists := res.JSONPath != "" && fileExists(t, res.JSONPath)
			if txtExists != tt.wantTxt {
				t.Errorf("txt written=%t, want %t", txtExists, tt.wantTxt)
			}
			if jsonExists != tt.wantJSON {
				t.Errorf("json written=%t, want %t", jsonExists, tt.wantJSON)
			}
			// Verify no stray files of the unwanted type landed in dir.
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if !tt.wantTxt && strings.HasSuffix(e.Name(), ".txt") {
					t.Errorf("unexpected .txt file %s for format %q", e.Name(), tt.format)
				}
				if !tt.wantJSON && strings.HasSuffix(e.Name(), ".json") {
					t.Errorf("unexpected .json file %s for format %q", e.Name(), tt.format)
				}
			}
		})
	}
}

func TestWriteForensicsPackage_BaselineFlag(t *testing.T) {
	dir := t.TempDir()
	forensicsOutput = dir
	forensicsFormat = "both"
	forensicsBaseline = true
	defer func() { forensicsOutput, forensicsFormat, forensicsBaseline = "", "both", false }()

	pkg := &forensics.Package{TS: "20260530T120000Z", Iface: "en0", GW: "10.0.0.1", Provider: "test"}
	res, err := writeForensicsPackage(pkg)
	if err != nil {
		t.Fatalf("writeForensicsPackage error: %v", err)
	}
	if res.BaselinePath == "" || !fileExists(t, res.BaselinePath) {
		t.Error("expected a baseline file to be written when --baseline is set")
	}
	if filepath.Base(res.BaselinePath) != "baseline-20260530T120000Z.txt" {
		t.Errorf("unexpected baseline filename: %s", res.BaselinePath)
	}
}

func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	return err == nil
}
