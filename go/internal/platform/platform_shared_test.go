// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package platform

import (
	"regexp"
	"testing"
)

func TestNormalizeMAC_TrimsAndLowercases(t *testing.T) {
	got, err := normalizeMAC("  AA:BB:CC:DD:EE:FF\n")
	if err != nil {
		t.Fatalf("normalizeMAC returned error: %v", err)
	}
	if got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("normalizeMAC returned %q, want %q", got, "aa:bb:cc:dd:ee:ff")
	}
}

func TestParseArpEntries_NormalizesAndSkipsInvalidMACs(t *testing.T) {
	re := regexp.MustCompile(`\S+\s+\((\S+)\)\s+at\s+(\S+)\s+on\s+(\S+)`)
	entries := parseArpEntries(`router (192.168.1.1) at AA:BB:CC:DD:EE:FF on en0
router (192.168.1.2) at aa:bb:cc:dd:ee:00 on en0
router (192.168.1.3) at (incomplete) on en0`, re, 1, 2, 3)

	if len(entries) != 2 {
		t.Fatalf("parseArpEntries returned %d entries, want 2", len(entries))
	}
	if entries[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("first entry MAC = %q, want %q", entries[0].MAC, "aa:bb:cc:dd:ee:ff")
	}
	if entries[1].MAC != "aa:bb:cc:dd:ee:00" {
		t.Fatalf("second entry MAC = %q, want %q", entries[1].MAC, "aa:bb:cc:dd:ee:00")
	}
}
