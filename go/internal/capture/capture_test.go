// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package capture

import (
	"os"
	"testing"
	"time"
)

func TestSaveAndListAudit(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	record := &AuditRecord{
		ID:         "test-001",
		Timestamp:  time.Now(),
		SSID:       "TestNetwork",
		Gateway:    "192.168.1.1",
		Portal:     true,
		Vendor:     "unifi",
		BypassUsed: "MAC clone",
		Success:    true,
		Probes:     map[string]bool{"dns": true, "icmp": false},
		Duration:   "2m30s",
	}

	if err := SaveAudit(record); err != nil {
		t.Fatalf("SaveAudit() error = %v", err)
	}

	// List should return the record.
	records, err := ListAudits()
	if err != nil {
		t.Fatalf("ListAudits() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ListAudits() returned %d records, want 1", len(records))
	}
	if records[0].ID != "test-001" {
		t.Errorf("record ID = %q, want test-001", records[0].ID)
	}
	if records[0].SSID != "TestNetwork" {
		t.Errorf("record SSID = %q, want TestNetwork", records[0].SSID)
	}
	if !records[0].Success {
		t.Error("record Success should be true")
	}
}

func TestGetAudit(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	record := &AuditRecord{
		ID:        "test-002",
		Timestamp: time.Now(),
		SSID:      "GetTest",
		Success:   false,
		Probes:    map[string]bool{},
	}

	if err := SaveAudit(record); err != nil {
		t.Fatalf("SaveAudit() error = %v", err)
	}

	got, err := GetAudit("test-002")
	if err != nil {
		t.Fatalf("GetAudit() error = %v", err)
	}
	if got.SSID != "GetTest" {
		t.Errorf("SSID = %q, want GetTest", got.SSID)
	}
}

func TestGetAuditNotFound(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	_, err := GetAudit("nonexistent")
	if err == nil {
		t.Error("GetAudit(nonexistent) should return error")
	}
}

func TestListAuditsEmpty(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	records, err := ListAudits()
	if err != nil {
		t.Fatalf("ListAudits() error = %v", err)
	}
	if len(records) != 0 {
		t.Errorf("ListAudits() returned %d records, want 0", len(records))
	}
}

func TestListAuditsSortedByTimestamp(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	now := time.Now()

	// Save older record first.
	SaveAudit(&AuditRecord{
		ID:        "old",
		Timestamp: now.Add(-1 * time.Hour),
		SSID:      "OldNetwork",
		Probes:    map[string]bool{},
	})

	// Save newer record.
	SaveAudit(&AuditRecord{
		ID:        "new",
		Timestamp: now,
		SSID:      "NewNetwork",
		Probes:    map[string]bool{},
	})

	records, err := ListAudits()
	if err != nil {
		t.Fatalf("ListAudits() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	// Newest first.
	if records[0].ID != "new" {
		t.Errorf("first record ID = %q, want 'new' (newest first)", records[0].ID)
	}
	if records[1].ID != "old" {
		t.Errorf("second record ID = %q, want 'old'", records[1].ID)
	}
}
