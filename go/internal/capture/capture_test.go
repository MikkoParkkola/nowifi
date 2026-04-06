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

func TestSaveAuditDirCreationFailure(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	// Create a file where the captures directory should be, blocking MkdirAll.
	nowifiDir := tmp + "/.nowifi"
	os.MkdirAll(nowifiDir, 0700)
	os.WriteFile(nowifiDir+"/captures", []byte("blocker"), 0600)

	record := &AuditRecord{
		ID:        "fail-dir",
		Timestamp: time.Now(),
		SSID:      "Test",
		Probes:    map[string]bool{},
	}

	err := SaveAudit(record)
	if err == nil {
		t.Error("SaveAudit should fail when captures dir cannot be created")
	}
}

func TestSaveAuditWriteError(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	// Create captures dir as read-only so write fails.
	captDir := tmp + "/.nowifi/captures"
	os.MkdirAll(captDir, 0700)

	record := &AuditRecord{
		ID:        "fail-write",
		Timestamp: time.Now(),
		SSID:      "Test",
		Probes:    map[string]bool{},
	}

	// Make the captures dir read-only so file writes fail.
	os.Chmod(captDir, 0500)
	defer os.Chmod(captDir, 0700)

	err := SaveAudit(record)
	if err == nil {
		t.Error("SaveAudit should fail when captures dir is read-only")
	}
}

func TestListAuditsCorruptedIndex(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	// Create a corrupted index file.
	captDir := tmp + "/.nowifi/captures"
	os.MkdirAll(captDir, 0700)
	os.WriteFile(captDir+"/index.json", []byte("{not valid json["), 0600)

	_, err := ListAudits()
	if err == nil {
		t.Error("ListAudits should fail with corrupted index")
	}
}

func TestLoadIndexEmptyFile(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	captDir := tmp + "/.nowifi/captures"
	os.MkdirAll(captDir, 0700)
	// Empty file is not valid JSON.
	os.WriteFile(captDir+"/index.json", []byte(""), 0600)

	_, err := loadIndex()
	if err == nil {
		t.Error("loadIndex should fail with empty file (invalid JSON)")
	}
}

func TestLoadIndexMissingFile(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	// No captures dir at all.
	records, err := loadIndex()
	if err != nil {
		t.Fatalf("loadIndex on missing file should return nil error, got %v", err)
	}
	if records != nil {
		t.Errorf("loadIndex on missing file should return nil records, got %d", len(records))
	}
}

func TestLoadIndexReadError(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	// Create index as a directory to cause a read error (not ENOENT).
	captDir := tmp + "/.nowifi/captures"
	os.MkdirAll(captDir+"/index.json", 0700)

	_, err := loadIndex()
	if err == nil {
		t.Error("loadIndex should fail when index.json is a directory")
	}
}

func TestSaveIndex_RenameError(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	captDir := tmp + "/.nowifi/captures"
	os.MkdirAll(captDir, 0700)

	// Create index.json as a directory so rename fails.
	os.MkdirAll(captDir+"/index.json", 0700)

	records := []AuditRecord{{ID: "x", Timestamp: time.Now(), Probes: map[string]bool{}}}
	err := saveIndex(records)
	if err == nil {
		t.Error("saveIndex should fail when index.json is a directory (rename fails)")
	}
}

func TestSaveIndexWriteError(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	captDir := tmp + "/.nowifi/captures"
	os.MkdirAll(captDir, 0700)
	os.Chmod(captDir, 0500)
	defer os.Chmod(captDir, 0700)

	records := []AuditRecord{{ID: "x", Timestamp: time.Now(), Probes: map[string]bool{}}}
	err := saveIndex(records)
	if err == nil {
		t.Error("saveIndex should fail when dir is read-only")
	}
}

func TestGetAuditCorruptedJSON(t *testing.T) {
	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)

	captDir := tmp + "/.nowifi/captures"
	os.MkdirAll(captDir, 0700)
	os.WriteFile(captDir+"/bad-json.json", []byte("{corrupted"), 0600)

	_, err := GetAudit("bad-json")
	if err == nil {
		t.Error("GetAudit should fail with corrupted JSON")
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
