// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package capture provides an audit trail for nowifi sessions.
//
// Each audit record captures what was tested, which bypass (if any) succeeded,
// and how long the session took. Records are stored as individual JSON files
// under ~/.nowifi/captures/ with a separate index for fast listing.
package capture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/config"
)

// AuditRecord represents a single nowifi session result.
type AuditRecord struct {
	ID         string          `json:"id"`
	Timestamp  time.Time       `json:"timestamp"`
	SSID       string          `json:"ssid"`
	Gateway    string          `json:"gateway"`
	Portal     bool            `json:"portal"`
	Vendor     string          `json:"vendor"`
	BypassUsed string          `json:"bypass_used,omitempty"`
	Success    bool            `json:"success"`
	Probes     map[string]bool `json:"probes"`
	Duration   string          `json:"duration"`
	ReportFile string          `json:"report_file,omitempty"`
}

// capturesDir returns the directory for audit captures.
func capturesDir() string {
	return filepath.Join(config.Dir(), "captures")
}

// indexPath returns the path to the captures index file.
func indexPath() string {
	return filepath.Join(capturesDir(), "index.json")
}

// SaveAudit persists an audit record to disk. It saves both an individual
// file (captures/{id}.json) and appends the record to the index.
func SaveAudit(record *AuditRecord) error {
	dir := capturesDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create captures dir: %w", err)
	}

	// Write individual record.
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}

	recPath := filepath.Join(dir, record.ID+".json")
	if err := os.WriteFile(recPath, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}

	// Append to index.
	index, err := loadIndex()
	if err != nil {
		return fmt.Errorf("load index: %w", err)
	}
	index = append(index, *record)
	return saveIndex(index)
}

// ListAudits returns all audit records sorted by timestamp (newest first).
func ListAudits() ([]AuditRecord, error) {
	index, err := loadIndex()
	if err != nil {
		return nil, err
	}

	sort.Slice(index, func(i, j int) bool {
		return index[i].Timestamp.After(index[j].Timestamp)
	})

	return index, nil
}

// GetAudit returns a single audit record by ID.
func GetAudit(id string) (*AuditRecord, error) {
	recPath := filepath.Join(capturesDir(), id+".json")
	data, err := os.ReadFile(recPath)
	if err != nil {
		return nil, fmt.Errorf("read audit %s: %w", id, err)
	}

	var record AuditRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parse audit %s: %w", id, err)
	}
	return &record, nil
}

// loadIndex reads the index file, returning an empty slice if it does not exist.
func loadIndex() ([]AuditRecord, error) {
	data, err := os.ReadFile(indexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read index: %w", err)
	}

	var records []AuditRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	return records, nil
}

// saveIndex writes the full index to disk atomically.
func saveIndex(records []AuditRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}

	tmp := indexPath() + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("write index: %w", err)
	}
	if err := os.Rename(tmp, indexPath()); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename index: %w", err)
	}
	return nil
}
