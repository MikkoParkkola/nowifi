// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package forensics

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteResult records the on-disk paths produced by a write.
type WriteResult struct {
	TextPath     string
	JSONPath     string
	BaselinePath string
}

// WriteOptions controls which artifacts Write emits.
type WriteOptions struct {
	// Format selects which report files to write: "both" (default), "json",
	// or "txt". An empty string is treated as "both".
	Format string
	// Baseline additionally writes a baseline-<ts>.txt capture-at-full-access
	// file for later diffing.
	Baseline bool
}

// Write persists the package to disk in dir as sibling files,
// holes-<ts>.txt and holes-<ts>.json (matching the shell script's naming),
// and returns the saved paths. This is LOCAL-ONLY: it writes to disk and
// never uploads or phones home.
//
// The Format option controls which report files are written; the default
// ("both") writes both. If opts.Baseline is true, it additionally writes a
// baseline-<ts>.txt file.
func (p *Package) Write(dir string, opts WriteOptions) (WriteResult, error) {
	var res WriteResult
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return res, fmt.Errorf("create output dir: %w", err)
	}

	wantTxt := opts.Format != "json"
	wantJSON := opts.Format != "txt"

	if wantTxt {
		txtPath := filepath.Join(dir, "holes-"+p.TS+".txt")
		if err := os.WriteFile(txtPath, []byte(p.Text()), 0o600); err != nil {
			return res, fmt.Errorf("write text report: %w", err)
		}
		res.TextPath = txtPath
	}

	if wantJSON {
		js, err := p.JSON()
		if err != nil {
			return res, fmt.Errorf("marshal json: %w", err)
		}
		jsonPath := filepath.Join(dir, "holes-"+p.TS+".json")
		if err := os.WriteFile(jsonPath, js, 0o600); err != nil {
			return res, fmt.Errorf("write json report: %w", err)
		}
		res.JSONPath = jsonPath
	}

	if opts.Baseline {
		basePath := filepath.Join(dir, "baseline-"+p.TS+".txt")
		if err := os.WriteFile(basePath, []byte(p.Baseline()), 0o600); err != nil {
			return res, fmt.Errorf("write baseline: %w", err)
		}
		res.BaselinePath = basePath
	}

	return res, nil
}

// ReadBaselineFile loads and parses a baseline file from disk for diffing.
func ReadBaselineFile(path string) ([]Hole, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline file: %w", err)
	}
	return ParseBaseline(string(data)), nil
}
