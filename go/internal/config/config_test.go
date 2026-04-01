// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Interface != "en0" {
		t.Errorf("default Interface = %q, want en0", cfg.Interface)
	}
	if !cfg.Stealth {
		t.Error("default Stealth should be true")
	}
	if cfg.TunnelServer != "" {
		t.Errorf("default TunnelServer = %q, want empty", cfg.TunnelServer)
	}
}

func TestDir(t *testing.T) {
	d := Dir()
	if d == "" {
		t.Fatal("Dir() returned empty string")
	}
	if filepath.Base(d) != ".nowifi" {
		t.Errorf("Dir() = %q, want to end with .nowifi", d)
	}
}

func TestPath(t *testing.T) {
	p := Path()
	if filepath.Base(p) != "config.json" {
		t.Errorf("Path() = %q, want to end with config.json", p)
	}
}

func TestLoadMissing(t *testing.T) {
	// Point to a temp directory that does not have config.json.
	InvalidateCache()

	// Save and restore HOME.
	origHome := os.Getenv("HOME")
	tmp := t.TempDir()
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)
	defer InvalidateCache()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil (missing file = defaults)", err)
	}
	if cfg.Interface != "en0" {
		t.Errorf("Interface = %q, want en0 (default)", cfg.Interface)
	}
}

func TestSaveAndLoad(t *testing.T) {
	InvalidateCache()

	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)
	defer InvalidateCache()

	cfg := &Config{
		Interface:    "wlan0",
		TunnelServer: "https://tunnel.example.com",
		Stealth:      false,
		AutoLogin:    true,
	}

	if err := Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file was written.
	data, err := os.ReadFile(filepath.Join(tmp, ".nowifi", "config.json"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if loaded.Interface != "wlan0" {
		t.Errorf("loaded Interface = %q, want wlan0", loaded.Interface)
	}
	if loaded.TunnelServer != "https://tunnel.example.com" {
		t.Errorf("loaded TunnelServer = %q", loaded.TunnelServer)
	}
	if loaded.Stealth {
		t.Error("loaded Stealth should be false")
	}
	if !loaded.AutoLogin {
		t.Error("loaded AutoLogin should be true")
	}

	// Test Load reads back correctly.
	InvalidateCache()
	cfg2, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg2.Interface != "wlan0" {
		t.Errorf("Load().Interface = %q, want wlan0", cfg2.Interface)
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	InvalidateCache()

	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)
	defer InvalidateCache()

	// .nowifi dir should not exist yet.
	dir := filepath.Join(tmp, ".nowifi")
	if _, err := os.Stat(dir); err == nil {
		t.Fatal(".nowifi dir should not exist before Save")
	}

	if err := Save(Defaults()); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf(".nowifi dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error(".nowifi should be a directory")
	}
}

func TestCacheInvalidation(t *testing.T) {
	InvalidateCache()

	tmp := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", origHome)
	defer InvalidateCache()

	// First load sets cache.
	cfg1, _ := Load()
	cfg1.Interface = "en0" // default

	// Save a different config.
	Save(&Config{Interface: "wlan1"})

	// Without invalidation, cache returns old value.
	cfg2, _ := Load()
	if cfg2.Interface != "wlan1" {
		// Save() updates the cache too, so this should be wlan1.
		t.Errorf("cached config should be wlan1 after Save, got %q", cfg2.Interface)
	}
}
