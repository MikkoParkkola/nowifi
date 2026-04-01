// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package config manages persistent configuration stored in ~/.nowifi/config.json.
//
// When a CLI flag is not explicitly set by the user, the config value is used as
// the fallback default. If no config file exists, sensible defaults are returned.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Config holds the persistent settings for nowifi.
type Config struct {
	Interface    string `json:"interface,omitempty"`
	TunnelServer string `json:"tunnel_server,omitempty"`
	DNSDomain    string `json:"dns_domain,omitempty"`
	ICMPServer   string `json:"icmp_server,omitempty"`
	CFWorkers    string `json:"cf_workers,omitempty"`
	QUICServer   string `json:"quic_server,omitempty"`
	NTPServer    string `json:"ntp_server,omitempty"`
	Stealth      bool   `json:"stealth"`
	AutoLogin    bool   `json:"auto_login"`
}

var (
	cached   *Config
	cacheMu  sync.Mutex
)

// Dir returns the nowifi configuration directory (~/.nowifi).
func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback if HOME is not set.
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".nowifi")
}

// Path returns the path to the config file.
func Path() string {
	return filepath.Join(Dir(), "config.json")
}

// Defaults returns the default configuration.
func Defaults() *Config {
	return &Config{
		Interface: "en0",
		Stealth:   true,
	}
}

// Load reads the config from ~/.nowifi/config.json.
// Returns defaults if the file does not exist.
func Load() (*Config, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if cached != nil {
		return cached, nil
	}

	cfg := Defaults()

	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			cached = cfg
			return cfg, nil
		}
		return cfg, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return Defaults(), err
	}

	cached = cfg
	return cfg, nil
}

// Save writes the config to ~/.nowifi/config.json, creating the directory
// if it does not exist.
func Save(c *Config) error {
	dir := Dir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically: write to temp then rename.
	tmp := Path() + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, Path()); err != nil {
		os.Remove(tmp)
		return err
	}

	cacheMu.Lock()
	cached = c
	cacheMu.Unlock()

	return nil
}

// InvalidateCache clears the cached config so the next Load reads from disk.
func InvalidateCache() {
	cacheMu.Lock()
	cached = nil
	cacheMu.Unlock()
}
