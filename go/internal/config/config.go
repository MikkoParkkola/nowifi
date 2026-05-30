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
// All server URLs are remembered after first use — configure once, use forever.
type Config struct {
	Interface    string `json:"interface,omitempty"`
	TunnelServer string `json:"tunnel_server,omitempty"`
	DNSDomain    string `json:"dns_domain,omitempty"`
	ICMPServer   string `json:"icmp_server,omitempty"`
	CFWorkers    string `json:"cf_workers,omitempty"`
	CFWorkersURL string `json:"cf_workers_url,omitempty"`
	QUICServer   string `json:"quic_server,omitempty"`
	NTPServer    string `json:"ntp_server,omitempty"`
	VPNServer    string `json:"vpn_server,omitempty"`
	DoQServer    string `json:"doq_server,omitempty"`
	HTTP3Server  string `json:"http3_server,omitempty"`
	Stealth      bool   `json:"stealth"`
	AutoLogin    bool   `json:"auto_login"`

	// Wave 21-22 server URLs (persisted for zero-config reuse).
	WSServer        string `json:"ws_server,omitempty"`
	ECHServer       string `json:"ech_server,omitempty"`
	ECHConfigList   string `json:"ech_config_list,omitempty"`
	MASQUEServer    string `json:"masque_server,omitempty"`
	WTServer        string `json:"wt_server,omitempty"`
	H2Proxy         string `json:"h2_proxy,omitempty"`
	SSEServer       string `json:"sse_server,omitempty"`
	GRPCServer      string `json:"grpc_server,omitempty"`
	ConnectIPServer string `json:"connectip_server,omitempty"`

	// ReportFailures controls whether nowifi NOTICES queued unsolved-network
	// forensic reports and PROMPTS to file a GitHub issue when internet is
	// available. It defaults to true, which does NOT violate the opt-in
	// telemetry invariant: it only enables the consent prompt — nothing is ever
	// uploaded without an explicit interactive "y". Set false to disable the
	// notice entirely. No omitempty: an explicit false must persist.
	ReportFailures bool `json:"report_failures"`
}

var (
	cached  *Config
	cacheMu sync.Mutex
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
		Interface:      "en0",
		Stealth:        true,
		ReportFailures: true,
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
	if cfg.CFWorkers == "" && cfg.CFWorkersURL != "" {
		cfg.CFWorkers = cfg.CFWorkersURL
	}
	if cfg.CFWorkersURL == "" && cfg.CFWorkers != "" {
		cfg.CFWorkersURL = cfg.CFWorkers
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

	existing := make(map[string]json.RawMessage)
	if data, err := os.ReadFile(Path()); err == nil {
		_ = json.Unmarshal(data, &existing)
	}

	for key := range knownConfigKeys() {
		delete(existing, key)
	}

	freshData, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var fresh map[string]json.RawMessage
	if err := json.Unmarshal(freshData, &fresh); err != nil {
		return err
	}
	for key, value := range fresh {
		existing[key] = value
	}

	data, err := json.MarshalIndent(existing, "", "  ")
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

func knownConfigKeys() map[string]struct{} {
	return map[string]struct{}{
		"interface":        {},
		"tunnel_server":    {},
		"dns_domain":       {},
		"icmp_server":      {},
		"cf_workers":       {},
		"cf_workers_url":   {},
		"quic_server":      {},
		"ntp_server":       {},
		"vpn_server":       {},
		"doq_server":       {},
		"http3_server":     {},
		"stealth":          {},
		"auto_login":       {},
		"ws_server":        {},
		"ech_server":       {},
		"ech_config_list":  {},
		"masque_server":    {},
		"wt_server":        {},
		"h2_proxy":         {},
		"sse_server":       {},
		"grpc_server":      {},
		"connectip_server": {},
		"report_failures":  {},
	}
}

// InvalidateCache clears the cached config so the next Load reads from disk.
func InvalidateCache() {
	cacheMu.Lock()
	cached = nil
	cacheMu.Unlock()
}
