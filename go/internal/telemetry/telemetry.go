// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package telemetry provides anonymous, opt-in usage reporting for nowifi.
//
// Purpose: aggregate which bypass techniques succeed against which captive
// portal providers to inform security research and improve client-side
// technique ordering over time.
//
// PRIVACY MODEL:
//   - Opt-in only. Disabled by default. User explicitly enables via CLI.
//   - No IP, MAC, SSID, portal URL, or DNS names are ever collected.
//   - Each event is independent — no session/user identifier.
//   - Endpoint is a single public Cloudflare Worker (free tier).
//
// CONFIG:
//   ~/.nowifi/telemetry.json  — stores the opt-in flag only
//
// USAGE (internal):
//   telemetry.Submit(Event{Technique: "warp_tunnel", Success: true, ...})
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// DefaultEndpoint is the public nowifi telemetry Cloudflare Worker.
// Users can override via ~/.nowifi/telemetry.json "endpoint" field.
const DefaultEndpoint = "https://nowifi-telemetry.mikkoparkkola.workers.dev"

// Event is the payload sent per bypass attempt.
// Field names match the worker's JSON schema.
type Event struct {
	Technique  string `json:"technique"`
	Success    bool   `json:"success"`
	Provider   string `json:"provider,omitempty"`
	DurationMs int    `json:"duration_ms"`
	Version    string `json:"version"`
	OSArch     string `json:"os_arch"`
}

// Config controls opt-in state and endpoint.
type Config struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint,omitempty"`
}

// configFile returns the path to ~/.nowifi/telemetry.json.
func configFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".nowifi", "telemetry.json")
}

// LoadConfig reads the telemetry config from disk.
// Returns an empty Config (disabled) if the file doesn't exist.
func LoadConfig() Config {
	path := configFile()
	if path == "" {
		return Config{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}
	}
	return cfg
}

// SaveConfig persists the config to disk with 0600 permissions.
func SaveConfig(cfg Config) error {
	path := configFile()
	if path == "" {
		return fmt.Errorf("no home directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Enable opts the user in to telemetry and persists the choice.
func Enable() error {
	cfg := LoadConfig()
	cfg.Enabled = true
	return SaveConfig(cfg)
}

// Disable opts the user out.
func Disable() error {
	cfg := LoadConfig()
	cfg.Enabled = false
	return SaveConfig(cfg)
}

// IsEnabled reports whether the user has opted in.
func IsEnabled() bool {
	return LoadConfig().Enabled
}

// Endpoint returns the configured or default endpoint URL.
func Endpoint() string {
	cfg := LoadConfig()
	if cfg.Endpoint != "" {
		return cfg.Endpoint
	}
	return DefaultEndpoint
}

// client is shared across Submit calls so connections can be reused.
var (
	clientOnce sync.Once
	client     *http.Client
)

func getClient() *http.Client {
	clientOnce.Do(func() {
		client = &http.Client{
			Timeout: 5 * time.Second,
		}
	})
	return client
}

// Submit sends an event to the telemetry endpoint. Non-blocking: if opt-in is
// disabled or the send fails, no error is surfaced to the caller. Fire-and-forget.
//
// The function spawns a goroutine so the caller is never blocked on network I/O.
func Submit(e Event, version string) {
	if !IsEnabled() {
		return
	}
	if e.Technique == "" {
		return
	}
	if e.Version == "" {
		e.Version = version
	}
	if e.OSArch == "" {
		e.OSArch = runtime.GOOS + "/" + runtime.GOARCH
	}

	go func() {
		sendEvent(e) //nolint:errcheck // fire-and-forget
	}()
}

// SubmitSync sends an event and returns any error. Used for testing.
func SubmitSync(e Event, version string) error {
	if !IsEnabled() {
		return nil
	}
	if e.Version == "" {
		e.Version = version
	}
	if e.OSArch == "" {
		e.OSArch = runtime.GOOS + "/" + runtime.GOARCH
	}
	return sendEvent(e)
}

func sendEvent(e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Endpoint()+"/event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nowifi-telemetry/1")

	resp, err := getClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("telemetry: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Status returns human-readable status text for the CLI.
func Status() string {
	cfg := LoadConfig()
	path := configFile()
	state := "DISABLED (opt-in required)"
	if cfg.Enabled {
		state = "ENABLED"
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint + " (default)"
	}
	return fmt.Sprintf("State:    %s\nEndpoint: %s\nConfig:   %s", state, endpoint, path)
}
