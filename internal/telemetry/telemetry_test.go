// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package telemetry

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withTempHome points HOME at a temp dir so tests don't touch real config.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func TestTelemetry_DefaultDisabled(t *testing.T) {
	withTempHome(t)
	if IsEnabled() {
		t.Error("telemetry should be disabled by default")
	}
}

func TestTelemetry_EnableDisablePersists(t *testing.T) {
	withTempHome(t)

	if err := Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !IsEnabled() {
		t.Error("IsEnabled=false after Enable")
	}

	if err := Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if IsEnabled() {
		t.Error("IsEnabled=true after Disable")
	}
}

func TestTelemetry_ConfigFilePermissions(t *testing.T) {
	home := withTempHome(t)
	if err := Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	path := filepath.Join(home, ".nowifi", "telemetry.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Permissions should be 0600 (user read/write only).
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestTelemetry_SubmitNoOpWhenDisabled(t *testing.T) {
	withTempHome(t)

	// Stand up a test server that would record a hit if called.
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Save config pointing at test server, but keep disabled.
	cfg := Config{Enabled: false, Endpoint: srv.URL}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	err := SubmitSync(Event{Technique: "test"}, "v0.0.0-test")
	if err != nil {
		t.Errorf("SubmitSync when disabled should return nil, got %v", err)
	}

	if called {
		t.Error("telemetry endpoint hit despite disabled opt-in")
	}
}

func TestTelemetry_SubmitSendsValidJSON(t *testing.T) {
	withTempHome(t)

	var received Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/event" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := Config{Enabled: true, Endpoint: srv.URL}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	evt := Event{
		Technique:  "warp_tunnel",
		Success:    true,
		Provider:   "panasonic_avionics",
		DurationMs: 1234,
	}
	if err := SubmitSync(evt, "v0.12.0"); err != nil {
		t.Fatalf("SubmitSync: %v", err)
	}

	if received.Technique != "warp_tunnel" {
		t.Errorf("technique = %q, want %q", received.Technique, "warp_tunnel")
	}
	if !received.Success {
		t.Error("success = false, want true")
	}
	if received.Provider != "panasonic_avionics" {
		t.Errorf("provider = %q, want %q", received.Provider, "panasonic_avionics")
	}
	if received.DurationMs != 1234 {
		t.Errorf("duration = %d, want 1234", received.DurationMs)
	}
	if received.Version != "v0.12.0" {
		t.Errorf("version = %q, want v0.12.0", received.Version)
	}
	if received.OSArch == "" {
		t.Error("os_arch not populated")
	}
}

func TestTelemetry_SubmitHandlesServerError(t *testing.T) {
	withTempHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	cfg := Config{Enabled: true, Endpoint: srv.URL}
	_ = SaveConfig(cfg)

	err := SubmitSync(Event{Technique: "test"}, "v0")
	if err == nil {
		t.Error("expected error on HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention HTTP 500, got: %v", err)
	}
}

func TestTelemetry_SubmitFireAndForgetNonBlocking(t *testing.T) {
	withTempHome(t)

	// Slow server: 2 seconds to respond.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := Config{Enabled: true, Endpoint: srv.URL}
	_ = SaveConfig(cfg)

	start := time.Now()
	Submit(Event{Technique: "test"}, "v0")
	elapsed := time.Since(start)

	// Fire-and-forget should return almost immediately (< 100ms).
	if elapsed > 100*time.Millisecond {
		t.Errorf("Submit took %v, expected <100ms (fire-and-forget)", elapsed)
	}
}

func TestTelemetry_StatusShowsState(t *testing.T) {
	withTempHome(t)

	s := Status()
	if !strings.Contains(s, "DISABLED") {
		t.Errorf("Status should mention DISABLED when opt-out, got: %s", s)
	}

	_ = Enable()
	s = Status()
	if !strings.Contains(s, "ENABLED") {
		t.Errorf("Status should mention ENABLED after opt-in, got: %s", s)
	}
}

func TestTelemetry_DefaultEndpointIsHTTPS(t *testing.T) {
	if !strings.HasPrefix(DefaultEndpoint, "https://") {
		t.Errorf("DefaultEndpoint should use HTTPS: %q", DefaultEndpoint)
	}
}

func TestTelemetry_EmptyEventRejected(t *testing.T) {
	withTempHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("endpoint should not be called for empty event")
	}))
	defer srv.Close()

	cfg := Config{Enabled: true, Endpoint: srv.URL}
	_ = SaveConfig(cfg)

	// Verify the async fire-and-forget Submit skips empty techniques.
	Submit(Event{}, "v0")
	time.Sleep(200 * time.Millisecond) // Let any goroutine finish.
}
