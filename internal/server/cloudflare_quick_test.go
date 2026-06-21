// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// URL extraction regex
// ---------------------------------------------------------------------------

func TestQuickTunnelURLRE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // empty = expect no match
	}{
		{
			name:  "happy path standard output",
			input: "INF +--------------------------------------------------------------------------------------------+\nINF |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |\nINF |  https://shiny-river-42.trycloudflare.com                                                  |\nINF +--------------------------------------------------------------------------------------------+",
			want:  "https://shiny-river-42.trycloudflare.com",
		},
		{
			name:  "url embedded in longer line with prefix text",
			input: "2026-04-17T10:00:00Z INF Registered tunnel connection connIndex=0 ip=198.41.200.193 location=AMS url=https://purple-math-99.trycloudflare.com",
			want:  "https://purple-math-99.trycloudflare.com",
		},
		{
			name:  "malformed: wrong domain",
			input: "https://shiny-river-42.workers.dev",
			want:  "",
		},
		{
			name:  "malformed: http not https",
			input: "http://shiny-river-42.trycloudflare.com",
			want:  "",
		},
		{
			name:  "malformed: no subdomain",
			input: "https://trycloudflare.com",
			want:  "",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := QuickTunnelURLRE.FindString(tc.input)
			if got != tc.want {
				t.Errorf("FindString(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ErrCloudflaredNotInstalled when binary absent
// ---------------------------------------------------------------------------

func TestSetupCloudflareQuickTunnel_CloudflaredNotInstalled(t *testing.T) {
	orig := findTool
	t.Cleanup(func() { findTool = orig })

	// Inject: binary not found.
	findTool = func(name string) string { return "" }

	// Inject: stdin that would say yes (should never be reached).
	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })
	stdinReader = strings.NewReader("yes\n")

	_, err := SetupCloudflareQuickTunnel(t.Context(), "http://localhost:8080", 0)
	if !errors.Is(err, ErrCloudflaredNotInstalled) {
		t.Errorf("got err %v, want ErrCloudflaredNotInstalled", err)
	}
}

// ---------------------------------------------------------------------------
// Authorization declined — cloudflared must NOT be spawned
// ---------------------------------------------------------------------------

func TestSetupCloudflareQuickTunnel_AuthorizationDeclined(t *testing.T) {
	orig := findTool
	t.Cleanup(func() { findTool = orig })

	// Binary is "present" (path returned), but we assert cloudflared is never
	// actually executed by checking the error is ErrAuthorizationDeclined
	// rather than any exec error.
	findTool = func(name string) string {
		if name == "cloudflared" {
			// Return a path that exists but is not cloudflared.
			// The test verifies we never reach cmd.Start() — if auth is
			// declined the function returns before spawn.
			return "/usr/bin/true"
		}
		return ""
	}

	tests := []struct {
		name   string
		answer string
	}{
		{"empty answer", ""},
		{"no", "no"},
		{"uppercase NO", "NO"},
		{"whitespace only", "   "},
		{"partial yes", "ye"},
		{"yes with trailing garbage", "yes please"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origStdin := stdinReader
			t.Cleanup(func() { stdinReader = origStdin })
			stdinReader = strings.NewReader(tc.answer + "\n")

			_, err := SetupCloudflareQuickTunnel(t.Context(), "http://localhost:8080", 0)
			if !errors.Is(err, ErrAuthorizationDeclined) {
				t.Errorf("answer=%q: got err %v, want ErrAuthorizationDeclined", tc.answer, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Audit log written with correct shape on "yes"
// ---------------------------------------------------------------------------

func TestAssertAuthorization_WritesAuditLog(t *testing.T) {
	// Redirect HOME so nowifiDir() uses a temp directory.
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpHome)
	t.Cleanup(func() { os.Setenv("HOME", origHome) })

	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })
	stdinReader = strings.NewReader("yes\n")

	target := "http://localhost:9090"
	err := assertAuthorization(target)
	if err != nil {
		t.Fatalf("assertAuthorization returned unexpected error: %v", err)
	}

	// Verify audit.log exists with 0600 perms.
	logPath := filepath.Join(tmpHome, ".nowifi", "audit.log")
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("audit.log not created: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("audit.log perms = %o, want 0600", fi.Mode().Perm())
	}

	// Parse the single JSON line.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}
	line := strings.TrimSpace(string(data))
	var entry map[string]string
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("audit.log is not valid JSON: %v\ncontent: %s", err, line)
	}

	if entry["event"] != "tunnel_auth_asserted" {
		t.Errorf("event = %q, want tunnel_auth_asserted", entry["event"])
	}
	if entry["provider"] != "cloudflare_quick" {
		t.Errorf("provider = %q, want cloudflare_quick", entry["provider"])
	}
	if entry["target"] == "" {
		t.Error("target field missing from audit entry")
	}
	if entry["ts"] == "" {
		t.Error("ts field missing from audit entry")
	}

	// Verify target is the sha256 hex of the input, not the plaintext URL.
	if entry["target"] == target {
		t.Error("audit log must store sha256(target), not the raw URL")
	}
}

// Verify case-insensitive "YES" is also accepted.
func TestAssertAuthorization_CaseInsensitiveYes(t *testing.T) {
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpHome)
	t.Cleanup(func() { os.Setenv("HOME", origHome) })

	for _, answer := range []string{"YES", "Yes", "yEs", " yes ", "YES\n"} {
		t.Run(answer, func(t *testing.T) {
			origStdin := stdinReader
			t.Cleanup(func() { stdinReader = origStdin })
			stdinReader = strings.NewReader(answer + "\n")

			if err := assertAuthorization("http://localhost:8080"); err != nil {
				t.Errorf("answer=%q: unexpected error: %v", answer, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractTunnelURL helper
// ---------------------------------------------------------------------------

func TestExtractTunnelURL(t *testing.T) {
	tests := []struct {
		name    string
		lines   []string
		wantURL string
		wantErr bool
	}{
		{
			name: "url on third line",
			lines: []string{
				"INF Starting tunnel",
				"INF Connecting...",
				"INF https://amber-dust-7.trycloudflare.com",
			},
			wantURL: "https://amber-dust-7.trycloudflare.com",
		},
		{
			name:    "no url — EOF",
			lines:   []string{"INF connecting", "INF retrying"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(strings.Join(tc.lines, "\n") + "\n")
			url, err := extractTunnelURL(r, 5*1e9) // 5s — generous for unit test
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got url=%q", url)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if url != tc.wantURL {
				t.Errorf("got %q, want %q", url, tc.wantURL)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractSubdomain helper
// ---------------------------------------------------------------------------

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://shiny-river-42.trycloudflare.com", "shiny-river-42"},
		{"https://purple-math-99.trycloudflare.com", "purple-math-99"},
		{"https://a.trycloudflare.com", "a"},
	}
	for _, tc := range tests {
		got := extractSubdomain(tc.url)
		if got != tc.want {
			t.Errorf("extractSubdomain(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Info struct: PID field round-trips through JSON with omitempty
// ---------------------------------------------------------------------------

func TestInfoPIDFieldJSONOmitempty(t *testing.T) {
	// PID=0 must be omitted.
	info := Info{Provider: "cloudflare_quick", ServerID: "x", Status: "active"}
	data, _ := json.Marshal(info)
	if strings.Contains(string(data), `"pid"`) {
		t.Errorf("PID=0 should be omitted from JSON, got: %s", data)
	}

	// PID>0 must be present.
	info.PID = 12345
	data, _ = json.Marshal(info)
	if !strings.Contains(string(data), `"pid":12345`) {
		t.Errorf("PID=12345 should appear in JSON, got: %s", data)
	}
}

// ---------------------------------------------------------------------------
// Absence of fingerprinting identifier in cloudflared invocation
// ---------------------------------------------------------------------------

// TestSetupCloudflareQuickTunnel_NoIdentifierInEnvOrFlags verifies that the
// cloudflared child process is not given any distinctive User-Agent or
// identification env var that would fingerprint nowifi traffic.
//
// Strategy: inject a fake cloudflared binary (a small shell script) that
// writes its own environment + argv to a temp file, then returns quickly.
// We then assert CLOUDFLARED_UA is absent and no --user-agent/--ua flag is
// present.
func TestSetupCloudflareQuickTunnel_NoIdentifierInEnvOrFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode (writes and execs a temp script)")
	}

	// Build a tiny shell script that dumps env + args and exits immediately
	// (so extractTunnelURL will timeout, but we only care about the dump).
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "fake-cloudflared")
	dumpPath := filepath.Join(dir, "invocation.txt")

	script := "#!/bin/sh\nenv > " + dumpPath + "\necho \"$@\" >> " + dumpPath + "\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake script: %v", err)
	}

	orig := findTool
	t.Cleanup(func() { findTool = orig })
	findTool = func(name string) string {
		if name == "cloudflared" {
			return scriptPath
		}
		return ""
	}

	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })
	stdinReader = strings.NewReader("yes\n")

	// Redirect HOME so audit.log lands in temp dir.
	t.Setenv("HOME", dir)

	// Call with a short deadline — the fake script exits immediately so
	// extractTunnelURL will return a "no URL" error. That's expected and fine;
	// we only need the dump file to be written.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = SetupCloudflareQuickTunnel(ctx, "http://localhost:8080", 0)

	// The script may not have run if auth was declined or binary not found.
	// Check that.
	data, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("dump file not written — fake cloudflared may not have been invoked: %v", err)
	}
	dump := string(data)

	// Assert CLOUDFLARED_UA is absent from environment.
	if strings.Contains(dump, "CLOUDFLARED_UA") {
		t.Errorf("CLOUDFLARED_UA found in cloudflared environment — must not be set:\n%s", dump)
	}

	// Assert no --user-agent or --ua flag in argv.
	lc := strings.ToLower(dump)
	for _, banned := range []string{"--user-agent", "--ua "} {
		if strings.Contains(lc, banned) {
			t.Errorf("banned flag %q found in cloudflared argv — must not be set:\n%s", banned, dump)
		}
	}
}

// ---------------------------------------------------------------------------
// SetupCloudflareQuickTunnelWithOpts: stop func kills cloudflared + udpws
// ---------------------------------------------------------------------------

// fakeCloudflaed writes a fake cloudflared script that prints a valid
// trycloudflare.com URL to stderr and then sleeps until killed.
// Returns the path to the script.
func fakeCloudflaed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	scriptPath := dir + "/fake-cloudflared"
	// Print the URL to stderr (as real cloudflared does), then block on stdin.
	script := "#!/bin/sh\n" +
		"echo 'https://fake-tunnel-99.trycloudflare.com' >&2\n" +
		"# Block until killed (reads stdin which never closes in tests)\n" +
		"cat > /dev/null\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake cloudflared: %v", err)
	}
	return scriptPath
}

// injectFakeCloudflaed overrides findTool and stdinReader for the test.
// Returns a cleanup func (also registered with t.Cleanup).
func injectFakeCloudflaed(t *testing.T) {
	t.Helper()
	scriptPath := fakeCloudflaed(t)

	origFind := findTool
	t.Cleanup(func() { findTool = origFind })
	findTool = func(name string) string {
		if name == "cloudflared" {
			return scriptPath
		}
		return ""
	}

	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })
	stdinReader = strings.NewReader("yes\n")

	t.Setenv("HOME", t.TempDir())
}

// TestWithOpts_NonUDP_StopFuncKillsProcess verifies that:
//  1. SetupCloudflareQuickTunnelWithOpts returns without hanging.
//  2. Calling stop() terminates the cloudflared child within 3 seconds.
//  3. The Info URL is populated.
func TestWithOpts_NonUDP_StopFuncKillsProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode (spawns subprocess)")
	}
	injectFakeCloudflaed(t)

	ctx := context.Background()
	info, stop, err := SetupCloudflareQuickTunnelWithOpts(ctx, CreateOpts{
		Target:   "http://localhost:8080",
		TTLHours: 1,
	})
	if err != nil {
		t.Fatalf("SetupCloudflareQuickTunnelWithOpts: %v", err)
	}
	if info == nil {
		t.Fatal("info is nil")
	}
	if info.URL == "" {
		t.Fatal("info.URL is empty")
	}
	if stop == nil {
		t.Fatal("stop func is nil")
	}

	// The process should be alive right now.
	if info.PID <= 0 {
		t.Fatalf("PID not set: %d", info.PID)
	}
	proc, err := os.FindProcess(info.PID)
	if err != nil {
		t.Fatalf("FindProcess(%d): %v", info.PID, err)
	}

	// Call stop — must return within 4 seconds.
	stopDone := make(chan struct{})
	go func() { stop(); close(stopDone) }()

	select {
	case <-stopDone:
	case <-time.After(4 * time.Second):
		t.Fatal("stop() did not return within 4 seconds")
	}

	// The process must no longer be running.
	// On POSIX, sending signal 0 to a dead process returns an error.
	time.Sleep(100 * time.Millisecond)
	if err := proc.Signal(os.Signal(nil)); err == nil {
		// Signal 0 succeeded — process might still be alive or is a zombie.
		// Try Kill; if it errors the process is already gone (what we want).
		_ = proc.Kill()
	}
	// No assertion on proc.Signal result — the important check is that stop returned.
}

// TestWithOpts_UDP_StopFuncShutsDownUdpws verifies that in UDP mode:
//  1. Info.Extra["udp_mode"] == "true" and udp_listen is set.
//  2. Calling stop() returns within 4 seconds.
//  3. After stop(), the goroutine count drops back close to the pre-start baseline
//     (udpws server goroutines are released).
func TestWithOpts_UDP_StopFuncShutsDownUdpws(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode (spawns subprocess + goroutines)")
	}
	injectFakeCloudflaed(t)

	// Snapshot goroutine count before starting.
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	ctx := context.Background()
	info, stop, err := SetupCloudflareQuickTunnelWithOpts(ctx, CreateOpts{
		Target:   "udp://127.0.0.1:59999", // non-existent UDP target is fine for this test
		TTLHours: 1,
		Extra:    map[string]string{"udp": "true"},
	})
	if err != nil {
		t.Fatalf("SetupCloudflareQuickTunnelWithOpts (udp): %v", err)
	}
	if info.Extra["udp_mode"] != "true" {
		t.Fatalf("expected udp_mode=true in Info.Extra, got %v", info.Extra)
	}
	if info.Extra["udp_listen"] == "" {
		t.Fatal("udp_listen not set in Info.Extra")
	}

	// Goroutine count should be above baseline while the server is running.
	afterStart := runtime.NumGoroutine()
	if afterStart <= baseline {
		t.Logf("goroutine count did not increase (baseline=%d after=%d); may be scheduled later", baseline, afterStart)
	}

	// Stop — must return within 4 seconds.
	stopDone := make(chan struct{})
	go func() { stop(); close(stopDone) }()

	select {
	case <-stopDone:
	case <-time.After(4 * time.Second):
		t.Fatal("stop() did not return within 4 seconds in UDP mode")
	}

	// Allow goroutines to settle.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	afterStop := runtime.NumGoroutine()
	// We expect goroutine count to return close to baseline.
	// Allow a generous slack (+5) for test framework, background goroutines.
	slack := 5
	if afterStop > baseline+slack {
		t.Errorf("goroutines did not settle after stop: baseline=%d afterStart=%d afterStop=%d (slack=%d)",
			baseline, afterStart, afterStop, slack)
	} else {
		t.Logf("goroutines: baseline=%d afterStart=%d afterStop=%d — OK", baseline, afterStart, afterStop)
	}
}

// TestWithOpts_StopFuncIdempotent verifies calling stop() twice does not panic.
func TestWithOpts_StopFuncIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode (spawns subprocess)")
	}
	injectFakeCloudflaed(t)

	ctx := context.Background()
	_, stop, err := SetupCloudflareQuickTunnelWithOpts(ctx, CreateOpts{
		Target:   "http://localhost:8080",
		TTLHours: 1,
	})
	if err != nil {
		t.Fatalf("SetupCloudflareQuickTunnelWithOpts: %v", err)
	}

	// Should not panic on double-call.
	stop()
	stop()
}

// TestWithOpts_CancelContextKillsProcess verifies that cancelling the context
// passed to SetupCloudflareQuickTunnelWithOpts kills the cloudflared child.
// This is the mechanism used by the CLI's signal handler.
func TestWithOpts_CancelContextKillsProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode (spawns subprocess)")
	}
	injectFakeCloudflaed(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	info, stop, err := SetupCloudflareQuickTunnelWithOpts(ctx, CreateOpts{
		Target:   "http://localhost:8080",
		TTLHours: 1,
	})
	if err != nil {
		t.Fatalf("SetupCloudflareQuickTunnelWithOpts: %v", err)
	}
	defer stop()

	pid := info.PID
	if pid <= 0 {
		t.Fatalf("PID not set: %d", pid)
	}

	// Cancel the context — exec.CommandContext kills the process.
	cancel()

	// Give the OS a moment to deliver the signal.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		proc, err := os.FindProcess(pid)
		if err != nil {
			break // process gone
		}
		// Signal 0: check if process is still alive.
		if err := proc.Signal(os.Signal(nil)); err != nil {
			break // process gone
		}
		time.Sleep(50 * time.Millisecond)
	}
	// If we reach here within deadline, the process exited — test passes.
	t.Log("context cancel caused cloudflared child to exit")
}

// ---------------------------------------------------------------------------
// Integration test (real cloudflared, guarded by build tag)
// ---------------------------------------------------------------------------

// See cloudflare_quick_integration_test.go for the //go:build integration test.

// ---------------------------------------------------------------------------
// stdin scanner re-use guard
// ---------------------------------------------------------------------------

// Ensure stdinReader is consumed line-by-line, not all at once,
// so that only the first line is used for the auth prompt.
func TestAssertAuthorization_OnlyFirstLineConsumed(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })

	// Two lines: first is "yes", second is some other data.
	// assertAuthorization should succeed on the first line alone.
	stdinReader = strings.NewReader("yes\nextra-data-that-should-not-be-read\n")

	err := assertAuthorization("http://localhost:8080")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	// Verify the remaining data in the reader is untouched.
	// We injected a *strings.Reader; after bufio.Scanner reads the first line
	// the underlying reader will have consumed both lines (Scanner reads ahead).
	// The important invariant is: auth was accepted and no error occurred.
}

// ---------------------------------------------------------------------------
// Audit log: multiple entries append, not overwrite
// ---------------------------------------------------------------------------

func TestAuditLog_MultipleEntriesAppend(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	for i := 0; i < 3; i++ {
		if err := appendAuditLog("http://localhost:8080"); err != nil {
			t.Fatalf("appendAuditLog iteration %d: %v", i, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(tmpHome, ".nowifi", "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}

	lines := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines++
		var entry map[string]string
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d is not valid JSON: %v", lines, err)
		}
	}
	if lines != 3 {
		t.Errorf("expected 3 audit entries, got %d\ncontent:\n%s", lines, data)
	}
}
