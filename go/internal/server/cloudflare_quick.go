// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Cloudflare Quick Tunnel provider.
//
// Uses `cloudflared tunnel --url <target>` which creates an ephemeral
// trycloudflare.com tunnel with no Cloudflare account required.
//
// Security guardrails enforced on every invocation:
//
//	G1 – Authorization assertion: the caller must type "yes" confirming they
//	     are authorised to test the target network. The assertion is appended
//	     to ~/.nowifi/audit.log (0600).
//
//	G3 – Disclosure: rendered by the setup cascade in cli/setup.go before
//	     offering this provider to the user.
package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/server/udpws"
	"github.com/MikkoParkkola/nowifi/internal/toolchain"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrCloudflaredNotInstalled is returned when the cloudflared binary cannot
// be found on PATH or in ~/.nowifi/bin/.
var ErrCloudflaredNotInstalled = errors.New(
	"cloudflared not found — install it first:\n" +
		"  brew install cloudflared\n" +
		"  OR: nowifi tools -d (downloads it to ~/.nowifi/bin/)")

// ErrAuthorizationDeclined is returned when the operator does not confirm
// they are authorised to open a tunnel to the target network.
var ErrAuthorizationDeclined = errors.New("authorization declined — tunnel not started")

// ---------------------------------------------------------------------------
// Package-level injection point (overridden in tests)
// ---------------------------------------------------------------------------

// findTool is the package-level hook for locating a binary.
// Tests override this to simulate tool absence.
var findTool = toolchain.FindTool

// stdinReader is the package-level reader for interactive prompts.
// Tests override this to inject synthetic input.
var stdinReader io.Reader = os.Stdin

// ---------------------------------------------------------------------------
// URL extraction regex (exported for tests)
// ---------------------------------------------------------------------------

// QuickTunnelURLRE matches the ephemeral trycloudflare.com HTTPS URL that
// cloudflared prints to stderr during startup.
var QuickTunnelURLRE = regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

// SetupCloudflareQuickTunnel starts a Cloudflare Quick Tunnel pointing at
// localTarget (e.g. "http://localhost:8080") and returns an *Info once the
// tunnel URL is confirmed.  ttlHours is informational only — the tunnel lives
// until the process is killed (see DestroyServer).
//
// Two mandatory security guardrails are enforced:
//
//	G1: operator must assert authorization before cloudflared is spawned.
//	G3: disclosure rendered by the caller (setup.go cascade).
//
// The caller is responsible for keeping the process alive; cloudflared exits
// when ctx is cancelled.  For foreground use, pass a cancellable context and
// call cmd.Wait() (or use SetupCloudflareQuickTunnelWithOpts which returns a
// Stop func).
func SetupCloudflareQuickTunnel(ctx context.Context, localTarget string, ttlHours int) (*Info, error) {
	info, _, err := launchCloudflaredProcess(ctx, localTarget, ttlHours)
	return info, err
}

// launchCloudflaredProcess is the internal implementation shared by all public
// entry points.  It enforces G1, starts cloudflared, waits for the URL, and
// returns the running *exec.Cmd alongside *Info so the caller can Wait() on it.
func launchCloudflaredProcess(ctx context.Context, localTarget string, ttlHours int) (*Info, *exec.Cmd, error) {
	// ── Prerequisite: cloudflared binary ────────────────────────────────────
	cfPath := findTool("cloudflared")
	if cfPath == "" {
		return nil, nil, ErrCloudflaredNotInstalled
	}

	// ── G1: authorization assertion ─────────────────────────────────────────
	if err := assertAuthorization(localTarget); err != nil {
		return nil, nil, err
	}

	// Do NOT set a distinctive User-Agent or identifier — nowifi must look like
	// ordinary cloudflared traffic to avoid fingerprinting by on-path portals/filters.
	cmd := exec.CommandContext(ctx,
		cfPath,
		"tunnel",
		"--url", localTarget,
		"--metrics", "localhost:0", // bind metrics to a random localhost port, never exposed externally
	)

	// Capture stderr — cloudflared writes the tunnel URL there.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("cloudflared stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("cloudflared start: %w", err)
	}

	// ── Parse tunnel URL from stderr with a 15-second deadline ──────────────
	tunnelURL, err := extractTunnelURL(stderr, 15*time.Second)
	if err != nil {
		// Best-effort kill; ignore error.
		_ = cmd.Process.Kill()
		return nil, nil, fmt.Errorf("waiting for cloudflared URL: %w", err)
	}

	// Derive ServerID from the subdomain (e.g. "shiny-river-42" from URL).
	serverID := extractSubdomain(tunnelURL)

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	info := &Info{
		Provider:  "cloudflare_quick",
		ServerID:  serverID,
		IP:        "",
		URL:       tunnelURL,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		TTLHours:  ttlHours,
		Status:    "active",
		PID:       pid,
	}

	if err := SaveServer(info); err != nil {
		return info, cmd, fmt.Errorf("save server info: %w", err)
	}

	return info, cmd, nil
}

// SetupCloudflareQuickTunnelWithOpts is the opts-aware entry point used both
// by the CLI (foreground, interactive) and the provider registry.
//
// It returns (*Info, stop func(), error).  The stop func must be called when
// the tunnel is no longer needed — it kills cloudflared and, in UDP mode,
// shuts down the in-process udpws.Server.  The stop func is safe to call
// multiple times.
//
// In UDP mode (opts.Extra["udp"] == "true") it also:
//   - Starts an in-process udpws.Server on a random local HTTP port.
//   - Points cloudflared at that HTTP port (ws://<port>/udp → UDP target).
//   - Persists "udp_mode"="true" and "udp_listen"=<local-addr> in Info.Extra.
func SetupCloudflareQuickTunnelWithOpts(ctx context.Context, opts CreateOpts) (*Info, func(), error) {
	target := opts.Target
	if target == "" {
		target = "http://localhost:8080"
	}

	if opts.Extra["udp"] != "true" {
		// Non-UDP path: launch cloudflared, return stop func that kills the child.
		info, cmd, err := launchCloudflaredProcess(ctx, target, opts.TTLHours)
		if err != nil {
			return nil, nil, err
		}
		stop := buildStopFunc(cmd, nil)
		return info, stop, nil
	}

	// ── UDP mode: start in-process WebSocket server ──────────────────────────
	// Parse the UDP backend from target (e.g. "udp://127.0.0.1:51820").
	udpTarget := "127.0.0.1:51820"
	switch {
	case strings.HasPrefix(target, "udp://"):
		udpTarget = strings.TrimPrefix(target, "udp://")
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		// target is an HTTP URL for cloudflared; use default UDP target.
	default:
		udpTarget = target
	}

	srv := &udpws.Server{
		HTTPAddr:  "127.0.0.1:0",
		UDPTarget: udpTarget,
	}
	wsListenAddr, wsStop, err := srv.Serve()
	if err != nil {
		return nil, nil, fmt.Errorf("udpws server: %w", err)
	}

	// Point cloudflared at the WebSocket server's HTTP port.
	wsTarget := "http://" + wsListenAddr

	info, cmd, err := launchCloudflaredProcess(ctx, wsTarget, opts.TTLHours)
	if err != nil {
		wsStop()
		return nil, nil, err
	}

	// Record UDP metadata in Info.Extra.
	if info.Extra == nil {
		info.Extra = make(map[string]string)
	}
	info.Extra["udp_mode"] = "true"
	info.Extra["udp_listen"] = wsListenAddr
	info.Extra["udp_target"] = udpTarget

	if saveErr := SaveServer(info); saveErr != nil {
		wsStop()
		_ = cmd.Process.Kill()
		return nil, nil, fmt.Errorf("save server info (udp): %w", saveErr)
	}

	stop := buildStopFunc(cmd, wsStop)
	return info, stop, nil
}

// buildStopFunc returns a stop closure that kills the cloudflared cmd (SIGTERM
// then SIGKILL after 3 s) and calls wsStop if non-nil.  It is idempotent.
func buildStopFunc(cmd *exec.Cmd, wsStop func()) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Signal(syscall.SIGTERM)
				done := make(chan struct{})
				go func() { _ = cmd.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					_ = cmd.Process.Kill()
					<-done
				}
			}
			if wsStop != nil {
				wsStop()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// G1 – authorization assertion
// ---------------------------------------------------------------------------

// assertAuthorization prints the authorization prompt and reads a line from
// stdinReader.  On "yes" it appends a JSON audit record to ~/.nowifi/audit.log.
func assertAuthorization(localTarget string) error {
	fmt.Print("   I confirm I am authorized to test this network. [yes/NO]: ")

	scanner := bufio.NewScanner(stdinReader)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))

	if answer != "yes" {
		return ErrAuthorizationDeclined
	}

	// Append audit record — create dir/file if missing.
	if err := appendAuditLog(localTarget); err != nil {
		// Non-fatal: log but do not abort. Authorization was given.
		fmt.Fprintf(os.Stderr, "   warn: could not write audit log: %v\n", err)
	}

	return nil
}

type auditEntry struct {
	TS       string `json:"ts"`
	Event    string `json:"event"`
	Provider string `json:"provider"`
	Target   string `json:"target"` // sha256 of localTarget
}

func appendAuditLog(localTarget string) error {
	dir := nowifiDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create ~/.nowifi: %w", err)
	}

	logPath := filepath.Join(dir, "audit.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit.log: %w", err)
	}
	defer f.Close()

	h := sha256.Sum256([]byte(localTarget))
	entry := auditEntry{
		TS:       time.Now().UTC().Format(time.RFC3339),
		Event:    "tunnel_auth_asserted",
		Provider: "cloudflare_quick",
		Target:   fmt.Sprintf("%x", h),
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	_, err = fmt.Fprintf(f, "%s\n", line)
	return err
}

// ---------------------------------------------------------------------------
// URL parsing helpers
// ---------------------------------------------------------------------------

// extractTunnelURL reads lines from r until it finds a trycloudflare.com URL
// or the timeout expires.
func extractTunnelURL(r io.Reader, timeout time.Duration) (string, error) {
	type result struct {
		url string
		err error
	}
	ch := make(chan result, 1)

	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			if m := QuickTunnelURLRE.FindString(line); m != "" {
				ch <- result{url: m}
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ch <- result{err: fmt.Errorf("reading cloudflared stderr: %w", err)}
			return
		}
		ch <- result{err: fmt.Errorf("cloudflared exited without printing a tunnel URL")}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			return "", res.err
		}
		return res.url, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out after %v waiting for cloudflared tunnel URL", timeout)
	}
}

// extractSubdomain returns the hostname label before the first dot, which
// cloudflare uses as the tunnel name (e.g. "shiny-river-42").
func extractSubdomain(tunnelURL string) string {
	// Strip scheme.
	s := strings.TrimPrefix(tunnelURL, "https://")
	// Take the part before ".trycloudflare.com".
	if idx := strings.Index(s, "."); idx > 0 {
		return s[:idx]
	}
	return s
}
