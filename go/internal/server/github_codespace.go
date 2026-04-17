// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// GitHub Codespace relay provider.
//
// Creates a GitHub Codespace running the user-supplied relay repo, then
// exposes a forwarded port as a public HTTPS endpoint.  Requires only a
// GitHub account and the `gh` CLI — no cloud tokens, no VPS.
//
// Prerequisites:
//   - `gh` CLI on PATH and authenticated (`gh auth login`)
//   - NOWIFI_CODESPACE_REPO env var OR opts.Extra["repo"] set to a fork of
//     github.com/MikkoParkkola/nowifi-codespace-relay
//
// Security guardrails:
//
//	G1 – Authorization assertion (shared with cloudflare_quick).
//	G3 – No-anonymity disclosure: GitHub logs your account + source IP.
//	     Rendered by setup.go step 6.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

func init() { Register(&githubCodespaceProvider{}) }

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrGhNotInstalled is returned when the `gh` CLI cannot be found.
var ErrGhNotInstalled = errors.New(
	"gh CLI not found — install it first:\n" +
		"  brew install gh\n" +
		"  OR: https://cli.github.com")

// ErrGhNotAuthenticated is returned when `gh auth status` reports no login.
var ErrGhNotAuthenticated = errors.New(
	"not authenticated with GitHub CLI — run:\n" +
		"  gh auth login")

// ErrCodespaceRepoNotConfigured is returned when neither NOWIFI_CODESPACE_REPO
// nor opts.Extra["repo"] specifies the relay repository.
var ErrCodespaceRepoNotConfigured = errors.New(
	"codespace relay repo not configured.\n" +
		"Fork https://github.com/MikkoParkkola/nowifi-codespace-relay then:\n" +
		"  export NOWIFI_CODESPACE_REPO=<your-github-username>/nowifi-codespace-relay\n" +
		"  nowifi server create -p github_codespace")

// ---------------------------------------------------------------------------
// Package-level injection points (overridden in tests)
// ---------------------------------------------------------------------------

// ghRunner is a test-injectable wrapper around exec.Command for `gh` calls.
// Default uses the real gh binary located via findTool.
var ghRunner ghRunnerFunc = realGhRunner

// ghRunnerFunc is the function signature for running gh subcommands.
// Returns combined stdout+stderr output and the exit error.
type ghRunnerFunc func(ctx context.Context, args ...string) ([]byte, error)

func realGhRunner(ctx context.Context, args ...string) ([]byte, error) {
	ghPath := findTool("gh")
	if ghPath == "" {
		return nil, ErrGhNotInstalled
	}
	return exec.CommandContext(ctx, ghPath, args...).CombinedOutput()
}

// ---------------------------------------------------------------------------
// Provider implementation
// ---------------------------------------------------------------------------

type githubCodespaceProvider struct{}

func (githubCodespaceProvider) Name() string { return "github_codespace" }

func (githubCodespaceProvider) Create(ctx context.Context, opts CreateOpts) (*Info, error) {
	return setupGithubCodespace(ctx, opts)
}

func (githubCodespaceProvider) Destroy(ctx context.Context, info *Info, _ string) error {
	return destroyGithubCodespace(ctx, info)
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func setupGithubCodespace(ctx context.Context, opts CreateOpts) (*Info, error) {
	// ── Prerequisite: gh binary ──────────────────────────────────────────────
	if findTool("gh") == "" {
		return nil, ErrGhNotInstalled
	}

	// ── Prerequisite: gh authenticated ──────────────────────────────────────
	if err := checkGhAuth(ctx); err != nil {
		return nil, err
	}

	// ── Prerequisite: relay repo configured ─────────────────────────────────
	repo := os.Getenv("NOWIFI_CODESPACE_REPO")
	if repo == "" && opts.Extra != nil {
		repo = opts.Extra["repo"]
	}
	if repo == "" {
		return nil, ErrCodespaceRepoNotConfigured
	}

	// ── G1: authorization assertion ─────────────────────────────────────────
	if err := assertAuthorizationFor("github_codespace", repo); err != nil {
		return nil, err
	}

	// ── Determine forwarded port ─────────────────────────────────────────────
	port := "8080"
	if opts.Extra != nil && opts.Extra["port"] != "" {
		port = opts.Extra["port"]
	}

	// ── 1. Create codespace ──────────────────────────────────────────────────
	suffix := randomSuffix(6)
	displayName := "nowifi-relay-" + suffix

	createOut, err := ghRunner(ctx,
		"codespace", "create",
		"--repo", repo,
		"--machine", "basicLinux32gb",
		"--display-name", displayName,
	)
	if err != nil {
		return nil, fmt.Errorf("gh codespace create failed: %s: %w",
			truncate(strings.TrimSpace(string(createOut)), 400), err)
	}

	codespaceName := strings.TrimSpace(string(createOut))
	if codespaceName == "" {
		return nil, fmt.Errorf("gh codespace create produced no output")
	}
	// gh codespace create may print only the name or a JSON blob; handle both.
	codespaceName = extractCodespaceName(codespaceName)

	// ── 2. Poll until Available ──────────────────────────────────────────────
	if err := waitForCodespaceAvailable(ctx, codespaceName, 90*time.Second); err != nil {
		// Best-effort cleanup.
		_, _ = ghRunner(context.Background(), "codespace", "delete", "-c", codespaceName, "--force")
		return nil, fmt.Errorf("codespace %q did not become available: %w", codespaceName, err)
	}

	// ── 3. Make port public ──────────────────────────────────────────────────
	visOut, err := ghRunner(ctx,
		"codespace", "ports", "visibility",
		port+":public",
		"-c", codespaceName,
	)
	if err != nil {
		return nil, fmt.Errorf("gh codespace ports visibility failed: %s: %w",
			truncate(strings.TrimSpace(string(visOut)), 400), err)
	}

	// ── 4. Construct forwarded-port URL ──────────────────────────────────────
	// Pattern: https://<codespace-name>-<port>.app.github.dev
	// Verify via `gh codespace ports` if the pattern has changed.
	tunnelURL := fmt.Sprintf("https://%s-%s.app.github.dev", codespaceName, port)

	info := &Info{
		Provider:  "github_codespace",
		ServerID:  codespaceName,
		IP:        "",
		URL:       tunnelURL,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		TTLHours:  opts.TTLHours,
		Status:    "active",
	}

	if err := SaveServer(info); err != nil {
		return info, fmt.Errorf("save server info: %w", err)
	}

	return info, nil
}

// ---------------------------------------------------------------------------
// Destroy
// ---------------------------------------------------------------------------

func destroyGithubCodespace(ctx context.Context, info *Info) error {
	out, err := ghRunner(ctx,
		"codespace", "delete",
		"-c", info.ServerID,
		"--force",
	)
	if err != nil {
		return fmt.Errorf("gh codespace delete failed: %s: %w",
			truncate(strings.TrimSpace(string(out)), 400), err)
	}

	if err := markDestroyed(info.Provider, info.ServerID); err != nil {
		return fmt.Errorf("mark destroyed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// checkGhAuth returns ErrGhNotAuthenticated if `gh auth status` exits non-zero.
func checkGhAuth(ctx context.Context) error {
	out, err := ghRunner(ctx, "auth", "status")
	if err != nil {
		return fmt.Errorf("%w\n(gh auth status: %s)", ErrGhNotAuthenticated,
			truncate(strings.TrimSpace(string(out)), 200))
	}
	return nil
}

// waitForCodespaceAvailable polls `gh codespace view --json state` until state
// is "Available" or the timeout expires.
func waitForCodespaceAvailable(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := ghRunner(ctx, "codespace", "view", "-c", name, "--json", "state")
		if err == nil {
			var v struct {
				State string `json:"state"`
			}
			if jsonErr := json.Unmarshal(out, &v); jsonErr == nil && v.State == "Available" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("timed out after %v waiting for codespace to become Available", timeout)
}

// extractCodespaceName handles both plain-name and JSON output from
// `gh codespace create`.  If it looks like JSON it extracts "name", otherwise
// returns the trimmed string.
func extractCodespaceName(raw string) string {
	raw = strings.TrimSpace(raw)
	// Some gh versions return a JSON object.
	var v struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err == nil && v.Name != "" {
		return v.Name
	}
	// Plain name — take the first line in case of trailing log lines.
	if idx := strings.IndexByte(raw, '\n'); idx > 0 {
		return strings.TrimSpace(raw[:idx])
	}
	return raw
}

// randomSuffix returns a lowercase alphanumeric string of length n.
func randomSuffix(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // non-cryptographic suffix
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}
	return string(b)
}
