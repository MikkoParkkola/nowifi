// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

//go:build integration

package server

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/toolchain"
)

// TestGithubCodespace_Integration creates a real Codespace and destroys it.
// Requires: gh installed + authenticated, NOWIFI_CODESPACE_REPO set.
//
// Run with:
//
//	go test -tags integration ./internal/server/... \
//	  -run TestGithubCodespace_Integration -timeout 5m -v
func TestGithubCodespace_Integration(t *testing.T) {
	if toolchain.FindTool("gh") == "" {
		t.Skip("gh not on PATH — skipping integration test")
	}
	repo := os.Getenv("NOWIFI_CODESPACE_REPO")
	if repo == "" {
		t.Skip("NOWIFI_CODESPACE_REPO not set — skipping integration test")
	}

	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })
	stdinReader = strings.NewReader("yes\n")

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	info, err := setupGithubCodespace(ctx, CreateOpts{
		Extra: map[string]string{"repo": repo},
	})
	if err != nil {
		if errors.Is(err, ErrGhNotAuthenticated) {
			t.Skip("gh not authenticated — run: gh auth login")
		}
		t.Fatalf("setupGithubCodespace: %v", err)
	}

	t.Logf("Codespace: %s  URL: %s", info.ServerID, info.URL)

	if !strings.Contains(info.URL, ".app.github.dev") {
		t.Errorf("unexpected URL pattern: %s", info.URL)
	}

	// Teardown.
	if err := destroyGithubCodespace(context.Background(), info); err != nil {
		t.Logf("destroyGithubCodespace: %v (non-fatal)", err)
	}
}
