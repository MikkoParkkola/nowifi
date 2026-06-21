// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

//go:build integration

package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/toolchain"
)

// TestSetupCloudflareQuickTunnel_Integration calls real cloudflared.
// Run with: go test -tags integration ./internal/server/... -run Integration -timeout 60s
func TestSetupCloudflareQuickTunnel_Integration(t *testing.T) {
	if toolchain.FindTool("cloudflared") == "" {
		t.Skip("cloudflared not on PATH — skipping integration test")
	}

	// Inject "yes" for authorization prompt.
	origStdin := stdinReader
	t.Cleanup(func() { stdinReader = origStdin })
	stdinReader = strings.NewReader("yes\n")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := SetupCloudflareQuickTunnel(ctx, "http://localhost:8080", 0)
	if err != nil {
		if errors.Is(err, ErrAuthorizationDeclined) {
			t.Fatal("authorization was not accepted despite injecting 'yes'")
		}
		// Other errors (network, cloudflared startup) are acceptable in CI.
		t.Logf("SetupCloudflareQuickTunnel returned error (may be network): %v", err)
		return
	}

	t.Logf("Tunnel URL: %s  PID: %d  ServerID: %s", info.URL, info.PID, info.ServerID)

	if !strings.Contains(info.URL, ".trycloudflare.com") {
		t.Errorf("unexpected tunnel URL: %s", info.URL)
	}
	if info.PID == 0 {
		t.Error("PID should be non-zero for a running tunnel")
	}

	// Teardown: kill the tunnel process.
	if err := DestroyServer(info, ""); err != nil {
		t.Logf("DestroyServer: %v (non-fatal)", err)
	}
}
