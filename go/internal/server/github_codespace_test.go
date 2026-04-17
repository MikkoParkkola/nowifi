// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers: inject fake gh runner + stdin
// ---------------------------------------------------------------------------

// withFakeGh replaces ghRunner for the duration of the test.
func withFakeGh(t *testing.T, fn ghRunnerFunc) {
	t.Helper()
	orig := ghRunner
	t.Cleanup(func() { ghRunner = orig })
	ghRunner = fn
}

// withStdinCS injects a string as stdin for the duration of the test.
// (named to avoid collision with withStdin in other test files in same package)
func withStdinCS(t *testing.T, s string) {
	t.Helper()
	orig := stdinReader
	t.Cleanup(func() { stdinReader = orig })
	stdinReader = strings.NewReader(s)
}

// withGhPresent makes findTool return a non-empty path for "gh".
func withGhPresent(t *testing.T) {
	t.Helper()
	orig := findTool
	t.Cleanup(func() { findTool = orig })
	findTool = func(name string) string {
		if name == "gh" {
			return "/usr/local/bin/gh"
		}
		return orig(name)
	}
}

// withGhAbsent makes findTool return "" for "gh".
func withGhAbsent(t *testing.T) {
	t.Helper()
	orig := findTool
	t.Cleanup(func() { findTool = orig })
	findTool = func(name string) string {
		if name == "gh" {
			return ""
		}
		return orig(name)
	}
}

// ---------------------------------------------------------------------------
// ErrGhNotInstalled when gh binary absent
// ---------------------------------------------------------------------------

func TestGithubCodespace_GhNotInstalled(t *testing.T) {
	withGhAbsent(t)
	withStdinCS(t, "yes\n")

	_, err := setupGithubCodespace(t.Context(), CreateOpts{
		Extra: map[string]string{"repo": "user/nowifi-codespace-relay"},
	})
	if !errors.Is(err, ErrGhNotInstalled) {
		t.Errorf("got %v, want ErrGhNotInstalled", err)
	}
}

// ---------------------------------------------------------------------------
// ErrGhNotAuthenticated when gh auth status fails
// ---------------------------------------------------------------------------

func TestGithubCodespace_GhNotAuthenticated(t *testing.T) {
	withGhPresent(t)
	withStdinCS(t, "yes\n")

	withFakeGh(t, func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "auth" {
			return []byte("not logged in"), fmt.Errorf("exit status 1")
		}
		return nil, nil
	})

	_, err := setupGithubCodespace(t.Context(), CreateOpts{
		Extra: map[string]string{"repo": "user/nowifi-codespace-relay"},
	})
	if !errors.Is(err, ErrGhNotAuthenticated) {
		t.Errorf("got %v, want ErrGhNotAuthenticated", err)
	}
}

// ---------------------------------------------------------------------------
// ErrCodespaceRepoNotConfigured when repo unset
// ---------------------------------------------------------------------------

func TestGithubCodespace_RepoNotConfigured(t *testing.T) {
	withGhPresent(t)
	withStdinCS(t, "yes\n")

	withFakeGh(t, func(_ context.Context, args ...string) ([]byte, error) {
		return []byte("Logged in to github.com"), nil
	})

	t.Setenv("NOWIFI_CODESPACE_REPO", "")

	_, err := setupGithubCodespace(t.Context(), CreateOpts{})
	if !errors.Is(err, ErrCodespaceRepoNotConfigured) {
		t.Errorf("got %v, want ErrCodespaceRepoNotConfigured", err)
	}
}

// ---------------------------------------------------------------------------
// Authorization declined before gh codespace create is called
// ---------------------------------------------------------------------------

func TestGithubCodespace_AuthDeclined(t *testing.T) {
	withGhPresent(t)
	withStdinCS(t, "no\n")

	calls := 0
	withFakeGh(t, func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if len(args) > 0 && args[0] == "auth" {
			return []byte("ok"), nil
		}
		return nil, nil
	})

	_, err := setupGithubCodespace(t.Context(), CreateOpts{
		Extra: map[string]string{"repo": "user/nowifi-codespace-relay"},
	})
	if !errors.Is(err, ErrAuthorizationDeclined) {
		t.Errorf("got %v, want ErrAuthorizationDeclined", err)
	}
	// Only the auth check should have run; codespace create must not be called.
	if calls > 1 {
		t.Errorf("expected at most 1 gh call (auth check), got %d", calls)
	}
}

// ---------------------------------------------------------------------------
// Happy-path URL construction
// ---------------------------------------------------------------------------

func TestGithubCodespace_HappyPathURL(t *testing.T) {
	withGhPresent(t)
	withStdinCS(t, "yes\n")
	t.Setenv("HOME", t.TempDir())

	const fakeName = "fictional-rotting-xyz123"

	withFakeGh(t, func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) == 0 {
			return nil, nil
		}
		switch args[0] {
		case "auth":
			return []byte("Logged in to github.com"), nil
		case "codespace":
			if len(args) < 2 {
				return nil, nil
			}
			switch args[1] {
			case "create":
				return []byte(fakeName + "\n"), nil
			case "view":
				return []byte(`{"state":"Available"}`), nil
			case "ports":
				return []byte(""), nil
			}
		}
		return nil, nil
	})

	info, err := setupGithubCodespace(t.Context(), CreateOpts{
		Extra: map[string]string{"repo": "user/nowifi-codespace-relay"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURL := fmt.Sprintf("https://%s-8080.app.github.dev", fakeName)
	if info.URL != wantURL {
		t.Errorf("URL = %q, want %q", info.URL, wantURL)
	}
	if info.ServerID != fakeName {
		t.Errorf("ServerID = %q, want %q", info.ServerID, fakeName)
	}
	if info.Provider != "github_codespace" {
		t.Errorf("Provider = %q, want github_codespace", info.Provider)
	}
}

// ---------------------------------------------------------------------------
// Custom port propagated to URL
// ---------------------------------------------------------------------------

func TestGithubCodespace_CustomPort(t *testing.T) {
	withGhPresent(t)
	withStdinCS(t, "yes\n")
	t.Setenv("HOME", t.TempDir())

	const fakeName = "custom-port-codespace"

	withFakeGh(t, func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) == 0 {
			return nil, nil
		}
		switch args[0] {
		case "auth":
			return []byte("ok"), nil
		case "codespace":
			if len(args) < 2 {
				return nil, nil
			}
			switch args[1] {
			case "create":
				return []byte(fakeName), nil
			case "view":
				return []byte(`{"state":"Available"}`), nil
			case "ports":
				return []byte(""), nil
			}
		}
		return nil, nil
	})

	info, err := setupGithubCodespace(t.Context(), CreateOpts{
		Extra: map[string]string{
			"repo": "user/relay",
			"port": "3000",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(info.URL, "-3000.app.github.dev") {
		t.Errorf("URL %q should contain -3000.app.github.dev", info.URL)
	}
}

// ---------------------------------------------------------------------------
// Destroy command shape
// ---------------------------------------------------------------------------

func TestGithubCodespace_DestroyCommandShape(t *testing.T) {
	withGhPresent(t)
	t.Setenv("HOME", t.TempDir())

	var capturedArgs []string
	withFakeGh(t, func(_ context.Context, args ...string) ([]byte, error) {
		capturedArgs = append(capturedArgs, args...)
		return []byte(""), nil
	})

	info := &Info{
		Provider: "github_codespace",
		ServerID: "my-codespace-name",
		Status:   "active",
	}

	err := destroyGithubCodespace(context.Background(), info)
	if err != nil {
		t.Fatalf("destroyGithubCodespace: %v", err)
	}

	joined := strings.Join(capturedArgs, " ")
	for _, must := range []string{"codespace", "delete", "-c", "my-codespace-name", "--force"} {
		if !strings.Contains(joined, must) {
			t.Errorf("expected %q in gh args %q", must, joined)
		}
	}
}

// ---------------------------------------------------------------------------
// extractCodespaceName handles plain-name and JSON output
// ---------------------------------------------------------------------------

func TestExtractCodespaceName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-codespace\n", "my-codespace"},
		{`{"name":"json-codespace"}`, "json-codespace"},
		{"first-line\nsecond-line", "first-line"},
		{"plain-no-newline", "plain-no-newline"},
	}
	for _, tc := range tests {
		got := extractCodespaceName(tc.input)
		if got != tc.want {
			t.Errorf("extractCodespaceName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Provider is registered in the global registry
// ---------------------------------------------------------------------------

func TestGithubCodespaceRegistered(t *testing.T) {
	p, ok := Get("github_codespace")
	if !ok {
		t.Fatal("github_codespace not in registry")
	}
	if p.Name() != "github_codespace" {
		t.Errorf("Name() = %q, want github_codespace", p.Name())
	}
}

// ---------------------------------------------------------------------------
// waitForCodespaceAvailable returns error on timeout
// ---------------------------------------------------------------------------

func TestWaitForCodespaceAvailable_Timeout(t *testing.T) {
	withGhPresent(t)
	withFakeGh(t, func(_ context.Context, args ...string) ([]byte, error) {
		return []byte(`{"state":"Provisioning"}`), nil
	})

	err := waitForCodespaceAvailable(context.Background(), "some-cs", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Integration test (real gh, guarded by build tag)
// ---------------------------------------------------------------------------

// See github_codespace_integration_test.go for the //go:build integration test.
