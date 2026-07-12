// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package toolchain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// FindTool — additional coverage
// ---------------------------------------------------------------------------

func TestFindTool_CommonTools(t *testing.T) {
	// Tools that should exist on any development machine.
	tools := []string{"go", "ls"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			path := FindTool(tool)
			if path == "" {
				t.Skipf("%s not found in PATH — skipping", tool)
			}
			if !filepath.IsAbs(path) {
				t.Errorf("FindTool(%q) = %q, expected absolute path", tool, path)
			}
		})
	}
}

func TestFindTool_EmptyName(t *testing.T) {
	path := FindTool("")
	if path != "" {
		t.Errorf("FindTool(\"\") = %q, want empty", path)
	}
}

func TestFindTool_PathTraversal(t *testing.T) {
	path := FindTool("../../etc/passwd")
	if path != "" {
		t.Errorf("FindTool with path traversal = %q, want empty", path)
	}
}

// ---------------------------------------------------------------------------
// ToolNotFoundError — additional coverage
// ---------------------------------------------------------------------------

func TestToolNotFoundError_ErrorInterface(t *testing.T) {
	var err error = &ToolNotFoundError{Tool: "mytool", InstallHint: "apt install mytool"}

	// Test errors.As.
	var tnf *ToolNotFoundError
	if !errors.As(err, &tnf) {
		t.Error("errors.As should match *ToolNotFoundError")
	}
	if tnf.Tool != "mytool" {
		t.Errorf("Tool = %q, want mytool", tnf.Tool)
	}
	if tnf.InstallHint != "apt install mytool" {
		t.Errorf("InstallHint = %q", tnf.InstallHint)
	}
}

func TestToolNotFoundError_EmptyFields(t *testing.T) {
	err := &ToolNotFoundError{}
	s := err.Error()
	if s == "" {
		t.Error("Error() should return non-empty even with empty fields")
	}
	if !strings.Contains(s, "not found") {
		t.Errorf("Error() = %q, should contain 'not found'", s)
	}
}

// ---------------------------------------------------------------------------
// expandTemplate — additional coverage
// ---------------------------------------------------------------------------

func TestExpandTemplate_ChiselURL(t *testing.T) {
	tmpl := "https://github.com/jpillora/chisel/releases/download/v{version}/chisel_{version}_{os}_{arch}.gz"
	vars := map[string]string{
		"version": "1.10.1",
		"os":      "darwin",
		"arch":    "arm64",
	}
	got := expandTemplate(tmpl, vars)
	want := "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_darwin_arm64.gz"
	if got != want {
		t.Errorf("expandTemplate chisel = %q, want %q", got, want)
	}
}

func TestExpandTemplate_HysteriaURL(t *testing.T) {
	tmpl := "https://github.com/apernet/hysteria/releases/download/app%2Fv{version}/hysteria-{os}-{arch}"
	vars := map[string]string{
		"version": "2.6.1",
		"os":      "linux",
		"arch":    "amd64",
	}
	got := expandTemplate(tmpl, vars)
	want := "https://github.com/apernet/hysteria/releases/download/app%2Fv2.6.1/hysteria-linux-amd64"
	if got != want {
		t.Errorf("expandTemplate hysteria = %q, want %q", got, want)
	}
}

func TestExpandTemplate_NoPlaceholders(t *testing.T) {
	tmpl := "https://example.com/binary"
	got := expandTemplate(tmpl, map[string]string{"version": "1.0"})
	if got != tmpl {
		t.Errorf("expandTemplate no placeholders = %q, want %q", got, tmpl)
	}
}

func TestExpandTemplate_EmptyVars(t *testing.T) {
	tmpl := "test-{version}-{os}"
	got := expandTemplate(tmpl, map[string]string{})
	if got != tmpl {
		t.Errorf("expandTemplate empty vars = %q, want %q", got, tmpl)
	}
}

func TestExpandTemplate_EmptyTemplate(t *testing.T) {
	got := expandTemplate("", map[string]string{"v": "1"})
	if got != "" {
		t.Errorf("expandTemplate empty template = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// indexOf — additional coverage
// ---------------------------------------------------------------------------

func TestIndexOf_StartBeyondEnd(t *testing.T) {
	got := indexOf("hello", "lo", 100)
	if got != -1 {
		t.Errorf("indexOf with start beyond string = %d, want -1", got)
	}
}

func TestIndexOf_EmptySubstring(t *testing.T) {
	got := indexOf("hello", "", 0)
	if got != 0 {
		t.Errorf("indexOf empty substring = %d, want 0", got)
	}
}

func TestIndexOf_EmptyString(t *testing.T) {
	got := indexOf("", "", 0)
	// Empty string with empty sub at start=0: len(s)==0, start(0) >= len(s)(0) -> returns -1.
	if got != -1 {
		t.Errorf("indexOf both empty = %d, want -1", got)
	}
}

// ---------------------------------------------------------------------------
// isExecutable — additional coverage
// ---------------------------------------------------------------------------

func TestIsExecutable_ExistingExecutable(t *testing.T) {
	// Create a temp executable file.
	tmpDir := t.TempDir()
	execPath := filepath.Join(tmpDir, "test-exec")
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !isExecutable(execPath) {
		t.Errorf("isExecutable(%q) = false, want true", execPath)
	}
}

func TestIsExecutable_NonExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test-noexec")
	if err := os.WriteFile(filePath, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	if isExecutable(filePath) {
		t.Errorf("isExecutable(%q) = true, want false (not executable)", filePath)
	}
}

func TestIsExecutable_Symlink(t *testing.T) {
	tmpDir := t.TempDir()
	realPath := filepath.Join(tmpDir, "real-exec")
	linkPath := filepath.Join(tmpDir, "link-exec")

	if err := os.WriteFile(realPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skip("symlink not supported")
	}

	if !isExecutable(linkPath) {
		t.Errorf("isExecutable(%q) = false for symlink to executable", linkPath)
	}
}

// ---------------------------------------------------------------------------
// EnsureTool — additional coverage
// ---------------------------------------------------------------------------

func TestEnsureTool_SystemTool_NotFound(t *testing.T) {
	// iodine is a system tool with an install hint.
	// On most dev machines it won't be installed.
	path, err := EnsureTool("iodine")
	if err != nil {
		var tnf *ToolNotFoundError
		if errors.As(err, &tnf) {
			if tnf.Tool != "iodine" {
				t.Errorf("ToolNotFoundError.Tool = %q, want iodine", tnf.Tool)
			}
			if !strings.Contains(tnf.InstallHint, "brew") {
				t.Errorf("InstallHint = %q, should mention brew", tnf.InstallHint)
			}
		}
		// If it returned error, path should be empty.
		if path != "" {
			t.Errorf("path should be empty on error, got %q", path)
		}
	}
	// If no error, the tool is installed — that's fine too.
}

// ---------------------------------------------------------------------------
// ListTools — additional coverage
// ---------------------------------------------------------------------------

func TestListTools_ToolCount(t *testing.T) {
	result := ListTools()
	// Must have at least downloadable (3) + system (8) = 11 tools.
	if len(result) < 11 {
		t.Errorf("ListTools returned %d tools, want >= 11", len(result))
	}
}

func TestListTools_DownloadableHaveDescription(t *testing.T) {
	result := ListTools()
	for name, status := range result {
		if status.Downloadable && status.Description == "" {
			t.Errorf("downloadable tool %s has empty Description", name)
		}
	}
}

func TestListTools_SystemHaveHints(t *testing.T) {
	result := ListTools()
	for name, status := range result {
		if !status.Downloadable && !status.Installed && status.InstallHint == "" {
			t.Errorf("uninstalled system tool %s has no InstallHint", name)
		}
	}
}

// ---------------------------------------------------------------------------
// DownloadTool — error cases
// ---------------------------------------------------------------------------

func TestDownloadTool_EmptyName(t *testing.T) {
	_, err := DownloadTool("")
	if err == nil {
		t.Error("DownloadTool('') should return error")
	}
}

// ---------------------------------------------------------------------------
// Registry data integrity
// ---------------------------------------------------------------------------

func TestRegistry_AllToolsHaveRequiredFor(t *testing.T) {
	for name, info := range tools {
		if len(info.RequiredFor) == 0 {
			t.Errorf("tool %s has empty RequiredFor", name)
		}
		for _, req := range info.RequiredFor {
			if req == "" {
				t.Errorf("tool %s has empty RequiredFor entry", name)
			}
		}
	}
}

func TestRegistry_AllVersionsNonEmpty(t *testing.T) {
	for name, info := range tools {
		if info.Version == "" {
			t.Errorf("tool %s has empty Version", name)
		}
		// Version should look like a semver (at least contain a dot).
		if !strings.Contains(info.Version, ".") {
			t.Errorf("tool %s version %q doesn't look like semver", name, info.Version)
		}
	}
}

func TestRegistry_URLsContainPlaceholders(t *testing.T) {
	for name, info := range tools {
		if info.DownloadURL == "" {
			t.Errorf("tool %s has empty DownloadURL", name)
			continue
		}
		// All URLs should contain at least {version}.
		if !strings.Contains(info.DownloadURL, "{version}") {
			t.Errorf("tool %s DownloadURL missing {version} placeholder", name)
		}
		// All URLs should start with https://.
		if !strings.HasPrefix(info.DownloadURL, "https://") {
			t.Errorf("tool %s DownloadURL should use HTTPS: %q", name, info.DownloadURL)
		}
	}
}

func TestSystemTools_AllNonEmpty(t *testing.T) {
	for name, hint := range systemTools {
		if name == "" {
			t.Error("systemTools has empty name key")
		}
		if hint == "" {
			t.Errorf("systemTools[%s] has empty hint", name)
		}
	}
}
