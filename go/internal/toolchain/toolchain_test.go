// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package toolchain

import (
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: FindTool returns path when tool exists
// ---------------------------------------------------------------------------

func TestFindTool_ExistingTool(t *testing.T) {
	// Use "go" as a tool we know exists on any Go development machine.
	path := FindTool("go")
	if path == "" {
		t.Error("FindTool(\"go\") returned empty, but go should be in PATH")
	}
}

// ---------------------------------------------------------------------------
// Test: FindTool returns empty when tool doesn't exist
// ---------------------------------------------------------------------------

func TestFindTool_NonexistentTool(t *testing.T) {
	path := FindTool("nowifi_tool_that_definitely_does_not_exist_12345")
	if path != "" {
		t.Errorf("FindTool returned %q for nonexistent tool", path)
	}
}

// ---------------------------------------------------------------------------
// Test: FindTool with os.Executable as test target
// ---------------------------------------------------------------------------

func TestFindTool_OsExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable() failed: %v", err)
	}
	// The test binary itself is an executable, but FindTool searches by
	// name in PATH. We can at least verify isExecutable works on it.
	if !isExecutable(exe) {
		t.Errorf("isExecutable(%q) = false, expected true", exe)
	}
}

// ---------------------------------------------------------------------------
// Test: ToolNotFoundError has correct message
// ---------------------------------------------------------------------------

func TestToolNotFoundError_Message(t *testing.T) {
	tests := []struct {
		tool string
		hint string
		want string
	}{
		{"chisel", "brew install chisel", "chisel not found. Install: brew install chisel"},
		{"iodine", "brew install iodine", "iodine not found. Install: brew install iodine"},
		{"foo", "build from source", "foo not found. Install: build from source"},
	}
	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			err := &ToolNotFoundError{Tool: tc.tool, InstallHint: tc.hint}
			got := err.Error()
			if got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: ToolNotFoundError implements error interface
// ---------------------------------------------------------------------------

func TestToolNotFoundError_ImplementsError(t *testing.T) {
	var err error = &ToolNotFoundError{Tool: "test", InstallHint: "hint"}
	if err.Error() == "" {
		t.Error("Error() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// Test: ListTools returns all known tools
// ---------------------------------------------------------------------------

func TestListTools_ReturnsAllKnown(t *testing.T) {
	result := ListTools()

	// Should contain at least all downloadable + system tools.
	expectedDownloadable := []string{"chisel", "hysteria", "cloudflared"}
	expectedSystem := []string{"iodine", "hans", "hashcat", "hcxdumptool",
		"hcxpcapngtool", "aircrack-ng", "ntpescape", "dnscrypt-proxy"}

	for _, name := range expectedDownloadable {
		status, ok := result[name]
		if !ok {
			t.Errorf("ListTools missing downloadable tool: %s", name)
			continue
		}
		if !status.Downloadable {
			t.Errorf("tool %s should be Downloadable=true", name)
		}
	}

	for _, name := range expectedSystem {
		status, ok := result[name]
		if !ok {
			t.Errorf("ListTools missing system tool: %s", name)
			continue
		}
		if status.Downloadable {
			t.Errorf("system tool %s should be Downloadable=false", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: ListTools shows installed status correctly
// ---------------------------------------------------------------------------

func TestListTools_InstalledStatus(t *testing.T) {
	result := ListTools()

	for name, status := range result {
		if status.Installed {
			if status.Path == "" {
				t.Errorf("tool %s is Installed=true but Path is empty", name)
			}
		} else {
			if status.Path != "" {
				t.Errorf("tool %s is Installed=false but Path=%q", name, status.Path)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Registry has chisel, hysteria, cloudflared
// ---------------------------------------------------------------------------

func TestRegistry_DownloadableTools(t *testing.T) {
	expectedTools := []struct {
		name       string
		hasDLURL   bool
		hasVersion bool
	}{
		{"chisel", true, true},
		{"hysteria", true, true},
		{"cloudflared", true, true},
	}

	for _, tc := range expectedTools {
		t.Run(tc.name, func(t *testing.T) {
			info, ok := tools[tc.name]
			if !ok {
				t.Fatalf("tool %q not in registry", tc.name)
			}
			if tc.hasDLURL && info.DownloadURL == "" {
				t.Errorf("tool %s has empty DownloadURL", tc.name)
			}
			if tc.hasVersion && info.Version == "" {
				t.Errorf("tool %s has empty Version", tc.name)
			}
			if info.BinaryName == "" {
				t.Errorf("tool %s has empty BinaryName", tc.name)
			}
			if info.Name != tc.name {
				t.Errorf("tool Name = %q, want %q", info.Name, tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Registry tool descriptions are non-empty
// ---------------------------------------------------------------------------

func TestRegistry_Descriptions(t *testing.T) {
	for name, info := range tools {
		if info.Description == "" {
			t.Errorf("tool %s has empty description", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Registry RequiredFor is populated
// ---------------------------------------------------------------------------

func TestRegistry_RequiredFor(t *testing.T) {
	for name, info := range tools {
		if len(info.RequiredFor) == 0 {
			t.Errorf("tool %s has empty RequiredFor", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: System tools have install hints
// ---------------------------------------------------------------------------

func TestSystemTools_InstallHints(t *testing.T) {
	for name, hint := range systemTools {
		if hint == "" {
			t.Errorf("system tool %s has empty install hint", name)
		}
		_ = name
	}
}

// ---------------------------------------------------------------------------
// Test: isExecutable
// ---------------------------------------------------------------------------

func TestIsExecutable(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"nonexistent", "/nonexistent/path/binary", false},
		{"directory", os.TempDir(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isExecutable(tc.path)
			if got != tc.want {
				t.Errorf("isExecutable(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: homeDir returns non-empty
// ---------------------------------------------------------------------------

func TestHomeDir(t *testing.T) {
	h := homeDir()
	if h == "" {
		t.Error("homeDir() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// Test: expandTemplate
// ---------------------------------------------------------------------------

func TestExpandTemplate(t *testing.T) {
	tests := []struct {
		name string
		tmpl string
		vars map[string]string
		want string
	}{
		{
			"single var",
			"https://example.com/{version}/tool",
			map[string]string{"version": "1.0.0"},
			"https://example.com/1.0.0/tool",
		},
		{
			"multiple vars",
			"tool_{os}_{arch}_{version}",
			map[string]string{"os": "darwin", "arch": "arm64", "version": "2.0"},
			"tool_darwin_arm64_2.0",
		},
		{
			"no vars",
			"https://example.com/tool",
			map[string]string{},
			"https://example.com/tool",
		},
		{
			"repeated var",
			"{v}-{v}",
			map[string]string{"v": "x"},
			"x-x",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := expandTemplate(tc.tmpl, tc.vars)
			if got != tc.want {
				t.Errorf("expandTemplate(%q, %v) = %q, want %q", tc.tmpl, tc.vars, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: resolvePlatform doesn't error on darwin/linux
// ---------------------------------------------------------------------------

func TestResolvePlatform(t *testing.T) {
	osName, arch, err := resolvePlatform()
	if err != nil {
		t.Fatalf("resolvePlatform() error: %v", err)
	}
	if osName != "darwin" && osName != "linux" {
		t.Errorf("unexpected osName: %s", osName)
	}
	if arch != "arm64" && arch != "amd64" {
		t.Errorf("unexpected arch: %s", arch)
	}
}

// ---------------------------------------------------------------------------
// Test: indexOf helper
// ---------------------------------------------------------------------------

func TestIndexOf(t *testing.T) {
	tests := []struct {
		s     string
		sub   string
		start int
		want  int
	}{
		{"hello world", "world", 0, 6},
		{"hello world", "hello", 0, 0},
		{"hello world", "x", 0, -1},
		{"aabaa", "a", 2, 3},
		{"", "a", 0, -1},
	}
	for _, tc := range tests {
		got := indexOf(tc.s, tc.sub, tc.start)
		if got != tc.want {
			t.Errorf("indexOf(%q, %q, %d) = %d, want %d", tc.s, tc.sub, tc.start, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: EnsureTool returns ToolNotFoundError for unknown tools
// ---------------------------------------------------------------------------

func TestEnsureTool_UnknownTool(t *testing.T) {
	_, err := EnsureTool("completely_fake_tool_99999")
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}

	tnf, ok := err.(*ToolNotFoundError)
	if !ok {
		t.Fatalf("expected *ToolNotFoundError, got %T: %v", err, err)
	}
	if tnf.Tool != "completely_fake_tool_99999" {
		t.Errorf("ToolNotFoundError.Tool = %q, want completely_fake_tool_99999", tnf.Tool)
	}
}

// ---------------------------------------------------------------------------
// Test: DownloadTool rejects unregistered tools
// ---------------------------------------------------------------------------

func TestDownloadTool_UnregisteredTool(t *testing.T) {
	_, err := DownloadTool("not_a_real_tool")
	if err == nil {
		t.Fatal("expected error for unregistered tool")
	}
	if !strings.Contains(err.Error(), "not in the downloadable registry") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: ToolDir is set to expected path
// ---------------------------------------------------------------------------

func TestToolDir(t *testing.T) {
	if ToolDir == "" {
		t.Error("ToolDir is empty")
	}
	if !strings.Contains(ToolDir, ".nowifi") {
		t.Errorf("ToolDir = %q, expected to contain .nowifi", ToolDir)
	}
}
