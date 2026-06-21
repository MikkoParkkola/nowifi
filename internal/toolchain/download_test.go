// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package toolchain

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDownloadTool_VerifiesAndExtractsGzipAsset(t *testing.T) {
	payload := []byte("#!/bin/sh\necho ok\n")
	archive := gzipBytes(t, payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	toolName := "test-gzip-tool"
	withDownloadTestTool(t, toolName, &ToolInfo{
		Name:          toolName,
		Description:   "test gzip asset",
		DownloadURL:   server.URL + "/tool-{os}-{arch}.gz",
		BinaryName:    toolName,
		Version:       "1.0.0",
		RequiredFor:   []string{"tests"},
		ArchiveFormat: assetFormatGzip,
		Checksums: map[string]string{
			currentPlatformKey(t): sha256Hex(archive),
		},
	})

	path, err := DownloadTool(toolName)
	if err != nil {
		t.Fatalf("DownloadTool returned error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded payload mismatch:\n got %q\nwant %q", got, payload)
	}
}

func TestDownloadTool_VerifiesAndExtractsTarGzAsset(t *testing.T) {
	payload := []byte("cloudflared-test-binary")
	archive := tarGzBytes(t, "cloudflared-test", payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	toolName := "cloudflared-test"
	withDownloadTestTool(t, toolName, &ToolInfo{
		Name:          toolName,
		Description:   "test tar.gz asset",
		DownloadURL:   server.URL + "/cloudflared-{os}-{arch}.tgz",
		BinaryName:    toolName,
		Version:       "1.0.0",
		RequiredFor:   []string{"tests"},
		ArchiveFormat: assetFormatTarGz,
		Checksums: map[string]string{
			currentPlatformKey(t): sha256Hex(archive),
		},
	})

	path, err := DownloadTool(toolName)
	if err != nil {
		t.Fatalf("DownloadTool returned error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded payload mismatch:\n got %q\nwant %q", got, payload)
	}
}

func TestExtractGzipWithLimit_RejectsOversizedPayload(t *testing.T) {
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "tool.gz")
	dest := filepath.Join(srcDir, "tool")
	payload := bytes.Repeat([]byte("a"), 9)
	if err := os.WriteFile(src, gzipBytes(t, payload), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", src, err)
	}

	err := extractGzipWithLimit(src, dest, 8)
	if err == nil {
		t.Fatal("extractGzipWithLimit succeeded with oversized payload, want error")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected size limit error, got %v", err)
	}
	info, statErr := os.Stat(dest)
	if statErr != nil {
		t.Fatalf("Stat(%q): %v", dest, statErr)
	}
	if info.Size() != 8 {
		t.Fatalf("dest size = %d, want 8-byte capped partial output", info.Size())
	}
}

func TestExtractTarGzWithLimit_RejectsOversizedPayload(t *testing.T) {
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "tool.tgz")
	dest := filepath.Join(srcDir, "cloudflared-test")
	payload := bytes.Repeat([]byte("b"), 9)
	if err := os.WriteFile(src, tarGzBytes(t, "cloudflared-test", payload), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", src, err)
	}

	err := extractTarGzWithLimit(src, "cloudflared-test", dest, 8)
	if err == nil {
		t.Fatal("extractTarGzWithLimit succeeded with oversized payload, want error")
	}
	if !strings.Contains(err.Error(), "exceeds max extracted size") {
		t.Fatalf("expected size limit error, got %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("expected no extracted file when tar header exceeds limit, got stat err %v", statErr)
	}
}

func TestDownloadTool_RejectsChecksumMismatch(t *testing.T) {
	payload := []byte("plain-binary")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	toolName := "test-bad-checksum"
	withDownloadTestTool(t, toolName, &ToolInfo{
		Name:        toolName,
		Description: "test checksum mismatch",
		DownloadURL: server.URL + "/tool-{os}-{arch}",
		BinaryName:  toolName,
		Version:     "1.0.0",
		RequiredFor: []string{"tests"},
		Checksums: map[string]string{
			currentPlatformKey(t): strings.Repeat("0", 64),
		},
	})

	path, err := DownloadTool(toolName)
	if err == nil {
		t.Fatal("DownloadTool succeeded with bad checksum, want error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error, got %v", err)
	}
	if path != "" {
		t.Fatalf("path = %q, want empty on failure", path)
	}
	if _, statErr := os.Stat(filepath.Join(ToolDir, toolName)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no installed binary after checksum failure, got stat err %v", statErr)
	}
}

func TestCloudflaredDarwinOverrideUsesTarball(t *testing.T) {
	info := tools["cloudflared"]
	url := expandTemplate(info.PlatformDownloadURLs["darwin/arm64"], map[string]string{
		"version": info.Version,
		"os":      "darwin",
		"arch":    "arm64",
	})
	if !strings.HasSuffix(url, ".tgz") {
		t.Fatalf("cloudflared darwin url = %q, want .tgz asset", url)
	}
	if got := archiveFormatForPlatform(info, "darwin/arm64"); got != assetFormatTarGz {
		t.Fatalf("cloudflared darwin archive format = %q, want %q", got, assetFormatTarGz)
	}
}

func TestRegistry_ChecksumsCoverSupportedPlatforms(t *testing.T) {
	supported := []string{
		"darwin/amd64",
		"darwin/arm64",
		"linux/amd64",
		"linux/arm64",
	}
	for name, info := range tools {
		for _, platform := range supported {
			if _, err := checksumForPlatform(info, platform); err != nil {
				t.Fatalf("tool %s missing checksum for %s: %v", name, platform, err)
			}
		}
	}
}

func withDownloadTestTool(t *testing.T, name string, info *ToolInfo) {
	t.Helper()

	prevToolDir := ToolDir
	prevInfo, existed := tools[name]

	ToolDir = t.TempDir()
	ensureOnce = sync.Once{}
	tools[name] = info

	t.Cleanup(func() {
		ToolDir = prevToolDir
		ensureOnce = sync.Once{}
		if existed {
			tools[name] = prevInfo
			return
		}
		delete(tools, name)
	})
}

func currentPlatformKey(t *testing.T) string {
	t.Helper()
	osName, arch, err := resolvePlatform()
	if err != nil {
		t.Skipf("resolvePlatform: %v", err)
	}
	return platformKey(osName, arch)
}

func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func tarGzBytes(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(payload)),
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
