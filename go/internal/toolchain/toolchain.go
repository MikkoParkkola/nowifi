// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package toolchain manages external tool binaries: find, download, ensure.
//
// Three downloadable tools (chisel, hysteria, cloudflared) have GitHub release
// URLs with auto-download. System-only tools (iodine, hans, etc.) require
// manual installation and only provide install hints.
package toolchain

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// ToolDir is the default directory for downloaded tool binaries.
var ToolDir = filepath.Join(homeDir(), ".nowifi", "bin")

type assetFormat string

const (
	assetFormatPlain           assetFormat = "plain"
	assetFormatGzip            assetFormat = "gzip"
	assetFormatTarGz           assetFormat = "tar.gz"
	maxExtractedToolBinarySize int64       = 256 << 20
)

// ToolInfo describes a downloadable tool binary.
type ToolInfo struct {
	Name                 string
	Description          string
	DownloadURL          string // URL template with {version}, {os}, {arch}
	PlatformDownloadURLs map[string]string
	BinaryName           string
	Version              string
	RequiredFor          []string
	Checksums            map[string]string
	ArchiveFormat        assetFormat
	PlatformFormats      map[string]assetFormat
}

// ToolStatus reports the installation state of a tool.
type ToolStatus struct {
	Installed    bool
	Path         string
	Description  string
	RequiredFor  []string
	Downloadable bool
	InstallHint  string
}

// ToolNotFoundError is returned when a required external tool cannot be located.
type ToolNotFoundError struct {
	Tool        string
	InstallHint string
}

func (e *ToolNotFoundError) Error() string {
	return fmt.Sprintf("%s not found. Install: %s", e.Tool, e.InstallHint)
}

// tools is the registry of downloadable binaries.
var tools = map[string]*ToolInfo{
	"chisel": {
		Name:          "chisel",
		Description:   "HTTPS/WebSocket tunnel",
		DownloadURL:   "https://github.com/jpillora/chisel/releases/download/v{version}/chisel_{version}_{os}_{arch}.gz",
		BinaryName:    "chisel",
		Version:       "1.10.1",
		RequiredFor:   []string{"chisel_tunnel"},
		ArchiveFormat: assetFormatGzip,
		Checksums: map[string]string{
			"darwin/amd64": "5a7e6ba198e840492d34d7110e1c90118642faac542773121a4c4cc9b44c226a",
			"darwin/arm64": "474bf6d3dd92c9162950d1a8d8e912709b1e48494ca6af5dc5d0381ab80e56bd",
			"linux/amd64":  "0525aa3c5d457f2a4075e66221d5125d434bedf15006d3271c213f5cd6ff2230",
			"linux/arm64":  "f55beb68fb99b69903df1adcff4197fbfdb82cb0ee596848c0f055dc219da983",
		},
	},
	"hysteria": {
		Name:          "hysteria",
		Description:   "QUIC/HTTP3 tunnel (UDP/443)",
		DownloadURL:   "https://github.com/apernet/hysteria/releases/download/app%2Fv{version}/hysteria-{os}-{arch}",
		BinaryName:    "hysteria",
		Version:       "2.6.1",
		RequiredFor:   []string{"quic_tunnel"},
		ArchiveFormat: assetFormatPlain,
		Checksums: map[string]string{
			"darwin/amd64": "9e8e3699bf42553f15d419d87bc8b7b08d5a9de6ef132dbc2df5fbfd9964b5e3",
			"darwin/arm64": "f636d9afc6f5bc69803b07f5e306d313adae4dabb78614f6ac36d06765f7246e",
			"linux/amd64":  "4bcdd7941a0fb85d3c55babe10cc2748fa0345c19a9b4bbf9b6b42613db149e3",
			"linux/arm64":  "2ee3fbbc0e590bae463fac38bd9f4bdfa7157e70bcf164037d817fc6d540d701",
		},
	},
	"cloudflared": {
		Name:        "cloudflared",
		Description: "Cloudflare Tunnel / DoH proxy",
		DownloadURL: "https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-{os}-{arch}",
		PlatformDownloadURLs: map[string]string{
			"darwin/amd64": "https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-darwin-amd64.tgz",
			"darwin/arm64": "https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-darwin-arm64.tgz",
		},
		BinaryName:    "cloudflared",
		Version:       "2024.12.2",
		RequiredFor:   []string{"doh_tunnel"},
		ArchiveFormat: assetFormatPlain,
		PlatformFormats: map[string]assetFormat{
			"darwin/amd64": assetFormatTarGz,
			"darwin/arm64": assetFormatTarGz,
		},
		Checksums: map[string]string{
			"darwin/amd64": "71b17468bab0426b20959d4eeadfff3658d07c636beea472539e0781381559cc",
			"darwin/arm64": "30eb982ab6dda1e12dbc17b3a9d51c80362874544032930055354965b1930621",
			"linux/amd64":  "5237675a5e806120729acc78c5be02f9db5f406717699587abfa72b49b39fe40",
			"linux/arm64":  "96e8f95e878c1d4154d91c42781749ab66ca8088f1f3e6e6bc78c25c921e6b64",
		},
	},
}

// systemTools lists tools that require manual installation (not auto-downloadable).
var systemTools = map[string]string{
	"iodine":         "brew install iodine",
	"hans":           "brew install hans  OR  build from https://github.com/friedrich/hans",
	"hashcat":        "brew install hashcat",
	"hcxdumptool":    "brew install hcxdumptool",
	"hcxpcapngtool":  "brew install hcxtools",
	"aircrack-ng":    "brew install aircrack-ng",
	"reaver":         "brew install reaver",
	"ntpescape":      "https://github.com/evallen/ntpescape",
	"dnscrypt-proxy": "brew install dnscrypt-proxy",
}

// ensureOnce protects the ToolDir creation.
var ensureOnce sync.Once

// ensureToolDir creates ~/.nowifi/bin/ if it does not exist.
func ensureToolDir() string {
	ensureOnce.Do(func() {
		_ = os.MkdirAll(ToolDir, 0o755)
	})
	return ToolDir
}

// FindTool searches for a tool binary in PATH, ~/.nowifi/bin/, ~/bin/,
// and /usr/local/bin/. Returns the path if found and executable, or empty string.
func FindTool(name string) string {
	// 1. PATH lookup via exec.LookPath
	if p, err := exec.LookPath(name); err == nil {
		return p
	}

	// 2. Additional candidate directories
	candidates := []string{
		filepath.Join(ToolDir, name),
		filepath.Join(homeDir(), "bin", name),
		filepath.Join("/usr/local/bin", name),
	}

	for _, p := range candidates {
		if isExecutable(p) {
			return p
		}
	}
	return ""
}

// DownloadTool downloads a registered tool to ~/.nowifi/bin/.
// Returns the path on success, or an error if download fails or the tool
// is not in the downloadable registry.
func DownloadTool(name string) (string, error) {
	info, ok := tools[name]
	if !ok {
		return "", fmt.Errorf("tool %q is not in the downloadable registry", name)
	}

	ensureToolDir()

	osName, arch, err := resolvePlatform()
	if err != nil {
		return "", err
	}

	url := expandTemplate(info.DownloadURL, map[string]string{
		"version": info.Version,
		"os":      osName,
		"arch":    arch,
	})
	platform := platformKey(osName, arch)
	if override, ok := info.PlatformDownloadURLs[platform]; ok {
		url = expandTemplate(override, map[string]string{
			"version": info.Version,
			"os":      osName,
			"arch":    arch,
		})
	}
	checksum, err := checksumForPlatform(info, platform)
	if err != nil {
		return "", err
	}
	format := archiveFormatForPlatform(info, platform)

	dest := filepath.Join(ToolDir, info.BinaryName)

	if err := downloadFile(url, checksum, format, info.BinaryName, dest); err != nil {
		// Clean up partial download.
		_ = os.Remove(dest)
		return "", fmt.Errorf("download %s: %w", name, err)
	}

	return dest, nil
}

// EnsureTool finds a tool or downloads it. Returns the path.
// Returns a *ToolNotFoundError if the tool cannot be obtained.
func EnsureTool(name string) (string, error) {
	if p := FindTool(name); p != "" {
		return p, nil
	}

	// Try auto-download for registered tools.
	if _, ok := tools[name]; ok {
		p, err := DownloadTool(name)
		if err == nil {
			return p, nil
		}
	}

	// Provide install hint.
	if hint, ok := systemTools[name]; ok {
		return "", &ToolNotFoundError{Tool: name, InstallHint: hint}
	}
	if info, ok := tools[name]; ok {
		return "", &ToolNotFoundError{Tool: name, InstallHint: "auto-download failed for " + info.Name}
	}
	return "", &ToolNotFoundError{Tool: name, InstallHint: "no auto-download available"}
}

// ListTools returns the status of all known tools (downloadable + system).
func ListTools() map[string]ToolStatus {
	result := make(map[string]ToolStatus, len(tools)+len(systemTools))

	for name, info := range tools {
		p := FindTool(name)
		result[name] = ToolStatus{
			Installed:    p != "",
			Path:         p,
			Description:  info.Description,
			RequiredFor:  info.RequiredFor,
			Downloadable: true,
		}
	}

	for name, hint := range systemTools {
		if _, exists := result[name]; exists {
			continue
		}
		p := FindTool(name)
		result[name] = ToolStatus{
			Installed:    p != "",
			Path:         p,
			Downloadable: false,
			InstallHint:  hint,
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "/tmp"
	}
	return h
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0o111 != 0
}

// resolvePlatform maps runtime.GOOS/GOARCH to download URL values.
func resolvePlatform() (osName, arch string, err error) {
	switch runtime.GOOS {
	case "darwin":
		osName = "darwin"
	case "linux":
		osName = "linux"
	default:
		return "", "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	switch runtime.GOARCH {
	case "arm64":
		arch = "arm64"
	case "amd64":
		arch = "amd64"
	default:
		return "", "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
	return osName, arch, nil
}

// expandTemplate replaces {key} placeholders in a URL template.
func expandTemplate(tmpl string, vars map[string]string) string {
	result := tmpl
	for k, v := range vars {
		placeholder := "{" + k + "}"
		for i := 0; i < len(result); {
			idx := indexOf(result, placeholder, i)
			if idx < 0 {
				break
			}
			result = result[:idx] + v + result[idx+len(placeholder):]
			i = idx + len(v)
		}
	}
	return result
}

func indexOf(s, sub string, start int) int {
	if start >= len(s) {
		return -1
	}
	for i := start; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func platformKey(osName, arch string) string {
	return osName + "/" + arch
}

func checksumForPlatform(info *ToolInfo, platform string) (string, error) {
	if info.Checksums == nil {
		return "", fmt.Errorf("no checksum configured for %s", info.Name)
	}
	sum, ok := info.Checksums[platform]
	if !ok || sum == "" {
		return "", fmt.Errorf("no checksum configured for %s on %s", info.Name, platform)
	}
	return strings.ToLower(sum), nil
}

func archiveFormatForPlatform(info *ToolInfo, platform string) assetFormat {
	if info.PlatformFormats != nil {
		if format, ok := info.PlatformFormats[platform]; ok {
			return format
		}
	}
	if info.ArchiveFormat != "" {
		return info.ArchiveFormat
	}
	return assetFormatPlain
}

// downloadFile fetches a URL to a local file, verifies its checksum, and
// extracts archives into the final executable path.
func downloadFile(url, checksum string, format assetFormat, binaryName, dest string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil) //nolint:gosec // URL is from internal registry, not user input
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	dir := filepath.Dir(dest)
	rawFile, err := os.CreateTemp(dir, binaryName+".*.asset")
	if err != nil {
		return err
	}
	rawPath := rawFile.Name()
	defer func() {
		_ = rawFile.Close()
		_ = os.Remove(rawPath)
	}()

	if _, err := io.Copy(rawFile, resp.Body); err != nil {
		return err
	}
	if err := rawFile.Close(); err != nil {
		return err
	}

	if err := verifySHA256(rawPath, checksum); err != nil {
		return err
	}

	tempDest, err := writeInstalledBinary(rawPath, format, binaryName, dir)
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(tempDest)
	}()

	if err := os.Chmod(tempDest, 0o755); err != nil {
		return fmt.Errorf("chmod %s: %w", tempDest, err)
	}
	if err := os.Rename(tempDest, dest); err != nil {
		return err
	}
	return nil
}

func verifySHA256(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	got := hex.EncodeToString(hasher.Sum(nil))
	if got != strings.ToLower(expected) {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, expected)
	}
	return nil
}

func writeInstalledBinary(rawPath string, format assetFormat, binaryName, dir string) (string, error) {
	tempDest, err := os.CreateTemp(dir, binaryName+".*.tmp")
	if err != nil {
		return "", err
	}
	tempDestPath := tempDest.Name()
	if err := tempDest.Close(); err != nil {
		return "", err
	}

	switch format {
	case assetFormatPlain:
		if err := os.Rename(rawPath, tempDestPath); err != nil {
			_ = os.Remove(tempDestPath)
			return "", err
		}
		return tempDestPath, nil
	case assetFormatGzip:
		if err := extractGzip(rawPath, tempDestPath); err != nil {
			_ = os.Remove(tempDestPath)
			return "", err
		}
		return tempDestPath, nil
	case assetFormatTarGz:
		if err := extractTarGz(rawPath, binaryName, tempDestPath); err != nil {
			_ = os.Remove(tempDestPath)
			return "", err
		}
		return tempDestPath, nil
	default:
		_ = os.Remove(tempDestPath)
		return "", fmt.Errorf("unsupported asset format: %s", format)
	}
}

func extractGzip(src, dest string) error {
	return extractGzipWithLimit(src, dest, maxExtractedToolBinarySize)
}

func extractGzipWithLimit(src, dest string, maxSize int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	gz, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	return copyExtractedBinaryWithLimit(out, gz, maxSize)
}

func extractTarGz(src, binaryName, dest string) error {
	return extractTarGzWithLimit(src, binaryName, dest, maxExtractedToolBinarySize)
}

func extractTarGzWithLimit(src, binaryName, dest string, maxSize int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	gz, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		if filepath.Base(hdr.Name) != binaryName {
			continue
		}
		if hdr.Size < 0 {
			return fmt.Errorf("archive entry %s has invalid size %d", hdr.Name, hdr.Size)
		}
		if hdr.Size > maxSize {
			return fmt.Errorf("archive entry %s exceeds max extracted size %d bytes", hdr.Name, maxSize)
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		if err := copyExtractedBinaryWithLimit(out, tr, maxSize); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("archive did not contain %s", binaryName)
}

func copyExtractedBinaryWithLimit(out *os.File, in io.Reader, maxSize int64) error {
	written, err := io.Copy(out, io.LimitReader(in, maxSize))
	if err != nil {
		return err
	}
	if written == maxSize {
		var probe [1]byte
		n, err := in.Read(probe[:])
		if err != nil && err != io.EOF {
			return err
		}
		if n > 0 {
			return fmt.Errorf("extracted binary exceeds max size %d bytes", maxSize)
		}
	}
	return nil
}
