// Package toolchain manages external tool binaries: find, download, ensure.
//
// Three downloadable tools (chisel, hysteria, cloudflared) have GitHub release
// URLs with auto-download. System-only tools (iodine, hans, etc.) require
// manual installation and only provide install hints.
package toolchain

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

// ToolDir is the default directory for downloaded tool binaries.
var ToolDir = filepath.Join(homeDir(), ".nowifi", "bin")

// ToolInfo describes a downloadable tool binary.
type ToolInfo struct {
	Name        string
	Description string
	DownloadURL string // URL template with {version}, {os}, {arch}
	BinaryName  string
	Version     string
	RequiredFor []string
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
		Name:        "chisel",
		Description: "HTTPS/WebSocket tunnel",
		DownloadURL: "https://github.com/jpillora/chisel/releases/download/v{version}/chisel_{version}_{os}_{arch}.gz",
		BinaryName:  "chisel",
		Version:     "1.10.1",
		RequiredFor: []string{"chisel_tunnel"},
	},
	"hysteria": {
		Name:        "hysteria",
		Description: "QUIC/HTTP3 tunnel (UDP/443)",
		DownloadURL: "https://github.com/apernet/hysteria/releases/download/app%2Fv{version}/hysteria-{os}-{arch}",
		BinaryName:  "hysteria",
		Version:     "2.6.1",
		RequiredFor: []string{"quic_tunnel"},
	},
	"cloudflared": {
		Name:        "cloudflared",
		Description: "Cloudflare Tunnel / DoH proxy",
		DownloadURL: "https://github.com/cloudflare/cloudflared/releases/download/{version}/cloudflared-{os}-{arch}",
		BinaryName:  "cloudflared",
		Version:     "2024.12.2",
		RequiredFor: []string{"doh_tunnel"},
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

	dest := filepath.Join(ToolDir, info.BinaryName)

	if err := downloadFile(url, dest); err != nil {
		// Clean up partial download.
		_ = os.Remove(dest)
		return "", fmt.Errorf("download %s: %w", name, err)
	}

	// Make executable (owner rwx, group rx, other rx).
	if err := os.Chmod(dest, 0o755); err != nil {
		return "", fmt.Errorf("chmod %s: %w", dest, err)
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

// downloadFile fetches a URL to a local file. Handles .gz decompression.
func downloadFile(url, dest string) error {
	resp, err := http.Get(url) //nolint:gosec // URL is from internal registry, not user input
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	var reader io.Reader = resp.Body

	// Decompress gzip if the URL ends with .gz
	if len(url) > 3 && url[len(url)-3:] == ".gz" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("gzip open: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, reader)
	return err
}
