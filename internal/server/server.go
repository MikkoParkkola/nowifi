// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package server provisions tunnel infrastructure: Cloudflare Workers,
// DigitalOcean droplets, and Hetzner Cloud servers.
//
// Three options:
//
//	A. Cloudflare Workers (FREE, no VPS needed) -- HTTPS proxy on CF edge
//	B. Ephemeral VPS (DigitalOcean / Hetzner) -- chisel + iodine + hans pre-installed
//	C. No external server -- fully local techniques only
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/techniques"
)

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// Info holds metadata about a provisioned server.
type Info struct {
	Provider  string            `json:"provider"`        // "cloudflare_worker", "digitalocean", "hetzner", "cloudflare_quick", "libp2p", "custom"
	ServerID  string            `json:"server_id"`       // Droplet ID, Hetzner server ID, or Worker / tunnel name
	IP        string            `json:"ip"`              // Public IP (empty for CF Workers / quick tunnels)
	URL       string            `json:"url"`             // Chisel/proxy URL
	CreatedAt string            `json:"created_at"`      // ISO 8601 timestamp
	TTLHours  int               `json:"ttl_hours"`       // Auto-destroy after this (0 = never)
	Status    string            `json:"status"`          // "active", "creating", "destroyed"
	PID       int               `json:"pid,omitempty"`   // OS process ID (cloudflare_quick only)
	Extra     map[string]string `json:"extra,omitempty"` // Provider-specific metadata
}

// ---------------------------------------------------------------------------
// Technique classification
// ---------------------------------------------------------------------------

// ServerlessTechniques lists bypass techniques that need no external server.
var ServerlessTechniques = techniqueIDs(techniques.ServerlessBypassTechniqueInfos())

// ServerRequiredTechniques lists bypass techniques that require an external
// endpoint the user controls.
var ServerRequiredTechniques = techniqueIDs(techniques.ServerRequiredBypassTechniqueInfos())

func techniqueIDs(infos []techniques.BypassTechniqueInfo) []string {
	ids := make([]string, len(infos))
	for i, info := range infos {
		ids[i] = string(info.ID)
	}
	return ids
}

// ---------------------------------------------------------------------------
// Config + persistence
// ---------------------------------------------------------------------------

func nowifiDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".nowifi")
}

func serversFile() string {
	return filepath.Join(nowifiDir(), "servers.json")
}

func configFile() string {
	return filepath.Join(nowifiDir(), "config.json")
}

func ensureDir() {
	_ = os.MkdirAll(nowifiDir(), 0o755)
}

// SaveServer saves server info to ~/.nowifi/servers.json.
// Updates an existing entry if the provider+server_id combination matches.
func SaveServer(info *Info) error {
	ensureDir()

	servers, _ := LoadServers()

	updated := false
	for i := range servers {
		if servers[i].ServerID == info.ServerID && servers[i].Provider == info.Provider {
			servers[i] = *info
			updated = true
			break
		}
	}
	if !updated {
		servers = append(servers, *info)
	}

	return writeServers(servers)
}

// LoadServers loads all saved servers from ~/.nowifi/servers.json.
func LoadServers() ([]Info, error) {
	data, err := os.ReadFile(serversFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var servers []Info
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, nil // Corrupt file: return empty.
	}
	return servers, nil
}

// ListServers returns active (non-destroyed) servers.
func ListServers() ([]Info, error) {
	servers, err := LoadServers()
	if err != nil {
		return nil, err
	}

	var active []Info
	for _, s := range servers {
		if s.Status != "destroyed" {
			active = append(active, s)
		}
	}
	return active, nil
}

func writeServers(servers []Info) error {
	data, err := json.MarshalIndent(servers, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(serversFile(), data, 0o600)
}

// LoadConfig loads ~/.nowifi/config.json (tokens, URLs).
func LoadConfig() map[string]string {
	data, err := os.ReadFile(configFile())
	if err != nil {
		return make(map[string]string)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return make(map[string]string)
	}
	cfg := make(map[string]string, len(raw))
	for key, value := range raw {
		var s string
		if err := json.Unmarshal(value, &s); err == nil {
			cfg[key] = s
		}
	}
	return cfg
}

// SaveConfig saves ~/.nowifi/config.json.
func SaveConfig(cfg map[string]string) error {
	ensureDir()
	existing := make(map[string]json.RawMessage)
	if data, err := os.ReadFile(configFile()); err == nil {
		_ = json.Unmarshal(data, &existing)
	}
	for key, value := range cfg {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		existing[key] = encoded
	}
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile(), data, 0o600)
}

func persistConfigValue(key, value string) error {
	cfg := LoadConfig()
	cfg[key] = value
	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config %q: %w", key, err)
	}
	return nil
}

// RedactURLSecrets removes nowifi authentication tokens before values are
// printed in status output, logs, or long-lived reports.
func RedactURLSecrets(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	if q.Has("nowifi_token") {
		q.Set("nowifi_token", "REDACTED")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// getToken gets an API token: explicit arg > config file > error.
func getToken(provider, explicitToken string) (string, error) {
	if explicitToken != "" {
		return explicitToken, nil
	}
	cfg := LoadConfig()
	key := provider + "_token"
	token := cfg[key]
	if token == "" {
		return "", fmt.Errorf("no API token for %s. Pass --token or set '%s' in %s", provider, key, configFile())
	}
	return token, nil
}

// ---------------------------------------------------------------------------
// Package-level injection points (overridable for tests)
// ---------------------------------------------------------------------------

// digitalOceanAPIBase is the DigitalOcean API root URL. // overridable for tests
var digitalOceanAPIBase = "https://api.digitalocean.com"

// hetznerAPIBase is the Hetzner Cloud API root URL. // overridable for tests
var hetznerAPIBase = "https://api.hetzner.cloud"

// findWranglerFn locates the wrangler CLI binary. // overridable for tests
var findWranglerFn = func() string {
	p, err := exec.LookPath("wrangler")
	if err == nil {
		return p
	}
	return ""
}

// ---------------------------------------------------------------------------
// Embedded assets
// ---------------------------------------------------------------------------

// CloudflareWorkerJS is the Cloudflare Worker JavaScript that acts as
// a transparent HTTPS proxy for nowifi.
const CloudflareWorkerJS = `// Cloudflare Worker -- transparent HTTPS proxy for nowifi
const AUTH_TOKEN = "__NOWIFI_AUTH_TOKEN__";

export default {
  async fetch(request) {
    if (request.headers.get("X-Nowifi-Token") !== AUTH_TOKEN) {
      return new Response("unauthorized", { status: 401 });
    }

    const url = new URL(request.url);
    // Path format: /https://target.com/path
    const targetUrl = url.pathname.slice(1) + url.search;
    if (!targetUrl.startsWith('http')) {
      return new Response('nowifi tunnel proxy active', { status: 200 });
    }
    try {
      const headers = new Headers(request.headers);
      headers.delete("X-Nowifi-Token");
      const resp = await fetch(targetUrl, {
        method: request.method,
        headers,
        body: request.body,
      });
      return new Response(resp.body, {
        status: resp.status,
        headers: resp.headers,
      });
    } catch (e) {
      return new Response(e.message, { status: 502 });
    }
  }
};
`

// CloudInitScript is the cloud-init user data script that installs chisel,
// iodine, and hans on a freshly provisioned VPS.
const CloudInitScript = `#!/bin/bash
set -e

# Install chisel
CHISEL_URL="https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz"
CHISEL_SHA256="0525aa3c5d457f2a4075e66221d5125d434bedf15006d3271c213f5cd6ff2230"
curl -fsSL "$CHISEL_URL" -o /tmp/chisel.gz
echo "$CHISEL_SHA256  /tmp/chisel.gz" | sha256sum -c -
gunzip -c /tmp/chisel.gz > /usr/local/bin/chisel
rm -f /tmp/chisel.gz
chmod +x /usr/local/bin/chisel

# Start chisel on multiple ports
chisel server --reverse --port 443 &
chisel server --reverse --port 8080 &
chisel server --reverse --port 80 &

# Install iodine (DNS tunnel)
apt-get update && apt-get install -y iodine

# Install hans (ICMP tunnel)
apt-get install -y hans
`

const cfWranglerTOML = `name = "nowifi-proxy"
main = "worker.js"
compatibility_date = "%s"
`

// ---------------------------------------------------------------------------
// Option A: Cloudflare Workers
// ---------------------------------------------------------------------------

// SetupCloudflareWorker deploys a Cloudflare Worker as an HTTPS proxy.
//
// Steps:
//  1. Check if wrangler is installed (install if missing)
//  2. Verify wrangler login
//  3. Create temp project with worker code
//  4. Deploy via wrangler deploy
//  5. Return the worker URL
func SetupCloudflareWorker() (*Info, error) {
	// 1. Find or install wrangler.
	wrangler := findWrangler()
	if wrangler == "" {
		npm, err := exec.LookPath("npm")
		if err != nil {
			return nil, fmt.Errorf(
				"wrangler (Cloudflare CLI) not found and npm is not installed.\n" +
					"Install Node.js first: https://nodejs.org\n" +
					"Then: npm install -g wrangler")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		out, err := exec.CommandContext(ctx, npm, "install", "-g", "wrangler").CombinedOutput()
		cancel()
		if err != nil {
			return nil, fmt.Errorf("failed to install wrangler: %s", truncate(string(out), 500))
		}

		wrangler = findWrangler()
		if wrangler == "" {
			return nil, fmt.Errorf("wrangler installed but not found on PATH. Try: npx wrangler")
		}
	}

	// 2. Check login status.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	out, err := exec.CommandContext(ctx, wrangler, "whoami").CombinedOutput()
	cancel()
	if err != nil || strings.Contains(strings.ToLower(string(out)), "not authenticated") {
		return nil, fmt.Errorf(
			"not logged in to Cloudflare. Run:\n" +
				"  wrangler login\n" +
				"Then retry: nowifi server create -p cloudflare")
	}

	workerToken, err := generateWorkerToken()
	if err != nil {
		return nil, fmt.Errorf("generate worker token: %w", err)
	}

	// 3. Create temp project directory with worker code.
	tmpDir, err := os.MkdirTemp("", "nowifi-cf-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	workerPath := filepath.Join(tmpDir, "worker.js")
	if err := os.WriteFile(workerPath, []byte(renderCloudflareWorkerJS(workerToken)), 0o600); err != nil {
		return nil, fmt.Errorf("write worker.js: %w", err)
	}

	today := time.Now().UTC().Format("2006-01-02")
	tomlContent := fmt.Sprintf(cfWranglerTOML, today)
	tomlPath := filepath.Join(tmpDir, "wrangler.toml")
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0o600); err != nil {
		return nil, fmt.Errorf("write wrangler.toml: %w", err)
	}

	// 4. Deploy.
	ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	deployCmd := exec.CommandContext(ctx, wrangler, "deploy")
	deployCmd.Dir = tmpDir
	deployOut, err := deployCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("wrangler deploy failed:\n%s", truncate(string(deployOut), 500))
	}

	// 5. Parse the worker URL from output.
	output := string(deployOut)
	urlRE := regexp.MustCompile(`(https://[^\s)]+\.workers\.dev)`)
	m := urlRE.FindStringSubmatch(output)
	if len(m) < 2 {
		return nil, fmt.Errorf("deploy succeeded but could not parse worker URL from output:\n%s", truncate(output, 500))
	}
	workerURL := withWorkerToken(strings.TrimRight(m[1], "/"), workerToken)

	// Save server info.
	info := &Info{
		Provider:  "cloudflare_worker",
		ServerID:  "nowifi-proxy",
		IP:        "",
		URL:       workerURL,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		TTLHours:  0,
		Status:    "active",
	}
	if err := SaveServer(info); err != nil {
		return info, fmt.Errorf("save server info: %w", err)
	}

	if err := persistConfigValue("cf_workers_url", workerURL); err != nil {
		return info, err
	}

	return info, nil
}

func generateWorkerToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func renderCloudflareWorkerJS(token string) string {
	return strings.ReplaceAll(CloudflareWorkerJS, "__NOWIFI_AUTH_TOKEN__", token)
}

func withWorkerToken(workerURL, token string) string {
	if token == "" {
		return workerURL
	}
	sep := "?"
	if strings.Contains(workerURL, "?") {
		sep = "&"
	}
	return workerURL + sep + "nowifi_token=" + token
}

// findWrangler delegates to the package-level findWranglerFn (overridable for tests).
func findWrangler() string { return findWranglerFn() }

// ---------------------------------------------------------------------------
// Option B: Ephemeral VPS
// ---------------------------------------------------------------------------

// CreateVPS creates an ephemeral VPS with tunnel tools pre-installed.
//
// Supported providers: "digitalocean", "hetzner".
// Uses cloud-init to install chisel + iodine + hans on first boot.
// Delegates to the provider registry; adding a new VPS provider requires
// only a new provider_*.go file with an init() — no edits here.
func CreateVPS(provider, apiToken string, ttlHours int) (*Info, error) {
	return CreateViaRegistry(context.Background(), provider, CreateOpts{
		APIToken: apiToken,
		TTLHours: ttlHours,
	})
}

// createDigitalOcean creates a DigitalOcean droplet ($0.007/hr, smallest instance).
func createDigitalOcean(token string, ttlHours int) (*Info, error) {
	body := map[string]interface{}{
		"name":      "nowifi-tunnel",
		"region":    "nyc1",
		"size":      "s-1vcpu-512mb-10gb",
		"image":     "ubuntu-24-04-x64",
		"user_data": CloudInitScript,
		"tags":      []string{"nowifi"},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, digitalOceanAPIBase+"/v2/droplets", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DigitalOcean API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 && resp.StatusCode != 202 {
		return nil, fmt.Errorf("DigitalOcean API error (%d): %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	var data struct {
		Droplet struct {
			ID int `json:"id"`
		} `json:"droplet"`
	}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, fmt.Errorf("parse DigitalOcean response: %w", err)
	}
	dropletID := fmt.Sprintf("%d", data.Droplet.ID)

	// Poll for public IP (droplet takes ~30-60s to provision).
	ip, err := waitForDropletIP(token, dropletID, 120*time.Second)
	if err != nil {
		return nil, err
	}

	info := &Info{
		Provider:  "digitalocean",
		ServerID:  dropletID,
		IP:        ip,
		URL:       fmt.Sprintf("https://%s:443", ip),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		TTLHours:  ttlHours,
		Status:    "active",
	}
	if err := SaveServer(info); err != nil {
		return info, fmt.Errorf("save server info: %w", err)
	}

	if err := persistConfigValue("tunnel_server", info.URL); err != nil {
		return info, err
	}

	return info, nil
}

// waitForDropletIP polls the DigitalOcean API until the droplet has a public IPv4 address.
func waitForDropletIP(token, dropletID string, timeout time.Duration) (string, error) {
	start := time.Now()
	client := &http.Client{Timeout: 15 * time.Second}

	for time.Since(start) < timeout {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, digitalOceanAPIBase+"/v2/droplets/"+dropletID, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			var data struct {
				Droplet struct {
					Networks struct {
						V4 []struct {
							Type      string `json:"type"`
							IPAddress string `json:"ip_address"`
						} `json:"v4"`
					} `json:"networks"`
				} `json:"droplet"`
			}
			if err := json.Unmarshal(body, &data); err == nil {
				for _, net := range data.Droplet.Networks.V4 {
					if net.Type == "public" {
						return net.IPAddress, nil
					}
				}
			}
		}

		time.Sleep(5 * time.Second)
	}

	return "", fmt.Errorf("droplet %s did not get a public IP within %v", dropletID, timeout)
}

// createHetzner creates a Hetzner Cloud server ($0.005/hr, smallest instance).
func createHetzner(token string, ttlHours int) (*Info, error) {
	body := map[string]interface{}{
		"name":        "nowifi-tunnel",
		"server_type": "cx22",
		"image":       "ubuntu-24.04",
		"location":    "fsn1",
		"user_data":   CloudInitScript,
		"labels":      map[string]string{"project": "nowifi"},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, hetznerAPIBase+"/v1/servers", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hetzner API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("hetzner API error (%d): %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	var data struct {
		Server struct {
			ID        int `json:"id"`
			PublicNet struct {
				IPv4 struct {
					IP string `json:"ip"`
				} `json:"ipv4"`
			} `json:"public_net"`
		} `json:"server"`
	}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, fmt.Errorf("parse Hetzner response: %w", err)
	}

	serverID := fmt.Sprintf("%d", data.Server.ID)
	ip := data.Server.PublicNet.IPv4.IP

	if ip == "" {
		var ipErr error
		ip, ipErr = waitForHetznerIP(token, serverID, 120*time.Second)
		if ipErr != nil {
			return nil, ipErr
		}
	}

	info := &Info{
		Provider:  "hetzner",
		ServerID:  serverID,
		IP:        ip,
		URL:       fmt.Sprintf("https://%s:443", ip),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		TTLHours:  ttlHours,
		Status:    "active",
	}
	if err := SaveServer(info); err != nil {
		return info, fmt.Errorf("save server info: %w", err)
	}

	if err := persistConfigValue("tunnel_server", info.URL); err != nil {
		return info, err
	}

	return info, nil
}

// waitForHetznerIP polls the Hetzner API until the server has a public IPv4 address.
func waitForHetznerIP(token, serverID string, timeout time.Duration) (string, error) {
	start := time.Now()
	client := &http.Client{Timeout: 15 * time.Second}

	for time.Since(start) < timeout {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, hetznerAPIBase+"/v1/servers/"+serverID, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			var data struct {
				Server struct {
					PublicNet struct {
						IPv4 struct {
							IP string `json:"ip"`
						} `json:"ipv4"`
					} `json:"public_net"`
				} `json:"server"`
			}
			if err := json.Unmarshal(body, &data); err == nil {
				if data.Server.PublicNet.IPv4.IP != "" {
					return data.Server.PublicNet.IPv4.IP, nil
				}
			}
		}

		time.Sleep(5 * time.Second)
	}

	return "", fmt.Errorf("hetzner server %s did not get a public IP within %v", serverID, timeout)
}

// ---------------------------------------------------------------------------
// Destroy server
// ---------------------------------------------------------------------------

// DestroyServer destroys a provisioned server (VPS or CF Worker).
// Returns nil on success.
// Delegates to the provider registry; adding a new provider requires
// only a new provider_*.go file with an init() — no edits here.
func DestroyServer(info *Info, apiToken string) error {
	return DestroyViaRegistry(context.Background(), info, apiToken)
}

func destroyDigitalOcean(token, dropletID string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, digitalOceanAPIBase+"/v2/droplets/"+dropletID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("delete request to digitalocean failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 204 {
		return fmt.Errorf("delete request to digitalocean returned status %d", resp.StatusCode)
	}

	if err := markDestroyed("digitalocean", dropletID); err != nil {
		return fmt.Errorf("mark destroyed: %w", err)
	}
	return nil
}

func destroyHetzner(token, serverID string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, hetznerAPIBase+"/v1/servers/"+serverID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("delete request to hetzner failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("delete request to hetzner returned status %d", resp.StatusCode)
	}

	if err := markDestroyed("hetzner", serverID); err != nil {
		return fmt.Errorf("mark destroyed: %w", err)
	}
	return nil
}

func destroyCloudflareWorker(workerName string) error {
	wrangler := findWrangler()
	if wrangler == "" {
		return fmt.Errorf("wrangler not found; cannot delete Cloudflare Worker")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, wrangler, "delete", "--name", workerName, "--force").CombinedOutput()
	if err != nil {
		return fmt.Errorf("wrangler delete failed: %s", truncate(string(out), 500))
	}

	if err := markDestroyed("cloudflare_worker", workerName); err != nil {
		return fmt.Errorf("mark destroyed: %w", err)
	}
	return nil
}

// destroyCloudflareQuick terminates the cloudflared process stored in
// info.PID.  It sends SIGTERM first, waits up to 3 seconds, then SIGKILLs.
func destroyCloudflareQuick(info *Info) error {
	if info.PID > 0 {
		proc, err := os.FindProcess(info.PID)
		if err == nil {
			// SIGTERM — polite shutdown.
			_ = proc.Signal(syscall.SIGTERM)

			done := make(chan error, 1)
			go func() {
				_, err := proc.Wait()
				done <- err
			}()

			select {
			case <-done:
				// Process exited cleanly.
			case <-time.After(3 * time.Second):
				// Timeout — force kill.
				_ = proc.Signal(syscall.SIGKILL)
				<-done
			}
		}
	}

	if err := markDestroyed(info.Provider, info.ServerID); err != nil {
		return fmt.Errorf("mark destroyed: %w", err)
	}
	return nil
}

func markDestroyed(provider, serverID string) error {
	servers, err := LoadServers()
	if err != nil {
		return err
	}
	for i := range servers {
		if servers[i].ServerID == serverID && servers[i].Provider == provider {
			servers[i].Status = "destroyed"
		}
	}
	ensureDir()
	if err := writeServers(servers); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Expired server check
// ---------------------------------------------------------------------------

// CheckExpiredServers finds servers that have exceeded their TTL.
func CheckExpiredServers() []Info {
	now := time.Now().UTC()
	servers, _ := LoadServers()

	var expired []Info
	for _, s := range servers {
		if s.Status == "destroyed" || s.TTLHours <= 0 {
			continue
		}
		created, err := time.Parse(time.RFC3339, s.CreatedAt)
		if err != nil {
			// Try ISO 8601 without timezone.
			created, err = time.Parse("2006-01-02T15:04:05", s.CreatedAt)
			if err != nil {
				continue
			}
			created = created.UTC()
		}
		elapsed := now.Sub(created).Hours()
		if elapsed > float64(s.TTLHours) {
			expired = append(expired, s)
		}
	}

	return expired
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
