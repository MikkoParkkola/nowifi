// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package server provisions tunnel infrastructure: Cloudflare Workers,
// DigitalOcean droplets, and Hetzner Cloud servers.
//
// Three options:
//
//	A. Cloudflare Workers (FREE, no server needed) -- HTTPS proxy on CF edge
//	B. Ephemeral VPS (DigitalOcean / Hetzner) -- chisel + iodine + hans pre-installed
//	C. No server -- 10 of 23 techniques need no server at all
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// Info holds metadata about a provisioned server.
type Info struct {
	Provider  string `json:"provider"`   // "cloudflare_worker", "digitalocean", "hetzner", "custom"
	ServerID  string `json:"server_id"`  // Droplet ID, Hetzner server ID, or Worker name
	IP        string `json:"ip"`         // Public IP (empty for CF Workers)
	URL       string `json:"url"`        // Chisel/proxy URL
	CreatedAt string `json:"created_at"` // ISO 8601 timestamp
	TTLHours  int    `json:"ttl_hours"`  // Auto-destroy after this (0 = never)
	Status    string `json:"status"`     // "active", "creating", "destroyed"
}

// ---------------------------------------------------------------------------
// Technique classification
// ---------------------------------------------------------------------------

// ServerlessTechniques lists techniques that need no external server.
var ServerlessTechniques = []string{
	"ipv6_bypass",
	"cna_useragent_spoof",
	"js_only_bypass",
	"http_connect_abuse",
	"mac_clone_idle",
	"mac_clone",
	"session_cookie_replay",
	"portal_default_creds",
	"mac_rotate",
	"dhcp_rotate",
}

// ServerRequiredTechniques lists techniques that require a tunnel server.
var ServerRequiredTechniques = []string{
	"chisel_tunnel",
	"dns_tunnel",
	"icmp_tunnel",
	"vpn_port_53",
	"whitelist_domain",
	"quic_tunnel",
	"cf_workers_proxy",
	"ntp_tunnel",
	"doh_tunnel",
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
	return os.WriteFile(serversFile(), data, 0o644)
}

// LoadConfig loads ~/.nowifi/config.json (tokens, URLs).
func LoadConfig() map[string]string {
	data, err := os.ReadFile(configFile())
	if err != nil {
		return make(map[string]string)
	}
	var cfg map[string]string
	if err := json.Unmarshal(data, &cfg); err != nil {
		return make(map[string]string)
	}
	return cfg
}

// SaveConfig saves ~/.nowifi/config.json.
func SaveConfig(cfg map[string]string) error {
	ensureDir()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile(), data, 0o644)
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
// Embedded assets
// ---------------------------------------------------------------------------

// CloudflareWorkerJS is the Cloudflare Worker JavaScript that acts as
// a transparent HTTPS proxy for nowifi.
const CloudflareWorkerJS = `// Cloudflare Worker -- transparent HTTPS proxy for nowifi
export default {
  async fetch(request) {
    const url = new URL(request.url);
    // Path format: /https://target.com/path
    const targetUrl = url.pathname.slice(1) + url.search;
    if (!targetUrl.startsWith('http')) {
      return new Response('nowifi tunnel proxy active', { status: 200 });
    }
    try {
      const resp = await fetch(targetUrl, {
        method: request.method,
        headers: request.headers,
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
curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > /usr/local/bin/chisel
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

		out, err := exec.Command(npm, "install", "-g", "wrangler").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to install wrangler: %s", truncate(string(out), 500))
		}

		wrangler = findWrangler()
		if wrangler == "" {
			return nil, fmt.Errorf("wrangler installed but not found on PATH. Try: npx wrangler")
		}
	}

	// 2. Check login status.
	out, err := exec.Command(wrangler, "whoami").CombinedOutput()
	if err != nil || strings.Contains(strings.ToLower(string(out)), "not authenticated") {
		return nil, fmt.Errorf(
			"not logged in to Cloudflare. Run:\n" +
				"  wrangler login\n" +
				"Then retry: nowifi server create -p cloudflare")
	}

	// 3. Create temp project directory with worker code.
	tmpDir, err := os.MkdirTemp("", "nowifi-cf-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	workerPath := filepath.Join(tmpDir, "worker.js")
	if err := os.WriteFile(workerPath, []byte(CloudflareWorkerJS), 0o644); err != nil {
		return nil, fmt.Errorf("write worker.js: %w", err)
	}

	today := time.Now().UTC().Format("2006-01-02")
	tomlContent := fmt.Sprintf(cfWranglerTOML, today)
	tomlPath := filepath.Join(tmpDir, "wrangler.toml")
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0o644); err != nil {
		return nil, fmt.Errorf("write wrangler.toml: %w", err)
	}

	// 4. Deploy.
	deployCmd := exec.Command(wrangler, "deploy")
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
	workerURL := strings.TrimRight(m[1], "/")

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

	// Update config with worker URL.
	cfg := LoadConfig()
	cfg["cf_workers_url"] = workerURL
	_ = SaveConfig(cfg)

	return info, nil
}

func findWrangler() string {
	p, err := exec.LookPath("wrangler")
	if err == nil {
		return p
	}
	return ""
}

// ---------------------------------------------------------------------------
// Option B: Ephemeral VPS
// ---------------------------------------------------------------------------

// CreateVPS creates an ephemeral VPS with tunnel tools pre-installed.
//
// Supported providers: "digitalocean", "hetzner".
// Uses cloud-init to install chisel + iodine + hans on first boot.
func CreateVPS(provider, apiToken string, ttlHours int) (*Info, error) {
	token, err := getToken(provider, apiToken)
	if err != nil {
		return nil, err
	}

	switch provider {
	case "digitalocean":
		return createDigitalOcean(token, ttlHours)
	case "hetzner":
		return createHetzner(token, ttlHours)
	default:
		return nil, fmt.Errorf("unknown provider: %q. Use 'digitalocean' or 'hetzner'", provider)
	}
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

	req, err := http.NewRequest("POST", "https://api.digitalocean.com/v2/droplets", bytes.NewReader(jsonBody))
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

	cfg := LoadConfig()
	cfg["tunnel_server"] = info.URL
	_ = SaveConfig(cfg)

	return info, nil
}

// waitForDropletIP polls the DigitalOcean API until the droplet has a public IPv4 address.
func waitForDropletIP(token, dropletID string, timeout time.Duration) (string, error) {
	start := time.Now()
	client := &http.Client{Timeout: 15 * time.Second}

	for time.Since(start) < timeout {
		req, err := http.NewRequest("GET", "https://api.digitalocean.com/v2/droplets/"+dropletID, nil)
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

	req, err := http.NewRequest("POST", "https://api.hetzner.cloud/v1/servers", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Hetzner API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("Hetzner API error (%d): %s", resp.StatusCode, truncate(string(respBody), 500))
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

	cfg := LoadConfig()
	cfg["tunnel_server"] = info.URL
	_ = SaveConfig(cfg)

	return info, nil
}

// waitForHetznerIP polls the Hetzner API until the server has a public IPv4 address.
func waitForHetznerIP(token, serverID string, timeout time.Duration) (string, error) {
	start := time.Now()
	client := &http.Client{Timeout: 15 * time.Second}

	for time.Since(start) < timeout {
		req, err := http.NewRequest("GET", "https://api.hetzner.cloud/v1/servers/"+serverID, nil)
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

	return "", fmt.Errorf("Hetzner server %s did not get a public IP within %v", serverID, timeout)
}

// ---------------------------------------------------------------------------
// Destroy server
// ---------------------------------------------------------------------------

// DestroyServer destroys a provisioned server (VPS or CF Worker).
// Returns nil on success.
func DestroyServer(info *Info, apiToken string) error {
	switch info.Provider {
	case "digitalocean":
		token, err := getToken("digitalocean", apiToken)
		if err != nil {
			return err
		}
		return destroyDigitalOcean(token, info.ServerID)

	case "hetzner":
		token, err := getToken("hetzner", apiToken)
		if err != nil {
			return err
		}
		return destroyHetzner(token, info.ServerID)

	case "cloudflare_worker":
		return destroyCloudflareWorker(info.ServerID)

	default:
		return fmt.Errorf("unknown provider: %q", info.Provider)
	}
}

func destroyDigitalOcean(token, dropletID string) error {
	req, err := http.NewRequest("DELETE", "https://api.digitalocean.com/v2/droplets/"+dropletID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("DigitalOcean delete failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 204 {
		return fmt.Errorf("DigitalOcean delete returned status %d", resp.StatusCode)
	}

	markDestroyed("digitalocean", dropletID)
	return nil
}

func destroyHetzner(token, serverID string) error {
	req, err := http.NewRequest("DELETE", "https://api.hetzner.cloud/v1/servers/"+serverID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Hetzner delete failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Hetzner delete returned status %d", resp.StatusCode)
	}

	markDestroyed("hetzner", serverID)
	return nil
}

func destroyCloudflareWorker(workerName string) error {
	wrangler := findWrangler()
	if wrangler == "" {
		return fmt.Errorf("wrangler not found; cannot delete Cloudflare Worker")
	}

	out, err := exec.Command(wrangler, "delete", "--name", workerName, "--force").CombinedOutput()
	if err != nil {
		return fmt.Errorf("wrangler delete failed: %s", truncate(string(out), 500))
	}

	markDestroyed("cloudflare_worker", workerName)
	return nil
}

func markDestroyed(provider, serverID string) {
	servers, _ := LoadServers()
	for i := range servers {
		if servers[i].ServerID == serverID && servers[i].Provider == provider {
			servers[i].Status = "destroyed"
		}
	}
	ensureDir()
	_ = writeServers(servers)
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
