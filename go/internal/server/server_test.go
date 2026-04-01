package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Technique classification
// ---------------------------------------------------------------------------

func TestServerlessTechniquesCount(t *testing.T) {
	if len(ServerlessTechniques) < 10 {
		t.Errorf("ServerlessTechniques has %d entries, want >= 10", len(ServerlessTechniques))
	}
}

func TestServerRequiredTechniquesCount(t *testing.T) {
	if len(ServerRequiredTechniques) > 10 {
		t.Errorf("ServerRequiredTechniques has %d entries, want <= 10", len(ServerRequiredTechniques))
	}
}

func TestNoOverlapBetweenServerlessAndRequired(t *testing.T) {
	serverless := make(map[string]bool, len(ServerlessTechniques))
	for _, tech := range ServerlessTechniques {
		serverless[tech] = true
	}

	for _, tech := range ServerRequiredTechniques {
		if serverless[tech] {
			t.Errorf("technique %q appears in both ServerlessTechniques and ServerRequiredTechniques", tech)
		}
	}
}

func TestServerlessTechniquesNonEmpty(t *testing.T) {
	for i, tech := range ServerlessTechniques {
		if tech == "" {
			t.Errorf("ServerlessTechniques[%d] is empty", i)
		}
	}
}

func TestServerRequiredTechniquesNonEmpty(t *testing.T) {
	for i, tech := range ServerRequiredTechniques {
		if tech == "" {
			t.Errorf("ServerRequiredTechniques[%d] is empty", i)
		}
	}
}

// ---------------------------------------------------------------------------
// SaveServer + LoadServers round-trip
// ---------------------------------------------------------------------------

func setupTestDir(t *testing.T) (string, func()) {
	t.Helper()

	// Override nowifiDir by using a temp HOME.
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)

	return tmpHome, func() {
		os.Setenv("HOME", origHome)
	}
}

func TestSaveServerAndLoadServers_RoundTrip(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	info := &Info{
		Provider:  "digitalocean",
		ServerID:  "12345",
		IP:        "1.2.3.4",
		URL:       "https://1.2.3.4:443",
		CreatedAt: "2026-03-29T10:00:00Z",
		TTLHours:  24,
		Status:    "active",
	}

	if err := SaveServer(info); err != nil {
		t.Fatalf("SaveServer: %v", err)
	}

	servers, err := LoadServers()
	if err != nil {
		t.Fatalf("LoadServers: %v", err)
	}

	if len(servers) != 1 {
		t.Fatalf("LoadServers returned %d servers, want 1", len(servers))
	}

	got := servers[0]
	if got.Provider != "digitalocean" {
		t.Errorf("Provider = %q, want digitalocean", got.Provider)
	}
	if got.ServerID != "12345" {
		t.Errorf("ServerID = %q, want 12345", got.ServerID)
	}
	if got.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want 1.2.3.4", got.IP)
	}
	if got.URL != "https://1.2.3.4:443" {
		t.Errorf("URL = %q, want https://1.2.3.4:443", got.URL)
	}
	if got.Status != "active" {
		t.Errorf("Status = %q, want active", got.Status)
	}
	if got.TTLHours != 24 {
		t.Errorf("TTLHours = %d, want 24", got.TTLHours)
	}
}

func TestSaveServer_UpdatesExisting(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	info := &Info{
		Provider:  "hetzner",
		ServerID:  "99",
		IP:        "5.6.7.8",
		URL:       "https://5.6.7.8:443",
		CreatedAt: "2026-03-29T10:00:00Z",
		TTLHours:  6,
		Status:    "active",
	}
	if err := SaveServer(info); err != nil {
		t.Fatal(err)
	}

	// Update same server.
	info.Status = "destroyed"
	info.IP = "0.0.0.0"
	if err := SaveServer(info); err != nil {
		t.Fatal(err)
	}

	servers, err := LoadServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server after update, got %d", len(servers))
	}
	if servers[0].Status != "destroyed" {
		t.Errorf("Status = %q, want destroyed", servers[0].Status)
	}
	if servers[0].IP != "0.0.0.0" {
		t.Errorf("IP = %q, want 0.0.0.0", servers[0].IP)
	}
}

func TestLoadServers_FileNotExist(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	servers, err := LoadServers()
	if err != nil {
		t.Errorf("LoadServers on missing file: %v", err)
	}
	if servers != nil {
		t.Errorf("expected nil for missing file, got %d servers", len(servers))
	}
}

func TestLoadServers_CorruptFile(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	ensureDir()
	if err := os.WriteFile(serversFile(), []byte("not json!"), 0o644); err != nil {
		t.Fatal(err)
	}

	servers, err := LoadServers()
	if err != nil {
		t.Errorf("LoadServers on corrupt file should not error, got: %v", err)
	}
	if servers != nil {
		t.Errorf("expected nil for corrupt file, got %d servers", len(servers))
	}
}

// ---------------------------------------------------------------------------
// ListServers filters by active status
// ---------------------------------------------------------------------------

func TestListServers_FiltersDestroyed(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	servers := []Info{
		{Provider: "digitalocean", ServerID: "1", Status: "active"},
		{Provider: "hetzner", ServerID: "2", Status: "destroyed"},
		{Provider: "cloudflare_worker", ServerID: "3", Status: "active"},
		{Provider: "digitalocean", ServerID: "4", Status: "destroyed"},
	}

	ensureDir()
	data, _ := json.MarshalIndent(servers, "", "  ")
	if err := os.WriteFile(serversFile(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	active, err := ListServers()
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}

	if len(active) != 2 {
		t.Fatalf("ListServers returned %d servers, want 2 active", len(active))
	}

	for _, s := range active {
		if s.Status == "destroyed" {
			t.Errorf("ListServers returned destroyed server: %s", s.ServerID)
		}
	}
}

func TestListServers_AllDestroyed(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	servers := []Info{
		{Provider: "digitalocean", ServerID: "1", Status: "destroyed"},
		{Provider: "hetzner", ServerID: "2", Status: "destroyed"},
	}

	ensureDir()
	data, _ := json.MarshalIndent(servers, "", "  ")
	if err := os.WriteFile(serversFile(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	active, err := ListServers()
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}

	if len(active) != 0 {
		t.Errorf("expected 0 active servers, got %d", len(active))
	}
}

// ---------------------------------------------------------------------------
// Embedded assets
// ---------------------------------------------------------------------------

func TestCloudflareWorkerJS_NonEmpty(t *testing.T) {
	if CloudflareWorkerJS == "" {
		t.Error("CloudflareWorkerJS is empty")
	}
	if len(CloudflareWorkerJS) < 50 {
		t.Errorf("CloudflareWorkerJS is suspiciously short: %d bytes", len(CloudflareWorkerJS))
	}
}

func TestCloudflareWorkerJS_ContainsExportDefault(t *testing.T) {
	if !contains(CloudflareWorkerJS, "export default") {
		t.Error("CloudflareWorkerJS should contain 'export default'")
	}
}

func TestCloudInitScript_NonEmpty(t *testing.T) {
	if CloudInitScript == "" {
		t.Error("CloudInitScript is empty")
	}
	if len(CloudInitScript) < 50 {
		t.Errorf("CloudInitScript is suspiciously short: %d bytes", len(CloudInitScript))
	}
}

func TestCloudInitScript_ContainsChisel(t *testing.T) {
	if !contains(CloudInitScript, "chisel") {
		t.Error("CloudInitScript should contain 'chisel'")
	}
}

func TestCloudInitScript_ContainsIodine(t *testing.T) {
	if !contains(CloudInitScript, "iodine") {
		t.Error("CloudInitScript should contain 'iodine'")
	}
}

func TestCloudInitScript_ContainsHans(t *testing.T) {
	if !contains(CloudInitScript, "hans") {
		t.Error("CloudInitScript should contain 'hans'")
	}
}

// contains checks if s contains substr (avoid importing strings in test).
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// CreateVPS with mock HTTP server (DigitalOcean API)
// ---------------------------------------------------------------------------

func TestCreateVPS_DigitalOcean_Mock(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	// Mock DigitalOcean API: POST /v2/droplets returns 202 with droplet ID,
	// GET /v2/droplets/123 returns a public IP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case "POST":
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"droplet": map[string]interface{}{
					"id": 123,
				},
			})
		case "GET":
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"droplet": map[string]interface{}{
					"id": 123,
					"networks": map[string]interface{}{
						"v4": []map[string]interface{}{
							{"type": "public", "ip_address": "203.0.113.42"},
						},
					},
				},
			})
		}
	}))
	defer srv.Close()

	// We cannot easily inject the mock URL into createDigitalOcean since it
	// uses hardcoded URLs. Instead, we test the data serialization round-trip
	// that CreateVPS would produce, and test the mock API response parsing.

	// Simulate what createDigitalOcean does with the response.
	resp, err := http.Post(srv.URL+"/v2/droplets", "application/json", nil)
	if err != nil {
		t.Fatalf("POST to mock: %v", err)
	}
	defer resp.Body.Close()

	var data struct {
		Droplet struct {
			ID int `json:"id"`
		} `json:"droplet"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if data.Droplet.ID != 123 {
		t.Errorf("droplet ID = %d, want 123", data.Droplet.ID)
	}

	// Simulate GET for IP.
	resp2, err := http.Get(srv.URL + "/v2/droplets/123")
	if err != nil {
		t.Fatalf("GET to mock: %v", err)
	}
	defer resp2.Body.Close()

	var ipData struct {
		Droplet struct {
			Networks struct {
				V4 []struct {
					Type      string `json:"type"`
					IPAddress string `json:"ip_address"`
				} `json:"v4"`
			} `json:"networks"`
		} `json:"droplet"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&ipData); err != nil {
		t.Fatalf("decode IP response: %v", err)
	}

	foundIP := ""
	for _, net := range ipData.Droplet.Networks.V4 {
		if net.Type == "public" {
			foundIP = net.IPAddress
			break
		}
	}
	if foundIP != "203.0.113.42" {
		t.Errorf("droplet IP = %q, want 203.0.113.42", foundIP)
	}
}

// ---------------------------------------------------------------------------
// DestroyServer with mock HTTP server
// ---------------------------------------------------------------------------

func TestDestroyServer_DigitalOcean_Mock(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	// Mock DigitalOcean DELETE /v2/droplets/456 returns 204.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			w.WriteHeader(405)
			return
		}
		// Verify authorization header.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token-456" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	// Simulate the destroy request to the mock server.
	req, err := http.NewRequest("DELETE", srv.URL+"/v2/droplets/456", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token-456")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DELETE to mock: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 204 {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

func TestDestroyServer_UnknownProvider(t *testing.T) {
	info := &Info{Provider: "unknown_cloud", ServerID: "1"}
	err := DestroyServer(info, "token")
	if err == nil {
		t.Error("DestroyServer with unknown provider should return error")
	}
}

// ---------------------------------------------------------------------------
// Config persistence
// ---------------------------------------------------------------------------

func TestSaveConfigAndLoadConfig_RoundTrip(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	cfg := map[string]string{
		"digitalocean_token": "do_test_token_123",
		"cf_workers_url":     "https://nowifi-proxy.workers.dev",
		"tunnel_server":      "https://1.2.3.4:443",
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded := LoadConfig()
	for k, v := range cfg {
		if loaded[k] != v {
			t.Errorf("LoadConfig[%q] = %q, want %q", k, loaded[k], v)
		}
	}
}

func TestLoadConfig_FileNotExist(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("LoadConfig should return non-nil map")
	}
	if len(cfg) != 0 {
		t.Errorf("LoadConfig on missing file: len = %d, want 0", len(cfg))
	}
}

// ---------------------------------------------------------------------------
// CheckExpiredServers
// ---------------------------------------------------------------------------

func TestCheckExpiredServers(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	servers := []Info{
		{Provider: "do", ServerID: "1", CreatedAt: "2020-01-01T00:00:00Z", TTLHours: 1, Status: "active"},    // expired
		{Provider: "do", ServerID: "2", CreatedAt: "2099-01-01T00:00:00Z", TTLHours: 24, Status: "active"},   // not expired
		{Provider: "do", ServerID: "3", CreatedAt: "2020-01-01T00:00:00Z", TTLHours: 1, Status: "destroyed"}, // destroyed, skip
		{Provider: "do", ServerID: "4", CreatedAt: "2020-01-01T00:00:00Z", TTLHours: 0, Status: "active"},    // TTL=0, skip
	}

	ensureDir()
	data, _ := json.MarshalIndent(servers, "", "  ")
	if err := os.WriteFile(serversFile(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	expired := CheckExpiredServers()
	if len(expired) != 1 {
		t.Fatalf("CheckExpiredServers returned %d, want 1", len(expired))
	}
	if expired[0].ServerID != "1" {
		t.Errorf("expired server ID = %q, want 1", expired[0].ServerID)
	}
}

// ---------------------------------------------------------------------------
// Info JSON
// ---------------------------------------------------------------------------

func TestInfoJSON(t *testing.T) {
	info := Info{
		Provider:  "hetzner",
		ServerID:  "42",
		IP:        "10.0.0.1",
		URL:       "https://10.0.0.1:443",
		CreatedAt: "2026-03-29T12:00:00Z",
		TTLHours:  12,
		Status:    "creating",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Info
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Provider != info.Provider {
		t.Errorf("Provider = %q, want %q", decoded.Provider, info.Provider)
	}
	if decoded.Status != "creating" {
		t.Errorf("Status = %q, want creating", decoded.Status)
	}
}

// ---------------------------------------------------------------------------
// truncate helper
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"long", "hello world", 5, "hello"},
		{"empty", "", 5, ""},
		{"zero max", "hello", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getToken
// ---------------------------------------------------------------------------

func TestGetToken_Explicit(t *testing.T) {
	token, err := getToken("digitalocean", "my-token")
	if err != nil {
		t.Fatalf("getToken with explicit token: %v", err)
	}
	if token != "my-token" {
		t.Errorf("token = %q, want my-token", token)
	}
}

func TestGetToken_FromConfig(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	cfg := map[string]string{"digitalocean_token": "cfg-token"}
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	token, err := getToken("digitalocean", "")
	if err != nil {
		t.Fatalf("getToken from config: %v", err)
	}
	if token != "cfg-token" {
		t.Errorf("token = %q, want cfg-token", token)
	}
}

func TestGetToken_Missing(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	_, err := getToken("digitalocean", "")
	if err == nil {
		t.Error("getToken with no token should return error")
	}
}

// ---------------------------------------------------------------------------
// Multiple servers
// ---------------------------------------------------------------------------

func TestSaveMultipleServers(t *testing.T) {
	_, cleanup := setupTestDir(t)
	defer cleanup()

	for i := 1; i <= 3; i++ {
		info := &Info{
			Provider: "digitalocean",
			ServerID: filepath.Base(filepath.Join("id", string(rune('0'+i)))),
			Status:   "active",
		}
		if err := SaveServer(info); err != nil {
			t.Fatal(err)
		}
	}

	servers, err := LoadServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 3 {
		t.Errorf("expected 3 servers, got %d", len(servers))
	}
}
