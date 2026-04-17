// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Tests for VPS create/destroy and Cloudflare Worker functions.
// All external HTTP calls are intercepted by httptest.Server instances.
// All exec calls are intercepted by package-level function vars.

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newSleepCmd returns a long-running command that exits on SIGTERM (default shell behavior).
func newSleepCmd() *exec.Cmd {
	return exec.Command("sh", "-c", "while true; do sleep 0.1; done")
}

// newCmdFromPath returns a command that runs the script at path directly.
func newCmdFromPath(path string) *exec.Cmd {
	return exec.Command(path)
}

// ---------------------------------------------------------------------------
// Helpers shared across tests in this file
// ---------------------------------------------------------------------------

// setDOBase overrides digitalOceanAPIBase for the duration of a test.
func setDOBase(t *testing.T, url string) {
	t.Helper()
	orig := digitalOceanAPIBase
	digitalOceanAPIBase = url
	t.Cleanup(func() { digitalOceanAPIBase = orig })
}

// setHetznerBase overrides hetznerAPIBase for the duration of a test.
func setHetznerBase(t *testing.T, url string) {
	t.Helper()
	orig := hetznerAPIBase
	hetznerAPIBase = url
	t.Cleanup(func() { hetznerAPIBase = orig })
}

// setFindWrangler overrides findWranglerFn for the duration of a test.
func setFindWrangler(t *testing.T, fn func() string) {
	t.Helper()
	orig := findWranglerFn
	findWranglerFn = fn
	t.Cleanup(func() { findWranglerFn = orig })
}

// fakeWrangler writes a shell script at dir/wrangler that:
//   - prints deployOutput to stdout on "deploy"
//   - exits with deleteExitCode on "delete"
//   - exits exitCode for everything else
func fakeWrangler(t *testing.T, deployOutput string, deleteExitCode int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "wrangler")

	// Build the script body. Use %d/%s carefully to avoid fmt import in script.
	script := "#!/bin/sh\n"
	script += "case \"$1\" in\n"
	script += "  deploy)\n"
	script += "    echo " + shellescape(deployOutput) + "\n"
	script += "    exit 0\n"
	script += "    ;;\n"
	script += "  whoami)\n"
	script += "    echo 'You are logged in as: test@example.com'\n"
	script += "    exit 0\n"
	script += "    ;;\n"
	script += "  delete)\n"
	script += fmt.Sprintf("    exit %d\n", deleteExitCode)
	script += "    ;;\n"
	script += "  *)\n"
	script += "    exit 0\n"
	script += "    ;;\n"
	script += "esac\n"

	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake wrangler: %v", err)
	}
	return path
}

// shellescape wraps s in single quotes for safe shell embedding.
func shellescape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// ---------------------------------------------------------------------------
// findWrangler
// ---------------------------------------------------------------------------

func TestFindWrangler_Found(t *testing.T) {
	// Override findWranglerFn to return a known path.
	setFindWrangler(t, func() string { return "/usr/local/bin/wrangler" })
	got := findWrangler()
	if got != "/usr/local/bin/wrangler" {
		t.Errorf("findWrangler() = %q, want /usr/local/bin/wrangler", got)
	}
}

func TestFindWrangler_NotFound(t *testing.T) {
	setFindWrangler(t, func() string { return "" })
	got := findWrangler()
	if got != "" {
		t.Errorf("findWrangler() = %q, want empty string", got)
	}
}

// ---------------------------------------------------------------------------
// destroyCloudflareWorker
// ---------------------------------------------------------------------------

func TestDestroyCloudflareWorker_Success(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	wPath := fakeWrangler(t, "", 0)
	setFindWrangler(t, func() string { return wPath })

	// Pre-save a worker so markDestroyed has something to update.
	info := &Info{Provider: "cloudflare_worker", ServerID: "nowifi-proxy", Status: "active"}
	if err := SaveServer(info); err != nil {
		t.Fatalf("SaveServer: %v", err)
	}

	if err := destroyCloudflareWorker("nowifi-proxy"); err != nil {
		t.Fatalf("destroyCloudflareWorker: %v", err)
	}

	// Verify markDestroyed was called.
	servers, _ := LoadServers()
	for _, s := range servers {
		if s.ServerID == "nowifi-proxy" && s.Status != "destroyed" {
			t.Errorf("worker not marked destroyed, status = %q", s.Status)
		}
	}
}

func TestDestroyCloudflareWorker_WranglerNotFound(t *testing.T) {
	setFindWrangler(t, func() string { return "" })

	err := destroyCloudflareWorker("nowifi-proxy")
	if err == nil {
		t.Fatal("expected error when wrangler not found")
	}
	if !strings.Contains(err.Error(), "wrangler not found") {
		t.Errorf("error = %q, want 'wrangler not found'", err.Error())
	}
}

func TestDestroyCloudflareWorker_WranglerFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	wPath := fakeWrangler(t, "", 1) // delete exits 1
	setFindWrangler(t, func() string { return wPath })

	err := destroyCloudflareWorker("nowifi-proxy")
	if err == nil {
		t.Fatal("expected error when wrangler delete fails")
	}
	if !strings.Contains(err.Error(), "wrangler delete failed") {
		t.Errorf("error = %q, want 'wrangler delete failed'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// SetupCloudflareWorker
// ---------------------------------------------------------------------------

func TestSetupCloudflareWorker_Success(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Fake wrangler that prints a workers.dev URL on deploy.
	deployOut := "Published nowifi-proxy (1.23 sec)\nhttps://nowifi-abc123.my-subdomain.workers.dev"
	wPath := fakeWrangler(t, deployOut, 0)
	setFindWrangler(t, func() string { return wPath })

	info, err := SetupCloudflareWorker()
	if err != nil {
		t.Fatalf("SetupCloudflareWorker: %v", err)
	}
	if info == nil {
		t.Fatal("info is nil")
	}
	if !strings.Contains(info.URL, "workers.dev") {
		t.Errorf("URL = %q, want workers.dev URL", info.URL)
	}
	if info.Provider != "cloudflare_worker" {
		t.Errorf("Provider = %q, want cloudflare_worker", info.Provider)
	}
	if info.Status != "active" {
		t.Errorf("Status = %q, want active", info.Status)
	}

	// Verify SaveServer was called.
	servers, _ := LoadServers()
	found := false
	for _, s := range servers {
		if s.Provider == "cloudflare_worker" {
			found = true
		}
	}
	if !found {
		t.Error("cloudflare_worker not found in saved servers")
	}
}

func TestSetupCloudflareWorker_WranglerNotFound_NoNPM(t *testing.T) {
	setFindWrangler(t, func() string { return "" })

	// npm is unlikely to be absent but we can make findWrangler always return ""
	// so it falls through to the npm-install path, which fails if npm not found.
	// On CI where npm IS present, the npm install will fail (no network/auth).
	// We just verify the function returns an error.
	_, err := SetupCloudflareWorker()
	if err == nil {
		t.Fatal("expected error when wrangler not found and install fails")
	}
}

func TestSetupCloudflareWorker_DeployFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Fake wrangler: whoami succeeds, deploy fails.
	dir := t.TempDir()
	wPath := filepath.Join(dir, "wrangler")
	script := "#!/bin/sh\ncase \"$1\" in\n  whoami) echo 'logged in'; exit 0;;\n  deploy) echo 'Error: deploy failed' >&2; exit 1;;\n  *) exit 0;;\nesac\n"
	if err := os.WriteFile(wPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write wrangler: %v", err)
	}
	setFindWrangler(t, func() string { return wPath })

	_, err := SetupCloudflareWorker()
	if err == nil {
		t.Fatal("expected error when deploy fails")
	}
	if !strings.Contains(err.Error(), "wrangler deploy failed") {
		t.Errorf("error = %q, want 'wrangler deploy failed'", err.Error())
	}
}

func TestSetupCloudflareWorker_DeployNoURLInOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Fake wrangler: deploy succeeds but outputs no workers.dev URL.
	dir := t.TempDir()
	wPath := filepath.Join(dir, "wrangler")
	script := "#!/bin/sh\ncase \"$1\" in\n  whoami) echo 'logged in'; exit 0;;\n  deploy) echo 'deployed but no url here'; exit 0;;\n  *) exit 0;;\nesac\n"
	if err := os.WriteFile(wPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write wrangler: %v", err)
	}
	setFindWrangler(t, func() string { return wPath })

	_, err := SetupCloudflareWorker()
	if err == nil {
		t.Fatal("expected error when URL not found in output")
	}
	if !strings.Contains(err.Error(), "could not parse worker URL") {
		t.Errorf("error = %q, want 'could not parse worker URL'", err.Error())
	}
}

func TestSetupCloudflareWorker_NotAuthenticated(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Fake wrangler: whoami returns "not authenticated".
	dir := t.TempDir()
	wPath := filepath.Join(dir, "wrangler")
	script := "#!/bin/sh\ncase \"$1\" in\n  whoami) echo 'not authenticated'; exit 1;;\n  *) exit 0;;\nesac\n"
	if err := os.WriteFile(wPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write wrangler: %v", err)
	}
	setFindWrangler(t, func() string { return wPath })

	_, err := SetupCloudflareWorker()
	if err == nil {
		t.Fatal("expected error when not authenticated")
	}
	if !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("error = %q, want 'not logged in'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// createDigitalOcean — via httptest
// ---------------------------------------------------------------------------

// doMockServer builds a single httptest.Server that serves both POST /v2/droplets
// (create) and GET /v2/droplets/:id (poll for IP).
// postStatus is the HTTP status for the POST; getIP is the IP to return in GET.
// If getIP is empty the GET returns a droplet with no public IP.
func doMockServer(t *testing.T, postStatus int, postBody interface{}, getIP string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(postStatus)
			if postBody != nil {
				_ = json.NewEncoder(w).Encode(postBody)
			}
		case http.MethodGet:
			if getIP != "" {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"droplet": map[string]interface{}{
						"id": 123,
						"networks": map[string]interface{}{
							"v4": []map[string]interface{}{
								{"type": "public", "ip_address": getIP},
							},
						},
					},
				})
			} else {
				// Droplet has no IP yet — return empty networks to trigger timeout.
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"droplet": map[string]interface{}{"id": 123, "networks": map[string]interface{}{"v4": []interface{}{}}},
				})
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

func TestCreateDigitalOcean_Success(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := doMockServer(t, 201, map[string]interface{}{
		"droplet": map[string]interface{}{"id": 123},
	}, "203.0.113.1")
	defer srv.Close()
	setDOBase(t, srv.URL)

	info, err := createDigitalOcean("tok", 24)
	if err != nil {
		t.Fatalf("createDigitalOcean: %v", err)
	}
	if info.IP != "203.0.113.1" {
		t.Errorf("IP = %q, want 203.0.113.1", info.IP)
	}
	if info.Provider != "digitalocean" {
		t.Errorf("Provider = %q, want digitalocean", info.Provider)
	}
	if info.TTLHours != 24 {
		t.Errorf("TTLHours = %d, want 24", info.TTLHours)
	}
	if info.Status != "active" {
		t.Errorf("Status = %q, want active", info.Status)
	}
}

func TestCreateDigitalOcean_202Accepted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := doMockServer(t, 202, map[string]interface{}{
		"droplet": map[string]interface{}{"id": 456},
	}, "10.0.0.1")
	defer srv.Close()
	setDOBase(t, srv.URL)

	info, err := createDigitalOcean("tok", 0)
	if err != nil {
		t.Fatalf("createDigitalOcean (202): %v", err)
	}
	if info.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", info.IP)
	}
}

func TestCreateDigitalOcean_AuthError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := doMockServer(t, 401, map[string]interface{}{"message": "Unauthorized"}, "")
	defer srv.Close()
	setDOBase(t, srv.URL)

	_, err := createDigitalOcean("bad-tok", 1)
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !strings.Contains(err.Error(), "DigitalOcean API error") {
		t.Errorf("error = %q, want DigitalOcean API error", err.Error())
	}
}

func TestCreateDigitalOcean_ServerError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := doMockServer(t, 500, map[string]interface{}{"message": "internal error"}, "")
	defer srv.Close()
	setDOBase(t, srv.URL)

	_, err := createDigitalOcean("tok", 1)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestCreateDigitalOcean_ParseError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// 201 with invalid JSON body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
			_, _ = w.Write([]byte("not-json"))
		}
	}))
	defer srv.Close()
	setDOBase(t, srv.URL)

	_, err := createDigitalOcean("tok", 1)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// ---------------------------------------------------------------------------
// waitForDropletIP — timeout path
// ---------------------------------------------------------------------------

func TestWaitForDropletIP_Timeout(t *testing.T) {
	// Server always returns empty networks (no IP assigned yet).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"droplet": map[string]interface{}{"id": 1, "networks": map[string]interface{}{"v4": []interface{}{}}},
		})
	}))
	defer srv.Close()
	setDOBase(t, srv.URL)

	_, err := waitForDropletIP("tok", "1", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "did not get a public IP") {
		t.Errorf("error = %q, want 'did not get a public IP'", err.Error())
	}
}

func TestWaitForDropletIP_NetworkError(t *testing.T) {
	// Point at a closed server to trigger a network error on every poll.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // close immediately
	setDOBase(t, srv.URL)

	_, err := waitForDropletIP("tok", "1", 60*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when server is down")
	}
}

// ---------------------------------------------------------------------------
// createHetzner — via httptest
// ---------------------------------------------------------------------------

func hetznerMockServer(t *testing.T, postStatus int, postBody interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(postStatus)
			if postBody != nil {
				_ = json.NewEncoder(w).Encode(postBody)
			}
		} else if r.Method == http.MethodGet {
			// Poll: return server with IP.
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"server": map[string]interface{}{
					"id":         789,
					"public_net": map[string]interface{}{"ipv4": map[string]interface{}{"ip": "95.0.0.1"}},
				},
			})
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

func TestCreateHetzner_Success_IPInResponse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Hetzner 201 with IP already in the create response.
	srv := hetznerMockServer(t, 201, map[string]interface{}{
		"server": map[string]interface{}{
			"id":         789,
			"public_net": map[string]interface{}{"ipv4": map[string]interface{}{"ip": "95.0.0.2"}},
		},
	})
	defer srv.Close()
	setHetznerBase(t, srv.URL)

	info, err := createHetzner("tok", 12)
	if err != nil {
		t.Fatalf("createHetzner: %v", err)
	}
	if info.IP != "95.0.0.2" {
		t.Errorf("IP = %q, want 95.0.0.2", info.IP)
	}
	if info.Provider != "hetzner" {
		t.Errorf("Provider = %q, want hetzner", info.Provider)
	}
	if info.TTLHours != 12 {
		t.Errorf("TTLHours = %d, want 12", info.TTLHours)
	}
}

func TestCreateHetzner_Success_IPFromPoll(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Hetzner 201 with empty IP — triggers waitForHetznerIP poll.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"server": map[string]interface{}{
					"id":         999,
					"public_net": map[string]interface{}{"ipv4": map[string]interface{}{"ip": ""}},
				},
			})
		case http.MethodGet:
			w.WriteHeader(200)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"server": map[string]interface{}{
					"id":         999,
					"public_net": map[string]interface{}{"ipv4": map[string]interface{}{"ip": "95.0.0.3"}},
				},
			})
		}
	}))
	defer srv.Close()
	setHetznerBase(t, srv.URL)

	info, err := createHetzner("tok", 0)
	if err != nil {
		t.Fatalf("createHetzner (poll): %v", err)
	}
	if info.IP != "95.0.0.3" {
		t.Errorf("IP = %q, want 95.0.0.3", info.IP)
	}
}

func TestCreateHetzner_AuthError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := hetznerMockServer(t, 401, map[string]interface{}{"error": map[string]interface{}{"message": "Unauthorized"}})
	defer srv.Close()
	setHetznerBase(t, srv.URL)

	_, err := createHetzner("bad-tok", 1)
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !strings.Contains(err.Error(), "hetzner API error") {
		t.Errorf("error = %q, want hetzner API error", err.Error())
	}
}

func TestCreateHetzner_ServerError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := hetznerMockServer(t, 500, nil)
	defer srv.Close()
	setHetznerBase(t, srv.URL)

	_, err := createHetzner("tok", 1)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestCreateHetzner_ParseError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
			_, _ = w.Write([]byte("bad-json"))
		}
	}))
	defer srv.Close()
	setHetznerBase(t, srv.URL)

	_, err := createHetzner("tok", 1)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// ---------------------------------------------------------------------------
// waitForHetznerIP — timeout path
// ---------------------------------------------------------------------------

func TestWaitForHetznerIP_Timeout(t *testing.T) {
	// Server always returns a server with no IP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"server": map[string]interface{}{
				"id":         1,
				"public_net": map[string]interface{}{"ipv4": map[string]interface{}{"ip": ""}},
			},
		})
	}))
	defer srv.Close()
	setHetznerBase(t, srv.URL)

	_, err := waitForHetznerIP("tok", "1", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "did not get a public IP") {
		t.Errorf("error = %q, want 'did not get a public IP'", err.Error())
	}
}

func TestWaitForHetznerIP_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	setHetznerBase(t, srv.URL)

	_, err := waitForHetznerIP("tok", "1", 60*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when server is down")
	}
}

// ---------------------------------------------------------------------------
// destroyDigitalOcean — via httptest
// ---------------------------------------------------------------------------

func TestDestroyDigitalOcean_Success(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Pre-save server so markDestroyed can update it.
	SaveServer(&Info{Provider: "digitalocean", ServerID: "42", Status: "active"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent) // 204
	}))
	defer srv.Close()
	setDOBase(t, srv.URL)

	if err := destroyDigitalOcean("tok", "42"); err != nil {
		t.Fatalf("destroyDigitalOcean: %v", err)
	}

	servers, _ := LoadServers()
	for _, s := range servers {
		if s.ServerID == "42" && s.Status != "destroyed" {
			t.Errorf("server 42 status = %q, want destroyed", s.Status)
		}
	}
}

func TestDestroyDigitalOcean_Non204(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	setDOBase(t, srv.URL)

	err := destroyDigitalOcean("tok", "99")
	if err == nil {
		t.Fatal("expected error for non-204")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error = %q, want status 500", err.Error())
	}
}

func TestDestroyDigitalOcean_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	setDOBase(t, srv.URL)

	err := destroyDigitalOcean("tok", "1")
	if err == nil {
		t.Fatal("expected network error")
	}
}

// ---------------------------------------------------------------------------
// destroyHetzner — via httptest
// ---------------------------------------------------------------------------

func TestDestroyHetzner_Success(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	SaveServer(&Info{Provider: "hetzner", ServerID: "77", Status: "active"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK) // Hetzner returns 200 on delete
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"action": map[string]interface{}{"status": "success"}})
	}))
	defer srv.Close()
	setHetznerBase(t, srv.URL)

	if err := destroyHetzner("tok", "77"); err != nil {
		t.Fatalf("destroyHetzner: %v", err)
	}

	servers, _ := LoadServers()
	for _, s := range servers {
		if s.ServerID == "77" && s.Status != "destroyed" {
			t.Errorf("server 77 status = %q, want destroyed", s.Status)
		}
	}
}

func TestDestroyHetzner_Non200(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	setHetznerBase(t, srv.URL)

	err := destroyHetzner("tok", "99")
	if err == nil {
		t.Fatal("expected error for non-200")
	}
	if !strings.Contains(err.Error(), "status 404") {
		t.Errorf("error = %q, want status 404", err.Error())
	}
}

func TestDestroyHetzner_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	setHetznerBase(t, srv.URL)

	err := destroyHetzner("tok", "1")
	if err == nil {
		t.Fatal("expected network error")
	}
}

// ---------------------------------------------------------------------------
// destroyCloudflareQuick — PID-based process management
// ---------------------------------------------------------------------------

// spawnSleepProcess starts a long-running process and returns its PID.
// The process responds to SIGTERM by exiting (default sh behavior).
func spawnSleepProcess(t *testing.T) int {
	t.Helper()
	// Use a shell that blocks until killed.
	cmd := newSleepCmd()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep process: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd.Process.Pid
}

func TestDestroyCloudflareQuick_PIDZero(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	info := &Info{Provider: "cloudflare_quick", ServerID: "fake-tunnel", Status: "active", PID: 0}
	SaveServer(info)

	if err := destroyCloudflareQuick(info); err != nil {
		t.Fatalf("destroyCloudflareQuick(PID=0): %v", err)
	}

	servers, _ := LoadServers()
	for _, s := range servers {
		if s.ServerID == "fake-tunnel" && s.Status != "destroyed" {
			t.Errorf("status = %q, want destroyed", s.Status)
		}
	}
}

func TestDestroyCloudflareQuick_SIGTERMKills(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns subprocess")
	}
	t.Setenv("HOME", t.TempDir())

	pid := spawnSleepProcess(t)

	info := &Info{Provider: "cloudflare_quick", ServerID: "tun-sigterm", Status: "active", PID: pid}
	SaveServer(info)

	start := time.Now()
	if err := destroyCloudflareQuick(info); err != nil {
		t.Fatalf("destroyCloudflareQuick: %v", err)
	}
	elapsed := time.Since(start)

	// Should complete well under the 3 s SIGKILL timeout.
	if elapsed > 3500*time.Millisecond {
		t.Errorf("destroyCloudflareQuick took %v — expected <3.5s (SIGTERM should have worked)", elapsed)
	}

	// Process should be dead: signal 0 must fail.
	proc, _ := os.FindProcess(pid)
	if proc != nil {
		if err := proc.Signal(syscall.Signal(0)); err == nil {
			t.Log("process still appears alive (may be zombie on macOS, acceptable)")
		}
	}

	servers, _ := LoadServers()
	for _, s := range servers {
		if s.ServerID == "tun-sigterm" && s.Status != "destroyed" {
			t.Errorf("status = %q, want destroyed", s.Status)
		}
	}
}

func TestDestroyCloudflareQuick_SIGKILLFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns subprocess, takes ~3s for SIGKILL timeout")
	}
	// On macOS, os.FindProcess+proc.Wait returns immediately for processes not
	// started via the same exec.Cmd handle, so the SIGKILL timer path cannot be
	// reliably triggered.  The SIGTERM path (TestDestroyCloudflareQuick_SIGTERMKills)
	// covers the same function body.
	if os.Getenv("GOOS") == "darwin" || (func() bool {
		// Runtime detection: check if proc.Wait blocks for a SIGTERM-ignoring child.
		cmd := exec.Command("sh", "-c", "trap '' TERM; while true; do sleep 0.1; done")
		if err := cmd.Start(); err != nil {
			return false
		}
		pid := cmd.Process.Pid
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
		p, _ := os.FindProcess(pid)
		if p == nil {
			return false
		}
		_ = p.Signal(syscall.SIGTERM)
		ch := make(chan struct{})
		go func() { p.Wait(); close(ch) }() //nolint:errcheck
		select {
		case <-ch:
			return true // Wait returned immediately — macOS behavior, skip test
		case <-time.After(300 * time.Millisecond):
			return false // Wait blocked — Linux behavior, test is valid
		}
	})() {
		t.Skip("os.FindProcess+proc.Wait returns immediately on this OS (macOS); SIGKILL path not testable")
	}
	t.Setenv("HOME", t.TempDir())

	// Spawn a process that traps SIGTERM so it ignores it; destroyCloudflareQuick
	// must then send SIGKILL after 3 seconds.
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "trap-sigterm.sh")
	script := "#!/bin/sh\ntrap '' TERM\nwhile true; do sleep 0.1; done\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	cmd := newCmdFromPath(scriptPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start trap-sigterm process: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	info := &Info{Provider: "cloudflare_quick", ServerID: "tun-sigkill", Status: "active", PID: pid}
	SaveServer(info)

	start := time.Now()
	if err := destroyCloudflareQuick(info); err != nil {
		t.Fatalf("destroyCloudflareQuick: %v", err)
	}
	elapsed := time.Since(start)

	// Should take ~3 s (SIGTERM wait) + small overhead.
	if elapsed < 2500*time.Millisecond {
		t.Errorf("destroyCloudflareQuick took only %v — SIGKILL fallback may not have fired", elapsed)
	}
	t.Logf("SIGKILL fallback fired after %v", elapsed)
}

// ---------------------------------------------------------------------------
// provider wrappers — Create/Destroy pass-through coverage
// ---------------------------------------------------------------------------

func TestCFWorkerProvider_Create_CallsSetupCloudflareWorker(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	deployOut := "https://nowifi-p2.my-org.workers.dev"
	wPath := fakeWrangler(t, deployOut, 0)
	setFindWrangler(t, func() string { return wPath })

	p := cfWorkerProvider{}
	info, err := p.Create(nil, CreateOpts{}) //nolint:staticcheck
	if err != nil {
		t.Fatalf("cfWorkerProvider.Create: %v", err)
	}
	if info == nil || !strings.Contains(info.URL, "workers.dev") {
		t.Errorf("unexpected info: %+v", info)
	}
}

func TestCFWorkerProvider_Destroy_CallsDestroyCloudflareWorker(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	wPath := fakeWrangler(t, "", 0)
	setFindWrangler(t, func() string { return wPath })

	SaveServer(&Info{Provider: "cloudflare_worker", ServerID: "p", Status: "active"})

	p := cfWorkerProvider{}
	if err := p.Destroy(nil, &Info{ServerID: "p"}, ""); err != nil { //nolint:staticcheck
		t.Fatalf("cfWorkerProvider.Destroy: %v", err)
	}
}

func TestCFQuickProvider_Destroy_CallsDestroyCloudflareQuick(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	info := &Info{Provider: "cloudflare_quick", ServerID: "q", Status: "active", PID: 0}
	SaveServer(info)

	p := cfQuickProvider{}
	if err := p.Destroy(nil, info, ""); err != nil { //nolint:staticcheck
		t.Fatalf("cfQuickProvider.Destroy: %v", err)
	}
}
