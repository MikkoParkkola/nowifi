// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ----------------------------------------------------------------------------
// WARP Bootstrap — zero-config tunnel via Cloudflare WARP free tier.
//
// Cloudflare WARP is a free, no-account VPN service using the MASQUE/WireGuard
// protocol. 10M+ active users. By auto-registering a device via the public
// WARP API, nowifi gets a legitimate tunnel endpoint with zero user config.
//
// Flow:
//   1. Generate WireGuard keypair
//   2. Register device with WARP API (POST /reg — no account required)
//   3. Cache registration in ~/.nowifi/warp.json
//   4. Connect via HTTP/2 CONNECT to WARP's proxy endpoint
//      (engage.cloudflareclient.com:443 — TCP, works through captive portals)
//
// The traffic is genuine Cloudflare WARP — not faking it, actually using it.
// Captive portals that block WARP also block iCloud+ and Apple Private Relay.
// ----------------------------------------------------------------------------

const (
	warpAPIBase     = "https://api.cloudflareclient.com/v0a2158"
	warpProxyHost   = "engage.cloudflareclient.com:443"
	warpDefaultPort = 1093
)

// WARPRegistration holds the cached WARP device registration.
type WARPRegistration struct {
	DeviceID     string `json:"device_id"`
	Token        string `json:"token"`
	PrivateKey   string `json:"private_key"` // hex-encoded
	PublicKey    string `json:"public_key"`  // hex-encoded
	Endpoint     string `json:"endpoint"`
	AssignedV4   string `json:"assigned_v4"`
	AssignedV6   string `json:"assigned_v6"`
	RegisteredAt string `json:"registered_at"`
}

// StartWARPTunnel auto-registers with Cloudflare WARP (if needed) and starts
// a local SOCKS5 proxy that tunnels through WARP's HTTP/2 CONNECT endpoint.
// Truly zero-config: no account, no server deployment, no URL to remember.
func StartWARPTunnel(localPort int, timeout time.Duration) (*Handle, error) {
	if localPort == 0 {
		localPort = warpDefaultPort
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	// Load or create WARP registration.
	reg, err := loadOrRegisterWARP(timeout)
	if err != nil {
		return nil, fmt.Errorf("warp: %w", err)
	}

	// Connect via HTTP/2 CONNECT to WARP's proxy endpoint.
	tlsConf := &tls.Config{
		ServerName: "engage.cloudflareclient.com",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	}

	// Probe: verify HTTP/2 negotiation.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), timeout)
	defer probeCancel()
	probeConn, err := (&tls.Dialer{}).DialContext(probeCtx, "tcp", warpProxyHost)
	if err != nil {
		return nil, fmt.Errorf("warp: TLS dial: %w", err)
	}
	tlsConn, ok := probeConn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = probeConn.Close()
		return nil, fmt.Errorf("warp: server did not negotiate h2")
	}
	_ = probeConn.Close()

	// Create HTTP/2 transport with WARP auth header.
	warpTransport := &http.Transport{
		TLSClientConfig:   tlsConf,
		ForceAttemptHTTP2: true,
	}

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("warp: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "warp_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveWARPForwarder(listener, warpTransport, reg.Token, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
		warpTransport.CloseIdleConnections()
	}
	return h, nil
}

func serveWARPForwarder(l net.Listener, transport *http.Transport, token string, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}
		if tl, ok := l.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(1 * time.Second))
		}
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		go handleWARPSocks(conn, transport, token)
	}
}

func handleWARPSocks(client net.Conn, transport *http.Transport, token string) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 handshake — shared helper.
	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	// HTTP/2 CONNECT through WARP with auth.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+warpProxyHost, pr)
	req.Host = target
	req.Header.Set("CF-Access-Client-Id", token)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		socks5SendFail(client)
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		socks5SendFail(client)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if err := socks5SendSuccess(client); err != nil {
		_ = resp.Body.Close()
		_ = pw.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(pw, client); _ = pw.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, resp.Body); _ = resp.Body.Close(); done <- struct{}{} }()
	<-done
}

// loadOrRegisterWARP loads cached registration or creates a new one.
func loadOrRegisterWARP(timeout time.Duration) (*WARPRegistration, error) {
	// Try loading cached registration.
	cached, err := loadWARPCache()
	if err == nil && cached.Token != "" {
		return cached, nil
	}

	// Register new device.
	reg, err := registerWARPDevice(timeout)
	if err != nil {
		return nil, err
	}

	// Cache for future use.
	_ = saveWARPCache(reg)
	return reg, nil
}

func warpCachePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".nowifi", "warp.json")
}

func loadWARPCache() (*WARPRegistration, error) {
	data, err := os.ReadFile(warpCachePath())
	if err != nil {
		return nil, err
	}
	var reg WARPRegistration
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

func saveWARPCache(reg *WARPRegistration) error {
	dir := filepath.Dir(warpCachePath())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// #nosec G117 -- private key is persisted to a 0600 user cache for reuse.
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(warpCachePath(), data, 0600)
}

// registerWARPDevice registers a new device with the Cloudflare WARP API.
// No account required — WARP free tier is open registration.
func registerWARPDevice(timeout time.Duration) (*WARPRegistration, error) {
	// Generate WireGuard keypair (Curve25519).
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	// Clamp private key per Curve25519 spec.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	// Generate install ID.
	installID := make([]byte, 11)
	_, _ = rand.Read(installID)

	// Registration payload.
	payload := map[string]any{
		"key":           hex.EncodeToString(publicKey),
		"install_id":    hex.EncodeToString(installID),
		"fcm_token":     "",
		"tos":           time.Now().UTC().Format(time.RFC3339),
		"model":         "nowifi",
		"serial_number": hex.EncodeToString(installID),
		"locale":        "en_US",
	}

	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "POST", warpAPIBase+"/reg",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Client-Version", "a-7.21-0721")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WARP register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("WARP register: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID      string `json:"id"`
		Token   string `json:"token"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
		Config struct {
			Peers []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4   string `json:"v4"`
					V6   string `json:"v6"`
					Host string `json:"host"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("WARP register: decode: %w", err)
	}

	endpoint := warpProxyHost
	if len(result.Config.Peers) > 0 && result.Config.Peers[0].Endpoint.Host != "" {
		endpoint = result.Config.Peers[0].Endpoint.Host
	}

	reg := &WARPRegistration{
		DeviceID:     result.ID,
		Token:        result.Token,
		PrivateKey:   hex.EncodeToString(privateKey[:]),
		PublicKey:    hex.EncodeToString(publicKey),
		Endpoint:     endpoint,
		AssignedV4:   result.Config.Interface.Addresses.V4,
		AssignedV6:   result.Config.Interface.Addresses.V6,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}

	return reg, nil
}
