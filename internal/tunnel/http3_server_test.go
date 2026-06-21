// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// TestHTTP3Server_EndToEnd spins up a server, points a client at it, and
// verifies the SOCKS5-lite proxy exposed by the client tunnels TCP traffic
// to a real HTTP server. Exercises every layer: QUIC handshake, ALPN
// negotiation, bidi streams, protocol header, target dial, byte piping.
func TestHTTP3Server_EndToEnd(t *testing.T) {
	// 1. Real HTTP origin on a random TCP port.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from origin"))
	}))
	defer origin.Close()

	// 2. Boot the tunnel server on a random UDP port.
	srv, err := ListenHTTP3Tunnel(HTTP3ServerConfig{
		Listen:   "127.0.0.1:0",
		Hostname: "nowifi-test.local",
	})
	if err != nil {
		t.Fatalf("ListenHTTP3Tunnel: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Give the listener a beat to be ready.
	time.Sleep(50 * time.Millisecond)

	// 3. Client against the server. Disable CA validation because the
	//    server uses a self-signed cert; this mirrors the stance nowifi
	//    takes in hostile captive networks.
	clientInsecureTLSForTest = true
	defer func() { clientInsecureTLSForTest = false }()

	handle, err := StartHTTP3Tunnel("https://"+srv.Addr(), 0, 8*time.Second)
	if err != nil {
		t.Fatalf("StartHTTP3Tunnel: %v", err)
	}
	defer handle.Stop()

	// 4. Talk to the origin through the SOCKS5-lite proxy.
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", handle.LocalPort), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	originHost := origin.Listener.Addr().String()
	conn, err := dialer.Dial("tcp", originHost)
	if err != nil {
		t.Fatalf("dial via tunnel: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originHost)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello from origin" {
		t.Fatalf("body = %q, want %q", string(body), "hello from origin")
	}
}

// TestHTTP3Server_CloseIsIdempotent exercises the Close path twice.
func TestHTTP3Server_CloseIsIdempotent(t *testing.T) {
	srv, err := ListenHTTP3Tunnel(HTTP3ServerConfig{
		Listen:   "127.0.0.1:0",
		Hostname: "nowifi-close.local",
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestValidateTargetHostPort(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"example.com:443", false},
		{"127.0.0.1:8080", false},
		{"", true},
		{"no-port", true},
		{":443", true},
		{"host:", true},
		{"localhost:80", true}, // explicitly rejected
	}
	for _, tc := range tests {
		err := validateTargetHostPort(tc.in)
		if tc.wantErr != (err != nil) {
			t.Errorf("validateTargetHostPort(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
	}
}

func TestGenerateSelfSignedCert_LoadsAsTLSCert(t *testing.T) {
	cert, err := generateSelfSignedCert("test.example.com")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("generated cert missing cert or key")
	}
	// Must load into a tls.Config without error.
	_ = &tls.Config{Certificates: []tls.Certificate{cert}}
}

func TestWriteSelfSignedCertFiles_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := WriteSelfSignedCertFiles("pair.example.com", certPath, keyPath); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Both files must exist with sane sizes.
	st, err := os.Stat(certPath)
	if err != nil || st.Size() < 100 {
		t.Fatalf("cert file missing or too small: %v / size=%d", err, st.Size())
	}
	st, err = os.Stat(keyPath)
	if err != nil || st.Size() < 50 {
		t.Fatalf("key file missing or too small: %v / size=%d", err, st.Size())
	}
	// Must reload as a usable keypair.
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("reload keypair: %v", err)
	}
}

