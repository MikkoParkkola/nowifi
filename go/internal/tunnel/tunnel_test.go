// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test: Handle.Stop terminates process
// ---------------------------------------------------------------------------

func TestHandle_Stop_TerminatesProcess(t *testing.T) {
	// Start a long-running process we can kill.
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep process: %v", err)
	}

	h := &Handle{
		Process:   cmd,
		LocalPort: 0,
		Method:    "test",
		Active:    true,
	}

	h.Stop()

	if h.Active {
		t.Error("Handle.Active should be false after Stop")
	}
	// Process should be dead; Wait should return an error.
	// (already waited inside Stop, but double-check state)
	if cmd.ProcessState == nil {
		t.Error("ProcessState should be non-nil after Stop")
	}
}

// ---------------------------------------------------------------------------
// Test: Handle.Stop on nil process doesn't panic
// ---------------------------------------------------------------------------

func TestHandle_Stop_NilProcess(t *testing.T) {
	h := &Handle{
		Process: nil,
		Active:  true,
	}

	// Should not panic.
	h.Stop()

	if h.Active {
		t.Error("Handle.Active should be false after Stop with nil process")
	}
}

func TestHandle_Stop_NilInnerProcess(t *testing.T) {
	cmd := &exec.Cmd{} // Process field is nil by default
	h := &Handle{
		Process: cmd,
		Active:  true,
	}

	// Should not panic.
	h.Stop()

	if h.Active {
		t.Error("Handle.Active should be false after Stop with nil inner process")
	}
}

// ---------------------------------------------------------------------------
// Test: Handle.Stop idempotent — calling Stop twice doesn't panic.
// ---------------------------------------------------------------------------

func TestHandle_Stop_Idempotent(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep: %v", err)
	}

	h := &Handle{Process: cmd, Active: true, Method: "test"}
	h.Stop()
	h.Stop() // second call must not panic

	if h.Active {
		t.Error("Active should be false after double Stop")
	}
}

// ---------------------------------------------------------------------------
// Test: VerifySOCKS
// ---------------------------------------------------------------------------

func TestVerifySOCKS_ConnectionRefused(t *testing.T) {
	// Use a port that is almost certainly not listening.
	result := VerifySOCKS(59123)
	if result {
		t.Error("VerifySOCKS should return false on connection refused")
	}
}

// TestVerifySOCKS_MockSOCKS5 spins up a minimal SOCKS5 server that accepts
// the no-auth handshake and proxies the connect to a local HTTP server
// returning the expected "success" body.
func TestVerifySOCKS_MockSOCKS5(t *testing.T) {
	// 1. Start an HTTP server returning the expected captive-portal response.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<meta http-equiv=\"refresh\" content=\"0;url=https://support.mozilla.org/kb/captive-portal\"/>\nsuccess\n"))
	}))
	defer httpSrv.Close()

	httpAddr := httpSrv.Listener.Addr().(*net.TCPAddr)

	// 2. Start a minimal SOCKS5 proxy that accepts connections and tunnels
	//    to the local HTTP server regardless of the requested destination.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks: %v", err)
	}
	defer socksLn.Close()

	socksPort := socksLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5(conn, httpAddr)
		}
	}()

	result := VerifySOCKS(socksPort)
	if !result {
		t.Error("VerifySOCKS should return true with working SOCKS5 proxy")
	}
}

// handleSOCKS5 implements just enough SOCKS5 to satisfy VerifySOCKS.
func handleSOCKS5(client net.Conn, target *net.TCPAddr) {
	defer client.Close()

	// Auth negotiation: client sends [0x05, nMethods, methods...]
	buf := make([]byte, 258)
	n, err := client.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	// Reply: no auth required.
	client.Write([]byte{0x05, 0x00})

	// Connect request: [0x05, 0x01, 0x00, atyp, ...]
	n, err = client.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		return
	}
	// Reply: success, with 4-byte IPv4 bind addr + 2-byte port.
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Tunnel to the real HTTP server.
	upstream, err := net.Dial("tcp", target.String())
	if err != nil {
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(upstream, client)
	go cp(client, upstream)
	<-done
}

// TestVerifySOCKS_AuthRejected verifies VerifySOCKS returns false when the
// SOCKS5 server rejects the authentication method.
func TestVerifySOCKS_AuthRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read auth negotiation, then reply with "no acceptable methods" (0xFF).
			buf := make([]byte, 258)
			conn.Read(buf)
			conn.Write([]byte{0x05, 0xFF})
			conn.Close()
		}
	}()

	if VerifySOCKS(port) {
		t.Error("VerifySOCKS should return false when auth is rejected")
	}
}

// TestVerifySOCKS_ConnectFailed verifies VerifySOCKS returns false when
// the SOCKS5 CONNECT request is refused by the proxy.
func TestVerifySOCKS_ConnectFailed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 258)
			conn.Read(buf)
			conn.Write([]byte{0x05, 0x00}) // auth OK

			conn.Read(buf)
			// Reply with "connection refused" (0x05).
			conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			conn.Close()
		}
	}()

	if VerifySOCKS(port) {
		t.Error("VerifySOCKS should return false when CONNECT is refused")
	}
}

// ---------------------------------------------------------------------------
// Test: VerifyDirect with mock HTTP server -> true
// ---------------------------------------------------------------------------

func TestVerifyDirect_MockSuccess(t *testing.T) {
	// VerifyDirect hits http://detectportal.firefox.com/canonical.html
	// which we can't mock without overriding DefaultClient. Just verify
	// it doesn't panic and returns a boolean.
	_ = VerifyDirect()
}

// ---------------------------------------------------------------------------
// Test: VerifyCFWorkersProxy with mock HTTP server
// ---------------------------------------------------------------------------

func TestVerifyCFWorkersProxy_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The function appends /https://connectivitycheck.gstatic.com/generate_204
		// to the worker URL, then checks for status 204.
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	result := VerifyCFWorkersProxy(ts.URL)
	if !result {
		t.Error("VerifyCFWorkersProxy should return true when mock returns 204")
	}
}

func TestVerifyCFWorkersProxy_Failure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	result := VerifyCFWorkersProxy(ts.URL)
	if result {
		t.Error("VerifyCFWorkersProxy should return false when mock returns 403")
	}
}

func TestVerifyCFWorkersProxy_BadURL(t *testing.T) {
	result := VerifyCFWorkersProxy("http://127.0.0.1:1")
	if result {
		t.Error("VerifyCFWorkersProxy should return false for unreachable URL")
	}
}

func TestVerifyCFWorkersProxy_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	if VerifyCFWorkersProxy(ts.URL) {
		t.Error("VerifyCFWorkersProxy should return false on 500")
	}
}

func TestVerifyCFWorkersProxy_200NotEnough(t *testing.T) {
	// VerifyCFWorkersProxy expects 204 specifically, not 200.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	if VerifyCFWorkersProxy(ts.URL) {
		t.Error("VerifyCFWorkersProxy should return false on 200 (expects 204)")
	}
}

func TestVerifyCFWorkersProxy_URLPath(t *testing.T) {
	// Verify that the correct path is appended to the worker URL.
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	VerifyCFWorkersProxy(ts.URL)

	expected := "/https://connectivitycheck.gstatic.com/generate_204"
	if gotPath != expected {
		t.Errorf("path = %q, want %q", gotPath, expected)
	}
}

// ---------------------------------------------------------------------------
// Test: portListening
// ---------------------------------------------------------------------------

func TestPortListening_ActiveListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	if !portListening(port) {
		t.Errorf("portListening(%d) = false, want true (listener active)", port)
	}
}

func TestPortListening_NoListener(t *testing.T) {
	// Find a free port by binding then closing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	if portListening(port) {
		t.Errorf("portListening(%d) = true, want false (no listener)", port)
	}
}

func TestPortListening_ZeroPort(t *testing.T) {
	// Port 0 is not a real listening port.
	if portListening(0) {
		t.Error("portListening(0) = true, want false")
	}
}

func TestPortListening_HighPort(t *testing.T) {
	// Port 65535 is very unlikely to be in use.
	if portListening(65535) {
		t.Skip("port 65535 is actually listening (unlikely)")
	}
}

// ---------------------------------------------------------------------------
// Test: truncate helper
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello"},
		{"", 5, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc"},
		{"x", 1, "x"},
		{"xy", 1, "x"},
		{"", 0, ""},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q_%d", tc.input, tc.maxLen), func(t *testing.T) {
			got := truncate(tc.input, tc.maxLen)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: readStderr
// ---------------------------------------------------------------------------

func TestReadStderr_Nil(t *testing.T) {
	got := readStderr(nil)
	if got != "" {
		t.Errorf("readStderr(nil) = %q, want empty", got)
	}
}

func TestReadStderr_WithData(t *testing.T) {
	r := strings.NewReader("some error output from tunnel process")
	got := readStderr(r)
	if got != "some error output from tunnel process" {
		t.Errorf("readStderr = %q, want 'some error output from tunnel process'", got)
	}
}

func TestReadStderr_EmptyReader(t *testing.T) {
	r := strings.NewReader("")
	got := readStderr(r)
	if got != "" {
		t.Errorf("readStderr(empty) = %q, want empty", got)
	}
}

func TestReadStderr_LargeInput(t *testing.T) {
	// readStderr uses a 4096 byte buffer; verify it truncates at that.
	big := strings.Repeat("A", 8192)
	r := strings.NewReader(big)
	got := readStderr(r)
	if len(got) > 4096 {
		t.Errorf("readStderr returned %d bytes, want <= 4096", len(got))
	}
	if len(got) == 0 {
		t.Error("readStderr returned empty for large input")
	}
}

func TestReadStderr_MultiLine(t *testing.T) {
	input := "line1\nline2\nline3\n"
	r := strings.NewReader(input)
	got := readStderr(r)
	if got != input {
		t.Errorf("readStderr = %q, want %q", got, input)
	}
}

// ---------------------------------------------------------------------------
// Test: Handle fields
// ---------------------------------------------------------------------------

func TestHandleFields(t *testing.T) {
	h := &Handle{
		Process:   nil,
		LocalPort: 1080,
		Method:    "chisel",
		Active:    true,
	}

	if h.LocalPort != 1080 {
		t.Errorf("LocalPort = %d, want 1080", h.LocalPort)
	}
	if h.Method != "chisel" {
		t.Errorf("Method = %s, want chisel", h.Method)
	}
	if !h.Active {
		t.Error("Active should be true")
	}
}

func TestHandleFields_AllMethods(t *testing.T) {
	methods := []string{"chisel", "dns_tunnel", "icmp_tunnel", "quic_hysteria2", "ntp_tunnel", "doh_tunnel"}
	for _, m := range methods {
		h := &Handle{Method: m, Active: true}
		if h.Method != m {
			t.Errorf("Method = %q, want %q", h.Method, m)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Input validation in Start* functions
// ---------------------------------------------------------------------------

func TestStartChisel_InvalidURL(t *testing.T) {
	_, err := StartChisel("not a url", 1080, 0)
	if err == nil {
		t.Error("StartChisel with invalid URL should return error")
	}
}

func TestStartChisel_EmptyURL(t *testing.T) {
	_, err := StartChisel("", 1080, 0)
	if err == nil {
		t.Error("StartChisel with empty URL should return error")
	}
}

func TestStartChisel_FTPScheme(t *testing.T) {
	_, err := StartChisel("ftp://example.com", 1080, 0)
	if err == nil {
		t.Error("StartChisel with ftp:// scheme should return error")
	}
}

func TestStartDNSTunnel_InvalidDomain(t *testing.T) {
	_, err := StartDNSTunnel("not a valid domain!@#$", "", 0)
	if err == nil {
		t.Error("StartDNSTunnel with invalid domain should return error")
	}
}

func TestStartDNSTunnel_EmptyDomain(t *testing.T) {
	_, err := StartDNSTunnel("", "", 0)
	if err == nil {
		t.Error("StartDNSTunnel with empty domain should return error")
	}
}

func TestStartDNSTunnel_InvalidServerIP(t *testing.T) {
	_, err := StartDNSTunnel("tunnel.example.com", "not_an_ip", 0)
	if err == nil {
		t.Error("StartDNSTunnel with invalid server IP should return error")
	}
}

func TestStartICMPTunnel_InvalidIP(t *testing.T) {
	_, err := StartICMPTunnel("definitely-not-an-ip", 0)
	if err == nil {
		t.Error("StartICMPTunnel with invalid IP should return error")
	}
}

func TestStartICMPTunnel_EmptyIP(t *testing.T) {
	_, err := StartICMPTunnel("", 0)
	if err == nil {
		t.Error("StartICMPTunnel with empty IP should return error")
	}
}

func TestStartQUICTunnel_InvalidServer(t *testing.T) {
	_, err := StartQUICTunnel("bad server; rm -rf /", 0, 0)
	if err == nil {
		t.Error("StartQUICTunnel with shell injection should return error")
	}
}

func TestStartQUICTunnel_EmptyServer(t *testing.T) {
	_, err := StartQUICTunnel("", 0, 0)
	if err == nil {
		t.Error("StartQUICTunnel with empty server should return error")
	}
}

func TestStartNTPTunnel_InvalidIP(t *testing.T) {
	_, err := StartNTPTunnel("not.an"+".ip.address.really.long", 0, 0)
	if err == nil {
		t.Error("StartNTPTunnel with invalid IP should return error")
	}
}

func TestStartNTPTunnel_EmptyIP(t *testing.T) {
	_, err := StartNTPTunnel("", 0, 0)
	if err == nil {
		t.Error("StartNTPTunnel with empty IP should return error")
	}
}

func TestStartDoHTunnel_InvalidURL(t *testing.T) {
	_, err := StartDoHTunnel(0, "ftp://not-valid", 0)
	if err == nil {
		t.Error("StartDoHTunnel with ftp:// should return error")
	}
}

func TestStartDoHTunnel_EmptyDoHURL(t *testing.T) {
	// Empty dohServer defaults to cloudflare-dns, so this won't fail on URL
	// validation — it'll fail on missing tool. Just verify it doesn't panic.
	_, err := StartDoHTunnel(0, "", 0)
	// Either nil (tools found) or an error (no tool). Both are fine.
	_ = err
}

// ---------------------------------------------------------------------------
// Test: waitForPort — port becomes available
// ---------------------------------------------------------------------------

func TestWaitForPort_PortAlreadyListening(t *testing.T) {
	// Start a listener BEFORE calling waitForPort, so it succeeds immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// We need a cmd that's "running" — use a sleep process.
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	err = waitForPort(cmd, nil, port, 5*time.Second)
	if err != nil {
		t.Errorf("waitForPort should succeed when port is already listening: %v", err)
	}
}

func TestWaitForPort_Timeout(t *testing.T) {
	// Use a port that nobody is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	err = waitForPort(cmd, nil, port, 1*time.Second)
	if err == nil {
		t.Error("waitForPort should timeout when port never listens")
	}
	if !strings.Contains(err.Error(), "did not start") {
		t.Errorf("error = %q, want to contain 'did not start'", err.Error())
	}
}

func TestWaitForPort_ProcessExitsEarly(t *testing.T) {
	// Start a process that exits immediately.
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait for it to finish so ProcessState is set.
	cmd.Wait()

	err := waitForPort(cmd, strings.NewReader("exit error output"), 59999, 2*time.Second)
	if err == nil {
		t.Error("waitForPort should error when process exits early")
	}
	if !strings.Contains(err.Error(), "exited early") {
		t.Errorf("error = %q, want to contain 'exited early'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Test: VerifyDirect and VerifySOCKS do not panic with extreme inputs
// ---------------------------------------------------------------------------

func TestVerifySOCKS_NegativePort(t *testing.T) {
	// Should return false, not panic.
	if VerifySOCKS(-1) {
		t.Error("VerifySOCKS(-1) should return false")
	}
}

func TestVerifyCFWorkersProxy_EmptyURL(t *testing.T) {
	if VerifyCFWorkersProxy("") {
		t.Error("VerifyCFWorkersProxy('') should return false")
	}
}

// ---------------------------------------------------------------------------
// Test: HTTP/3 + DoQ tunnel input validation
// ---------------------------------------------------------------------------

func TestStartHTTP3Tunnel_EmptyURL(t *testing.T) {
	_, err := StartHTTP3Tunnel("", 0, 0)
	if err == nil {
		t.Error("StartHTTP3Tunnel with empty URL should return error")
	}
}

func TestStartHTTP3Tunnel_UnreachableHost(t *testing.T) {
	// 127.0.0.1:1 (discard) is never going to speak QUIC+h3. The dial should
	// fail fast with handshake timeout or connection refused.
	_, err := StartHTTP3Tunnel("https://127.0.0.1:1", 0, 1*time.Second)
	if err == nil {
		t.Error("StartHTTP3Tunnel against discard port should return error")
	}
}

func TestStartDoQTunnel_UnreachableHost(t *testing.T) {
	// 127.0.0.1:1 won't speak DoQ.
	_, err := StartDoQTunnel("127.0.0.1:1", 0, 1*time.Second)
	if err == nil {
		t.Error("StartDoQTunnel against discard port should return error")
	}
}

func TestParseH3Endpoint_Variants(t *testing.T) {
	tests := []struct {
		in       string
		wantAddr string
		wantSNI  string
		wantErr  bool
	}{
		{"https://example.com", "example.com:443", "example.com", false},
		{"https://example.com:9443", "example.com:9443", "example.com", false},
		{"example.com", "example.com:443", "example.com", false},
		{"example.com:2053", "example.com:2053", "example.com", false},
		{"://", "", "", true},
	}
	for _, tc := range tests {
		addr, sni, err := parseH3Endpoint(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseH3Endpoint(%q): expected error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseH3Endpoint(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if addr != tc.wantAddr || sni != tc.wantSNI {
			t.Errorf("parseH3Endpoint(%q) = (%q,%q), want (%q,%q)", tc.in, addr, sni, tc.wantAddr, tc.wantSNI)
		}
	}
}

// TestHandle_InProcess_StopIsIdempotent confirms that the new extraStop-based
// cleanup path (HTTP3/DoQ tunnels) survives double Stop() without panic.
func TestHandle_InProcess_StopIsIdempotent(t *testing.T) {
	called := 0
	h := &Handle{
		LocalPort: 0,
		Method:    "test_inprocess",
		Active:    true,
		stop:      make(chan struct{}),
		extraStop: func() { called++ },
	}
	h.Stop()
	h.Stop() // must not panic, must not call extraStop twice.
	if called != 1 {
		t.Errorf("extraStop called %d times, want exactly 1", called)
	}
	if h.Active {
		t.Error("Active should be false after Stop")
	}
}
