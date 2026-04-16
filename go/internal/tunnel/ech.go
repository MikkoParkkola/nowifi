// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// Wave 21 technique #24 — Encrypted Client Hello (ECH) domain fronting.
//
// TLS 1.3 ECH (RFC 9147) splits the handshake into an outer ClientHello that
// carries a "cover" SNI (CDN, e.g. cloudflare-ech.com) and an inner,
// HPKE-encrypted ClientHello that carries the real target SNI (the user's
// bypass backend). A portal's DPI sees only the outer SNI; even SNI-based
// blocklists cannot read the real destination.
//
// This file ships the client half. The server half is left to the user:
// Cloudflare Workers, a self-hosted HTTPS proxy, or any endpoint whose
// hostname publishes an ECH ConfigList in its DNS HTTPS RR works. The
// technique succeeds when a TLS+ECH handshake completes to that endpoint
// and the endpoint forwards TCP traffic to arbitrary targets (standard
// HTTPS CONNECT proxy semantics inside the ECH-cloaked channel).
//
// Key invariants:
//   - If ECH fails to negotiate (server lacks matching key, middlebox
//     tampers with the ClientHello), tls.Conn.ConnectionState().ECHAccepted
//     is false and we report failure. No silent fallback to non-ECH.
//   - TLS 1.3 is mandatory (ECH is a TLS-1.3-only feature).
//   - The outer SNI is whatever is in the ECH ConfigList public_name field;
//     the inner SNI comes from the URL's hostname.
// ----------------------------------------------------------------------------

// ECHServerConfig captures the user-facing knobs for StartECHProxy.
type ECHServerConfig struct {
	// ServerURL is the HTTPS endpoint of the user's bypass proxy
	// (e.g. https://worker.example.com). Scheme must be https; port
	// defaults to 443. The hostname is used as the inner SNI.
	ServerURL string
	// ECHConfigList is the raw serialized ECHConfigList (the bytes
	// stored in the HTTPS DNS RR's ech= field). Either this or
	// ECHConfigListBase64 must be set.
	ECHConfigList []byte
	// ECHConfigListBase64 is a convenience: base64-encoded ECHConfigList.
	// Standard base64 (with or without padding) accepted.
	ECHConfigListBase64 string
	// Timeout bounds the TLS dial. Zero means 15s.
	Timeout time.Duration
}

// StartECHProxy opens a TLS 1.3 connection with ECH to the configured HTTPS
// proxy, verifies ECH was actually accepted by the server, and starts a
// local SOCKS5-lite TCP listener that tunnels each client connection via
// an HTTPS CONNECT request inside the ECH-cloaked channel.
//
// Returns an error if ECH does not negotiate — we never fall back to plain
// TLS, since the whole point of the technique is SNI concealment.
func StartECHProxy(cfg ECHServerConfig, localPort int) (*Handle, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("ech tunnel: ServerURL required")
	}
	if localPort == 0 {
		localPort = 1086
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}

	configList, err := resolveECHConfigList(cfg)
	if err != nil {
		return nil, fmt.Errorf("ech tunnel: %w", err)
	}

	addr, sni, err := parseECHEndpoint(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("ech tunnel: %w", err)
	}

	tlsConf := &tls.Config{
		ServerName:                      sni,
		MinVersion:                      tls.VersionTLS13,
		EncryptedClientHelloConfigList:  configList,
		EncryptedClientHelloRejectionVerify: nil,
	}
	if clientInsecureTLSForTest {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // test-only
	}

	// Probe handshake: prove ECH actually negotiates before we start a listener.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	d := &tls.Dialer{Config: tlsConf}
	probe, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ech tunnel: probe handshake: %w", err)
	}
	pstate := probe.(*tls.Conn).ConnectionState()
	_ = probe.Close()
	if !pstate.ECHAccepted {
		return nil, errors.New("ech tunnel: server did not accept ECH (check ConfigList freshness)")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("ech tunnel: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "ech_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveECHForwarder(listener, tlsConf, addr, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
	}
	return h, nil
}

// resolveECHConfigList returns the ECHConfigList bytes from either the raw
// field or the base64-encoded field. Exactly one must be set; both-empty is
// an error (ECH requires a ConfigList, there is no default).
func resolveECHConfigList(cfg ECHServerConfig) ([]byte, error) {
	if len(cfg.ECHConfigList) > 0 && cfg.ECHConfigListBase64 != "" {
		return nil, errors.New("ECHConfigList and ECHConfigListBase64 are mutually exclusive")
	}
	if len(cfg.ECHConfigList) > 0 {
		return cfg.ECHConfigList, nil
	}
	if cfg.ECHConfigListBase64 == "" {
		return nil, errors.New("ECH config list required (serialize from HTTPS DNS RR ech= field)")
	}
	// Accept both standard and URL-safe base64, with or without padding.
	s := cfg.ECHConfigListBase64
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, dec := range decoders {
		if b, err := dec.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, errors.New("ECHConfigListBase64 is not valid base64")
}

// parseECHEndpoint turns a user-facing URL (or bare host[:port]) into a
// "host:port" dial address and the inner SNI. Default port 443. Scheme must
// be https or empty.
func parseECHEndpoint(s string) (addr, sni string, err error) {
	if !containsScheme(s) {
		s = "https://" + s
	}
	u, perr := url.Parse(s)
	if perr != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid endpoint %q", s)
	}
	if u.Scheme != "https" && u.Scheme != "" {
		return "", "", fmt.Errorf("ECH requires https scheme, got %q", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), host, nil
}

func containsScheme(s string) bool {
	for i := 0; i+3 < len(s); i++ {
		if s[i] == ':' && s[i+1] == '/' && s[i+2] == '/' {
			return true
		}
	}
	return false
}

// serveECHForwarder accepts SOCKS5-lite TCP connections and tunnels each one
// via an HTTPS CONNECT request over an ECH-cloaked TLS session to the server.
func serveECHForwarder(l net.Listener, tlsConf *tls.Config, serverAddr string, stop chan struct{}, wg *sync.WaitGroup) {
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
		go handleECHSocks(conn, tlsConf, serverAddr)
	}
}

// handleECHSocks mirrors handleSocks5Lite but uses an HTTPS CONNECT request
// over an ECH-cloaked TLS connection for the upstream path.
func handleECHSocks(client net.Conn, tlsConf *tls.Config, serverAddr string) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// Minimum SOCKS5 greeting + auth-none reply.
	greet := make([]byte, 257)
	if _, err := io.ReadAtLeast(client, greet[:2], 2); err != nil {
		return
	}
	if greet[0] != 0x05 {
		return
	}
	nmethods := int(greet[1])
	if nmethods > 0 {
		if _, err := io.ReadFull(client, greet[:nmethods]); err != nil {
			return
		}
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[1] != 0x01 {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch hdr[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(client, length); err != nil {
			return
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, name); err != nil {
			return
		}
		host = string(name)
	default:
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := fmt.Sprintf("%s:%d", host, port)

	// Dial upstream with TLS+ECH.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d := &tls.Dialer{Config: tlsConf}
	up, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = up.Close() }()

	// Refuse to proceed if ECH didn't actually negotiate on this connection.
	if !up.(*tls.Conn).ConnectionState().ECHAccepted {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// HTTPS CONNECT to the upstream proxy; the proxy bridges to `target`.
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", target, target)
	if _, err := up.Write([]byte(connectReq)); err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Read the status line; accept any 2xx.
	if !readHTTP2xxStatus(up) {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	// Drain remaining response headers.
	if err := drainHTTPHeaders(up); err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Success.
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// readHTTP2xxStatus reads the HTTP/1.x status line from r and reports whether
// the status code is 2xx. Does not consume the response body or headers.
func readHTTP2xxStatus(r io.Reader) bool {
	line, err := readLine(r, 256)
	if err != nil {
		return false
	}
	// "HTTP/1.1 200 OK"
	fields := splitFirstSpaces(line, 3)
	if len(fields) < 2 {
		return false
	}
	code := fields[1]
	return len(code) == 3 && code[0] == '2'
}

func drainHTTPHeaders(r io.Reader) error {
	for i := 0; i < 64; i++ {
		line, err := readLine(r, 1024)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
	return errors.New("too many response headers")
}

// readLine reads a CRLF-terminated line, returning the line without CRLF.
// Bounded by maxLen to prevent unbounded allocation.
func readLine(r io.Reader, maxLen int) (string, error) {
	buf := make([]byte, 0, 128)
	one := make([]byte, 1)
	for len(buf) < maxLen {
		if _, err := io.ReadFull(r, one); err != nil {
			return "", err
		}
		buf = append(buf, one[0])
		if len(buf) >= 2 && buf[len(buf)-2] == '\r' && buf[len(buf)-1] == '\n' {
			return string(buf[:len(buf)-2]), nil
		}
	}
	return "", errors.New("header line too long")
}

// splitFirstSpaces returns up to n fields split on single ASCII spaces.
// Simple, allocation-minimal, no regex.
func splitFirstSpaces(s string, n int) []string {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == ' ' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
