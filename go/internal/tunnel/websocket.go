// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// Wave 21 technique #26 — WireGuard-over-WebSocket.
//
// Wraps arbitrary TCP/UDP payloads (typically WireGuard) in WebSocket binary
// frames over a TLS/443 connection. Captive portals that allow WebSocket
// upgrades (required for Teams, Zoom, Discord, Slack) pass this traffic
// transparently.
//
// Protocol:
//   - Client opens TCP to wss://server:443, does HTTP/1.1 → WebSocket upgrade.
//   - After upgrade, each message is a framed tunnel payload: the same uint16
//     length-prefixed "host:port" header used by HTTP3Tunnel (#22), then raw
//     bytes.
//   - Server bridges each framed connection to the requested TCP target.
//
// The WebSocket framing makes the traffic look like a normal long-lived WS
// session to DPI. Most captive portals inspect only the HTTP upgrade and
// then stop — they don't parse WS frame payloads.
//
// This file implements only the client side. The server uses the companion
// nowifi WS tunnel server (a separate `nowifi server listen --ws` mode, or
// any wstunnel-compatible endpoint).
// ----------------------------------------------------------------------------

// StartWebSocketTunnel opens a WebSocket connection to serverURL (wss://...),
// verifies the upgrade succeeds, and starts a local SOCKS5-lite TCP listener.
// Each SOCKS connection sends a length-prefixed target header over the WS
// connection, then pipes bytes.
func StartWebSocketTunnel(serverURL string, localPort int, timeout time.Duration) (*Handle, error) {
	if serverURL == "" {
		return nil, errors.New("ws tunnel: serverURL required")
	}
	if localPort == 0 {
		localPort = 1087
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	addr, path, useTLS, err := parseWSEndpoint(serverURL)
	if err != nil {
		return nil, fmt.Errorf("ws tunnel: %w", err)
	}

	// Probe: verify WebSocket upgrade succeeds before we start a listener.
	probeConn, err := dialWebSocket(addr, path, useTLS, timeout)
	if err != nil {
		return nil, fmt.Errorf("ws tunnel: probe: %w", err)
	}
	_ = probeConn.Close()

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("ws tunnel: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "ws_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveWSForwarder(listener, addr, path, useTLS, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
	}
	return h, nil
}

// parseWSEndpoint parses a ws:// or wss:// URL into a dial address, path,
// and TLS flag.
func parseWSEndpoint(s string) (addr, path string, useTLS bool, err error) {
	switch {
	case len(s) > 6 && s[:6] == "wss://":
		useTLS = true
		s = s[6:]
	case len(s) > 5 && s[:5] == "ws://":
		s = s[5:]
	case len(s) > 8 && s[:8] == "https://":
		useTLS = true
		s = s[8:]
	case len(s) > 7 && s[:7] == "http://":
		s = s[7:]
	default:
		// Bare host:port, default to TLS.
		useTLS = true
	}

	// Split host:port from path.
	path = "/"
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			path = s[i:]
			s = s[:i]
			break
		}
	}

	host := s
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		// No port — add default.
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	if host == "" || host == ":443" || host == ":80" {
		return "", "", false, errors.New("empty host in WebSocket URL")
	}
	return host, path, useTLS, nil
}

// dialWebSocket performs a raw TCP (or TLS) connection and HTTP/1.1 WebSocket
// upgrade. Returns the hijacked connection on success.
func dialWebSocket(addr, path string, useTLS bool, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: timeout}

	if useTLS {
		host, _, _ := net.SplitHostPort(addr)
		tlsConf := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
		if clientInsecureTLSForTest {
			tlsConf.InsecureSkipVerify = true //nolint:gosec // test-only
		}
		td := &tls.Dialer{
			NetDialer: dialer,
			Config:    tlsConf,
		}
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	// HTTP/1.1 WebSocket upgrade request.
	upgradeReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"\r\n", path, addr)
	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write upgrade: %w", err)
	}

	// Read the response status line.
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("upgrade rejected: HTTP %d", resp.StatusCode)
	}

	// Clear deadline for long-lived connection.
	_ = conn.SetReadDeadline(time.Time{})
	return conn, nil
}

func serveWSForwarder(l net.Listener, addr, path string, useTLS bool, stop chan struct{}, wg *sync.WaitGroup) {
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
		go handleWSSocks(conn, addr, path, useTLS)
	}
}

// handleWSSocks mirrors handleSocks5Lite but tunnels through a fresh WS
// connection per SOCKS session. Uses the uint16 length-prefix "host:port"
// protocol on the WS stream for the target header.
func handleWSSocks(client net.Conn, wsAddr, wsPath string, useTLS bool) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 handshake — shared helper parses greeting + CONNECT request.
	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	// Open a fresh WebSocket connection for this tunnel session.
	ws, err := dialWebSocket(wsAddr, wsPath, useTLS, 15*time.Second)
	if err != nil {
		socks5SendFail(client)
		return
	}
	defer func() { _ = ws.Close() }()

	// Send target header: uint16 length + "host:port".
	targetBytes := []byte(target)
	if len(targetBytes) > 512 { //nolint:gosec // bounded
		socks5SendFail(client)
		return
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes))) //nolint:gosec // bounded to 512
	if _, err := ws.Write(lenBuf); err != nil {
		socks5SendFail(client)
		return
	}
	if _, err := ws.Write(targetBytes); err != nil {
		socks5SendFail(client)
		return
	}

	// SOCKS5 success.
	if err := socks5SendSuccess(client); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ws, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, ws); done <- struct{}{} }()
	<-done
}
