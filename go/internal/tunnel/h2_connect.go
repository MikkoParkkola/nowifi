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
// Wave 22 technique #29 — HTTP/2 CONNECT tunnel.
//
// Opens a TLS/443 connection negotiating HTTP/2 via ALPN "h2", then sends
// HTTP/2 CONNECT requests to the proxy for each SOCKS5 connection. The
// traffic is indistinguishable from gRPC health checks, Google Cloud API
// calls, or any HTTP/2-capable application traffic.
//
// Key bypass properties:
//   - HTTP/2 binary framing is opaque to middleboxes that only inspect
//     HTTP/1.1 headers. Most captive portal DPI parses only HTTP/1.1.
//   - The CONNECT method over HTTP/2 multiplexes streams, so all tunnel
//     traffic shares a single TLS connection with normal HTTP/2 framing.
//   - gRPC uses exactly this transport (content-type: application/grpc),
//     making traffic indistinguishable from legitimate cloud API calls.
//
// Protocol:
//   Client → TLS dial to proxy:443 (ALPN "h2")
//   Verify NegotiatedProtocol == "h2"
//   Per SOCKS connection:
//     Client → HTTP/2 CONNECT to target_host:port
//     Client ← HTTP 200
//     Client ↔ bidirectional data on the stream
//
// This file implements the client side only.
// ----------------------------------------------------------------------------

// StartH2ConnectTunnel opens an HTTP/2 connection to the proxy and starts a
// local SOCKS5-lite TCP listener. Each SOCKS connection sends an HTTP/2
// CONNECT to the target through the proxy.
func StartH2ConnectTunnel(serverURL string, localPort int, timeout time.Duration) (*Handle, error) {
	if serverURL == "" {
		return nil, errors.New("h2 tunnel: serverURL required")
	}
	if localPort == 0 {
		localPort = 1090
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	addr, sni, err := parseH2Endpoint(serverURL)
	if err != nil {
		return nil, fmt.Errorf("h2 tunnel: %w", err)
	}

	// Probe: verify HTTP/2 is negotiated.
	tlsConf := &tls.Config{
		ServerName: sni,
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	}
	if clientInsecureTLSForTest {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // test-only
	}

	probeCtx, probeCancel := context.WithTimeout(context.Background(), timeout)
	defer probeCancel()
	probeConn, err := (&tls.Dialer{}).DialContext(probeCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("h2 tunnel: TLS dial %s: %w", addr, err)
	}
	tlsConn, ok := probeConn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = probeConn.Close()
		return nil, fmt.Errorf("h2 tunnel: server did not negotiate h2 (got %q)", tlsConn.ConnectionState().NegotiatedProtocol)
	}
	_ = probeConn.Close()

	// Create HTTP/2 transport to the proxy.
	h2Transport := &http.Transport{
		TLSClientConfig: tlsConf,
		ForceAttemptHTTP2: true,
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("h2 tunnel: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "h2_connect_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveH2Forwarder(listener, h2Transport, fmt.Sprintf("https://%s", addr), h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
		h2Transport.CloseIdleConnections()
	}
	return h, nil
}

func parseH2Endpoint(s string) (addr, sni string, err error) {
	switch {
	case len(s) > 8 && s[:8] == "https://":
		s = s[8:]
	case len(s) > 7 && s[:7] == "http://":
		return "", "", errors.New("HTTP/2 CONNECT requires TLS (use https://)")
	}
	// Strip path.
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			s = s[:i]
			break
		}
	}
	host := s
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		host += ":443"
	}
	sniHost, _, _ := net.SplitHostPort(host)
	if sniHost == "" {
		return "", "", errors.New("empty host in H2 URL")
	}
	return host, sniHost, nil
}

func serveH2Forwarder(l net.Listener, transport *http.Transport, proxyBase string, stop chan struct{}, wg *sync.WaitGroup) {
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
		go handleH2Socks(conn, transport, proxyBase)
	}
}

// handleH2Socks processes a SOCKS5 connection by sending an HTTP/2 CONNECT
// request to the proxy for the requested target.
func handleH2Socks(client net.Conn, transport *http.Transport, proxyBase string) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 greeting.
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

	// SOCKS5 CONNECT request.
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

	// Send HTTP/2 CONNECT to the proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, proxyBase, pr)
	req.Host = target

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success.
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = resp.Body.Close()
		_ = pw.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})

	// Bidirectional: client→pw→proxy (via request body) and proxy→client (via response body).
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(pw, client); _ = pw.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, resp.Body); _ = resp.Body.Close(); done <- struct{}{} }()
	<-done
}

// Ensure bufio import is used (for potential future use in HTTP/1.1 fallback).
var _ = bufio.NewReader
