// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
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
	// Pass the ALPN-carrying tlsConf into the probe dialer; the zero-value
	// tls.Dialer{} sends no NextProtos, so NegotiatedProtocol is always the
	// empty string and the h2 check below always fails (or, worse, succeeds
	// against a server that ignores the missing ALPN and happens to speak h2
	// by default).
	probeConn, err := (&tls.Dialer{Config: tlsConf}).DialContext(probeCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("h2 tunnel: TLS dial %s: %w", addr, err)
	}
	tlsConn, ok := probeConn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		negotiated := ""
		if ok {
			negotiated = tlsConn.ConnectionState().NegotiatedProtocol
		}
		_ = probeConn.Close()
		return nil, fmt.Errorf("h2 tunnel: server did not negotiate h2 (got %q)", negotiated)
	}
	_ = probeConn.Close()

	// Create HTTP/2 transport to the proxy.
	h2Transport := &http.Transport{
		TLSClientConfig:   tlsConf,
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

	// SOCKS5 handshake — shared helper parses greeting + CONNECT request.
	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	// Send HTTP/2 CONNECT to the proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pr, pw := io.Pipe()
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodConnect, proxyBase, pr)
	if reqErr != nil {
		// Defensive: NewRequestWithContext can return nil,err on URL parse
		// errors. The previous code discarded the error and dereferenced
		// the nil request on the next line, crashing the goroutine.
		_ = pw.Close()
		socks5SendFail(client)
		return
	}
	req.Host = target

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

	// SOCKS5 success.
	if err := socks5SendSuccess(client); err != nil {
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
