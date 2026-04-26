// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxGRPCPayloadSize = 4 * 1024 * 1024

// ----------------------------------------------------------------------------
// Wave 22 technique #31 — gRPC bidirectional streaming tunnel.
//
// Opens an HTTP/2 connection to the tunnel server and sends requests with
// content-type "application/grpc", using the standard gRPC 5-byte binary
// frame header (1 byte compressed flag + 4 byte message length). From DPI's
// perspective, this is indistinguishable from a gRPC bidirectional streaming
// RPC — the traffic matches Kubernetes API calls, microservice communication,
// and any gRPC-based cloud application.
//
// Key bypass properties:
//   - Uses HTTP/2 POST with content-type: application/grpc — matches real gRPC
//   - gRPC binary framing is opaque to HTTP/1.1-only DPI
//   - Path looks like a real gRPC service: /grpc.tunnel.v1.Tunnel/Bidi
//   - No protobuf or google.golang.org/grpc dependency — proto-less framing
//     gives identical wire format with zero dependency weight
//
// Protocol:
//   Client → HTTP/2 POST to server/grpc.tunnel.v1.Tunnel/Bidi
//   Headers: content-type: application/grpc, te: trailers
//   First gRPC message: target "host:port" (plain text in gRPC frame)
//   Subsequent messages: raw tunnel data in gRPC frames
//
// This file implements the client side only.
// ----------------------------------------------------------------------------

const (
	grpcDefaultPort = 1092
	grpcServicePath = "/grpc.tunnel.v1.Tunnel/Bidi"
)

// StartGRPCTunnel opens an HTTP/2 connection to the gRPC tunnel server and
// starts a local SOCKS5-lite TCP listener. Each SOCKS connection opens a
// gRPC bidi stream carrying tunnel data.
func StartGRPCTunnel(serverURL string, localPort int, timeout time.Duration) (*Handle, error) {
	if serverURL == "" {
		return nil, errors.New("grpc tunnel: serverURL required")
	}
	if localPort == 0 {
		localPort = grpcDefaultPort
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	addr, sni, err := parseGRPCEndpoint(serverURL)
	if err != nil {
		return nil, fmt.Errorf("grpc tunnel: %w", err)
	}

	// Probe: verify HTTP/2 negotiation via ALPN.
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
		return nil, fmt.Errorf("grpc tunnel: TLS dial %s: %w", addr, err)
	}
	tlsConn, ok := probeConn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = probeConn.Close()
		return nil, fmt.Errorf("grpc tunnel: server did not negotiate h2 (got %q)", tlsConn.ConnectionState().NegotiatedProtocol)
	}
	_ = probeConn.Close()

	// HTTP/2 transport for gRPC requests.
	grpcTransport := &http.Transport{
		TLSClientConfig:   tlsConf,
		ForceAttemptHTTP2: true,
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("grpc tunnel: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "grpc_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveGRPCForwarder(listener, grpcTransport, fmt.Sprintf("https://%s", addr), h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
		grpcTransport.CloseIdleConnections()
	}
	return h, nil
}

func parseGRPCEndpoint(s string) (addr, sni string, err error) {
	switch {
	case len(s) > 8 && s[:8] == "https://":
		s = s[8:]
	case len(s) > 7 && s[:7] == "http://":
		return "", "", errors.New("gRPC tunnel requires TLS (use https://)")
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	host := s
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		host += ":443"
	}
	sniHost, _, _ := net.SplitHostPort(host)
	if sniHost == "" {
		return "", "", errors.New("empty host in gRPC URL")
	}
	return host, sniHost, nil
}

func serveGRPCForwarder(l net.Listener, transport *http.Transport, serverBase string, stop chan struct{}, wg *sync.WaitGroup) {
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
		go handleGRPCSocks(conn, transport, serverBase)
	}
}

// handleGRPCSocks processes a SOCKS5 connection by opening a gRPC bidi
// stream to the tunnel server for the requested target.
func handleGRPCSocks(client net.Conn, transport *http.Transport, serverBase string) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 handshake — shared helper.
	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	// Open gRPC bidi stream via HTTP/2 POST.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, serverBase+grpcServicePath, pr)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	// Send target as first gRPC message.
	if err := grpcWriteFrame(pw, []byte(target)); err != nil {
		_ = pw.Close()
		socks5SendFail(client)
		return
	}

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

	// Bidirectional: client → gRPC frames → server, server → gRPC frames → client.
	done := make(chan struct{}, 2)

	// Uplink: client → gRPC frame → pipe → HTTP/2 request body.
	go func() {
		defer func() { _ = pw.Close(); done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, readErr := client.Read(buf)
			if n > 0 {
				if wErr := grpcWriteFrame(pw, buf[:n]); wErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Downlink: HTTP/2 response body → gRPC frame → client.
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			data, readErr := grpcReadFrame(resp.Body)
			if readErr != nil {
				return
			}
			if len(data) > 0 {
				if _, wErr := client.Write(data); wErr != nil {
					return
				}
			}
		}
	}()

	<-done
	_ = resp.Body.Close()
}

// grpcWriteFrame writes a gRPC 5-byte framed message: [compressed(1)][length(4)][payload].
func grpcWriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxGRPCPayloadSize {
		return errors.New("grpc payload too large")
	}
	hdr := make([]byte, 5)
	hdr[0] = 0                                                // not compressed
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload))) //nolint:gosec // len checked against maxGRPCPayloadSize above
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// grpcReadFrame reads a gRPC 5-byte framed message from r.
func grpcReadFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[1:])
	if length > maxGRPCPayloadSize {
		return nil, errors.New("grpc frame too large")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}
