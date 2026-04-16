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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ----------------------------------------------------------------------------
// Wave 21 technique #27 — MASQUE CONNECT-UDP tunnel (RFC 9298).
//
// Establishes an HTTP/3 connection with Extended CONNECT and Datagrams
// enabled, matching the traffic fingerprint of Apple Private Relay,
// Cloudflare WARP, and browser-initiated WebTransport sessions. For TCP
// tunneling, each SOCKS5 connection opens an HTTP/3 Extended CONNECT
// stream to the proxy, which bridges it to the requested target.
//
// From a DPI perspective this is indistinguishable from a legitimate
// MASQUE session on UDP/443: the QUIC handshake advertises "h3",
// SETTINGS include ENABLE_CONNECT_PROTOCOL + H3_DATAGRAM, and each
// stream uses the Extended CONNECT method. No commercial captive portal
// DPI parses HTTP/3 frame types at this depth.
//
// Protocol:
//   Client → QUIC dial to proxy:443 (ALPN "h3")
//   Client ← Server SETTINGS: EnableExtendedConnect=true, EnableDatagrams=true
//   Per SOCKS connection:
//     Client → Extended CONNECT stream: :method=CONNECT, :protocol=connect-tcp,
//              :authority=target_host:port
//     Client ← HTTP 200
//     Client ↔ bidirectional data on the stream
//
// This file implements the client side only.
// ----------------------------------------------------------------------------

// StartMASQUETunnel opens an HTTP/3 connection with MASQUE settings to the
// proxy at serverURL and starts a local SOCKS5-lite TCP listener. Each SOCKS
// connection opens an Extended CONNECT stream to the target through the proxy.
func StartMASQUETunnel(serverURL string, localPort int, timeout time.Duration) (*Handle, error) {
	if serverURL == "" {
		return nil, errors.New("masque tunnel: serverURL required")
	}
	if localPort == 0 {
		localPort = 1088
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	addr, sni, err := parseMASQUEEndpoint(serverURL)
	if err != nil {
		return nil, fmt.Errorf("masque tunnel: %w", err)
	}

	// Dial QUIC with HTTP/3 ALPN and datagram support.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConf := &tls.Config{
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}
	if clientInsecureTLSForTest {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // test-only
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
	}

	qconn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("masque tunnel: QUIC dial %s: %w", addr, err)
	}

	// Create HTTP/3 client conn with datagram support.
	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(qconn)

	// Wait for server SETTINGS.
	settingsCtx, settingsCancel := context.WithTimeout(context.Background(), timeout)
	defer settingsCancel()
	select {
	case <-cc.ReceivedSettings():
	case <-settingsCtx.Done():
		_ = qconn.CloseWithError(0, "settings timeout")
		return nil, errors.New("masque tunnel: timeout waiting for server SETTINGS")
	case <-cc.Context().Done():
		return nil, fmt.Errorf("masque tunnel: connection closed: %w", context.Cause(cc.Context()))
	}

	settings := cc.Settings()
	if !settings.EnableExtendedConnect {
		_ = qconn.CloseWithError(0, "")
		return nil, errors.New("masque tunnel: server does not support Extended CONNECT (RFC 9220)")
	}

	// Start local SOCKS5 listener.
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("masque tunnel: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "masque_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveMASQUEForwarder(listener, cc, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
		_ = qconn.CloseWithError(0, "client shutdown")
	}
	return h, nil
}

// parseMASQUEEndpoint extracts dial address and SNI from a URL string.
// Accepts https://, or bare host:port (defaults to TLS on 443).
func parseMASQUEEndpoint(s string) (addr, sni string, err error) {
	switch {
	case len(s) > 8 && s[:8] == "https://":
		s = s[8:]
	case len(s) > 7 && s[:7] == "http://":
		return "", "", errors.New("MASQUE requires TLS (use https://)")
	}

	// Strip any path.
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}

	host := s
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		host += ":443"
	}

	sniHost, _, _ := net.SplitHostPort(host)
	if sniHost == "" {
		return "", "", errors.New("empty host in MASQUE URL")
	}

	return host, sniHost, nil
}

func serveMASQUEForwarder(l net.Listener, cc *http3.ClientConn, stop chan struct{}, wg *sync.WaitGroup) {
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
		go handleMASQUESocks(conn, cc)
	}
}

// handleMASQUESocks handles a single SOCKS5 connection by opening an HTTP/3
// Extended CONNECT stream through the MASQUE proxy to the requested target.
func handleMASQUESocks(client net.Conn, cc *http3.ClientConn) {
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

	// Open an HTTP/3 Extended CONNECT stream to the target through the proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rstr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send Extended CONNECT request. The :protocol pseudo-header tells the
	// proxy this is a MASQUE-style tunneled connection.
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-tcp",
		Host:   target,
		URL:    &url.URL{Host: target},
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{"?1"},
		},
	}); err != nil {
		rstr.CancelWrite(0)
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	resp, err := rstr.ReadResponse()
	if err != nil {
		rstr.CancelWrite(0)
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		rstr.CancelWrite(0)
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success.
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	// Bidirectional pipe between SOCKS client and HTTP/3 stream.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(rstr, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, rstr); done <- struct{}{} }()
	<-done
}
