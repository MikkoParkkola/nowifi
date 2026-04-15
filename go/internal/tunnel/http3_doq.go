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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// clientInsecureTLSForTest, when set true by an in-package test, disables
// TLS certificate validation on HTTP/3 tunnel dials so tests can exercise
// the pipeline against an in-tree self-signed server. Never set in prod.
var clientInsecureTLSForTest = false

// ----------------------------------------------------------------------------
// HTTP/3-ALPN tunnel (Wave 20 technique #22)
//
// Opens a QUIC connection to the user's tunnel server on UDP/443 with ALPN
// "h3". From a middlebox's perspective this is indistinguishable from an
// ordinary HTTP/3 browser session: ClientHello advertises h3, packets use
// QUIC v1 framing on UDP/443. Inside, we use raw bidirectional QUIC streams
// to carry arbitrary TCP payloads — each incoming SOCKS5-lite connection
// opens one stream and we pipe bytes between the stream and the TCP client.
//
// Transport bypass properties:
//   - UDP/443 passes TCP-only DPI and middleboxes.
//   - "h3" ALPN matches normal browsers, avoiding protocol fingerprinting.
//   - No HTTP/3 CONNECT semantics needed — streams are dumb byte pipes.
//
// Server side: a matching nowifi-server running on the same host that
// accepts QUIC connections with ALPN "h3" and bridges each stream to the
// requested target (first bytes of the stream carry a length-prefixed
// "host:port" destination spec).
// ----------------------------------------------------------------------------

// StartHTTP3Tunnel opens an HTTP/3-ALPN QUIC tunnel to serverURL (scheme+host,
// e.g. "https://tunnel.example.com:443") and listens locally on localPort as
// a SOCKS5-lite TCP proxy. Returns a Handle with Stop() that closes the
// listener and the QUIC connection.
func StartHTTP3Tunnel(serverURL string, localPort int, timeout time.Duration) (*Handle, error) {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if localPort == 0 {
		localPort = 1084
	}
	if serverURL == "" {
		return nil, errors.New("http3 tunnel: serverURL required")
	}

	addr, sni, err := parseH3Endpoint(serverURL)
	if err != nil {
		return nil, fmt.Errorf("http3 tunnel: %w", err)
	}

	tlsConf := &tls.Config{
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
		ServerName: sni,
	}
	if clientInsecureTLSForTest {
		// Test-only: accept self-signed certs from the in-tree server. Set by
		// test files via the same-package variable; never flipped in prod paths.
		tlsConf.InsecureSkipVerify = true //nolint:gosec // test-only; see http3_server_test.go
	}
	qconf := &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       30 * time.Second,
		EnableDatagrams:      true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, addr, tlsConf, qconf)
	if err != nil {
		return nil, fmt.Errorf("http3 dial %s: %w", addr, err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		_ = qconn.CloseWithError(0, "listener-failed")
		return nil, fmt.Errorf("listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "http3_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveHTTP3Forwarder(listener, qconn, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
		_ = qconn.CloseWithError(0, "shutdown")
	}
	return h, nil
}

// parseH3Endpoint resolves a user-facing URL or host:port into a dialable
// "host:port" and an SNI name. Default port 443.
func parseH3Endpoint(s string) (addr, sni string, err error) {
	// Accept bare host:port too.
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, perr := url.Parse(s)
	if perr != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid endpoint %q", s)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), host, nil
}

func serveHTTP3Forwarder(l net.Listener, qconn *quic.Conn, stop chan struct{}, wg *sync.WaitGroup) {
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
		go handleSocks5Lite(conn, qconn)
	}
}

// handleSocks5Lite implements the minimum SOCKS5 handshake (no auth, CONNECT
// only, IPv4/DOMAIN ATYP) and bridges the client TCP socket to a fresh QUIC
// stream on qconn. The first payload bytes on the stream are a length-prefixed
// "host:port" string consumed by the remote nowifi-server.
func handleSocks5Lite(client net.Conn, qconn *quic.Conn) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting: VER NMETHODS METHODS...
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
	// Reply: no auth required.
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[1] != 0x01 { // CONNECT only
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03: // Domain
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

	// Open a fresh QUIC bidi stream for this connection.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = stream.Close() }()

	// Protocol header: uint16 length + "host:port". Minimal, matches the
	// companion nowifi tunnel-server implementation. Bound-check the length
	// so the uint16 cast can never silently truncate a maliciously-crafted
	// target (the server also caps at 512 bytes).
	targetBytes := []byte(target)
	if len(targetBytes) > 512 {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes))) //nolint:gosec // bounded to 512 above
	if _, err := stream.Write(lenBuf); err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := stream.Write(targetBytes); err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS success reply.
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Clear deadlines for long-lived bidirectional copy.
	_ = client.SetDeadline(time.Time{})

	// Pipe bytes in both directions until either side closes.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(stream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, stream); done <- struct{}{} }()
	<-done
}

// ----------------------------------------------------------------------------
// DoQ tunnel (Wave 20 technique #21)
//
// Opens a QUIC connection to a DNS-over-QUIC server (default: dns.adguard.com
// on UDP/853 per RFC 9250) and runs a local UDP listener that proxies DNS
// queries over per-query QUIC streams. Bypass-relevant because DoQ is rarely
// filtered distinctly from generic QUIC/HTTP/3.
// ----------------------------------------------------------------------------

// StartDoQTunnel opens a DNS-over-QUIC connection to doqServer (host:port) and
// listens on 127.0.0.1:localPort/udp as a plain DNS proxy.
func StartDoQTunnel(doqServer string, localPort int, timeout time.Duration) (*Handle, error) {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if localPort == 0 {
		localPort = 1085
	}
	if doqServer == "" {
		doqServer = "dns.adguard.com:853"
	}
	// RFC 9250: ALPN must be "doq".
	tlsConf := &tls.Config{
		NextProtos: []string{"doq"},
		MinVersion: tls.VersionTLS13,
		ServerName: strings.SplitN(doqServer, ":", 2)[0],
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, doqServer, tlsConf, &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("doq dial %s: %w", doqServer, err)
	}

	// Local UDP listener that forwards to DoQ.
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		_ = conn.CloseWithError(0, "listener-failed")
		return nil, fmt.Errorf("listen udp %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "doq_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveDoQProxy(udp, conn, h.stop, h.wg)

	h.extraStop = func() {
		_ = udp.Close()
		_ = conn.CloseWithError(0, "shutdown")
	}
	return h, nil
}

func serveDoQProxy(udp *net.UDPConn, conn *quic.Conn, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 4096)
	for {
		select {
		case <-stop:
			return
		default:
		}
		_ = udp.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		go func(query []byte, from *net.UDPAddr) {
			reply, err := doqQuery(conn, query)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(reply, from)
		}(append([]byte(nil), buf[:n]...), clientAddr)
	}
}

// doqQuery sends a single DNS query over a new QUIC stream per RFC 9250.
// Wire format: 2-byte length prefix followed by the DNS message.
func doqQuery(conn *quic.Conn, query []byte) ([]byte, error) {
	// RFC 1035 caps DNS messages at 65535 bytes; reject anything longer so
	// the uint16 length-prefix cast cannot silently truncate.
	if len(query) == 0 || len(query) > 65535 {
		return nil, fmt.Errorf("invalid DNS query length: %d", len(query))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	// Write: length-prefixed DNS message.
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query))) //nolint:gosec // bounded to 65535 above
	if _, err := stream.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("write len: %w", err)
	}
	if _, err := stream.Write(query); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}

	// Read response: length prefix, then payload.
	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, respLenBuf); err != nil {
		return nil, fmt.Errorf("read len: %w", err)
	}
	respLen := binary.BigEndian.Uint16(respLenBuf)
	if respLen == 0 || respLen > 8192 {
		return nil, fmt.Errorf("invalid response length: %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return nil, fmt.Errorf("read resp: %w", err)
	}
	return resp, nil
}
