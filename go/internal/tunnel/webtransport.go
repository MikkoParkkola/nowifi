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
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// ----------------------------------------------------------------------------
// Wave 21 technique #28 — WebTransport tunnel (RFC 9220).
//
// Opens a WebTransport session over HTTP/3 to the tunnel server. From a DPI
// perspective this is indistinguishable from Google Meet, Zoom, or any
// browser-initiated WebTransport session: the QUIC handshake advertises "h3",
// the session establishment uses Extended CONNECT with :protocol=webtransport,
// and data flows over bidi QUIC streams within the HTTP/3 session.
//
// Each SOCKS5 connection opens a new bidi stream within the WT session,
// sends a uint16 length-prefixed "host:port" target header, then pipes bytes.
// This is the same sub-stream protocol as HTTP3Tunnel (#22) and WS Tunnel
// (#25), allowing the same server-side bridge implementation.
//
// Key advantage over raw QUIC (#22): the WebTransport session setup matches
// real browser traffic exactly. DPI that allow Google Meet/Zoom WebTransport
// connections will pass this without inspection.
//
// This file implements the client side only.
// ----------------------------------------------------------------------------

// StartWebTransportTunnel opens a WebTransport session to serverURL and
// starts a local SOCKS5-lite TCP listener. Each SOCKS connection opens a
// bidi stream within the session.
func StartWebTransportTunnel(serverURL string, localPort int, timeout time.Duration) (*Handle, error) {
	if serverURL == "" {
		return nil, errors.New("wt tunnel: serverURL required")
	}
	if localPort == 0 {
		localPort = 1089
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	tlsConf := &tls.Config{
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}
	if clientInsecureTLSForTest {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // test-only
	}

	d := &webtransport.Dialer{
		TLSClientConfig: tlsConf,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, session, err := d.Dial(ctx, serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("wt tunnel: dial %s: %w", serverURL, err)
	}

	// Probe: open one stream to verify the server responds, then close it.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	probeStr, err := session.OpenStreamSync(probeCtx)
	probeCancel()
	if err != nil {
		_ = session.CloseWithError(0, "probe failed")
		_ = d.Close()
		return nil, fmt.Errorf("wt tunnel: probe stream: %w", err)
	}
	_ = probeStr.Close()

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		_ = session.CloseWithError(0, "")
		_ = d.Close()
		return nil, fmt.Errorf("wt tunnel: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "webtransport_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveWTForwarder(listener, session, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
		_ = session.CloseWithError(0, "client shutdown")
		_ = d.Close()
	}
	return h, nil
}

func serveWTForwarder(l net.Listener, session *webtransport.Session, stop chan struct{}, wg *sync.WaitGroup) {
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
		go handleWTSocks(conn, session)
	}
}

// handleWTSocks handles a SOCKS5 connection by opening a WebTransport bidi
// stream and forwarding data through it. Uses the same uint16 length-prefix
// "host:port" target header protocol as HTTP3Tunnel and WS Tunnel.
func handleWTSocks(client net.Conn, session *webtransport.Session) {
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

	// Open a bidi stream within the WebTransport session.
	str, err := session.OpenStream()
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send target header: uint16 length + "host:port".
	targetBytes := []byte(target)
	if len(targetBytes) > 512 { //nolint:gosec // bounded
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes))) //nolint:gosec // bounded to 512
	if _, err := str.Write(lenBuf); err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := str.Write(targetBytes); err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success.
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(str, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, str); done <- struct{}{} }()
	<-done
}
