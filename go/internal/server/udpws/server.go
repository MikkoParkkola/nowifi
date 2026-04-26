// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package udpws implements in-process UDP-over-WebSocket encapsulation.
//
// Frame format: each WebSocket binary message carries exactly one UDP
// datagram.  No length prefix is added — the WebSocket frame boundary
// IS the datagram boundary.  Datagrams larger than MTU (default 1400 B)
// are truncated and logged; the sender is responsible for staying within
// the MTU if loss-free delivery is required.
//
// Server: listens for incoming WebSocket connections on an HTTP port,
// and for each connection forwards frames to/from a target UDP address.
//
// Client: listens on a local UDP port, connects to a remote WebSocket URL,
// and forwards datagrams in both directions.  Reconnects with exponential
// backoff (1s → 30s cap) on connection loss.
package udpws

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// DefaultMTU is the maximum datagram payload size (bytes).  Datagrams
// exceeding this are truncated with a warning log.
const DefaultMTU = 1400

// Server bridges WebSocket connections to a UDP backend.
//
// For each incoming WS connection on /udp it:
//  1. Dials udpTarget (e.g. "127.0.0.1:51820")
//  2. Pumps WS binary frames → UDP socket
//  3. Pumps UDP responses → WS binary frames
//
// The HTTP listener is started by Serve; it shuts down cleanly when the
// provided context is cancelled (via the returned stop function).
type Server struct {
	// HTTPAddr is the address to bind the HTTP/WS listener (e.g. ":8080").
	HTTPAddr string

	// UDPTarget is the UDP address to forward traffic to (e.g. "127.0.0.1:51820").
	UDPTarget string

	// MTU caps inbound datagram size.  Zero uses DefaultMTU.
	MTU int

	// Logger, if nil uses the standard log package.
	Logger *log.Logger

	// httpServer is the underlying http.Server, set by Serve.
	httpServer *http.Server
	mu         sync.Mutex
}

func (s *Server) mtu() int {
	if s.MTU > 0 {
		return s.MTU
	}
	return DefaultMTU
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Serve starts the HTTP listener and blocks until Stop is called or an error
// occurs.  It returns the actual listen address (useful when HTTPAddr is ":0")
// and a stop function.
func (s *Server) Serve() (listenAddr string, stop func(), err error) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.HTTPAddr)
	if err != nil {
		return "", nil, fmt.Errorf("udpws server listen %s: %w", s.HTTPAddr, err)
	}
	stopFn, hs := s.serveOn(ln)
	_ = hs
	return ln.Addr().String(), stopFn, nil
}

// serveOn starts serving on an already-bound listener.  Extracted to allow
// test injection of a custom net.Listener (e.g. to trigger non-ErrServerClosed
// paths).  Returns the stop function and the underlying http.Server.
func (s *Server) serveOn(ln net.Listener) (stop func(), hs *http.Server) {
	mux := http.NewServeMux()
	mux.Handle("/udp", websocket.Handler(s.handleWS))

	hs = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.mu.Lock()
	s.httpServer = hs
	s.mu.Unlock()

	go func() {
		if serveErr := hs.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			s.logf("udpws: http server exited: %v", serveErr)
		}
	}()

	return func() { _ = hs.Close() }, hs
}

// handleWS is called for each incoming WebSocket connection on /udp.
func (s *Server) handleWS(ws *websocket.Conn) {
	defer ws.Close()

	// Each WS connection gets its own UDP socket to the target.
	udpAddr, err := net.ResolveUDPAddr("udp", s.UDPTarget)
	if err != nil {
		s.logf("udpws: resolve udp target %s: %v", s.UDPTarget, err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		s.logf("udpws: dial udp %s: %v", s.UDPTarget, err)
		return
	}
	defer udpConn.Close()

	mtu := s.mtu()
	done := make(chan struct{})

	// UDP → WS goroutine.
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, _, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			payload := buf[:n]
			if err := websocket.Message.Send(ws, payload); err != nil {
				return
			}
		}
	}()

	// WS → UDP (this goroutine).
	buf := make([]byte, 65535)
	for {
		var msg []byte
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			break
		}
		if len(msg) > mtu {
			s.logf("udpws: truncating datagram %d→%d bytes", len(msg), mtu)
			msg = msg[:mtu]
		}
		if _, err := udpConn.Write(msg); err != nil {
			break
		}
		_ = buf // keep buf alive for potential future use
	}

	<-done
}
