// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// ----------------------------------------------------------------------------
// Unified HTTP/3 tunnel server (Wave 21).
//
// Accepts three client protocols over a single QUIC/h3 listener:
//
//  1. HTTP/3 Extended CONNECT (MASQUE #27 clients) — reads the :authority
//     pseudo-header as "host:port", bridges the stream to TCP.
//  2. WebTransport sessions (#28 clients) — accepts bidi streams within the
//     WebTransport session, each carrying a uint16 length-prefix target header.
//  3. Plain HTTP/3 CONNECT (#22 fallback) — standard HTTP CONNECT tunneling.
//
// All three converge on the same TCP bridging path: parse target → dial TCP →
// bidirectional copy.
//
// CLI: `nowifi server listen --mode h3` (default mode remains raw QUIC for
// backwards compatibility with existing HTTP3Tunnel #22 clients).
// ----------------------------------------------------------------------------

// H3UnifiedServer is an HTTP/3 tunnel server supporting Extended CONNECT
// and WebTransport alongside plain CONNECT.
type H3UnifiedServer struct {
	h3Server *http3.Server
	wtServer *webtransport.Server
	udpConn  *net.UDPConn
	mu       sync.Mutex
	closed   bool
	addr     string
}

// ListenH3Unified starts the unified HTTP/3 server and returns it.
func ListenH3Unified(cfg HTTP3ServerConfig) (*H3UnifiedServer, error) {
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:443"
	}
	if cfg.Hostname == "" {
		cfg.Hostname = "nowifi.local"
	}

	tlsConf, err := loadOrGenerateTLSConfig(cfg.CertFile, cfg.KeyFile, cfg.Hostname)
	if err != nil {
		return nil, fmt.Errorf("tls config: %w", err)
	}
	tlsConf.NextProtos = []string{http3.NextProtoH3}
	tlsConf.MinVersion = tls.VersionTLS13

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", cfg.Listen, err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", cfg.Listen, err)
	}

	srv := &H3UnifiedServer{
		udpConn: pc,
		addr:    pc.LocalAddr().String(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleHTTP)

	// WebTransport server wraps the HTTP/3 server.
	srv.h3Server = &http3.Server{
		Handler:         mux,
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
	}

	srv.wtServer = &webtransport.Server{
		H3:          srv.h3Server,
		CheckOrigin: func(*http.Request) bool { return true }, // tunnel server, no CORS
	}
	webtransport.ConfigureHTTP3Server(srv.h3Server)

	// Override the mux to use the WT server's upgrade handler.
	mux.HandleFunc("/wt", func(w http.ResponseWriter, r *http.Request) {
		session, err := srv.wtServer.Upgrade(w, r)
		if err != nil {
			log.Printf("  h3 server: WebTransport upgrade failed: %v", err)
			return
		}
		srv.handleWTSession(session, cfg.MaxStreamIdle)
	})

	go func() {
		if err := srv.h3Server.Serve(pc); err != nil {
			srv.mu.Lock()
			closed := srv.closed
			srv.mu.Unlock()
			if !closed {
				log.Printf("  h3 server: %v", err)
			}
		}
	}()

	return srv, nil
}

// Addr returns the bound UDP address.
func (s *H3UnifiedServer) Addr() string { return s.addr }

// Close stops the server.
func (s *H3UnifiedServer) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.h3Server != nil {
		_ = s.h3Server.Close()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	return nil
}

// Protocols returns the protocols this server supports.
func (s *H3UnifiedServer) Protocols() []string {
	return []string{"Extended CONNECT (MASQUE)", "WebTransport", "HTTP CONNECT"}
}

// handleHTTP dispatches incoming HTTP/3 requests.
func (s *H3UnifiedServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Extended CONNECT: method=CONNECT with :protocol header present.
	if r.Method == http.MethodConnect {
		s.handleExtendedConnect(w, r)
		return
	}
	// Everything else: 404.
	http.Error(w, "nowifi tunnel server — use CONNECT or WebTransport", http.StatusNotFound)
}

// handleExtendedConnect bridges an HTTP/3 Extended CONNECT stream to a TCP
// target. The target is taken from the request's Host (which maps to :authority).
func (s *H3UnifiedServer) handleExtendedConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}
	if err := validateTargetHostPort(target); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Dial the TCP target.
	dialCtx, dialCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer dialCancel()
	var d net.Dialer
	upstream, err := d.DialContext(dialCtx, "tcp", target)
	if err != nil {
		http.Error(w, fmt.Sprintf("dial %s: %v", target, err), http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Send 200 to complete the CONNECT handshake.
	w.WriteHeader(http.StatusOK)
	// Flush the response so the client sees 200 before we start piping.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Hijack the HTTP/3 stream for bidirectional data. For http3, the
	// ResponseWriter wraps a stream that supports Read/Write after headers.
	// We use the request body for client→server and the response writer for
	// server→client.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, r.Body); done <- struct{}{} }()
	go func() { _, _ = io.Copy(flushWriter{w}, upstream); done <- struct{}{} }()
	<-done
}

// handleWTSession handles an established WebTransport session. Each bidi
// stream carries the uint16 length-prefix target header protocol (same as
// HTTP3Tunnel #22 and WS Tunnel #25).
func (s *H3UnifiedServer) handleWTSession(session *webtransport.Session, maxStreamIdle time.Duration) {
	defer func() { _ = session.CloseWithError(0, "done") }()
	for {
		stream, err := session.AcceptStream(session.Context())
		if err != nil {
			return
		}
		go s.handleWTStream(stream, maxStreamIdle)
	}
}

func (s *H3UnifiedServer) handleWTStream(str *webtransport.Stream, maxStreamIdle time.Duration) {
	defer func() { _ = str.Close() }()

	// Read header: uint16 len + host:port.
	if maxStreamIdle > 0 {
		_ = str.SetReadDeadline(time.Now().Add(maxStreamIdle))
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(str, lenBuf); err != nil {
		return
	}
	targetLen := binary.BigEndian.Uint16(lenBuf)
	if targetLen == 0 || targetLen > 512 {
		return
	}
	targetBuf := make([]byte, int(targetLen))
	if _, err := io.ReadFull(str, targetBuf); err != nil {
		return
	}
	target := string(targetBuf)
	if err := validateTargetHostPort(target); err != nil {
		return
	}

	// Dial the target.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	var d net.Dialer
	upstream, err := d.DialContext(dialCtx, "tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	_ = str.SetReadDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, str); done <- struct{}{} }()
	go func() { _, _ = io.Copy(str, upstream); done <- struct{}{} }()
	<-done
}

// flushWriter wraps an http.ResponseWriter to flush after each Write.
type flushWriter struct {
	w http.ResponseWriter
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}
