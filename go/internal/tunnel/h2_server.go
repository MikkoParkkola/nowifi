// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// HTTP/2 CONNECT proxy server (peer for StartH2ConnectTunnel client #29).
//
// A minimal HTTP/2 proxy that accepts CONNECT requests and bridges each to
// the requested TCP target. The proxy negotiates h2 via ALPN and multiplexes
// streams within a single TLS connection.
// ----------------------------------------------------------------------------

// H2ProxyServer is an HTTP/2 CONNECT proxy server.
type H2ProxyServer struct {
	server *http.Server
	ln     net.Listener
	addr   string
	mu     sync.Mutex
	closed bool
}

// ListenH2Proxy starts an HTTP/2 CONNECT proxy server.
func ListenH2Proxy(cfg HTTP3ServerConfig) (*H2ProxyServer, error) {
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
	tlsConf.NextProtos = []string{"h2", "http/1.1"}
	tlsConf.MinVersion = tls.VersionTLS12

	ln, err := tls.Listen("tcp", cfg.Listen, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}

	srv := &H2ProxyServer{
		ln:   ln,
		addr: ln.Addr().String(),
	}

	srv.server = &http.Server{
		Handler:           http.HandlerFunc(srv.handleProxy),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			srv.mu.Lock()
			closed := srv.closed
			srv.mu.Unlock()
			if !closed {
				log.Printf("  h2 proxy: %v", err)
			}
		}
	}()

	return srv, nil
}

// Addr returns the listen address.
func (s *H2ProxyServer) Addr() string { return s.addr }

// Close stops the server.
func (s *H2ProxyServer) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *H2ProxyServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "nowifi H2 proxy — use CONNECT method", http.StatusMethodNotAllowed)
		return
	}

	target := r.Host
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}
	if err := validateTargetHostPort(target); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Dial target.
	dialCtx, dialCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer dialCancel()
	var d net.Dialer
	upstream, err := d.DialContext(dialCtx, "tcp", target)
	if err != nil {
		http.Error(w, fmt.Sprintf("dial %s: %v", target, err), http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, r.Body); done <- struct{}{} }()
	go func() { _, _ = io.Copy(flushWriter{w}, upstream); done <- struct{}{} }()
	<-done
}
