// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// gRPC tunnel server (peer for StartGRPCTunnel client #31).
//
// Accepts HTTP/2 POST requests with content-type "application/grpc" on
// /grpc.tunnel.v1.Tunnel/Bidi. Each request is a bidi stream carrying:
//
//   First gRPC frame: target "host:port" (plain text)
//   Subsequent frames: raw tunnel data
//
// The server dials TCP to the target and bridges:
//   Downlink: upstream TCP → gRPC frames → HTTP/2 response body
//   Uplink:   HTTP/2 request body → gRPC frames → upstream TCP
// ----------------------------------------------------------------------------

// GRPCTunnelServer is a gRPC-style tunnel relay.
type GRPCTunnelServer struct {
	server *http.Server
	ln     net.Listener
	addr   string
	mu     sync.Mutex
	closed bool
}

// ListenGRPCTunnel starts a gRPC tunnel server.
func ListenGRPCTunnel(cfg HTTP3ServerConfig) (*GRPCTunnelServer, error) {
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

	srv := &GRPCTunnelServer{
		ln:   ln,
		addr: ln.Addr().String(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(grpcServicePath, srv.handleBidi)

	// Health check — looks like grpc.health.v1 from DPI perspective.
	mux.HandleFunc("/grpc.health.v1.Health/Check", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "0")
		w.WriteHeader(http.StatusOK)
	})

	srv.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			srv.mu.Lock()
			closed := srv.closed
			srv.mu.Unlock()
			if !closed {
				log.Printf("  grpc tunnel: %v", err)
			}
		}
	}()

	return srv, nil
}

// Addr returns the listen address.
func (s *GRPCTunnelServer) Addr() string { return s.addr }

// Close stops the server.
func (s *GRPCTunnelServer) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *GRPCTunnelServer) handleBidi(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	// Read first gRPC frame: target "host:port".
	targetData, err := grpcReadFrame(r.Body)
	if err != nil {
		w.Header().Set("Grpc-Status", "2") // UNKNOWN
		http.Error(w, "read target frame", http.StatusBadRequest)
		return
	}
	target := string(targetData)

	if err := validateTargetHostPort(target); err != nil {
		w.Header().Set("Grpc-Status", "3") // INVALID_ARGUMENT
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Dial target.
	dialCtx, dialCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer dialCancel()
	var d net.Dialer
	upstream, err := d.DialContext(dialCtx, "tcp", target)
	if err != nil {
		w.Header().Set("Grpc-Status", "14") // UNAVAILABLE
		http.Error(w, fmt.Sprintf("dial: %v", err), http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	// gRPC response headers.
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "0") // OK (trailer, but set early for DPI)
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	done := make(chan struct{}, 2)

	// Uplink: gRPC frames from request body → upstream TCP.
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			data, readErr := grpcReadFrame(r.Body)
			if readErr != nil {
				return
			}
			if len(data) > 0 {
				if _, wErr := upstream.Write(data); wErr != nil {
					return
				}
			}
		}
	}()

	// Downlink: upstream TCP → gRPC frames → response body.
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, readErr := upstream.Read(buf)
			if n > 0 {
				if wErr := grpcWriteFrame(flushWriter{w}, buf[:n]); wErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	<-done
}
