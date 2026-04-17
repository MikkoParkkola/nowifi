// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"

)

// ----------------------------------------------------------------------------
// All-Modes Unified Server
//
// Multiplexes HTTP/2 CONNECT (#29), SSE relay (#30), and gRPC tunnel (#31)
// on a single TLS port. Routing is by path and content-type:
//
//   - /grpc.tunnel.v1.Tunnel/Bidi      → gRPC tunnel handler
//   - /grpc.health.v1.Health/Check      → gRPC health check
//   - /stream, /send                    → SSE relay handlers
//   - CONNECT method                    → HTTP/2 CONNECT proxy
//   - Everything else                   → status page
//
// This is the "one port does it all" mode for operators who want a single
// server endpoint instead of running three separate processes.
// ----------------------------------------------------------------------------

// AllModesServer serves H2 CONNECT + SSE + gRPC on one TLS listener.
type AllModesServer struct {
	listener net.Listener
	server   *http.Server
	mu       sync.Mutex
	closed   bool
	addr     string

	// Sub-handlers.
	grpcHandler *grpcHandler
	sseHandler  *sseRelayHandler
}

// ListenAllModes creates a unified server with all TCP-based tunnel modes.
func ListenAllModes(cfg HTTP3ServerConfig) (*AllModesServer, error) {
	tlsConfig, err := loadOrGenerateTLSConfig(cfg.CertFile, cfg.KeyFile, cfg.Hostname)
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	addr := cfg.Listen
	if addr == "" {
		addr = "0.0.0.0:443"
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	grpcH := &grpcHandler{}
	sseH := newSSERelayHandler()

	mux := http.NewServeMux()

	// gRPC tunnel paths.
	mux.HandleFunc("/grpc.tunnel.v1.Tunnel/Bidi", grpcH.handleBidi)
	mux.HandleFunc("/grpc.health.v1.Health/Check", grpcH.handleHealth)

	// SSE relay paths.
	mux.HandleFunc("/stream", sseH.handleStream)
	mux.HandleFunc("/send", sseH.handleSend)

	// Status page for everything else.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleH2Connect(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "nowifi unified server\n\nActive modes:\n- HTTP/2 CONNECT (#29)\n- SSE relay (#30)\n- gRPC tunnel (#31)\n")
	})

	srv := &AllModesServer{
		listener:    listener,
		addr:        listener.Addr().String(),
		grpcHandler: grpcH,
		sseHandler:  sseH,
	}

	srv.server = &http.Server{
		Handler: mux,
	}

	go func() { _ = srv.server.Serve(listener) }()

	return srv, nil
}

// Addr returns the listen address.
func (s *AllModesServer) Addr() string { return s.addr }

// Close shuts down the unified server.
func (s *AllModesServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.server.Close()
}

// grpcHandler handles gRPC tunnel requests.
type grpcHandler struct{}

func (h *grpcHandler) handleBidi(w http.ResponseWriter, r *http.Request) {
	// Read first gRPC frame to get target.
	payload, err := grpcReadFrame(r.Body)
	if err != nil {
		http.Error(w, "bad grpc frame", http.StatusBadRequest)
		return
	}
	target := string(payload)

	// Dial target.
	upstream, err := net.DialTimeout("tcp", target, 10e9) // 10s
	if err != nil {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// Set gRPC response headers.
	w.Header().Set("Content-Type", "application/grpc")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Bidirectional pipe.
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				_ = grpcWriteFrame(w, buf[:n])
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		for {
			data, err := grpcReadFrame(r.Body)
			if err != nil {
				done <- struct{}{}
				return
			}
			_, _ = upstream.Write(data)
		}
	}()
	<-done
}

func (h *grpcHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "0")
	w.WriteHeader(http.StatusOK)
}

// sseRelayHandler handles SSE stream + POST relay.
type sseRelayHandler struct {
	mu       sync.Mutex
	channels map[string]chan []byte
}

func newSSERelayHandler() *sseRelayHandler {
	return &sseRelayHandler{channels: make(map[string]chan []byte)}
}

func (h *sseRelayHandler) handleStream(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("id")
	if sessionID == "" {
		sessionID = "default"
	}

	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.channels[sessionID] = ch
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.channels, sessionID)
		h.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}

func (h *sseRelayHandler) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("id")
	if sessionID == "" {
		sessionID = "default"
	}

	body := make([]byte, 65536)
	n, _ := r.Body.Read(body)

	h.mu.Lock()
	ch, ok := h.channels[sessionID]
	h.mu.Unlock()

	if !ok {
		http.Error(w, "no active session", http.StatusNotFound)
		return
	}

	select {
	case ch <- body[:n]:
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "channel full", http.StatusServiceUnavailable)
	}
}

// handleH2Connect handles HTTP/2 CONNECT for direct TCP proxying.
func handleH2Connect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" {
		http.Error(w, "no target", http.StatusBadRequest)
		return
	}

	upstream, err := net.DialTimeout("tcp", target, 10e9)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = upstream.Write(buf[:n])
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}
