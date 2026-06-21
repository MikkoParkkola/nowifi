// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// SSE relay server (peer for StartSSETunnel client #30).
//
// Accepts SSE /stream requests (text/event-stream) and HTTP POST /send
// requests. For each /stream request with a ?target=host:port, the server
// dials TCP to the target and bridges:
//
//   Downlink: upstream TCP → base64 → SSE data: events → client
//   Uplink:   client POST /send → base64 decode → upstream TCP
//
// Sessions are correlated by a random session ID returned in X-Session-Id.
// ----------------------------------------------------------------------------

// SSERelayServer is an SSE-based tunnel relay.
type SSERelayServer struct {
	server   *http.Server
	ln       net.Listener
	addr     string
	sessions sync.Map // sessionID → *sseSession
	mu       sync.Mutex
	closed   bool
}

type sseSession struct {
	upstream net.Conn
	mu       sync.Mutex
}

// ListenSSERelay starts an SSE relay server.
func ListenSSERelay(cfg HTTP3ServerConfig) (*SSERelayServer, error) {
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

	srv := &SSERelayServer{
		ln:   ln,
		addr: ln.Addr().String(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", srv.handleStream)
	mux.HandleFunc("/send", srv.handleSend)

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
				log.Printf("  sse relay: %v", err)
			}
		}
	}()

	return srv, nil
}

// Addr returns the listen address.
func (s *SSERelayServer) Addr() string { return s.addr }

// Close stops the server.
func (s *SSERelayServer) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	// Close all upstream connections.
	s.sessions.Range(func(key, value any) bool {
		if sess, ok := value.(*sseSession); ok {
			_ = sess.upstream.Close()
		}
		s.sessions.Delete(key)
		return true
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *SSERelayServer) handleStream(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")

	// Probe request — just return event-stream content type.
	if r.URL.Query().Get("probe") == "1" || target == "" {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "data: probe-ok\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
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
		http.Error(w, fmt.Sprintf("dial: %v", err), http.StatusBadGateway)
		return
	}

	// Generate session ID.
	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	sessionID := hex.EncodeToString(idBytes)

	sess := &sseSession{upstream: upstream}
	s.sessions.Store(sessionID, sess)
	defer func() {
		s.sessions.Delete(sessionID)
		_ = upstream.Close()
	}()

	// SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Session-Id", sessionID)
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// Downlink: upstream → base64 → SSE events.
	buf := make([]byte, 4096)
	for {
		n, readErr := upstream.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			if _, wErr := fmt.Fprintf(w, "data: %s\n\n", encoded); wErr != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if readErr != nil {
			return
		}
	}
}

func (s *SSERelayServer) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "missing session", http.StatusBadRequest)
		return
	}

	val, ok := s.sessions.Load(sessionID)
	if !ok {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	sess := val.(*sseSession)

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		http.Error(w, "decode", http.StatusBadRequest)
		return
	}

	sess.mu.Lock()
	_, err = sess.upstream.Write(decoded)
	sess.mu.Unlock()
	if err != nil {
		http.Error(w, "write upstream", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
