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
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ----------------------------------------------------------------------------
// CONNECT-IP tunnel server (peer for StartConnectIPTunnel client #32).
//
// Accepts HTTP/3 Extended CONNECT requests with :protocol=connect-ip.
// For each session:
//   1. Assigns a virtual IP from 10.73.0.0/24 pool
//   2. Sends address assignment capsule via stream datagram
//   3. Forwards IP packets between stream datagrams and a TUN device
//
// In production, the TUN device routes packets to the internet via NAT.
// For testing, we use a simplified forwarding model.
// ----------------------------------------------------------------------------

// ConnectIPServer is a CONNECT-IP tunnel server.
type ConnectIPServer struct {
	h3Server *http3.Server
	ln       *quic.Listener
	addr     string
	nextIP   atomic.Uint32 // counter for IP assignment (10.73.0.x)
	mu       sync.Mutex
	closed   bool
}

// ListenConnectIP starts a CONNECT-IP tunnel server.
func ListenConnectIP(cfg HTTP3ServerConfig) (*ConnectIPServer, error) {
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
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", cfg.Listen, err)
	}

	tr := &quic.Transport{
		Conn: udpConn,
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
	}

	ln, err := tr.Listen(tlsConf, quicConf)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("quic listen: %w", err)
	}

	srv := &ConnectIPServer{
		ln:   ln,
		addr: udpConn.LocalAddr().String(),
	}
	srv.nextIP.Store(1) // first session → 10.73.1.0/24

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleConnectIP)

	srv.h3Server = &http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}

	go func() {
		if err := srv.h3Server.ServeListener(ln); err != nil {
			srv.mu.Lock()
			closed := srv.closed
			srv.mu.Unlock()
			if !closed {
				log.Printf("  connect-ip server: %v", err)
			}
		}
	}()

	return srv, nil
}

// Addr returns the listen address.
func (s *ConnectIPServer) Addr() string { return s.addr }

// Close stops the server.
func (s *ConnectIPServer) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	_ = s.h3Server.Close()
	return s.ln.Close()
}

func (s *ConnectIPServer) handleConnectIP(w http.ResponseWriter, r *http.Request) {
	// Verify Extended CONNECT with connect-ip protocol.
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	if r.Proto != "connect-ip" {
		http.Error(w, "protocol must be connect-ip", http.StatusBadRequest)
		return
	}

	// Assign a unique /24 per concurrent session from 10.73.0.0/16, so every
	// session gets its own gateway IP (session N → 10.73.N.1 gateway,
	// 10.73.N.2 client). Previously every concurrent session was handed
	// 10.73.0.1 as its gateway and a sequential host within 10.73.0.0/24,
	// which collides as soon as two clients are active: both server-side TUNs
	// try to configure 10.73.0.1 and forwarding becomes ambiguous.
	sessionNum := s.nextIP.Add(1) - 1
	if sessionNum > 255 {
		http.Error(w, "session pool exhausted", http.StatusServiceUnavailable)
		return
	}
	assignedIP := net.IPv4(10, 73, byte(sessionNum), 2)
	gatewayIP := net.IPv4(10, 73, byte(sessionNum), 1)

	// Hijack the HTTP/3 stream to access datagram methods.
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "stream hijack unavailable", http.StatusInternalServerError)
		return
	}

	// Send 200 OK before hijacking.
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	str := streamer.HTTPStream()

	// Send address assignment capsule via stream datagram.
	ip4 := assignedIP.To4()
	addrCapsule := make([]byte, 5)
	addrCapsule[0] = 0x01 // address assign marker
	copy(addrCapsule[1:], ip4)
	if err := str.SendDatagram(addrCapsule); err != nil {
		return
	}

	// Open TUN device for this session's traffic forwarding.
	tun, err := OpenTUN(connectIPDefaultMTU)
	if err != nil {
		log.Printf("  connect-ip: TUN create: %v", err)
		return
	}
	defer func() { _ = tun.Close() }()

	// Configure the server-side TUN with this session's gateway IP.
	if err := configureTUNAddress(tun.Name(), gatewayIP); err != nil {
		log.Printf("  connect-ip: TUN configure: %v", err)
		return
	}

	// Bidirectional forwarding: stream datagrams ↔ TUN device.
	done := make(chan struct{}, 2)

	// TUN → stream datagram (downlink to client).
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, connectIPDefaultMTU)
		for {
			n, readErr := tun.Read(buf)
			if readErr != nil {
				return
			}
			if n > 0 {
				dgram := make([]byte, 1+n)
				dgram[0] = 0x00
				copy(dgram[1:], buf[:n])
				if sendErr := str.SendDatagram(dgram); sendErr != nil {
					return
				}
			}
		}
	}()

	// Stream datagram → TUN (uplink from client).
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			dgram, recvErr := str.ReceiveDatagram(context.Background())
			if recvErr != nil {
				return
			}
			if len(dgram) < 2 || dgram[0] != 0x00 {
				continue
			}
			if _, wErr := tun.Write(dgram[1:]); wErr != nil {
				return
			}
		}
	}()

	<-done
}

// ConnectIPServerConfig wraps HTTP3ServerConfig for consistency.
type ConnectIPServerConfig = HTTP3ServerConfig
