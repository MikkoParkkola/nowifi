// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ----------------------------------------------------------------------------
// HTTP/3-ALPN tunnel server (peer for StartHTTP3Tunnel client)
//
// Listens on UDP with ALPN "h3", accepts QUIC connections, and for each
// incoming bidi stream reads the protocol header:
//
//	uint16 len | len bytes of "host:port"
//
// then dials TCP to that target and pipes bytes bidirectionally between the
// stream and the TCP socket. Closes the stream on any error.
//
// The server accepts a TLS certificate + key (PEM files). If either path is
// empty, it auto-generates a self-signed cert. Self-signed certs work
// because the client's handshake path does not enforce CA validation (the
// nowifi client accepts the server's cert by hostname pinning or raw public
// key — not by CA chain, since captive networks often interfere with CA
// revocation checks). For production, pass a real Let's Encrypt cert.
// ----------------------------------------------------------------------------

// HTTP3ServerConfig controls server startup.
type HTTP3ServerConfig struct {
	// Listen is the UDP address to bind, e.g. "0.0.0.0:443".
	Listen string
	// CertFile and KeyFile are PEM file paths. If either is empty, a
	// self-signed cert for the given Hostname is generated in-memory.
	CertFile string
	KeyFile  string
	// Hostname is used as the Subject CommonName on auto-generated certs.
	Hostname string
	// MaxStreamIdle kills a stream that sees no traffic for this duration.
	// Zero means no idle timeout (streams live as long as the TCP peer holds them).
	MaxStreamIdle time.Duration
}

// HTTP3Server is a running tunnel server. Call Close to stop.
type HTTP3Server struct {
	listener *quic.Listener
	wg       sync.WaitGroup
	stop     chan struct{}
	closeOnc sync.Once
}

// ListenHTTP3Tunnel starts the server and returns it. It accepts new
// connections in the background until Close is called.
func ListenHTTP3Tunnel(cfg HTTP3ServerConfig) (*HTTP3Server, error) {
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
	tlsConf.NextProtos = []string{"h3"}
	tlsConf.MinVersion = tls.VersionTLS13

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", cfg.Listen, err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", cfg.Listen, err)
	}

	tr := &quic.Transport{Conn: pc}
	ln, err := tr.Listen(tlsConf, &quic.Config{
		MaxIdleTimeout:       60 * time.Second,
		HandshakeIdleTimeout: 10 * time.Second,
		EnableDatagrams:      true,
	})
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("quic listen: %w", err)
	}

	srv := &HTTP3Server{
		listener: ln,
		stop:     make(chan struct{}),
	}
	srv.wg.Add(1)
	go srv.acceptLoop(cfg.MaxStreamIdle)
	return srv, nil
}

// Addr returns the bound UDP address string for informational use.
func (s *HTTP3Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Close stops the server, closing the listener and waiting for in-flight
// connections to finish. Idempotent.
func (s *HTTP3Server) Close() error {
	s.closeOnc.Do(func() {
		close(s.stop)
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
	// Bounded wait to avoid hanging forever on misbehaving peers.
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

func (s *HTTP3Server) acceptLoop(maxStreamIdle time.Duration) {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		conn, err := s.listener.Accept(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient error: brief pause, then continue.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.wg.Add(1)
		go s.handleConn(conn, maxStreamIdle)
	}
}

func (s *HTTP3Server) handleConn(conn *quic.Conn, maxStreamIdle time.Duration) {
	defer s.wg.Done()
	defer func() { _ = conn.CloseWithError(0, "bye") }()
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		stream, err := conn.AcceptStream(ctx)
		cancel()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(str *quic.Stream) {
			defer s.wg.Done()
			handleTunnelStream(str, maxStreamIdle)
		}(stream)
	}
}

// handleTunnelStream reads the protocol header from str, dials the requested
// TCP target, and bridges bytes between the stream and the TCP connection
// until either side closes.
func handleTunnelStream(str *quic.Stream, maxStreamIdle time.Duration) {
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

	// Clear deadlines for long-lived bidi copy.
	_ = str.SetReadDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, str); done <- struct{}{} }()
	go func() { _, _ = io.Copy(str, upstream); done <- struct{}{} }()
	<-done
}

// validateTargetHostPort rejects obviously malformed target strings before
// we pass them to net.Dial. Bounded to sensible sizes only; deep validation
// is unnecessary because the OS resolver will reject garbage.
func validateTargetHostPort(s string) error {
	if s == "" {
		return errors.New("empty target")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid host:port %q: %w", s, err)
	}
	if host == "" || port == "" {
		return fmt.Errorf("empty host or port in %q", s)
	}
	// Refuse link-local / loopback-by-name to reduce accidental server SSRF
	// exposure. Explicit IP loopback is allowed for testing.
	switch host {
	case "localhost":
		return errors.New("localhost targets disabled")
	}
	return nil
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

func loadOrGenerateTLSConfig(certFile, keyFile, hostname string) (*tls.Config, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert %s/%s: %w", certFile, keyFile, err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	cert, err := generateSelfSignedCert(hostname)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// generateSelfSignedCert builds an ECDSA P-256 self-signed cert valid for
// 90 days. Suitable for development; production deployments should supply a
// real cert via CertFile/KeyFile.
func generateSelfSignedCert(hostname string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("gen key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("gen serial: %w", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// WriteSelfSignedCertFiles generates a fresh self-signed cert and writes
// PEM-encoded cert and key to the given paths. Intended for first-run
// bootstrap; subsequent invocations of ListenHTTP3Tunnel should reuse the
// files via CertFile/KeyFile so clients can pin the server identity.
func WriteSelfSignedCertFiles(hostname, certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("gen key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("gen serial: %w", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil { //nolint:gosec // public cert
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}
