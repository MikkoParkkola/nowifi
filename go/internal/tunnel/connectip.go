// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ----------------------------------------------------------------------------
// Wave 22 technique #32 — CONNECT-IP tunnel (RFC 9484).
//
// Tunnels raw IP packets (not just TCP) through HTTP/3 DATAGRAM frames.
// From DPI's perspective, this is indistinguishable from Apple Private
// Relay, iCloud+, or Cloudflare WARP — all of which use HTTP/3 with
// datagrams on UDP/443.
//
// Unlike MASQUE CONNECT-UDP (#27) which tunnels individual TCP streams,
// CONNECT-IP creates a full virtual network interface (TUN device) and
// routes ALL traffic through it. DNS, ICMP ping, UDP gaming — everything
// works.
//
// Protocol (simplified, inspired by RFC 9484):
//   Client → QUIC dial to proxy:443 (ALPN "h3", datagrams enabled)
//   Client → Extended CONNECT :protocol=connect-ip
//   Proxy  → 200 OK + assigns virtual IP via capsule
//   Client ↔ IP packets in HTTP/3 DATAGRAM frames
//
// We implement a simplified capsule protocol:
//   First datagram from server: 4 bytes IPv4 addr (assigned to client)
//   Subsequent datagrams: raw IP packets
//
// This file implements the client side.
// ----------------------------------------------------------------------------

const (
	connectIPDefaultMTU = 1400 // conservative MTU for QUIC encapsulation
)

// ConnectIPConfig holds configuration for the CONNECT-IP tunnel.
type ConnectIPConfig struct {
	ServerURL string
	Timeout   time.Duration
}

// StartConnectIPTunnel opens an HTTP/3 connection with CONNECT-IP to the
// proxy server, creates a TUN device, and routes traffic through it.
// Returns a Handle for lifecycle management.
func StartConnectIPTunnel(cfg ConnectIPConfig) (*Handle, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("connect-ip: serverURL required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}

	addr, sni, err := parseConnectIPEndpoint(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: %w", err)
	}

	// Dial QUIC with HTTP/3 ALPN and datagram support.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	tlsConf := &tls.Config{
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}
	if clientInsecureTLSForTest {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // test-only
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
	}

	qconn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: QUIC dial %s: %w", addr, err)
	}

	// Create HTTP/3 client conn.
	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(qconn)

	// Wait for server SETTINGS.
	settingsCtx, settingsCancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer settingsCancel()
	select {
	case <-cc.ReceivedSettings():
	case <-settingsCtx.Done():
		_ = qconn.CloseWithError(0, "settings timeout")
		return nil, errors.New("connect-ip: timeout waiting for server SETTINGS")
	case <-cc.Context().Done():
		return nil, fmt.Errorf("connect-ip: connection closed: %w", context.Cause(cc.Context()))
	}

	settings := cc.Settings()
	if !settings.EnableExtendedConnect {
		_ = qconn.CloseWithError(0, "")
		return nil, errors.New("connect-ip: server does not support Extended CONNECT")
	}

	// Open Extended CONNECT stream with connect-ip protocol.
	rstr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("connect-ip: open request stream: %w", err)
	}

	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-ip",
		Host:   sni,
		URL:    &url.URL{Host: sni},
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{"?1"},
		},
	}); err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("connect-ip: send request: %w", err)
	}

	resp, err := rstr.ReadResponse()
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("connect-ip: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("connect-ip: server returned HTTP %d", resp.StatusCode)
	}

	// Receive assigned IP address from first datagram.
	addrCtx, addrCancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer addrCancel()
	addrDgram, err := qconn.ReceiveDatagram(addrCtx)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("connect-ip: receive address: %w", err)
	}

	if len(addrDgram) < 5 || addrDgram[0] != 0x01 { // 0x01 = address assign
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("connect-ip: invalid address capsule (len=%d)", len(addrDgram))
	}
	assignedIP := net.IP(addrDgram[1:5])

	// Create TUN device.
	tun, err := OpenTUN(connectIPDefaultMTU)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("connect-ip: create TUN: %w", err)
	}

	// Configure TUN interface with assigned IP.
	if err := configureTUNAddress(tun.Name(), assignedIP); err != nil {
		_ = tun.Close()
		_ = qconn.CloseWithError(0, "")
		return nil, fmt.Errorf("connect-ip: configure TUN: %w", err)
	}

	h := &Handle{
		LocalPort: 0, // TUN-based, no SOCKS port
		Method:    "connect_ip_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}

	// Start bidirectional forwarding: TUN ↔ QUIC datagrams.
	h.wg.Add(2)
	go tunToQUIC(tun, qconn, h.stop, h.wg)
	go quicToTUN(tun, qconn, h.stop, h.wg)

	h.extraStop = func() {
		_ = tun.Close()
		_ = qconn.CloseWithError(0, "client shutdown")
	}
	return h, nil
}

func parseConnectIPEndpoint(s string) (addr, sni string, err error) {
	switch {
	case len(s) > 8 && s[:8] == "https://":
		s = s[8:]
	case len(s) > 7 && s[:7] == "http://":
		return "", "", errors.New("CONNECT-IP requires TLS (use https://)")
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	host := s
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		host += ":443"
	}
	sniHost, _, _ := net.SplitHostPort(host)
	if sniHost == "" {
		return "", "", errors.New("empty host in CONNECT-IP URL")
	}
	return host, sniHost, nil
}

// tunToQUIC reads IP packets from the TUN device and sends them as
// QUIC datagrams. Datagram format: [0x00 (data marker)] [IP packet].
func tunToQUIC(tun TUNDevice, conn *quic.Conn, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, connectIPDefaultMTU)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := tun.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		// Prepend data marker byte.
		dgram := make([]byte, 1+n)
		dgram[0] = 0x00 // data packet
		copy(dgram[1:], buf[:n])
		if sendErr := conn.SendDatagram(dgram); sendErr != nil {
			return
		}
	}
}

// quicToTUN reads QUIC datagrams and writes IP packets to the TUN device.
func quicToTUN(tun TUNDevice, conn *quic.Conn, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}
		dgram, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if len(dgram) < 2 {
			continue
		}
		switch dgram[0] {
		case 0x00: // data packet
			if _, wErr := tun.Write(dgram[1:]); wErr != nil {
				return
			}
		case 0x01: // address assign (ignore after initial)
			continue
		}
	}
}

// configureTUNAddress assigns an IP address to the TUN interface and
// brings it up. Uses platform-appropriate methods.
func configureTUNAddress(ifname string, ip net.IP) error {
	return configureTUNAddressPlatform(ifname, ip)
}

// sendAddressCapsule creates the simplified address assignment datagram.
// Format: [0x01] [4 bytes IPv4 address].
func sendAddressCapsule(conn *quic.Conn, ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return errors.New("only IPv4 address assignment supported")
	}
	dgram := make([]byte, 5)
	dgram[0] = 0x01 // address assign marker
	copy(dgram[1:], ip4)
	return conn.SendDatagram(dgram)
}

// Helper: encode uint16 for capsule fields.
func encodeUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
