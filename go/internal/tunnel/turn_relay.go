// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // STUN/TURN uses SHA1 per RFC 5389
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// TURN Relay — zero-config tunnel through public TURN/STUN servers.
//
// WebRTC's TURN protocol (RFC 5766) relays arbitrary UDP/TCP data through
// TURN servers. Several public TURN servers exist:
//
//   - Google: stun.l.google.com:19302 (STUN only, but validates reachability)
//   - Twilio: global.turn.twilio.com (free tier available)
//   - Metered: relay.metered.ca:443 (free tier)
//   - Open Relay: openrelay.metered.ca:443 (truly free)
//
// TURN uses UDP/3478 or TCP/443 (TURN-over-TLS). The TCP/443 variant is
// particularly effective because it looks like HTTPS to portal DPI.
//
// Flow:
//   1. Connect to TURN server via TCP/443 (TURN-over-TLS)
//   2. Allocate relay address (TURN Allocate request)
//   3. Use ChannelBind + ChannelData to relay TCP data through TURN
//   4. SOCKS5 proxy locally, forward through TURN channel
//
// This is zero-config: uses public TURN servers that require no account.
// The technique leverages the fact that TURN/443 is indistinguishable from
// HTTPS traffic to captive portal DPI.
// ----------------------------------------------------------------------------

const turnRelayDefaultPort = 1095

// PublicTURNServers lists well-known public TURN/STUN servers.
// These are probed in order; the first responsive one is used.
var PublicTURNServers = []TURNServerConfig{
	// Open relay servers (no credentials required).
	{Host: "openrelay.metered.ca", Port: 443, UseTLS: true, Username: "openrelayproject", Credential: "openrelayproject"},
	{Host: "relay.metered.ca", Port: 443, UseTLS: true, Username: "free", Credential: "free"},
	// Standard STUN-only servers (for reachability probing).
	{Host: "stun.l.google.com", Port: 19302, UseTLS: false, STUNOnly: true},
	{Host: "stun1.l.google.com", Port: 19302, UseTLS: false, STUNOnly: true},
	{Host: "stun.cloudflare.com", Port: 3478, UseTLS: false, STUNOnly: true},
}

// TURNServerConfig describes a TURN/STUN server endpoint.
type TURNServerConfig struct {
	Host       string
	Port       int
	UseTLS     bool
	Username   string
	Credential string
	STUNOnly   bool // STUN-only servers can't relay, but validate reachability
}

// STUN/TURN message types (RFC 5389, RFC 5766).
const (
	stunBindingRequest   = 0x0001
	stunBindingResponse  = 0x0101
	turnAllocateRequest  = 0x0003
	turnAllocateResponse = 0x0103
	turnAllocateError    = 0x0113
	turnChannelBind      = 0x0009
	turnChannelBindResp  = 0x0109
	turnChannelData      = 0x4000 // Channel numbers 0x4000-0x7FFF
)

// STUN attribute types.
const (
	attrMappedAddress      = 0x0001
	attrUsername           = 0x0006
	attrMessageIntegrity   = 0x0008
	attrXORMappedAddress   = 0x0020
	attrLifetime           = 0x000D
	attrRequestedTransport = 0x0019
	attrXORRelayedAddress  = 0x0016
	attrXORPeerAddress     = 0x0012
	attrChannelNumber      = 0x000C
	attrRealm              = 0x0014
	attrNonce              = 0x0015
	attrSoftware           = 0x8022
)

const stunMagicCookie = 0x2112A442

// StartTURNRelayTunnel connects to a public TURN server and creates a local
// SOCKS5 proxy that relays traffic through the TURN allocation. Zero-config.
func StartTURNRelayTunnel(localPort int, timeout time.Duration) (*Handle, error) {
	if localPort == 0 {
		localPort = turnRelayDefaultPort
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	// Find a working TURN server.
	var workingServer *TURNServerConfig
	var turnConn net.Conn

	for i := range PublicTURNServers {
		srv := &PublicTURNServers[i]
		if srv.STUNOnly {
			continue // Skip STUN-only for relay
		}

		conn, err := dialTURN(srv, timeout)
		if err != nil {
			continue
		}

		// Try TURN allocate.
		if err := sendTURNAllocate(conn, srv, timeout); err != nil {
			_ = conn.Close()
			continue
		}

		workingServer = srv
		turnConn = conn
		break
	}

	if workingServer == nil {
		return nil, fmt.Errorf("turn relay: no public TURN server accepts allocations")
	}

	// Start local SOCKS5 proxy.
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		_ = turnConn.Close()
		return nil, fmt.Errorf("turn relay: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "turn_relay",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveTURNRelay(listener, turnConn, workingServer, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
		_ = turnConn.Close()
	}
	return h, nil
}

func dialTURN(srv *TURNServerConfig, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	dialer := &net.Dialer{Timeout: timeout}

	if srv.UseTLS {
		return (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
	}
	conn, err := dialer.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// sendTURNAllocate sends a TURN Allocate request and reads the response.
func sendTURNAllocate(conn net.Conn, srv *TURNServerConfig, timeout time.Duration) error {
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build STUN Binding request first to verify connectivity.
	txID := makeTransactionID()
	bindReq := buildSTUNMessage(stunBindingRequest, txID, nil)
	if _, err := conn.Write(bindReq); err != nil {
		return fmt.Errorf("stun binding: %w", err)
	}

	// Read binding response.
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("stun binding response: %w", err)
	}
	if n < 20 {
		return fmt.Errorf("stun binding: response too short (%d bytes)", n)
	}
	msgType := binary.BigEndian.Uint16(buf[0:2])
	if msgType != stunBindingResponse {
		return fmt.Errorf("stun binding: unexpected type 0x%04x", msgType)
	}

	// Now send TURN Allocate request.
	txID = makeTransactionID()
	var attrs []byte

	// Requested-Transport: UDP (17)
	reqTransport := make([]byte, 4)
	reqTransport[0] = 17 // UDP
	attrs = appendSTUNAttr(attrs, attrRequestedTransport, reqTransport)

	// Username
	if srv.Username != "" {
		attrs = appendSTUNAttr(attrs, attrUsername, []byte(srv.Username))
	}

	// Software
	attrs = appendSTUNAttr(attrs, attrSoftware, []byte("nowifi/1.0"))

	allocReq := buildSTUNMessage(turnAllocateRequest, txID, attrs)

	// Add message integrity if credentials present.
	if srv.Credential != "" {
		allocReq = addMessageIntegrity(allocReq, []byte(srv.Credential))
	}

	if _, err := conn.Write(allocReq); err != nil {
		return fmt.Errorf("turn allocate: %w", err)
	}

	n, err = conn.Read(buf)
	if err != nil {
		return fmt.Errorf("turn allocate response: %w", err)
	}
	if n < 20 {
		return fmt.Errorf("turn allocate: response too short (%d bytes)", n)
	}

	msgType = binary.BigEndian.Uint16(buf[0:2])
	switch msgType {
	case turnAllocateResponse:
		return nil // Success
	case turnAllocateError:
		return fmt.Errorf("turn allocate: server returned error (0x%04x)", msgType)
	default:
		return fmt.Errorf("turn allocate: unexpected response type 0x%04x", msgType)
	}
}

func serveTURNRelay(l net.Listener, turnConn net.Conn, srv *TURNServerConfig, stop chan struct{}, wg *sync.WaitGroup) {
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
		go handleTURNRelaySocks(conn, turnConn, srv)
	}
}

func handleTURNRelaySocks(client net.Conn, turnConn net.Conn, srv *TURNServerConfig) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	// Resolve target to IP for TURN peer address.
	host, portStr, _ := net.SplitHostPort(target)
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		socks5SendFail(client)
		return
	}

	ip := net.ParseIP(ips[0])
	if ip == nil {
		socks5SendFail(client)
		return
	}

	port := 80
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port) //nolint:errcheck
	}

	// Create a new TURN connection for this relay session.
	relayConn, err := dialTURN(srv, 10*time.Second)
	if err != nil {
		socks5SendFail(client)
		return
	}
	defer func() { _ = relayConn.Close() }()

	// Allocate and bind channel.
	if err := sendTURNAllocate(relayConn, srv, 10*time.Second); err != nil {
		socks5SendFail(client)
		return
	}

	// ChannelBind to the target peer.
	channelNum := uint16(0x4000 + (rand.Intn(0x3FFF))) //nolint:gosec // non-crypto rand OK for channel numbers
	if err := sendChannelBind(relayConn, srv, channelNum, ip, port); err != nil {
		socks5SendFail(client)
		return
	}

	if err := socks5SendSuccess(client); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	// Bidirectional relay: client ↔ TURN ChannelData.
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := client.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			// Wrap in ChannelData header.
			hdr := make([]byte, 4)
			binary.BigEndian.PutUint16(hdr[0:2], channelNum)
			binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
			_, _ = relayConn.Write(append(hdr, buf[:n]...))
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := relayConn.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			// Unwrap ChannelData header.
			if n < 4 {
				continue
			}
			ch := binary.BigEndian.Uint16(buf[0:2])
			if ch < 0x4000 || ch > 0x7FFF {
				continue // Not channel data
			}
			dataLen := binary.BigEndian.Uint16(buf[2:4])
			if int(dataLen)+4 > n {
				continue
			}
			_, _ = client.Write(buf[4 : 4+dataLen])
		}
	}()
	<-done
}

func sendChannelBind(conn net.Conn, srv *TURNServerConfig, channelNum uint16, peerIP net.IP, peerPort int) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	txID := makeTransactionID()
	var attrs []byte

	// Channel Number attribute.
	chanAttr := make([]byte, 4)
	binary.BigEndian.PutUint16(chanAttr[0:2], channelNum)
	// Reserved (2 bytes zero).
	attrs = appendSTUNAttr(attrs, attrChannelNumber, chanAttr)

	// XOR-Peer-Address.
	xorAddr := encodeXORAddress(peerIP, peerPort, txID)
	attrs = appendSTUNAttr(attrs, attrXORPeerAddress, xorAddr)

	if srv.Username != "" {
		attrs = appendSTUNAttr(attrs, attrUsername, []byte(srv.Username))
	}

	msg := buildSTUNMessage(turnChannelBind, txID, attrs)
	if srv.Credential != "" {
		msg = addMessageIntegrity(msg, []byte(srv.Credential))
	}

	if _, err := conn.Write(msg); err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < 20 {
		return fmt.Errorf("channel bind: response too short")
	}

	msgType := binary.BigEndian.Uint16(buf[0:2])
	if msgType != turnChannelBindResp {
		return fmt.Errorf("channel bind: unexpected type 0x%04x", msgType)
	}
	return nil
}

// STUN message helpers.

func makeTransactionID() [12]byte {
	var txID [12]byte
	_, _ = io.ReadFull(rand.New(rand.NewSource(time.Now().UnixNano())), txID[:]) //nolint:gosec
	return txID
}

func buildSTUNMessage(msgType uint16, txID [12]byte, attrs []byte) []byte {
	msg := make([]byte, 20+len(attrs))
	binary.BigEndian.PutUint16(msg[0:2], msgType)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID[:])
	copy(msg[20:], attrs)
	return msg
}

func appendSTUNAttr(buf []byte, attrType uint16, value []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], attrType)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(value)))
	buf = append(buf, hdr...)
	buf = append(buf, value...)
	// Pad to 4-byte boundary.
	if pad := len(value) % 4; pad != 0 {
		buf = append(buf, make([]byte, 4-pad)...)
	}
	return buf
}

func encodeXORAddress(ip net.IP, port int, txID [12]byte) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		// IPv6 XOR-Mapped-Address.
		buf := make([]byte, 20)
		buf[1] = 0x02 // IPv6
		binary.BigEndian.PutUint16(buf[2:4], uint16(port)^uint16(stunMagicCookie>>16))
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunMagicCookie)
		xorKey := append(cookie, txID[:]...)
		for i := 0; i < 16; i++ {
			buf[4+i] = ip[i] ^ xorKey[i]
		}
		return buf
	}

	buf := make([]byte, 8)
	buf[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(buf[2:4], uint16(port)^uint16(stunMagicCookie>>16))
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, stunMagicCookie)
	for i := 0; i < 4; i++ {
		buf[4+i] = ip4[i] ^ cookieBytes[i]
	}
	return buf
}

func addMessageIntegrity(msg []byte, key []byte) []byte {
	// Update message length to include MESSAGE-INTEGRITY (24 bytes: 4 hdr + 20 HMAC).
	attrLen := binary.BigEndian.Uint16(msg[2:4])
	binary.BigEndian.PutUint16(msg[2:4], attrLen+24)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	integrity := mac.Sum(nil)

	return appendSTUNAttr(msg, attrMessageIntegrity, integrity)
}
