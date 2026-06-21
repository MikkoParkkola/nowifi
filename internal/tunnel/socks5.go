// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// ----------------------------------------------------------------------------
// Shared SOCKS5-lite handshake helpers.
//
// Every tunnel client (MASQUE, WebTransport, H2 CONNECT, SSE, gRPC, etc.)
// exposes a local SOCKS5 proxy. The greeting and CONNECT-request parsing
// is identical across all of them — this file provides a single
// implementation to avoid duplication.
// ----------------------------------------------------------------------------

// socks5Reply constants for SOCKS5 response codes.
var (
	socks5Success       = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	socks5GeneralFail   = []byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	socks5CmdNotSupport = []byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	socks5AddrNotSupport = []byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
)

// socks5Handshake reads a SOCKS5 greeting and CONNECT request from conn,
// returning the requested "host:port" target. On protocol errors it writes
// the appropriate SOCKS5 error reply and returns a non-nil error.
func socks5Handshake(conn net.Conn) (string, error) {
	// Greeting: version(1) + nmethods(1) + methods(nmethods).
	greet := make([]byte, 257)
	if _, err := io.ReadAtLeast(conn, greet[:2], 2); err != nil {
		return "", fmt.Errorf("socks5: read greeting: %w", err)
	}
	if greet[0] != 0x05 {
		return "", fmt.Errorf("socks5: unsupported version %d", greet[0])
	}
	nmethods := int(greet[1])
	if nmethods > 0 {
		if _, err := io.ReadFull(conn, greet[:nmethods]); err != nil {
			return "", fmt.Errorf("socks5: read methods: %w", err)
		}
	}
	// Reply: no authentication required.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", fmt.Errorf("socks5: write greeting reply: %w", err)
	}

	// CONNECT request: ver(1) + cmd(1) + rsv(1) + atyp(1).
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", fmt.Errorf("socks5: read connect header: %w", err)
	}
	if hdr[1] != 0x01 { // Only CONNECT supported.
		_, _ = conn.Write(socks5CmdNotSupport)
		return "", fmt.Errorf("socks5: unsupported command %d", hdr[1])
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", fmt.Errorf("socks5: read ipv4: %w", err)
		}
		host = net.IP(ip).String()
	case 0x03: // Domain name
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", fmt.Errorf("socks5: read domain length: %w", err)
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", fmt.Errorf("socks5: read domain: %w", err)
		}
		host = string(name)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", fmt.Errorf("socks5: read ipv6: %w", err)
		}
		host = net.IP(ip).String()
	default:
		_, _ = conn.Write(socks5AddrNotSupport)
		return "", fmt.Errorf("socks5: unsupported address type %d", hdr[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("socks5: read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// socks5SendSuccess writes the SOCKS5 success reply.
func socks5SendSuccess(conn net.Conn) error {
	_, err := conn.Write(socks5Success)
	return err
}

// socks5SendFail writes the SOCKS5 general failure reply.
func socks5SendFail(conn net.Conn) {
	_, _ = conn.Write(socks5GeneralFail)
}
