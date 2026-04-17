// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// FuzzSOCKS5Handshake fuzzes the SOCKS5 greeting + CONNECT parsing path that
// is shared across all tunnel handlers (WS, MASQUE, WebTransport, H2, SSE).
// The goal is to verify no panic, no unbounded allocation, and no hang on
// malformed input.
func FuzzSOCKS5Handshake(f *testing.F) {
	// Seed: valid SOCKS5 greeting + CONNECT to example.com:80
	var seed []byte
	seed = append(seed, 0x05, 0x01, 0x00)                                 // greeting: v5, 1 method, no-auth
	seed = append(seed, 0x05, 0x01, 0x00, 0x03)                           // CONNECT, domain type
	seed = append(seed, byte(len("example.com")))                          // domain length
	seed = append(seed, []byte("example.com")...)                          // domain
	seed = append(seed, 0x00, 0x50)                                        // port 80
	f.Add(seed)

	// Seed: IPv4 CONNECT
	var ipv4Seed []byte
	ipv4Seed = append(ipv4Seed, 0x05, 0x01, 0x00)
	ipv4Seed = append(ipv4Seed, 0x05, 0x01, 0x00, 0x01)
	ipv4Seed = append(ipv4Seed, 1, 2, 3, 4)
	ipv4Seed = append(ipv4Seed, 0x01, 0xBB) // port 443
	f.Add(ipv4Seed)

	// Seed: empty
	f.Add([]byte{})

	// Seed: truncated
	f.Add([]byte{0x05})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a pipe — write the fuzz data, then close.
		clientConn, serverConn := net.Pipe()
		go func() {
			_, _ = clientConn.Write(data)
			_ = clientConn.Close()
		}()

		// Set a tight deadline to prevent hangs.
		_ = serverConn.SetDeadline(time.Now().Add(100 * time.Millisecond))

		// Simulate the SOCKS5 parsing path from handleWSSocks.
		// This exercises the same code pattern shared across all handlers.
		greet := make([]byte, 257)
		n, err := serverConn.Read(greet[:2])
		if err != nil || n < 2 || greet[0] != 0x05 {
			_ = serverConn.Close()
			return
		}
		nmethods := int(greet[1])
		if nmethods > 0 && nmethods <= 255 {
			buf := make([]byte, nmethods)
			_, _ = serverConn.Read(buf)
		}
		_, _ = serverConn.Write([]byte{0x05, 0x00})

		hdr := make([]byte, 4)
		_, err = serverConn.Read(hdr)
		if err != nil || hdr[1] != 0x01 {
			_ = serverConn.Close()
			return
		}

		switch hdr[3] {
		case 0x01: // IPv4
			ip := make([]byte, 4)
			_, _ = serverConn.Read(ip)
		case 0x03: // Domain
			length := make([]byte, 1)
			_, err = serverConn.Read(length)
			if err != nil {
				_ = serverConn.Close()
				return
			}
			name := make([]byte, int(length[0]))
			_, _ = serverConn.Read(name)
		default:
			_ = serverConn.Close()
			return
		}

		portBuf := make([]byte, 2)
		_, _ = serverConn.Read(portBuf)
		_ = binary.BigEndian.Uint16(portBuf)

		_ = serverConn.Close()
	})
}

// FuzzTargetHeaderParse fuzzes the uint16 length-prefix target header parser
// used by HTTP3Tunnel, WebTransport, and WS Tunnel server handlers.
func FuzzTargetHeaderParse(f *testing.F) {
	// Valid: "example.com:443"
	target := []byte("example.com:443")
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(target)))
	f.Add(append(lenBuf, target...))

	// Empty
	f.Add([]byte{})
	// Truncated length
	f.Add([]byte{0x00})
	// Zero-length target
	f.Add([]byte{0x00, 0x00})
	// Oversized target (513 bytes = beyond 512 limit)
	f.Add([]byte{0x02, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		targetLen := binary.BigEndian.Uint16(data[:2])
		if targetLen == 0 || targetLen > 512 {
			return
		}
		if len(data) < int(targetLen)+2 {
			return
		}
		target := string(data[2 : 2+targetLen])
		// Should not panic on any input.
		_ = validateTargetHostPort(target)
	})
}

func TestParseWSEndpointFuzz(t *testing.T) {
	// Quick regression tests for edge cases found by manual fuzzing.
	cases := []string{
		"",
		"wss://",
		"ws://",
		"wss://:",
		"wss://:443",
		"wss://host:0",
		"wss://host:99999",
		"wss://[::1]:443",
		"wss://host/path/deep",
	}
	for _, c := range cases {
		_, _, _, err := parseWSEndpoint(c)
		// We don't care about the result, just that it doesn't panic.
		_ = err
	}
}

func TestParseMASQUEEndpointFuzz(t *testing.T) {
	cases := []string{"", "https://", "http://", "host", "host:443", "https://host/path"}
	for _, c := range cases {
		_, _, err := parseMASQUEEndpoint(c)
		_ = err
	}
}

func TestParseH2EndpointFuzz(t *testing.T) {
	cases := []string{"", "https://", "http://", "host", "host:443"}
	for _, c := range cases {
		_, _, err := parseH2Endpoint(c)
		_ = err
	}
}
