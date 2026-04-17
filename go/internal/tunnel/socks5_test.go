// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestSocks5HandshakeIPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Send SOCKS5 greeting: version 5, 1 method (no auth).
		_, _ = client.Write([]byte{0x05, 0x01, 0x00})

		// Read greeting reply.
		reply := make([]byte, 2)
		_, _ = client.Read(reply)

		// Send CONNECT request: IPv4 127.0.0.1:8080.
		_, _ = client.Write([]byte{
			0x05, 0x01, 0x00, 0x01, // ver, cmd=CONNECT, rsv, atyp=IPv4
			127, 0, 0, 1, // IPv4 address
			0x1F, 0x90, // port 8080
		})
	}()

	target, err := socks5Handshake(server)
	if err != nil {
		t.Fatalf("socks5Handshake: %v", err)
	}
	if target != "127.0.0.1:8080" {
		t.Fatalf("target = %q, want 127.0.0.1:8080", target)
	}
}

func TestSocks5HandshakeDomain(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Greeting.
		_, _ = client.Write([]byte{0x05, 0x01, 0x00})
		reply := make([]byte, 2)
		_, _ = client.Read(reply)

		// CONNECT with domain name "example.com:443".
		domain := []byte("example.com")
		buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
		buf = append(buf, domain...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, 443)
		buf = append(buf, portBuf...)
		_, _ = client.Write(buf)
	}()

	target, err := socks5Handshake(server)
	if err != nil {
		t.Fatalf("socks5Handshake: %v", err)
	}
	if target != "example.com:443" {
		t.Fatalf("target = %q, want example.com:443", target)
	}
}

func TestSocks5HandshakeIPv6(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00})
		reply := make([]byte, 2)
		_, _ = client.Read(reply)

		// CONNECT with IPv6 ::1 port 80.
		buf := []byte{0x05, 0x01, 0x00, 0x04} // atyp=IPv6
		ipv6 := net.ParseIP("::1").To16()
		buf = append(buf, ipv6...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, 80)
		buf = append(buf, portBuf...)
		_, _ = client.Write(buf)
	}()

	target, err := socks5Handshake(server)
	if err != nil {
		t.Fatalf("socks5Handshake: %v", err)
	}
	if target != "::1:80" {
		t.Fatalf("target = %q, want ::1:80", target)
	}
}

func TestSocks5HandshakeWrongVersion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Send SOCKS4 greeting (wrong version).
		_, _ = client.Write([]byte{0x04, 0x01, 0x00})
	}()

	_, err := socks5Handshake(server)
	if err == nil {
		t.Fatal("expected error for wrong SOCKS version")
	}
}

func TestSocks5HandshakeUnsupportedCmd(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00})
		reply := make([]byte, 2)
		_, _ = client.Read(reply)

		// Send BIND command (0x02) instead of CONNECT (0x01).
		// Only send the 4-byte header — net.Pipe blocks until all bytes
		// are consumed, and socks5Handshake only reads 4 bytes before
		// writing the error reply. Sending more would deadlock.
		_, _ = client.Write([]byte{0x05, 0x02, 0x00, 0x01})

		// Read error reply written by socks5Handshake.
		errReply := make([]byte, 10)
		_, _ = client.Read(errReply)
		errCh <- nil
	}()

	_, err := socks5Handshake(server)
	if err == nil {
		t.Fatal("expected error for unsupported command")
	}
	<-errCh
}
