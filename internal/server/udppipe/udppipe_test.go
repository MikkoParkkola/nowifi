// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package udppipe

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

// silentLogger discards all log output to keep test output clean.
var silentLogger = log.New(io.Discard, "", 0)

// pipeConn is a full-duplex in-memory byte pipe that implements Stream.
// Each Write becomes a complete message for a single Read.
type pipeConn struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  [][]byte
	closed bool

	// peer is the other end of the pipe (set after construction).
	peer *pipeConn
}

func newPipePair() (*pipeConn, *pipeConn) {
	a := &pipeConn{}
	b := &pipeConn{}
	a.cond = sync.NewCond(&a.mu)
	b.cond = sync.NewCond(&b.mu)
	a.peer = b
	b.peer = a
	return a, b
}

func (p *pipeConn) Read(buf []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.cond.Wait()
	}
	if p.closed && len(p.buf) == 0 {
		return 0, io.EOF
	}
	msg := p.buf[0]
	p.buf = p.buf[1:]
	n := copy(buf, msg)
	return n, nil
}

func (p *pipeConn) Write(data []byte) (int, error) {
	p.peer.mu.Lock()
	defer p.peer.mu.Unlock()
	if p.peer.closed {
		return 0, io.ErrClosedPipe
	}
	msg := make([]byte, len(data))
	copy(msg, data)
	p.peer.buf = append(p.peer.buf, msg)
	p.peer.cond.Signal()
	return len(data), nil
}

func (p *pipeConn) Close() error {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()

	p.peer.mu.Lock()
	p.peer.closed = true
	p.peer.cond.Broadcast()
	p.peer.mu.Unlock()
	return nil
}

// startEchoUDP starts a UDP echo server on an ephemeral port.
func startEchoUDP(t *testing.T) (addr string, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo UDP listen: %v", err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}

// ── Tests ────────────────────────────────────────────────────────────────────

// AC: MIK.NOWI.1 — libp2p P2P tunnel provider fourth tunnel provider.
// Tested here: the udppipe Bridge is the core UDP↔stream abstraction shared
// by both the existing WebSocket transport and the new libp2p transport.
//
// AC: MIK.NOWI.2 — Regression test covers the fixed behavior.
// Tested here: loopback round-trip, multi-datagram, truncation, and
// Stop/Wait lifecycle are all covered.

// TestBridge_SingleDatagram verifies a single UDP datagram round-trips
// through the pipe bridge to a UDP echo server and back.
func TestBridge_SingleDatagram(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpAddr, err := net.ResolveUDPAddr("udp", echoAddr)
	if err != nil {
		t.Fatalf("resolve echo addr: %v", err)
	}

	// Client-side: bridge local UDP port ↔ pipe stream.
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer clientUDP.Close()

	// Server-side: forward pipe stream ↔ echo UDP.
	serverUDP, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer serverUDP.Close()

	// Create pipe pair — client and server share a bidirectional pipe.
	clientPipe, serverPipe := newPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	// Server bridge: pipe stream ↔ echo UDP.
	srvBridge := &Bridge{
		UDPConn:    serverUDP,
		Stream:     serverPipe,
		RemoteAddr: udpAddr,
		Logger:     silentLogger,
	}
	go srvBridge.Run()
	defer srvBridge.Stop()

	// Client bridge: local UDP ↔ pipe stream.
	cliBridge := &Bridge{
		UDPConn: clientUDP,
		Stream:  clientPipe,
		Logger:  silentLogger,
	}
	go cliBridge.Run()
	defer cliBridge.Stop()

	time.Sleep(30 * time.Millisecond)

	// Send a datagram from a test UDP socket to the client bridge.
	testConn, err := net.Dial("udp", clientUDP.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial client bridge: %v", err)
	}
	defer testConn.Close()

	payload := []byte("hello-udppipe")
	_ = testConn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := testConn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 65535)
	n, err := testConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], payload)
	}
}

// TestBridge_MultipleDatagrams verifies multiple datagrams round-trip correctly.
func TestBridge_MultipleDatagrams(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpAddr, _ := net.ResolveUDPAddr("udp", echoAddr)

	clientUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer clientUDP.Close()

	serverUDP, _ := net.DialUDP("udp", nil, udpAddr)
	defer serverUDP.Close()

	clientPipe, serverPipe := newPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	srvBridge := &Bridge{UDPConn: serverUDP, Stream: serverPipe, RemoteAddr: udpAddr, Logger: silentLogger}
	go srvBridge.Run()
	defer srvBridge.Stop()

	cliBridge := &Bridge{UDPConn: clientUDP, Stream: clientPipe, Logger: silentLogger}
	go cliBridge.Run()
	defer cliBridge.Stop()

	time.Sleep(30 * time.Millisecond)

	testConn, _ := net.Dial("udp", clientUDP.LocalAddr().String())
	defer testConn.Close()
	_ = testConn.SetDeadline(time.Now().Add(8 * time.Second))

	const total = 50
	recv := 0
	for i := range total {
		payload := []byte("pkt-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i/10)) + "-" + string(rune('0'+i%10)))
		if _, err := testConn.Write(payload); err != nil {
			t.Fatalf("write pkt %d: %v", i, err)
		}

		buf := make([]byte, 256)
		n, err := testConn.Read(buf)
		if err != nil {
			t.Fatalf("read pkt %d: %v", i, err)
		}
		if bytes.Equal(buf[:n], payload) {
			recv++
		}
	}

	if recv != total {
		t.Errorf("received %d/%d datagrams", recv, total)
	}
}

// TestBridge_MTUTruncation verifies datagrams exceeding the bridge MTU
// are truncated on the forward path.
func TestBridge_MTUTruncation(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpAddr, _ := net.ResolveUDPAddr("udp", echoAddr)

	clientUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer clientUDP.Close()

	serverUDP, _ := net.DialUDP("udp", nil, udpAddr)
	defer serverUDP.Close()

	clientPipe, serverPipe := newPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	const smallMTU = 16

	srvBridge := &Bridge{UDPConn: serverUDP, Stream: serverPipe, RemoteAddr: udpAddr, MTU: smallMTU, Logger: silentLogger}
	go srvBridge.Run()
	defer srvBridge.Stop()

	cliBridge := &Bridge{UDPConn: clientUDP, Stream: clientPipe, Logger: silentLogger}
	go cliBridge.Run()
	defer cliBridge.Stop()

	time.Sleep(30 * time.Millisecond)

	testConn, _ := net.Dial("udp", clientUDP.LocalAddr().String())
	defer testConn.Close()
	_ = testConn.SetDeadline(time.Now().Add(3 * time.Second))

	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := testConn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	n, err := testConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if n != smallMTU {
		t.Errorf("expected truncated echo len=%d, got %d", smallMTU, n)
	}
	if !bytes.Equal(buf[:n], payload[:smallMTU]) {
		t.Errorf("truncated content mismatch")
	}
}

// TestBridge_StopCleanup verifies Stop() terminates both forwarding loops.
func TestBridge_StopCleanup(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpAddr, _ := net.ResolveUDPAddr("udp", echoAddr)

	clientUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer clientUDP.Close()

	serverUDP, _ := net.DialUDP("udp", nil, udpAddr)
	defer serverUDP.Close()

	clientPipe, serverPipe := newPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	srvBridge := &Bridge{UDPConn: serverUDP, Stream: serverPipe, RemoteAddr: udpAddr, Logger: silentLogger}
	go srvBridge.Run()

	cliBridge := &Bridge{UDPConn: clientUDP, Stream: clientPipe, Logger: silentLogger}
	go cliBridge.Run()

	time.Sleep(30 * time.Millisecond)

	// Stop both bridges — must not hang.
	done := make(chan struct{})
	go func() {
		cliBridge.Stop()
		srvBridge.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("Bridge.Stop() timed out")
	}
}

// TestBridge_StopIdempotent verifies calling Stop multiple times is safe.
func TestBridge_StopIdempotent(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpAddr, _ := net.ResolveUDPAddr("udp", echoAddr)

	clientUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer clientUDP.Close()

	serverUDP, _ := net.DialUDP("udp", nil, udpAddr)
	defer serverUDP.Close()

	clientPipe, serverPipe := newPipePair()
	defer clientPipe.Close()
	defer serverPipe.Close()

	srvBridge := &Bridge{UDPConn: serverUDP, Stream: serverPipe, RemoteAddr: udpAddr, Logger: silentLogger}
	go srvBridge.Run()

	time.Sleep(20 * time.Millisecond)

	// Multiple Stop calls should not panic.
	srvBridge.Stop()
	srvBridge.Stop()
	srvBridge.Stop()
}

// TestBridge_StreamClosePropagates verifies that closing the stream
// causes the bridge to stop cleanly without panic.
func TestBridge_StreamClosePropagates(t *testing.T) {
	clientUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer clientUDP.Close()

	clientPipe, serverPipe := newPipePair()

	cliBridge := &Bridge{UDPConn: clientUDP, Stream: clientPipe, Logger: silentLogger}
	go cliBridge.Run()

	time.Sleep(20 * time.Millisecond)

	// Close the stream from the other end — bridge should exit.
	serverPipe.Close()

	// Wait for bridge to stop.
	select {
	case <-cliBridge.done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not stop after stream close")
	}
}

// TestBridge_DefaultMTU verifies zero MTU uses DefaultMTU.
func TestBridge_DefaultMTU(t *testing.T) {
	b := &Bridge{}
	if b.mtu() != DefaultMTU {
		t.Errorf("default MTU = %d, want %d", b.mtu(), DefaultMTU)
	}
}

// TestBridge_CustomMTU verifies non-zero MTU is used.
func TestBridge_CustomMTU(t *testing.T) {
	b := &Bridge{MTU: 512}
	if b.mtu() != 512 {
		t.Errorf("custom MTU = %d, want 512", b.mtu())
	}
}

// TestBridge_ErrStreamClosed verifies the sentinel error is non-nil.
func TestBridge_ErrStreamClosed(t *testing.T) {
	if ErrStreamClosed == nil {
		t.Error("ErrStreamClosed should be non-nil")
	}
}
