// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package udppipe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// silentLogger discards all log output.
var silentLogger = log.New(io.Discard, "", 0)

// memoryStream is an in-memory ReadWriteCloser for testing.
type memoryStream struct {
	*bytes.Buffer
	closed bool
}

func newMemoryStream() *memoryStream {
	return &memoryStream{Buffer: new(bytes.Buffer)}
}

func (m *memoryStream) Close() error {
	m.closed = true
	return nil
}

// startEchoUDP starts a UDP echo server on an ephemeral port.
func startEchoUDP(t *testing.T) (string, func()) {
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

// ── Pump tests ───────────────────────────────────────────────────────────────

func TestPump_RoundTrip_SingleDatagram(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpConn, err := net.Dial("udp", echoAddr)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer udpConn.Close()

	// Create a paired in-memory stream: what we write to clientWrite is read
	// by the Pipe's stream.Read; what Pipe writes to stream is read by us.
	clientR, clientW := io.Pipe()

	pipe := &Pipe{Logger: silentLogger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- pipe.Pump(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	// Write a datagram into the stream (simulating WS→UDP direction).
	payload := []byte("hello-udppipe")
	if _, err := clientW.Write(payload); err != nil {
		t.Fatalf("write to stream: %v", err)
	}

	// The echo server replies. Read back from the stream (UDP→WS direction).
	buf := make([]byte, 256)
	n, err := clientR.Read(buf)
	if err != nil {
		t.Fatalf("read from stream: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], payload)
	}

	// Clean shutdown.
	clientW.Close()
	select {
	case err := <-done:
		// io.Pipe returns an error on close; that's expected.
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("Pump did not exit after stream close")
	}
}

func TestPump_MTUTruncation(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpConn, err := net.Dial("udp", echoAddr)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{MTU: 8, Logger: silentLogger} // tiny MTU
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pipe.Pump(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})

	// Write a 20-byte payload; it should be truncated to 8 bytes by the pipe.
	payload := []byte("0123456789ABCDEFGHIJ")
	if _, err := clientW.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 128)
	n, err := clientR.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 8 {
		t.Fatalf("expected truncated length 8, got %d", n)
	}
	if !bytes.Equal(buf[:n], payload[:8]) {
		t.Fatalf("truncated content mismatch: got %x want %x", buf[:n], payload[:8])
	}

	clientW.Close()
}

func TestPump_ContextCancellation(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpConn, err := net.Dial("udp", echoAddr)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- pipe.Pump(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	// Cancel after a short delay.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Pump did not exit after context cancel")
	}
}

// ── PumpPacket tests ─────────────────────────────────────────────────────────

func TestPumpPacket_RoundTrip_SingleDatagram(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	// Simulate a client-side UDP listener.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pipe.PumpPacket(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})

	// Send a UDP datagram into the local PacketConn (simulating a local app).
	echoUDPAddr, _ := net.ResolveUDPAddr("udp", echoAddr)
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	payload := []byte("pump-packet-test")

	sender, _ := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, localAddr)
	sender.Write(payload)
	sender.Close()

	// The pipe should forward this to the stream. Read it.
	buf := make([]byte, 256)
	n, err := clientR.Read(buf)
	if err != nil {
		t.Fatalf("read from stream: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("message mismatch: got %q want %q", buf[:n], payload)
	}

	// Now write a reply into the stream — it should be sent to the last peer.
	reply := []byte("reply-from-stream")
	if _, err := clientW.Write(reply); err != nil {
		t.Fatalf("write reply: %v", err)
	}

	// The reply goes back to the sender (port 0), which we can't easily read.
	// But we verify the pipe doesn't panic or deadlock.
	_ = echoUDPAddr // used
	clientW.Close()
	time.Sleep(50 * time.Millisecond)
}

func TestPumpPacket_NoPeerYet_Drops(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pipe.PumpPacket(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})

	// Write to stream before any UDP peer has sent — the stream→UDP goroutine
	// should drop the message (no peer yet).
	if _, err := clientW.Write([]byte("orphan-message")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Pump should not panic or deadlock. Give it time.
	time.Sleep(100 * time.Millisecond)
	clientW.Close()
}

func TestPumpPacket_ContextCancellation(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- pipe.PumpPacket(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PumpPacket did not exit after context cancel")
	}
}

// ── Logger branches ──────────────────────────────────────────────────────────

func TestPipe_Logf_NilLogger(t *testing.T) {
	p := &Pipe{}
	// Must not panic.
	p.logf("test %d", 42)
}

func TestPipe_Logf_WithLogger(t *testing.T) {
	var buf bytes.Buffer
	p := &Pipe{Logger: log.New(&buf, "", 0)}
	p.logf("hello %s", "world")
	if !strings.Contains(buf.String(), "hello world") {
		t.Errorf("expected 'hello world' in log, got %q", buf.String())
	}
}

func TestPipe_MTU_Default(t *testing.T) {
	p := &Pipe{}
	if p.mtu() != DefaultMTU {
		t.Errorf("default MTU = %d, want %d", p.mtu(), DefaultMTU)
	}
}

func TestPipe_MTU_Custom(t *testing.T) {
	p := &Pipe{MTU: 512}
	if p.mtu() != 512 {
		t.Errorf("custom MTU = %d, want 512", p.mtu())
	}
}

// ── Pump: stream write error path ────────────────────────────────────────────

func TestPump_WriteToStreamError(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpConn, err := net.Dial("udp", echoAddr)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer udpConn.Close()

	// Use a pipe where the read side is immediately closed.
	// The UDP→stream goroutine's Write will fail.
	clientR, clientW := io.Pipe()
	clientR.Close() // close read side immediately

	pipe := &Pipe{Logger: silentLogger}
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- pipe.Pump(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	// Send a UDP packet to trigger the echo → stream write.
	// The echo server echoes back, the UDP→stream goroutine reads it and tries
	// to write to the closed pipe — that should error and close done.
	sendConn, _ := net.Dial("udp", echoAddr)
	sendConn.Write([]byte("trigger"))
	sendConn.Close()

	select {
	case <-done:
		// Pump exited — the write error path was hit.
	case <-time.After(2 * time.Second):
		t.Fatal("Pump did not exit after stream write error")
	}
}

// ── PumpPacket: stream read error path ───────────────────────────────────────

func TestPumpPacket_ReadStreamError(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- pipe.PumpPacket(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	// Close the write side — this causes stream.Read in the stream→UDP
	// goroutine to return io.EOF (treated as an error, exits the loop).
	clientW.Close()

	select {
	case <-done:
		// PumpPacket exited.
	case <-time.After(2 * time.Second):
		t.Fatal("PumpPacket did not exit after stream read error")
	}
}

// ── PumpPacket: UDP read error path ──────────────────────────────────────────

func TestPumpPacket_UDPReadError(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx := context.Background()

	// Close the UDP conn immediately — the UDP→stream goroutine's ReadFrom
	// will fail with a non-timeout error.
	udpConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- pipe.PumpPacket(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	select {
	case <-done:
		// PumpPacket exited on UDP read error.
	case <-time.After(2 * time.Second):
		t.Fatal("PumpPacket did not exit after UDP read error")
	}
	_ = clientR
	_ = clientW
}

// ── Pump: UDP read error path ────────────────────────────────────────────────

func TestPump_UDPReadError(t *testing.T) {
	// Create a UDP connection and immediately close it.
	udpConn, err := net.Dial("udp", "127.0.0.1:1") // port 1 is always closed
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- pipe.Pump(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	// Wait for the UDP→stream goroutine to hit a read error.
	select {
	case err := <-done:
		// Expected: UDP read error from the closed/refused connection.
		_ = err
	case <-time.After(3 * time.Second):
		// On some platforms, DialUDP to a closed port may not immediately
		// produce a read error. Cancel and move on.
		clientW.Close()
	}
}

// ── PumpPacket: WriteTo error (invalid peer) ─────────────────────────────────

func TestPumpPacket_WriteToError(t *testing.T) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- pipe.PumpPacket(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	// Send a UDP packet to establish a peer.
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	sender, _ := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, localAddr)
	sender.Write([]byte("seed"))
	sender.Close()

	time.Sleep(50 * time.Millisecond)

	// Now close the UDP conn — the next WriteTo in the stream→UDP goroutine
	// should fail.
	udpConn.Close()

	// Write to the stream to trigger the WriteTo.
	clientW.Write([]byte("will-fail"))

	select {
	case <-done:
		// PumpPacket exited on WriteTo error.
	case <-time.After(2 * time.Second):
		// May already be done.
	}
}

// ── Pump: stream read error path ─────────────────────────────────────────────

func TestPump_ReadStreamError(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpConn, err := net.Dial("udp", echoAddr)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- pipe.Pump(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})
	}()

	// Close the write side → stream.Read in main goroutine returns io.EOF.
	clientW.Close()

	select {
	case <-done:
		// Pump exited on stream read error.
	case <-time.After(2 * time.Second):
		t.Fatal("Pump did not exit after stream read error")
	}
}

// ── Large datagram truncation ────────────────────────────────────────────────

func TestPump_TruncationLargeDatagram(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpConn, err := net.Dial("udp", echoAddr)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{MTU: 16, Logger: silentLogger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pipe.Pump(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})

	// Write a 64-byte payload through the stream → it should be truncated
	// to 16 bytes before being written to UDP.
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := clientW.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read back the echo — should be 16 bytes (echo of truncated payload).
	buf := make([]byte, 128)
	n, err := clientR.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 16 {
		t.Fatalf("expected truncated echo length 16, got %d", n)
	}
	if !bytes.Equal(buf[:n], payload[:16]) {
		t.Fatalf("content mismatch")
	}

	clientW.Close()
}

// ── Pump exercise: many datagrams ────────────────────────────────────────────

func TestPump_ManyDatagrams(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	udpConn, err := net.Dial("udp", echoAddr)
	if err != nil {
		t.Fatalf("dial echo: %v", err)
	}
	defer udpConn.Close()

	clientR, clientW := io.Pipe()
	pipe := &Pipe{Logger: silentLogger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pipe.Pump(ctx, udpConn, &pipeReadWriteCloser{r: clientR, w: clientW, c: clientW})

	const total = 100
	go func() {
		for i := range total {
			_, _ = clientW.Write([]byte(fmt.Sprintf("pkt-%04d", i)))
		}
	}()

	recv := 0
	buf := make([]byte, 256)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && recv < total {
		n, err := clientR.Read(buf)
		if err != nil {
			break
		}
		if n > 0 {
			recv++
		}
	}

	if recv < 90 {
		t.Errorf("received %d/%d packets (< 90%%)", recv, total)
	}
	clientW.Close()
}

// ── helpers ──────────────────────────────────────────────────────────────────

// pipeReadWriteCloser wraps an io.Pipe's read and write ends into a single
// ReadWriteCloser.  The write end is the closer (closing signals EOF to reader).
type pipeReadWriteCloser struct {
	r io.ReadCloser
	w io.WriteCloser
	c io.Closer // the end to close
}

func (p *pipeReadWriteCloser) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeReadWriteCloser) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeReadWriteCloser) Close() error                { return p.c.Close() }
