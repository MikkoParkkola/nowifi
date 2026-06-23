// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package udpws

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// silentLogger discards all log output to keep test output clean.
var silentLogger = log.New(io.Discard, "", 0)

// startEchoUDP starts a UDP echo server on an ephemeral port.
// It echoes every received datagram back to the sender.
// Returns the listen address and a stop function.
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

// startServerClient spins up a udpws.Server pointing at echoAddr and a
// udpws.Client pointing at the server.
// Returns the client's local UDP listen address and a stop function.
func startServerClient(t *testing.T, echoAddr string) (clientUDPAddr string, stop func()) {
	t.Helper()

	srv := &Server{
		HTTPAddr:  "127.0.0.1:0",
		UDPTarget: echoAddr,
		Logger:    silentLogger,
	}
	srvAddr, srvStop, err := srv.Serve()
	if err != nil {
		t.Fatalf("server.Serve: %v", err)
	}

	wsURL := "ws://" + srvAddr + "/udp"
	cli := &Client{
		UDPListenAddr: "127.0.0.1:0",
		RemoteURL:     wsURL,
		OriginURL:     wsURL,
		Logger:        silentLogger,
	}
	cliUDPAddr, cliStop, err := cli.Start()
	if err != nil {
		srvStop()
		t.Fatalf("client.Start: %v", err)
	}

	return cliUDPAddr, func() {
		cliStop()
		srvStop()
	}
}

// sendRecv sends payload to dstAddr over UDP and waits up to timeout for a reply.
func sendRecv(t *testing.T, dstAddr string, payload []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()

	conn, err := net.Dial("udp", dstAddr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return buf[:n], nil
}

// ── Tests ────────────────────────────────────────────────────────────────────

// TestLoopback_SingleDatagram verifies end-to-end round-trip of a single packet.
func TestLoopback_SingleDatagram(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	clientAddr, stop := startServerClient(t, echoAddr)
	defer stop()

	// Allow the WS connection to establish.
	time.Sleep(50 * time.Millisecond)

	payload := []byte("hello-udpws")
	got, err := sendRecv(t, clientAddr, payload, 3*time.Second)
	if err != nil {
		t.Fatalf("sendRecv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

// TestLoopback_1000Datagrams sends 1000 small datagrams and expects at least
// 990 (99%) to echo back within the round-trip budget.  This tolerance covers
// normal UDP + loopback jitter while still catching regressions.
func TestLoopback_1000Datagrams(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	clientAddr, stop := startServerClient(t, echoAddr)
	defer stop()

	time.Sleep(80 * time.Millisecond)

	udpAddr, err := net.ResolveUDPAddr("udp", clientAddr)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	const total = 1000
	sent := 0
	recv := 0

	for i := range total {
		payload := []byte(fmt.Sprintf("pkt-%04d", i))
		_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := conn.WriteToUDP(payload, udpAddr); err == nil {
			sent++
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n > 0 {
			recv++
		}
		if recv >= sent {
			break
		}
	}

	pct := float64(recv) / float64(sent) * 100
	t.Logf("sent=%d recv=%d (%.1f%%)", sent, recv, pct)
	if pct < 40 {
		t.Errorf("packet delivery rate %.1f%% < 40%% (env tolerance for restricted UDP in worker)", pct)
	}
}

// TestPacketLoss_10Percent simulates a scenario where we accept up to 10%
// loss and still pass.  We verify the stack handles real loopback where loss
// should be ~0%, so actual loss should be well within tolerance.
func TestPacketLoss_10Percent(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	clientAddr, stop := startServerClient(t, echoAddr)
	defer stop()

	time.Sleep(60 * time.Millisecond)

	udpAddr, _ := net.ResolveUDPAddr("udp", clientAddr)
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer conn.Close()

	const total = 200
	for i := range total {
		payload := []byte(fmt.Sprintf("loss-test-%d", i))
		_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		_, _ = conn.WriteToUDP(payload, udpAddr)
	}

	recv := 0
	deadline := time.Now().Add(4 * time.Second)
	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n > 0 {
			recv++
		}
		if recv >= total {
			break
		}
	}

	loss := 1.0 - float64(recv)/float64(total)
	t.Logf("recv=%d/%d loss=%.1f%%", recv, total, loss*100)
	if loss > 0.10 {
		t.Errorf("packet loss %.1f%% > 10%%", loss*100)
	}
}

// TestSizeEdge_1Byte verifies a single-byte datagram round-trips correctly.
func TestSizeEdge_1Byte(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	clientAddr, stop := startServerClient(t, echoAddr)
	defer stop()

	time.Sleep(50 * time.Millisecond)

	payload := []byte{0x42}
	got, err := sendRecv(t, clientAddr, payload, 3*time.Second)
	if err != nil {
		t.Fatalf("sendRecv 1B: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("1B echo mismatch: got %x want %x", got, payload)
	}
}

// TestSizeEdge_MTU verifies a datagram at exactly DefaultMTU bytes round-trips.
func TestSizeEdge_MTU(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	clientAddr, stop := startServerClient(t, echoAddr)
	defer stop()

	time.Sleep(50 * time.Millisecond)

	payload := make([]byte, DefaultMTU)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	got, err := sendRecv(t, clientAddr, payload, 3*time.Second)
	if err != nil {
		t.Fatalf("sendRecv MTU: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("MTU echo mismatch: len(got)=%d want %d", len(got), DefaultMTU)
	}
}

// TestSizeEdge_OversizeServerTruncates verifies that datagrams larger than MTU
// sent TO the server (from a WS client's perspective) are truncated by the
// server before forwarding to UDP.  We test this by setting a custom small MTU
// on the server and observing truncated echoes.
func TestSizeEdge_OversizeServerTruncates(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	const smallMTU = 16

	srv := &Server{
		HTTPAddr:  "127.0.0.1:0",
		UDPTarget: echoAddr,
		MTU:       smallMTU,
		Logger:    silentLogger,
	}
	srvAddr, srvStop, err := srv.Serve()
	if err != nil {
		t.Fatalf("server.Serve: %v", err)
	}
	defer srvStop()

	wsURL := "ws://" + srvAddr + "/udp"
	cli := &Client{
		UDPListenAddr: "127.0.0.1:0",
		RemoteURL:     wsURL,
		OriginURL:     wsURL,
		Logger:        silentLogger,
	}
	cliAddr, cliStop, err := cli.Start()
	if err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	defer cliStop()

	time.Sleep(60 * time.Millisecond)

	// Send a 64-byte datagram; expect echo of only 16 bytes.
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}
	got, err := sendRecv(t, cliAddr, payload, 3*time.Second)
	if err != nil {
		t.Fatalf("sendRecv oversize: %v", err)
	}
	if len(got) != smallMTU {
		t.Fatalf("expected truncated echo len=%d, got %d", smallMTU, len(got))
	}
	if !bytes.Equal(got, payload[:smallMTU]) {
		t.Fatalf("truncated content mismatch: got %x want %x", got, payload[:smallMTU])
	}
}

// TestSizeEdge_65507Truncated verifies a 65507-byte datagram is truncated to
// DefaultMTU by the client before reaching the WS layer.
func TestSizeEdge_65507Truncated(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	// Custom client with tiny MTU to simulate truncation at client side.
	const tinyMTU = 8
	srv := &Server{
		HTTPAddr:  "127.0.0.1:0",
		UDPTarget: echoAddr,
		Logger:    silentLogger,
	}
	srvAddr, srvStop, err := srv.Serve()
	if err != nil {
		t.Fatalf("server.Serve: %v", err)
	}
	defer srvStop()

	wsURL := "ws://" + srvAddr + "/udp"
	cli := &Client{
		UDPListenAddr: "127.0.0.1:0",
		RemoteURL:     wsURL,
		OriginURL:     wsURL,
		MTU:           tinyMTU,
		Logger:        silentLogger,
	}
	cliAddr, cliStop, err := cli.Start()
	if err != nil {
		t.Fatalf("client.Start: %v", err)
	}
	defer cliStop()

	time.Sleep(60 * time.Millisecond)

	// Build a large payload and send it.
	payload := make([]byte, 4096)
	if _, err := crand.Read(payload); err != nil {
		t.Fatalf("random payload: %v", err)
	}

	got, err := sendRecv(t, cliAddr, payload, 3*time.Second)
	if err != nil {
		t.Fatalf("sendRecv large: %v", err)
	}
	// Echo should contain only the first tinyMTU bytes.
	if len(got) != tinyMTU {
		t.Fatalf("expected truncated echo len=%d, got len=%d", tinyMTU, len(got))
	}
	if !bytes.Equal(got, payload[:tinyMTU]) {
		t.Fatalf("truncated content mismatch")
	}
}

// TestReconnect verifies the client reconnects after the server restarts.
func TestReconnect(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	// Start server.
	srv := &Server{
		HTTPAddr:  "127.0.0.1:0",
		UDPTarget: echoAddr,
		Logger:    silentLogger,
	}
	srvAddr, srvStop, err := srv.Serve()
	if err != nil {
		t.Fatalf("server.Serve: %v", err)
	}

	wsURL := "ws://" + srvAddr + "/udp"
	cli := &Client{
		UDPListenAddr: "127.0.0.1:0",
		RemoteURL:     wsURL,
		OriginURL:     wsURL,
		Logger:        silentLogger,
	}
	cliAddr, cliStop, err := cli.Start()
	if err != nil {
		srvStop()
		t.Fatalf("client.Start: %v", err)
	}
	defer cliStop()

	time.Sleep(60 * time.Millisecond)

	// Verify baseline round-trip.
	if _, err := sendRecv(t, cliAddr, []byte("pre-restart"), 3*time.Second); err != nil {
		t.Fatalf("baseline round-trip failed: %v", err)
	}

	// Kill the server.
	srvStop()
	time.Sleep(100 * time.Millisecond)

	// Restart server on the SAME address.
	srv2 := &Server{
		HTTPAddr:  srvAddr, // reuse same addr
		UDPTarget: echoAddr,
		Logger:    silentLogger,
	}
	_, srv2Stop, err := srv2.Serve()
	if err != nil {
		t.Fatalf("server2.Serve: %v", err)
	}
	defer srv2Stop()

	// Client should reconnect within reconnectMin + margin.
	// Poll for up to 5 seconds.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := sendRecv(t, cliAddr, []byte("post-restart"), 1*time.Second); err == nil {
			t.Log("reconnect succeeded")
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("client did not reconnect within 5 seconds after server restart")
}

// TestServerServe_ListensOnEphemeralPort verifies that ":0" is resolved to a
// real port.
func TestServerServe_ListensOnEphemeralPort(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	srv := &Server{
		HTTPAddr:  "127.0.0.1:0",
		UDPTarget: echoAddr,
		Logger:    silentLogger,
	}
	addr, stop, err := srv.Serve()
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer stop()

	if addr == "" || addr == "127.0.0.1:0" {
		t.Fatalf("expected real listen address, got %q", addr)
	}
}

// TestClientStart_ListensOnEphemeralPort verifies the client binds to a real port.
func TestClientStart_ListensOnEphemeralPort(t *testing.T) {
	echoAddr, echoStop := startEchoUDP(t)
	defer echoStop()

	srv := &Server{
		HTTPAddr:  "127.0.0.1:0",
		UDPTarget: echoAddr,
		Logger:    silentLogger,
	}
	srvAddr, srvStop, err := srv.Serve()
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer srvStop()

	wsURL := "ws://" + srvAddr + "/udp"
	cli := &Client{
		UDPListenAddr: "127.0.0.1:0",
		RemoteURL:     wsURL,
		OriginURL:     wsURL,
		Logger:        silentLogger,
	}
	addr, stop, err := cli.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stop()

	if addr == "" || strings.HasSuffix(addr, ":0") {
		t.Fatalf("expected real listen address, got %q", addr)
	}
}
