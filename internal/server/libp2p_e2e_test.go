// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"context"
	"net"
	"testing"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
)

// startUDPEcho stands up a local UDP echo server (the stand-in for the offer's
// bridged service, e.g. a WireGuard endpoint). It echoes every datagram back to
// its sender and is torn down when the test finishes.
func startUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], src)
		}
	}()
	return conn.LocalAddr().String()
}

func loopbackNode(t *testing.T, ctx context.Context, bootstraps []peer.AddrInfo) *p2pNode {
	t.Helper()
	n, err := startNode(ctx, nodeOpts{
		listenAddrs:  []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		bootstraps:   bootstraps,
		dhtMode:      dht.ModeServer, // forced server mode: reliable Provide/Find in a tiny in-process DHT
		natTraversal: false,          // no UPnP/hole-punch/relay — hermetic, loopback only
	})
	if err != nil {
		t.Fatalf("startNode: %v", err)
	}
	t.Cleanup(func() {
		_ = n.dht.Close()
		_ = n.host.Close()
	})
	return n
}

// TestLibp2pPairAndTunnelE2E proves the full open-network milestone end-to-end,
// hermetically: two peers that were never previously connected discover each
// other COLD through a local in-process DHT (no public bootstrap.libp2p.io, no
// third-party egress), pair using only a 3-word code, and then tunnel real
// bidirectional UDP traffic over the libp2p stream.
//
// Topology (all in-process, loopback QUIC):
//
//	client local UDP app  <->  client node  ==libp2p stream==>  offer node  <->  UDP echo
//
// A datagram sent into the client's local socket must traverse the tunnel to
// the echo server and come back — proving both directions actually carry bytes.
func TestLibp2pPairAndTunnelE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping libp2p e2e (network/host setup) in -short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Local in-process DHT bootstrap/rendezvous point (replaces the public
	//    bootstrap.libp2p.io nodes — this is what makes the test hermetic).
	boot := loopbackNode(t, ctx, nil)
	bootInfo := peer.AddrInfo{ID: boot.host.ID(), Addrs: boot.host.Addrs()}
	t.Logf("bootstrap node up: %s", boot.host.ID())

	// 2. Offer and client nodes, each bootstrapped ONLY to the local bootstrap
	//    and NOT to each other (proves cold discovery via the DHT).
	offer := loopbackNode(t, ctx, []peer.AddrInfo{bootInfo})
	client := loopbackNode(t, ctx, []peer.AddrInfo{bootInfo})
	t.Logf("offer node:  %s", offer.host.ID())
	t.Logf("client node: %s", client.host.ID())

	// Sanity: the two peers share no prior connection.
	if len(offer.host.Network().ConnsToPeer(client.host.ID())) != 0 {
		t.Fatal("offer and client are already connected; cold-discovery precondition violated")
	}

	// 3. The offer's bridged UDP service (echo server) and the pairing code.
	echoAddr := startUDPEcho(t)
	code := generatePairingCode()
	t.Logf("pairing code generated: %s  (offer bridges to udp target %s)", code, echoAddr)

	// 4. Offer side: accept authenticated streams -> bridge to echo; advertise.
	offerServe(ctx, offer, code, echoAddr)
	t.Log("offer advertising on DHT rendezvous; waiting to be discovered")

	// 5. Client side: discover the offer via the code, connect, open stream,
	//    bridge a local UDP listener. This is the previously-stubbed join path.
	remoteID, clientLocal, stop, err := clientJoin(ctx, client, code, "127.0.0.1:0", 45*time.Second)
	if err != nil {
		t.Fatalf("clientJoin failed (pairing did not complete): %v", err)
	}
	defer stop()
	t.Logf("CONNECTION ESTABLISHED: client discovered+paired with offer %s; local udp %s", remoteID, clientLocal)

	if remoteID != offer.host.ID() {
		t.Fatalf("client paired with %s, expected offer %s", remoteID, offer.host.ID())
	}

	// 6. Act as the local app behind the client: send a datagram into the
	//    client's local UDP socket and expect it echoed back THROUGH the tunnel.
	app, err := net.DialUDP("udp", nil, mustUDPAddr(t, clientLocal))
	if err != nil {
		t.Fatalf("dial client local udp: %v", err)
	}
	defer func() { _ = app.Close() }()

	payloads := [][]byte{
		[]byte("nowifi-e2e-hello"),
		[]byte("second-datagram-\x00\x01\x02-binary-safe"),
	}
	for i, want := range payloads {
		if _, err := app.Write(want); err != nil {
			t.Fatalf("app write #%d: %v", i, err)
		}
		t.Logf("BYTES OUT #%d: wrote %d bytes into client local socket", i, len(want))

		_ = app.SetReadDeadline(time.Now().Add(15 * time.Second))
		buf := make([]byte, 65535)
		n, err := app.Read(buf)
		if err != nil {
			t.Fatalf("app read #%d (no echo returned through tunnel): %v", i, err)
		}
		got := buf[:n]
		if string(got) != string(want) {
			t.Fatalf("echo #%d mismatch: got %q want %q", i, got, want)
		}
		t.Logf("BYTES BACK #%d: received %d bytes echoed through the libp2p tunnel (round-trip OK)", i, n)
	}

	t.Log("E2E PROVEN: cold DHT pairing + bidirectional UDP tunnel over libp2p")
}

func mustUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatalf("resolve %s: %v", s, err)
	}
	return a
}

// TestLibp2pPair_SkipsDecoyAndAuthenticatesOffer proves the rendezvous
// robustness + mutual-auth fixes: a decoy peer advertises the SAME rendezvous
// namespace (as a hostile/confused peer would) but does not hold the pairing
// code. The client must reject the decoy on the mutual handshake, keep trying
// the remaining candidates, and pair only with the real offer — then tunnel.
func TestLibp2pPair_SkipsDecoyAndAuthenticatesOffer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping libp2p decoy/auth e2e in -short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	boot := loopbackNode(t, ctx, nil)
	bootInfo := peer.AddrInfo{ID: boot.host.ID(), Addrs: boot.host.Addrs()}

	offer := loopbackNode(t, ctx, []peer.AddrInfo{bootInfo})
	decoy := loopbackNode(t, ctx, []peer.AddrInfo{bootInfo})
	client := loopbackNode(t, ctx, []peer.AddrInfo{bootInfo})

	echoAddr := startUDPEcho(t)
	code := generatePairingCode()
	rv := rendezvousForCode(code)

	// Real offer: authenticates with the true code and bridges to the echo.
	offerServe(ctx, offer, code, echoAddr)

	// Decoy: advertises the SAME rendezvous namespace but does NOT hold the
	// pairing code. It runs the PAKE responder half with a wrong code, so the
	// derived key differs and the client's key-confirmation check must reject it.
	decoy.host.SetStreamHandler(udpProto, func(s network.Stream) {
		clientID := s.Conn().RemotePeer()
		_, _ = offerPairHandshake(s, "wrong-decoy-code", clientID, decoy.host.ID())
		_ = s.Reset()
	})
	dutil.Advertise(ctx, decoy.rd, rv)
	t.Logf("decoy %s advertising the rendezvous without the code", decoy.host.ID())

	// Client must skip the decoy and pair with the real offer.
	remoteID, clientLocal, stop, err := clientJoin(ctx, client, code, "127.0.0.1:0", 50*time.Second)
	if err != nil {
		t.Fatalf("clientJoin failed (should have skipped decoy and paired with offer): %v", err)
	}
	defer stop()

	if remoteID != offer.host.ID() {
		t.Fatalf("client paired with %s, expected the real offer %s (decoy was %s)", remoteID, offer.host.ID(), decoy.host.ID())
	}
	t.Logf("client correctly skipped decoy and paired with real offer %s", remoteID)

	// Confirm the tunnel actually carries traffic end-to-end.
	app, err := net.DialUDP("udp", nil, mustUDPAddr(t, clientLocal))
	if err != nil {
		t.Fatalf("dial client local udp: %v", err)
	}
	defer func() { _ = app.Close() }()

	want := []byte("decoy-skipped-tunnel-works")
	if _, err := app.Write(want); err != nil {
		t.Fatalf("app write: %v", err)
	}
	_ = app.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 65535)
	n, err := app.Read(buf)
	if err != nil {
		t.Fatalf("app read (no echo through tunnel): %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], want)
	}
	t.Log("MUTUAL-AUTH PROVEN: decoy rejected, real offer authenticated, tunnel carries traffic")
}
