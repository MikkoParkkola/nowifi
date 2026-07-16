// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// libp2p P2P tunnel provider — decentralized, native-UDP, zero-config.
//
// Issue: https://github.com/MikkoParkkola/nowifi/issues/29
//
// Open-network milestone (Part of #29): both the offer (`server create -p
// libp2p`) and the joiner (`server client --pair CODE`) sides are implemented
// and exchange real bidirectional UDP traffic over a libp2p stream.
//
// Peer discovery ("rendezvous") uses the Kademlia DHT + RoutingDiscovery: each
// side advertises/queries a namespace derived from the 3-word pairing code, so
// two peers that were never previously connected find each other cold through
// the DHT. (Bare pubsub over bootstrap nodes cannot do this — it needs an
// already-connected mesh.) After discovery the client dials a stream, both
// sides prove knowledge of the pairing code with a handshake token, then the
// udppipe bridge carries UDP datagrams over the stream.
//
// Architecture:
//
//   local UDP app ⇄ udppipe ⇄ libp2p stream ⇄ udppipe ⇄ UDP target
//   Transport: QUIC/UDP (+ circuit-relay-v2 + DCUtR hole-punching)
//   Rendezvous: DHT RoutingDiscovery on sha256(pairing-code)
//
// OUT OF SCOPE for this milestone (deferred to #29 Phase 2): WSS-over-443 /
// TCP-443 fallback for captive-portal / UDP-blocked networks. This provider is
// QUIC-only and will not connect where UDP is fully blocked.

package server

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/server/udppipe"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	ma "github.com/multiformats/go-multiaddr"
	pake "github.com/schollz/pake/v3"
)

func init() { Register(&libp2pProvider{}) }

// ─── Provider ────────────────────────────────────────────────────────────────

type libp2pProvider struct{}

func (libp2pProvider) Name() string { return "libp2p" }

func (p libp2pProvider) Create(ctx context.Context, opts CreateOpts) (*Info, error) {
	// Guard G1: explicit operator authorization before using P2P.
	if err := assertAuthorizationFor("libp2p", opts.Target); err != nil {
		return nil, err
	}

	// G3 disclosure (per design + GH#29 AC).
	fmt.Println("Note: your peer IP will be visible to the paired peer and briefly to circuit relays.")

	// Generate 3-word pairing code (33 bits entropy).
	code := generatePairingCode()

	// Determine UDP target to bridge to (from Extra or default).
	udpTarget := "127.0.0.1:51820"
	if t := opts.Extra["udp_target"]; t != "" {
		udpTarget = t
	}

	fmt.Printf("  Pairing code: %s\n", code)
	fmt.Println("  Share this code with your peer. Waiting for them to join...")

	n, err := startNode(ctx, nodeOpts{
		bootstraps:   bootstrapPeersFn(),
		dhtMode:      dht.ModeAuto,
		natTraversal: enableNATTraversal,
	})
	if err != nil {
		return nil, fmt.Errorf("libp2p: start node: %w", err)
	}

	// Offer side: accept an authenticated stream and bridge it to udpTarget,
	// and advertise ourselves on the DHT rendezvous so the joiner can find us.
	offerServe(ctx, n, code, udpTarget)
	storeActive(func() { _ = n.dht.Close(); _ = n.host.Close() })

	info := &Info{
		Provider: "libp2p",
		ServerID: n.host.ID().String()[:12],
		Status:   "active",
		Extra: map[string]string{
			"pairing_code": code,
			"peer_id":      n.host.ID().String(),
			"udp_target":   udpTarget,
			"rendezvous":   rendezvousForCode(code),
		},
	}
	return info, nil
}

func (libp2pProvider) Destroy(ctx context.Context, info *Info, _ string) error {
	closeActive()
	_ = ctx
	_ = info
	return nil
}

// ─── libp2p node + DHT rendezvous ────────────────────────────────────────────

// udpProto is the stream protocol carrying tunnelled UDP datagrams. Bumped to
// 2.0.0 for the PAKE-authenticated + AEAD-encrypted handshake (was a bespoke
// HMAC token in 1.0.0).
const udpProto = protocol.ID("/nowifi/udp/2.0.0")

// pakeCurve is the elliptic curve schollz/pake/v3 runs over. "siec" is croc's
// default and most-exercised configuration.
const pakeCurve = "siec"

// handshakeTimeout bounds the whole pairing handshake (PAKE exchange + mutual
// key confirmation) before the stream is reset.
const handshakeTimeout = 15 * time.Second

// pairingWindow bounds how long an offer honours its pairing code, enforced at
// the application layer (the DHT provider-record TTL is a library default we do
// not control and is longer; this is the real, short window).
const pairingWindow = 5 * time.Minute

// maxConcurrentHandshakes caps in-flight handshakes per offer so a flood of
// bogus connections cannot exhaust CPU/goroutines running PAKE.
const maxConcurrentHandshakes = 4

// AEAD nonce direction tags keep the two traffic directions in separate nonce
// spaces (client->offer vs offer->client) so a deterministic counter never
// repeats a (key, nonce) pair.
const (
	dirClientToOffer byte = 1
	dirOfferToClient byte = 2
)

// p2pNode bundles a libp2p host with its Kademlia DHT and a RoutingDiscovery
// helper for pairing-code rendezvous.
type p2pNode struct {
	host host.Host
	dht  *dht.IpfsDHT
	rd   *drouting.RoutingDiscovery
}

// nodeOpts configures startNode. Production leaves listenAddrs empty (QUIC on
// all interfaces), passes the public bootstraps and natTraversal=true. Tests
// inject a loopback listen addr, a local in-process bootstrap and mode Server
// so cold DHT discovery can be proven without any public-internet egress.
type nodeOpts struct {
	listenAddrs  []string
	bootstraps   []peer.AddrInfo
	dhtMode      dht.ModeOpt
	natTraversal bool
}

// startNode creates a QUIC libp2p host, attaches a Kademlia DHT, connects the
// supplied bootstrap peers, and returns a node ready for rendezvous.
func startNode(ctx context.Context, o nodeOpts) (*p2pNode, error) {
	listen := o.listenAddrs
	if len(listen) == 0 {
		listen = []string{"/ip4/0.0.0.0/udp/0/quic-v1"}
	}
	hopts := []libp2p.Option{libp2p.ListenAddrStrings(listen...)}
	if o.natTraversal {
		hopts = append(hopts,
			libp2p.EnableHolePunching(),
			libp2p.EnableRelay(),
			libp2p.NATPortMap(),
		)
	}
	h, err := libp2p.New(hopts...)
	if err != nil {
		return nil, fmt.Errorf("libp2p: new host: %w", err)
	}

	kdht, err := dht.New(ctx, h, dht.Mode(o.dhtMode))
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("libp2p: new dht: %w", err)
	}

	// Connect bootstrap peers concurrently (best effort, bounded).
	var wg sync.WaitGroup
	for _, pi := range o.bootstraps {
		wg.Add(1)
		go func(pi peer.AddrInfo) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			_ = h.Connect(cctx, pi)
		}(pi)
	}
	wg.Wait()

	if err := kdht.Bootstrap(ctx); err != nil {
		_ = kdht.Close()
		_ = h.Close()
		return nil, fmt.Errorf("libp2p: dht bootstrap: %w", err)
	}

	return &p2pNode{host: h, dht: kdht, rd: drouting.NewRoutingDiscovery(kdht)}, nil
}

// rendezvousForCode maps a pairing code to a DHT rendezvous namespace.
func rendezvousForCode(code string) string {
	sum := sha256.Sum256([]byte("nowifi/pair/rendezvous/v1:" + code))
	return fmt.Sprintf("/nowifi/pair/%x", sum[:16])
}

// ─── PAKE-authenticated pairing handshake ────────────────────────────────────
//
// Security model: the 3-word pairing code is LOW entropy (33 bits). We therefore
// do NOT use it as a secret that must resist offline guessing. Instead a PAKE
// (schollz/pake/v3, the library croc uses) turns the low-entropy code into a
// high-entropy shared session key such that:
//   - each online interaction tests at most ONE code guess (no offline
//     dictionary attack on a captured transcript);
//   - a man-in-the-middle that only relays handshake bytes never learns the
//     session key.
// Honest caveat: no Go PAKE has an independent third-party audit. schollz/pake
// implements a CPace/SPAKE2-style construction; we do NOT claim RFC-9382
// conformance. This is a large improvement over the prior bespoke HMAC token,
// not a formally audited primitive.
//
// Channel binding (defeats the relay-splice MITM): the session key is bound to
// both peers' libp2p peer IDs and the protocol via HKDF, both sides run an
// explicit mutual key-confirmation over that binding, AND every tunnelled UDP
// datagram is AEAD-encrypted (AES-256-GCM) under the session key. A relayer
// without the key can neither read nor inject tunnel traffic.

// maxHandshakeFrame bounds a single handshake message (PAKE points are a few
// hundred bytes; confirmations are 32).
const maxHandshakeFrame = 8192

// writeFrame writes a length-prefixed (2-byte big-endian) message.
func writeFrame(w io.Writer, b []byte) error {
	if len(b) > 65535 {
		return errors.New("libp2p: handshake frame too large")
	}
	hdr := []byte{byte(len(b) >> 8), byte(len(b))}
	if err := writeAllBytes(w, hdr); err != nil {
		return err
	}
	return writeAllBytes(w, b)
}

// readFrame reads a length-prefixed message, rejecting anything over max.
func readFrame(r io.Reader, max int) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n > max {
		return nil, fmt.Errorf("libp2p: handshake frame %d exceeds max %d", n, max)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// writeAllBytes writes all of b, looping over short writes.
func writeAllBytes(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			// A well-behaved io.Writer returns a non-nil error when it writes
			// fewer than len(b) bytes; guard against a misbehaving one so this
			// loop cannot spin forever.
			return errors.New("libp2p: writer made no progress")
		}
		b = b[n:]
	}
	return nil
}

// deriveSessionKey turns the raw PAKE key into a 32-byte AEAD key bound to the
// protocol and BOTH peer IDs (channel binding). The peer IDs are ordered
// (client, offer) identically on both sides.
func deriveSessionKey(pakeKey []byte, clientID, offerID peer.ID) ([]byte, error) {
	info := "nowifi/pair/session/v1|" + string(udpProto) + "|" + clientID.String() + "|" + offerID.String()
	return hkdf.Key(sha256.New, pakeKey, nil, info, 32)
}

// confirmMAC is the mutual key-confirmation tag, bound to the session key, a
// role tag, the protocol, and both peer IDs.
func confirmMAC(sessionKey []byte, role string, clientID, offerID peer.ID) []byte {
	h := hmac.New(sha256.New, sessionKey)
	h.Write([]byte("nowifi/pair/confirm/v1|" + role + "|"))
	h.Write([]byte(udpProto))
	h.Write([]byte(clientID))
	h.Write([]byte(offerID))
	return h.Sum(nil)
}

// deadlineConn is the subset of network.Stream the PAKE handshake needs. Using
// it (rather than network.Stream) lets the handshake — and a relay-splice MITM
// harness — be exercised over net.Pipe in tests without a full libp2p host.
type deadlineConn interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
}

// safePakeUpdate calls p.Update on attacker-controlled bytes with a recover
// boundary. schollz/pake unmarshals peer JSON into curve coordinates and can
// panic on malformed input (e.g. nil coordinates reaching big.Int arithmetic
// via SIEC IsOnCurve), so a hostile peer must not be able to crash the process
// merely by opening the pairing stream. Panics are converted to errors and the
// caller resets the stream.
func safePakeUpdate(p *pake.Pake, msg []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("libp2p: pake update panicked on hostile input: %v", r)
		}
	}()
	return p.Update(msg)
}

// clientPairHandshake runs the initiator half: PAKE exchange, session-key
// derivation with channel binding, then mutual key confirmation. Returns the
// 32-byte AEAD session key on success.
func clientPairHandshake(s deadlineConn, code string, clientID, offerID peer.ID) ([]byte, error) {
	_ = s.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = s.SetDeadline(time.Time{}) }()

	p, err := pake.InitCurve([]byte(code), 0, pakeCurve) // role 0 = initiator
	if err != nil {
		return nil, fmt.Errorf("libp2p: pake init: %w", err)
	}
	if err := writeFrame(s, p.Bytes()); err != nil { // msg1: client -> offer
		return nil, err
	}
	msg2, err := readFrame(s, maxHandshakeFrame) // msg2: offer -> client
	if err != nil {
		return nil, err
	}
	if err := safePakeUpdate(p, msg2); err != nil {
		return nil, fmt.Errorf("libp2p: pake update: %w", err)
	}
	pakeKey, err := p.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("libp2p: pake session key: %w", err)
	}
	key, err := deriveSessionKey(pakeKey, clientID, offerID)
	if err != nil {
		return nil, err
	}
	// Mutual key confirmation: prove our key, then verify the offer's.
	if err := writeFrame(s, confirmMAC(key, "client", clientID, offerID)); err != nil {
		return nil, err
	}
	confO, err := readFrame(s, 128)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(confO, confirmMAC(key, "offer", clientID, offerID)) {
		return nil, errors.New("offer failed key confirmation (wrong code or MITM)")
	}
	return key, nil
}

// offerPairHandshake runs the responder half.
func offerPairHandshake(s deadlineConn, code string, clientID, offerID peer.ID) ([]byte, error) {
	_ = s.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = s.SetDeadline(time.Time{}) }()

	p, err := pake.InitCurve([]byte(code), 1, pakeCurve) // role 1 = responder
	if err != nil {
		return nil, fmt.Errorf("libp2p: pake init: %w", err)
	}
	msg1, err := readFrame(s, maxHandshakeFrame) // msg1: client -> offer
	if err != nil {
		return nil, err
	}
	if err := safePakeUpdate(p, msg1); err != nil {
		return nil, fmt.Errorf("libp2p: pake update: %w", err)
	}
	if err := writeFrame(s, p.Bytes()); err != nil { // msg2: offer -> client
		return nil, err
	}
	pakeKey, err := p.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("libp2p: pake session key: %w", err)
	}
	key, err := deriveSessionKey(pakeKey, clientID, offerID)
	if err != nil {
		return nil, err
	}
	// Mutual key confirmation: verify the client's, then prove ours.
	confC, err := readFrame(s, 128)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(confC, confirmMAC(key, "client", clientID, offerID)) {
		return nil, errors.New("joiner failed key confirmation (wrong code or MITM)")
	}
	if err := writeFrame(s, confirmMAC(key, "offer", clientID, offerID)); err != nil {
		return nil, err
	}
	return key, nil
}

// offerServe installs the stream handler (PAKE-authenticating each stream, then
// bridging the AEAD-encrypted tunnel to udpTarget) and advertises this node on
// the DHT rendezvous for the code. The code is SINGLE-USE (advertising stops and
// further handshakes are rejected after one successful pairing) and TIME-BOXED
// (honoured for at most pairingWindow). Only the offer advertises; see clientJoin.
func offerServe(ctx context.Context, n *p2pNode, code, udpTarget string) {
	offerID := n.host.ID()

	// advCtx bounds advertising to the pairing window and is cancelled early on a
	// successful pairing (single-use).
	advCtx, advCancel := context.WithTimeout(ctx, pairingWindow)

	var paired atomic.Bool
	sem := make(chan struct{}, maxConcurrentHandshakes)

	n.host.SetStreamHandler(udpProto, func(s network.Stream) {
		// Defence in depth: a hostile peer must not be able to crash the offer
		// by wedging the handshake path. safePakeUpdate already converts the
		// known PAKE-parse panic to an error; this backstops anything else.
		defer func() {
			if r := recover(); r != nil {
				_ = s.Reset()
			}
		}()
		// Concurrency cap: reject when too many handshakes are already in flight.
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			_ = s.Reset()
			return
		}
		// Single-use + window: reject once paired or after the window closes.
		if paired.Load() || advCtx.Err() != nil {
			_ = s.Reset()
			return
		}
		clientID := s.Conn().RemotePeer()
		key, err := offerPairHandshake(s, code, clientID, offerID)
		if err != nil {
			_ = s.Reset()
			return
		}

		// Build the AEAD tunnel and UDP bridge BEFORE consuming the single-use
		// code, so a failure here does not permanently burn a valid pairing.
		pipe, err := udppipe.NewAEADPipe(s, key, dirOfferToClient, dirClientToOffer, []byte(udpProto), udppipe.DefaultMTU)
		if err != nil {
			_ = s.Reset()
			return
		}
		_, stop, err := udppipe.BridgeUDPToPipe(udpTarget, pipe, udppipe.DefaultMTU, nil)
		if err != nil {
			_ = s.Reset()
			return
		}

		// Tunnel is live. NOW consume the code atomically; a losing race (another
		// concurrent authenticated client won) tears down this bridge and resets.
		if !paired.CompareAndSwap(false, true) {
			stop()
			_ = s.Reset()
			return
		}
		advCancel() // stop advertising — code is now single-use-consumed

		// Stop the bridge if the offer's context is cancelled. AfterFunc does not
		// park a goroutine blocked on <-ctx.Done() per stream.
		context.AfterFunc(ctx, stop)
	})

	// Only the OFFER advertises on the rendezvous namespace. If clients also
	// advertised, a joining client could be discovered by (and try to pair with)
	// another client rather than the offer.
	dutil.Advertise(advCtx, n.rd, rendezvousForCode(code))
}

// clientJoin queries the DHT rendezvous for the pairing code and tries each
// discovered candidate in turn — connect, open the tunnel stream, run the PAKE
// handshake — until one authenticates or findTimeout expires. It does NOT
// advertise (only the offer does). The tunnel is AEAD-encrypted under the
// PAKE-derived session key. Returns the remote peer ID, the bound local UDP
// address, and a stop func that tears the bridge down.
func clientJoin(ctx context.Context, n *p2pNode, code, udpLocal string, findTimeout time.Duration) (peer.ID, string, func(), error) {
	rendezvous := rendezvousForCode(code)
	findCtx, cancel := context.WithTimeout(ctx, findTimeout)
	defer cancel()

	tried := make(map[peer.ID]bool)
	for {
		peerCh, err := n.rd.FindPeers(findCtx, rendezvous)
		if err == nil {
			for pi := range peerCh {
				if pi.ID == n.host.ID() || len(pi.Addrs) == 0 || tried[pi.ID] {
					continue
				}
				tried[pi.ID] = true
				// Try this candidate. On any failure — stale record, a decoy,
				// another client, or a peer with the wrong code — move on and
				// keep querying rather than aborting the whole pairing.
				s, key, err := dialAndAuth(ctx, n, pi, code)
				if err != nil {
					continue
				}
				pipe, err := udppipe.NewAEADPipe(s, key, dirClientToOffer, dirOfferToClient, []byte(udpProto), udppipe.DefaultMTU)
				if err != nil {
					_ = s.Reset()
					return "", "", nil, fmt.Errorf("libp2p: aead: %w", err)
				}
				listenAddr, stop, err := udppipe.ListenUDPAndBridge(udpLocal, pipe, udppipe.DefaultMTU, nil)
				if err != nil {
					_ = s.Reset()
					return "", "", nil, fmt.Errorf("libp2p: udp bridge: %w", err)
				}
				cancelAfter := context.AfterFunc(ctx, stop)
				wrapped := func() {
					cancelAfter()
					stop()
				}
				return pi.ID, listenAddr, wrapped, nil
			}
		}
		select {
		case <-findCtx.Done():
			return "", "", nil, fmt.Errorf("libp2p: no matching peer for pairing code: %w", findCtx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// dialAndAuth connects to a candidate, opens the tunnel stream, and runs the
// PAKE handshake. Returns the authenticated stream and the AEAD session key on
// success; on any failure the caller should try the next candidate.
func dialAndAuth(ctx context.Context, n *p2pNode, pi peer.AddrInfo, code string) (network.Stream, []byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if err := n.host.Connect(cctx, pi); err != nil {
		return nil, nil, err
	}
	s, err := n.host.NewStream(cctx, pi.ID, udpProto)
	if err != nil {
		return nil, nil, err
	}
	key, err := clientPairHandshake(s, code, n.host.ID(), pi.ID)
	if err != nil {
		_ = s.Reset()
		return nil, nil, err
	}
	return s, key, nil
}

// ─── Active-session state (single active P2P session at a time) ──────────────

var (
	activeMu    sync.Mutex
	activeClean func()
)

func storeActive(clean func()) {
	activeMu.Lock()
	if activeClean != nil {
		activeClean()
	}
	activeClean = clean
	activeMu.Unlock()
}

func closeActive() {
	activeMu.Lock()
	if activeClean != nil {
		activeClean()
		activeClean = nil
	}
	activeMu.Unlock()
}

// ─── Bootstrap configuration (overridable in tests for hermeticity) ──────────

// bootstrapPeersFn returns the DHT bootstrap peers to dial. Overridable in
// tests to inject a local bootstrap (or none) and avoid public egress.
var bootstrapPeersFn = defaultBootstrapPeers

// enableNATTraversal toggles hole-punching / relay / NAT-PMP. Tests disable it
// to keep nodes loopback-only and hermetic.
var enableNATTraversal = true

// defaultBootstrapPeers returns the public libp2p bootstrap nodes.
func defaultBootstrapPeers() []peer.AddrInfo {
	addrs := []string{
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtb1RNz8h2V7o3G7z",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
	}
	out := make([]peer.AddrInfo, 0, len(addrs))
	for _, s := range addrs {
		m, err := ma.NewMultiaddr(s)
		if err != nil {
			continue
		}
		pi, err := peer.AddrInfoFromP2pAddr(m)
		if err != nil {
			continue
		}
		out = append(out, *pi)
	}
	return out
}

// ConnectLibp2pClientPair is the joiner side invoked by
// `nowifi server client --pair CODE`. It stands up a libp2p node, discovers the
// offering peer through the DHT rendezvous derived from the code, and bridges
// the local UDP socket (udpLocal) to the peer over a libp2p stream.
func ConnectLibp2pClientPair(ctx context.Context, code, udpLocal string) error {
	if udpLocal == "" {
		udpLocal = "127.0.0.1:51821"
	}
	n, err := startNode(ctx, nodeOpts{
		bootstraps:   bootstrapPeersFn(),
		dhtMode:      dht.ModeAuto,
		natTraversal: enableNATTraversal,
	})
	if err != nil {
		return fmt.Errorf("libp2p: start node: %w", err)
	}
	_, _, stop, err := clientJoin(ctx, n, code, udpLocal, 2*time.Minute)
	if err != nil {
		_ = n.dht.Close()
		_ = n.host.Close()
		return err
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			stop()
			_ = n.dht.Close()
			_ = n.host.Close()
		})
	}
	// Full teardown (bridge + DHT + host) both on context cancellation and via
	// Destroy through the active-session slot — not just the bridge.
	context.AfterFunc(ctx, cleanup)
	storeActive(cleanup)
	return nil
}

// ─── Pairing code generator ─────────────────────────────

// bip39Raw is the canonical BIP-39 English wordlist: exactly 2048 unique words
// (sha256 2f5eed53…). 2048 = 2^11, so each word carries 11 bits and a 3-word
// code carries the full documented 33 bits of entropy. The previous inline list
// was only 1043 words (~30 bits, sub-second brute force) — see the #29 review.
//
//go:embed pairing_wordlist.txt
var bip39Raw string

// wordlist is the parsed + validated pairing wordlist.
var wordlist = mustParseWordlist(bip39Raw)

// mustParseWordlist enforces the 2048-unique-word invariant at startup so the
// keyspace can never silently regress below the documented 33 bits again.
func mustParseWordlist(raw string) []string {
	words := strings.Fields(raw)
	if len(words) != 2048 {
		panic(fmt.Sprintf("libp2p: pairing wordlist must be exactly 2048 words, got %d", len(words)))
	}
	seen := make(map[string]struct{}, len(words))
	for _, w := range words {
		if _, dup := seen[w]; dup {
			panic("libp2p: pairing wordlist contains a duplicate: " + w)
		}
		seen[w] = struct{}{}
	}
	return words
}

// generatePairingCode returns a 3-word mnemonic like "abandon-river-oyster".
// 2048-word list -> 11 bits/word -> 33 bits total (~8.6e9 possibilities).
//
// NOTE: 33 bits is LOW entropy. Pairing security does NOT rely on the code
// resisting an offline dictionary attack: it uses a PAKE (clientPairHandshake /
// offerPairHandshake) so each guess costs one online interaction, plus a
// single-use, time-boxed rendezvous. Do not treat the code as a high-entropy
// secret.
func generatePairingCode() string {
	var parts [3]string
	for i := range parts {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		if err != nil {
			// CSPRNG failure is fatal — no pairing code is better than a weak one.
			panic(fmt.Sprintf("libp2p: CSPRNG failed: %v", err))
		}
		parts[i] = wordlist[n.Int64()]
	}
	return strings.Join(parts[:], "-")
}
