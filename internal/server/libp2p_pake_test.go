// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/MikkoParkkola/nowifi/internal/server/udppipe"
)

// Two fixed, distinct peer IDs. The PAKE channel binding folds both IDs into the
// session key on each side identically, so any consistent values work here — a
// full libp2p host is unnecessary for the crypto tests.
var (
	testClientID = peer.ID("client-peer-id-aaaaaaaaaaaaaaaa")
	testOfferID  = peer.ID("offer-peer-id-bbbbbbbbbbbbbbbb")
)

// runHandshakePair drives both handshake halves concurrently over the given
// duplex connections and returns their derived keys and errors.
func runHandshakePair(clientConn, offerConn deadlineConn, clientCode, offerCode string) (clientKey, offerKey []byte, clientErr, offerErr error) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		offerKey, offerErr = offerPairHandshake(offerConn, offerCode, testClientID, testOfferID)
	}()
	go func() {
		defer wg.Done()
		clientKey, clientErr = clientPairHandshake(clientConn, clientCode, testClientID, testOfferID)
	}()
	wg.Wait()
	return
}

// TestPAKE_MatchingCodeAgrees proves the happy path: with the same code, both
// halves complete key confirmation and derive an identical 32-byte session key.
func TestPAKE_MatchingCodeAgrees(t *testing.T) {
	clientConn, offerConn := net.Pipe()
	defer func() { _ = clientConn.Close(); _ = offerConn.Close() }()

	code := "abandon-river-oyster"
	ck, ok, cerr, oerr := runHandshakePair(clientConn, offerConn, code, code)
	if cerr != nil || oerr != nil {
		t.Fatalf("handshake failed: client=%v offer=%v", cerr, oerr)
	}
	if len(ck) != 32 || len(ok) != 32 {
		t.Fatalf("expected 32-byte keys, got client=%d offer=%d", len(ck), len(ok))
	}
	if !bytes.Equal(ck, ok) {
		t.Fatalf("session keys disagree despite matching code")
	}
}

// TestPAKE_WrongCodeFailsKeyConfirmation proves the PAKE property that matters
// for a low-entropy code: a wrong guess costs exactly ONE online interaction and
// fails closed at key confirmation — it never yields a usable key, and (unlike
// the old SHA256 scheme) leaks nothing that enables an offline dictionary attack.
func TestPAKE_WrongCodeFailsKeyConfirmation(t *testing.T) {
	clientConn, offerConn := net.Pipe()
	defer func() { _ = clientConn.Close(); _ = offerConn.Close() }()

	ck, ok, cerr, oerr := runHandshakePair(clientConn, offerConn, "right-code-here", "wrong-code-here")
	if cerr == nil {
		t.Fatalf("client accepted a wrong-code peer (key=%x)", ck)
	}
	if oerr == nil {
		t.Fatalf("offer accepted a wrong-code peer (key=%x)", ok)
	}
}

// TestPAKE_MalformedInputReturnsErrorNotPanic proves a hostile peer cannot crash
// the offer by opening the pairing stream and sending malformed PAKE bytes. The
// schollz/pake parser can panic on coordinate-missing input (nil big.Int through
// SIEC IsOnCurve); safePakeUpdate must convert that to an error so the stream is
// reset rather than the process aborted.
func TestPAKE_MalformedInputReturnsErrorNotPanic(t *testing.T) {
	offerConn, attackerConn := net.Pipe()
	defer func() { _ = offerConn.Close(); _ = attackerConn.Close() }()

	errCh := make(chan error, 1)
	go func() {
		_, err := offerPairHandshake(offerConn, "some-code", testClientID, testOfferID)
		errCh <- err
	}()

	// A role-correct object with no curve coordinates — the panic vector the
	// adversarial review identified.
	payload := []byte(`{"Role":0}`)
	go func() {
		_, _ = attackerConn.Write([]byte{byte(len(payload) >> 8), byte(len(payload))})
		_, _ = attackerConn.Write(payload)
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected an error on malformed PAKE input, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("offerPairHandshake hung on malformed input")
	}
}

// recordingRelay is a transparent man-in-the-middle: it forwards every byte in
// one direction and records a copy of the ciphertext/handshake bytes it carried.
func recordingRelay(dst io.Writer, src io.Reader, rec *bytes.Buffer, mu *sync.Mutex) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			mu.Lock()
			rec.Write(buf[:n])
			mu.Unlock()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// TestPAKE_RelaySpliceMITMCannotReadTunnel is the decisive channel-binding test.
//
// A relay-splice MITM sits between two legitimate peers and forwards the whole
// PAKE handshake verbatim (the strongest passive/relaying position: it cannot
// inject its own PAKE messages without being detected by key confirmation, so it
// simply relays). Because it holds no code and runs no PAKE of its own, it never
// obtains the session key. This test proves:
//
//  1. the two legit peers still agree on a key through the relay, and
//  2. the tunnel ciphertext the relay faithfully carried is UNREADABLE to it —
//     an attacker with any key other than the session key cannot Open a frame.
func TestPAKE_RelaySpliceMITMCannotReadTunnel(t *testing.T) {
	// client <-pipeC-> MITM <-pipeO-> offer
	clientConn, mitmC := net.Pipe()
	mitmO, offerConn := net.Pipe()
	defer func() {
		_ = clientConn.Close()
		_ = mitmC.Close()
		_ = mitmO.Close()
		_ = offerConn.Close()
	}()

	var mu sync.Mutex
	var c2o, o2c bytes.Buffer                  // ciphertext the MITM observed, per direction
	go recordingRelay(mitmO, mitmC, &c2o, &mu) // client -> offer
	go recordingRelay(mitmC, mitmO, &o2c, &mu) // offer -> client

	code := "abandon-river-oyster"
	ck, ok, cerr, oerr := runHandshakePair(clientConn, offerConn, code, code)
	if cerr != nil || oerr != nil {
		t.Fatalf("handshake through relay failed: client=%v offer=%v", cerr, oerr)
	}
	if !bytes.Equal(ck, ok) {
		t.Fatalf("legit peers disagree on key despite faithful relay")
	}

	// Drop the recorded handshake bytes so `observed` below is exactly the tunnel
	// ciphertext frame the MITM relayed — nothing else.
	mu.Lock()
	c2o.Reset()
	mu.Unlock()

	aad := []byte(udpProto)
	clientPipe, err := udppipe.NewAEADPipe(clientConn, ck, dirClientToOffer, dirOfferToClient, aad, udppipe.DefaultMTU)
	if err != nil {
		t.Fatalf("client aead: %v", err)
	}
	offerPipe, err := udppipe.NewAEADPipe(offerConn, ok, dirOfferToClient, dirClientToOffer, aad, udppipe.DefaultMTU)
	if err != nil {
		t.Fatalf("offer aead: %v", err)
	}

	secret := []byte("top-secret-tunnel-payload-42")
	recvErr := make(chan error, 1)
	recvGot := make(chan []byte, 1)
	go func() {
		got, err := offerPipe.Recv()
		if err != nil {
			recvErr <- err
			return
		}
		recvGot <- got
	}()
	if err := clientPipe.Send(secret); err != nil {
		t.Fatalf("client send: %v", err)
	}
	select {
	case got := <-recvGot:
		if !bytes.Equal(got, secret) {
			t.Fatalf("tunnel corrupted through relay: got %q want %q", got, secret)
		}
	case err := <-recvErr:
		t.Fatalf("offer recv failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel datagram never arrived through relay")
	}

	// The MITM faithfully carried the ciphertext; prove it is unreadable. Build
	// the same AEAD as the offer's receive side but with a WRONG key (the best a
	// key-less attacker can do), and try to Open the observed frame.
	mu.Lock()
	observed := append([]byte(nil), c2o.Bytes()...)
	mu.Unlock()
	if len(observed) < 3 {
		t.Fatalf("expected the relay to observe a ciphertext frame, got %d bytes", len(observed))
	}

	var wrongKey [32]byte
	if _, err := crand.Read(wrongKey[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	attackerRecv, attackerSend := net.Pipe()
	defer func() { _ = attackerRecv.Close(); _ = attackerSend.Close() }()
	attackerPipe, err := udppipe.NewAEADPipe(attackerRecv, wrongKey[:], dirOfferToClient, dirClientToOffer, aad, udppipe.DefaultMTU)
	if err != nil {
		t.Fatalf("attacker aead: %v", err)
	}
	go func() { _, _ = attackerSend.Write(observed) }()
	if pt, err := attackerPipe.Recv(); err == nil {
		t.Fatalf("MITM decrypted the tunnel without the session key: recovered %q", pt)
	}
}

// TestAEADPipe_RejectsWrongKeyForgeryAndReplay proves the tunnel cannot be
// injected into: a frame sealed under a different key is rejected, a bit-flipped
// frame is rejected, and replaying a valid frame is rejected (the receive
// counter has advanced). Together with the read test above, this is the full
// "key-less relayer can neither read nor inject" property.
func TestAEADPipe_RejectsWrongKeyForgeryAndReplay(t *testing.T) {
	aad := []byte(udpProto)
	var realKey, otherKey [32]byte
	if _, err := crand.Read(realKey[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := crand.Read(otherKey[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Wrong-key injection: attacker seals under otherKey; receiver keyed with
	// realKey must reject on Open.
	{
		rConn, sConn := net.Pipe()
		defer func() { _ = rConn.Close(); _ = sConn.Close() }()
		recv, err := udppipe.NewAEADPipe(rConn, realKey[:], dirOfferToClient, dirClientToOffer, aad, udppipe.DefaultMTU)
		if err != nil {
			t.Fatalf("recv aead: %v", err)
		}
		forger, err := udppipe.NewAEADPipe(sConn, otherKey[:], dirClientToOffer, dirOfferToClient, aad, udppipe.DefaultMTU)
		if err != nil {
			t.Fatalf("forger aead: %v", err)
		}
		go func() { _ = forger.Send([]byte("forged-injection")) }()
		if pt, err := recv.Recv(); err == nil {
			t.Fatalf("receiver accepted a wrong-key frame: %q", pt)
		}
	}

	// Capture one valid frame's wire bytes (sealed at sendCtr=0) for the tamper
	// and replay sub-tests below.
	captureR, captureW := net.Pipe()
	sender, err := udppipe.NewAEADPipe(captureW, realKey[:], dirClientToOffer, dirOfferToClient, aad, udppipe.DefaultMTU)
	if err != nil {
		t.Fatalf("sender aead: %v", err)
	}
	framed := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := captureR.Read(buf)
		framed <- append([]byte(nil), buf[:n]...)
	}()
	go func() { _ = sender.Send([]byte("legit-datagram")) }()
	frame := <-framed
	_ = captureR.Close()
	_ = captureW.Close()
	if len(frame) < 3 {
		t.Fatalf("captured frame too short: %d", len(frame))
	}

	// Bit-flip tamper: a single flipped byte must be rejected by the AEAD tag.
	{
		rConn, sConn := net.Pipe()
		defer func() { _ = rConn.Close(); _ = sConn.Close() }()
		// Receiver's recvDir is dirClientToOffer, matching the sender's sendDir.
		recv, err := udppipe.NewAEADPipe(rConn, realKey[:], dirOfferToClient, dirClientToOffer, aad, udppipe.DefaultMTU)
		if err != nil {
			t.Fatalf("recv aead: %v", err)
		}
		tampered := append([]byte(nil), frame...)
		tampered[len(tampered)-1] ^= 0x01
		go func() { _, _ = sConn.Write(tampered) }()
		if pt, err := recv.Recv(); err == nil {
			t.Fatalf("receiver accepted a bit-flipped frame: %q", pt)
		}
	}

	// Replay: the SAME valid frame accepted once (recvCtr 0->1) must be rejected
	// on a second delivery, because the per-direction nonce counter has advanced
	// and no longer matches the frame sealed at counter 0.
	{
		rConn, sConn := net.Pipe()
		defer func() { _ = rConn.Close(); _ = sConn.Close() }()
		recv, err := udppipe.NewAEADPipe(rConn, realKey[:], dirOfferToClient, dirClientToOffer, aad, udppipe.DefaultMTU)
		if err != nil {
			t.Fatalf("recv aead: %v", err)
		}
		go func() {
			_, _ = sConn.Write(frame) // first delivery: valid
			_, _ = sConn.Write(frame) // second delivery: replay
		}()
		if got, err := recv.Recv(); err != nil {
			t.Fatalf("first (valid) delivery rejected: %v", err)
		} else if string(got) != "legit-datagram" {
			t.Fatalf("first delivery payload mismatch: %q", got)
		}
		if pt, err := recv.Recv(); err == nil {
			t.Fatalf("receiver accepted a replayed frame: %q", pt)
		}
	}
}
