// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package udppipe provides a transport-neutral UDP datagram bridge.
//
// It carries the framing/pump logic used by the libp2p stream transport
// (the udpws WebSocket provider has its own separate pump). DatagramPipe lets
// any byte-stream or message transport reuse the same UDP <-> datagram pumps.
//
// Concurrency: a DatagramPipe supports one concurrent Send and one concurrent
// Recv (the two bridge pumps). lenPrefixPipe additionally serialises Send with
// an internal lock, but callers should not assume other implementations do.
//
// DatagramPipe is the abstraction: a bidirectional message-oriented
// transport where each Send/Recv corresponds to one UDP datagram.
// Implementations supply framing when the underlying transport is a
// byte stream (e.g. length-prefixed over libp2p).
package udppipe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// DefaultMTU is the maximum datagram payload size (bytes).
const DefaultMTU = 1400

// DatagramPipe is a message-oriented pipe. Each Send/Recv carries
// exactly one datagram (no internal length prefix assumed; the
// implementation of the pipe is responsible for any framing).
type DatagramPipe interface {
	Send([]byte) error
	Recv() ([]byte, error)
	Close() error
}

// BridgeUDPToPipe dials (or listens if udpTarget looks like a listen? No:
// it always dials the target as client of the UDP side) the UDP target
// and pumps datagrams to/from the supplied pipe.
//
// It returns the local UDP address it bound (useful for :0) and a
// stop func that closes the UDP side and the pipe.
//
// This is the shared pump used by both udpws and libp2p providers.
func BridgeUDPToPipe(udpTarget string, pipe DatagramPipe, mtu int, logger *log.Logger) (listenAddr string, stop func(), err error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	udpAddr, err := net.ResolveUDPAddr("udp", udpTarget)
	if err != nil {
		return "", nil, fmt.Errorf("udppipe: resolve target %s: %w", udpTarget, err)
	}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return "", nil, fmt.Errorf("udppipe: dial %s: %w", udpTarget, err)
	}
	la := udpConn.LocalAddr().String()

	done := make(chan struct{})
	var once sync.Once
	stopFn := func() {
		once.Do(func() {
			_ = udpConn.Close()
			_ = pipe.Close()
			close(done)
		})
	}

	// UDP -> pipe (use Read because DialUDP makes it connected)
	go func() {
		defer stopFn()
		buf := make([]byte, 65535)
		for {
			n, err := udpConn.Read(buf)
			if err != nil {
				return
			}
			payload := buf[:n]
			if len(payload) > mtu {
				if logger != nil {
					logger.Printf("udppipe: truncating datagram %d>%d", len(payload), mtu)
				}
				payload = payload[:mtu]
			}
			if err := pipe.Send(payload); err != nil {
				return
			}
		}
	}()

	// pipe -> UDP
	go func() {
		defer stopFn()
		for {
			msg, err := pipe.Recv()
			if err != nil {
				return
			}
			if len(msg) > mtu {
				if logger != nil {
					logger.Printf("udppipe: truncating datagram %d>%d", len(msg), mtu)
				}
				msg = msg[:mtu]
			}
			if _, err := udpConn.Write(msg); err != nil {
				return
			}
		}
	}()

	return la, stopFn, nil
}

// ListenUDPAndBridge is used by the "local UDP listener" side (client role):
// it binds a local UDP port, and pumps every datagram to/from the pipe.
// Returns the bound listen addr and stop.
func ListenUDPAndBridge(udpListen string, pipe DatagramPipe, mtu int, logger *log.Logger) (listenAddr string, stop func(), err error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	udpAddr, err := net.ResolveUDPAddr("udp", udpListen)
	if err != nil {
		return "", nil, fmt.Errorf("udppipe: resolve listen %s: %w", udpListen, err)
	}
	ln, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", nil, fmt.Errorf("udppipe: listen %s: %w", udpListen, err)
	}
	la := ln.LocalAddr().String()

	done := make(chan struct{})
	var once sync.Once
	stopFn := func() {
		once.Do(func() {
			_ = ln.Close()
			_ = pipe.Close()
			close(done)
		})
	}

	// The listening socket is unconnected, so return datagrams must be written
	// back to a specific address with WriteToUDP. We track the last source the
	// local app sent from and reply there (the standard "UDP tunnel endpoint"
	// pattern). A plain ln.Write on an unconnected socket fails with
	// "destination address required", which would silently break the return
	// path — so guard on having seen a peer first.
	var (
		peerMu   sync.Mutex
		peerAddr *net.UDPAddr
	)

	// local UDP -> pipe
	go func() {
		defer stopFn()
		buf := make([]byte, 65535)
		for {
			n, src, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if src != nil {
				peerMu.Lock()
				peerAddr = src
				peerMu.Unlock()
			}
			payload := buf[:n]
			if len(payload) > mtu {
				if logger != nil {
					logger.Printf("udppipe: trunc %d>%d", len(payload), mtu)
				}
				payload = payload[:mtu]
			}
			if err := pipe.Send(payload); err != nil {
				return
			}
		}
	}()

	// pipe -> local UDP
	go func() {
		defer stopFn()
		for {
			msg, err := pipe.Recv()
			if err != nil {
				return
			}
			if len(msg) > mtu {
				if logger != nil {
					logger.Printf("udppipe: trunc %d>%d", len(msg), mtu)
				}
				msg = msg[:mtu]
			}
			peerMu.Lock()
			dst := peerAddr
			peerMu.Unlock()
			if dst == nil {
				// No local app has sent yet, so we have no return address.
				// Drop until the app initiates (it always sends first).
				if logger != nil {
					logger.Printf("udppipe: dropping return datagram; no local peer yet")
				}
				continue
			}
			if _, err := ln.WriteToUDP(msg, dst); err != nil {
				return
			}
		}
	}()

	return la, stopFn, nil
}

// NewLenPrefixPipe wraps a byte-oriented io.ReadWriteCloser (e.g. libp2p stream)
// into a DatagramPipe using 2-byte big-endian length prefix.
// This supplies the message framing that WS gets for free.
func NewLenPrefixPipe(rw interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}, mtu int) DatagramPipe {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	// The length prefix is 2 bytes, so a frame cannot exceed 65535 bytes.
	// Clamp rather than let a larger MTU silently wrap the prefix.
	if mtu > 65535 {
		mtu = 65535
	}
	return &lenPrefixPipe{rw: rw, mtu: mtu}
}

type lenPrefixPipe struct {
	rw interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
	mtu    int
	sendMu sync.Mutex
}

func (p *lenPrefixPipe) Send(b []byte) error {
	if len(b) > p.mtu {
		b = b[:p.mtu]
	}
	// Build the whole frame (2-byte length prefix + payload) in one buffer and
	// write it under a lock so a header is never split from its payload and
	// concurrent Send calls cannot interleave frames on the wire.
	frame := make([]byte, 2+len(b))
	frame[0] = byte(len(b) >> 8)
	frame[1] = byte(len(b))
	copy(frame[2:], b)
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return writeAll(p.rw, frame)
}

func (p *lenPrefixPipe) Recv() ([]byte, error) {
	// io.ReadFull is required: the underlying transport is a byte stream, so a
	// single Read may return a partial frame. Reading fewer bytes than the
	// length prefix promises would desync all subsequent frames.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(p.rw, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n > p.mtu {
		// A frame larger than the negotiated MTU is a protocol violation
		// (peer bug or hostile). Truncating and reading only mtu bytes would
		// leave the rest of the payload in the stream and desync every
		// subsequent frame, so fail the pipe instead.
		return nil, fmt.Errorf("udppipe: frame length %d exceeds mtu %d", n, p.mtu)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(p.rw, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeAll writes all of b, looping over short writes (io.Writer is permitted
// to write fewer bytes than requested and return a nil error).
func writeAll(w interface {
	Write([]byte) (int, error)
}, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return fmt.Errorf("udppipe: writer returned %d with nil error", n)
		}
		b = b[n:]
	}
	return nil
}

func (p *lenPrefixPipe) Close() error {
	return p.rw.Close()
}

// ─── AEAD datagram pipe (authenticated encryption over a byte stream) ─────────

// aeadPipe wraps a reliable, ordered byte stream (e.g. a libp2p stream) with
// per-datagram AES-256-GCM. Each datagram is sealed under a deterministic nonce
// (a per-direction tag + a monotonic counter) so no nonce is ever reused for a
// given key, and no nonce is sent on the wire. It relies on the underlying
// transport being reliable + in-order (libp2p streams are); a dropped or
// reordered frame desyncs the counter and every subsequent Open fails closed.
//
// This is the channel binding that defeats a relay-splice MITM: a relayer that
// does not hold the session key can neither decrypt (Open fails) nor inject
// (forged tag fails) tunnel datagrams.
type aeadPipe struct {
	rw interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
	aead    cipher.AEAD
	aad     []byte
	mtu     int
	sendDir byte
	recvDir byte
	sendCtr uint64
	recvCtr uint64
	sendMu  sync.Mutex
}

// NewAEADPipe builds an authenticated-encryption DatagramPipe over rw using a
// 32-byte key (AES-256-GCM). sendDir/recvDir MUST differ between the two peers'
// send directions (each peer's sendDir is the other's recvDir) so the two
// directions occupy disjoint nonce spaces. aad is bound into every frame.
func NewAEADPipe(rw interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}, key []byte, sendDir, recvDir byte, aad []byte, mtu int) (DatagramPipe, error) {
	if sendDir == recvDir {
		return nil, fmt.Errorf("udppipe: sendDir and recvDir must differ")
	}
	block, err := aes.NewCipher(key) // key must be 16/24/32 bytes; we pass 32
	if err != nil {
		return nil, fmt.Errorf("udppipe: aead cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("udppipe: aead gcm: %w", err)
	}
	if mtu <= 0 || mtu > 65535 {
		mtu = DefaultMTU
	}
	return &aeadPipe{rw: rw, aead: gcm, aad: aad, mtu: mtu, sendDir: sendDir, recvDir: recvDir}, nil
}

func (p *aeadPipe) nonce(dir byte, ctr uint64) []byte {
	n := make([]byte, p.aead.NonceSize()) // 12 for GCM
	n[0] = dir
	binary.BigEndian.PutUint64(n[len(n)-8:], ctr)
	return n
}

func (p *aeadPipe) Send(b []byte) error {
	if len(b) > p.mtu {
		b = b[:p.mtu]
	}
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	ct := p.aead.Seal(nil, p.nonce(p.sendDir, p.sendCtr), b, p.aad)
	p.sendCtr++
	if len(ct) > 65535 {
		return fmt.Errorf("udppipe: aead frame %d too large", len(ct))
	}
	frame := make([]byte, 2+len(ct))
	frame[0] = byte(len(ct) >> 8)
	frame[1] = byte(len(ct))
	copy(frame[2:], ct)
	return writeAll(p.rw, frame)
}

func (p *aeadPipe) Recv() ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(p.rw, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	ct := make([]byte, n)
	if _, err := io.ReadFull(p.rw, ct); err != nil {
		return nil, err
	}
	pt, err := p.aead.Open(nil, p.nonce(p.recvDir, p.recvCtr), ct, p.aad)
	if err != nil {
		// Tampered, injected, or out-of-order frame: fail closed. Do not advance
		// the counter — the stream is unusable once this happens.
		return nil, fmt.Errorf("udppipe: aead open failed (tampered/injected frame): %w", err)
	}
	p.recvCtr++
	return pt, nil
}

func (p *aeadPipe) Close() error {
	return p.rw.Close()
}
