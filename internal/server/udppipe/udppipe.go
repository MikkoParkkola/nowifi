// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package udppipe provides a transport-neutral UDP datagram bridge.
//
// It extracts the framing/pump logic that was previously duplicated in
// the udpws package so that both WebSocket (legacy) and libp2p stream
// (new) transports can reuse the exact same UDP <-> datagram pump code.
//
// DatagramPipe is the abstraction: a bidirectional message-oriented
// transport where each Send/Recv corresponds to one UDP datagram.
// Implementations supply framing when the underlying transport is a
// byte stream (e.g. length-prefixed over libp2p).
package udppipe

import (
	"fmt"
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

	// local UDP -> pipe
	go func() {
		defer stopFn()
		buf := make([]byte, 65535)
		for {
			n, _, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
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
			// Write back to whoever sent last is not required; for tunnel we just forward.
			// In practice the udp socket can Write to last remote, but here we assume the
			// app is bound and we forward regardless of src (same as original udpws client).
			if _, err := ln.Write(msg); err != nil {
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
	return &lenPrefixPipe{rw: rw, mtu: mtu}
}

type lenPrefixPipe struct {
	rw  interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
	mtu int
}

func (p *lenPrefixPipe) Send(b []byte) error {
	if len(b) > p.mtu {
		b = b[:p.mtu]
	}
	hdr := []byte{byte(len(b) >> 8), byte(len(b))}
	if _, err := p.rw.Write(hdr); err != nil {
		return err
	}
	_, err := p.rw.Write(b)
	return err
}

func (p *lenPrefixPipe) Recv() ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := p.rw.Read(hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n > p.mtu || n < 0 {
		n = p.mtu
	}
	buf := make([]byte, n)
	if _, err := p.rw.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (p *lenPrefixPipe) Close() error {
	return p.rw.Close()
}
