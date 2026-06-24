// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package udppipe provides a transport-agnostic UDP ↔ byte-stream bridge.
//
// It extracts the UDP-framing logic from the udpws package so both WebSocket
// (existing) and libp2p stream (new) transports can share the same UDP
// forwarding core.
//
// Each UDP datagram is written as a single frame. The frame boundary IS the
// datagram boundary — no length prefix. Datagrams exceeding the configured
// MTU are truncated with a warning log.
package udppipe

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// DefaultMTU is the maximum datagram payload size in bytes.
const DefaultMTU = 1400

// Stream is the byte-stream interface a transport must implement.
// Each Write call sends exactly one frame; each Read call receives one frame.
// The transport is responsible for message framing.
type Stream interface {
	io.ReadWriteCloser
}

// Bridge couples a UDP socket with a byte Stream, forwarding datagrams in
// both directions.
//
// Usage:
//
//	stream := ... // libp2p stream or WebSocket conn
//	conn, _ := net.ListenUDP("udp", ...)
//	bridge := &udppipe.Bridge{UDPConn: conn, Stream: stream}
//	bridge.Run()
type Bridge struct {
	// UDPConn is the local UDP socket to bridge.
	UDPConn *net.UDPConn

	// Stream is the byte-stream transport.
	Stream Stream

	// MTU caps outbound datagram size. Zero uses DefaultMTU.
	MTU int

	// Logger, if nil uses the standard log package.
	Logger *log.Logger

	// RemoteAddr, if set, is the fixed destination for all UDP→Stream
	// datagrams. When nil (the default for server-side), datagrams are
	// echoed back to whichever peer last sent a UDP datagram.
	RemoteAddr *net.UDPAddr

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

func (b *Bridge) mtu() int {
	if b.MTU > 0 {
		return b.MTU
	}
	return DefaultMTU
}

func (b *Bridge) logf(format string, args ...any) {
	if b.Logger != nil {
		b.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Run starts the bidirectional forward loop. Blocks until Stop is called
// or either side errors. Safe to call exactly once per Bridge.
func (b *Bridge) Run() {
	b.stop = make(chan struct{})
	b.done = make(chan struct{})
	defer close(b.done)

	mtu := b.mtu()

	// lastPeer tracks the most recent UDP sender for server-side echo.
	var lastPeerMu sync.Mutex
	var lastPeer *net.UDPAddr

	// Stream → UDP goroutine.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-b.stop:
				return
			default:
			}

			n, err := b.Stream.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}

			payload := buf[:n]
			if len(payload) > mtu {
				b.logf("udppipe: truncating datagram %d→%d bytes", len(payload), mtu)
				payload = payload[:mtu]
			}

			var target *net.UDPAddr
			if b.RemoteAddr != nil {
				target = b.RemoteAddr
			} else {
				lastPeerMu.Lock()
				target = lastPeer
				lastPeerMu.Unlock()
			}
			if target == nil {
				continue // no peer yet; drop
			}

			if _, err := b.UDPConn.WriteToUDP(payload, target); err != nil {
				return
			}
		}
	}()

	// UDP → Stream (this goroutine).
	buf := make([]byte, 65535)
	for {
		select {
		case <-b.stop:
			wg.Wait()
			return
		default:
		}

		_ = b.UDPConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := b.UDPConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Non-timeout error — close stream and wait for the Stream→UDP
			// goroutine to exit.
			b.Stream.Close()
			wg.Wait()
			return
		}

		lastPeerMu.Lock()
		lastPeer = addr
		lastPeerMu.Unlock()

		payload := buf[:n]
		if len(payload) > mtu {
			b.logf("udppipe: truncating datagram %d→%d bytes", len(payload), mtu)
			payload = payload[:mtu]
		}

		if _, err := b.Stream.Write(payload); err != nil {
			b.Stream.Close()
			wg.Wait()
			return
		}
	}
}

// Stop signals the bridge to stop and blocks until both forwarding loops
// have exited. Safe to call multiple times.
func (b *Bridge) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
	})
	<-b.done
}

// Wait blocks until the bridge has stopped.
func (b *Bridge) Wait() {
	<-b.done
}

// ─── Error types ─────────────────────────────────────────────────────────────

// ErrStreamClosed indicates the byte-stream transport has been closed.
var ErrStreamClosed = fmt.Errorf("udppipe: stream closed")
