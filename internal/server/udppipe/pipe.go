// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package udppipe provides a transport-agnostic UDP ↔ byte-stream bridge.
//
// It is the shared core used by both udpws (UDP-over-WebSocket) and the
// future libp2p provider (UDP-over-libp2p-stream).  Both implementations
// feed into the same Pump function; only the byte-stream transport differs.
//
// Architecture:
//
//	┌──────────┐    Pump()    ┌──────────────┐
//	│ net.Conn │◄────────────►│ io.ReadWriter │
//	│  (UDP)   │              │ (WS, libp2p…) │
//	└──────────┘              └──────────────┘
//
// Usage (server side — DialUDP to a target):
//
//	udpConn, _ := net.Dial("udp", target)
//	pipe := udppipe.Pipe{MTU: 1400}
//	pipe.Pump(ctx, udpConn, stream) // blocks until either side closes
//
// Usage (client side — local PacketConn to a remote stream):
//
//	udpConn, _ := net.ListenUDP("udp", addr)
//	pipe := udppipe.Pipe{MTU: 1400}
//	pipe.PumpPacket(ctx, udpConn, stream) // remembers peer, writes back
package udppipe

import (
	"context"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// DefaultMTU is the maximum datagram payload size (bytes).
const DefaultMTU = 1400

// Pipe bridges a UDP connection and a bidirectional byte stream.
//
// Zero value is usable; MTU defaults to DefaultMTU and Logger falls
// through to the standard library log package.
type Pipe struct {
	// MTU caps outbound datagram size.  Zero uses DefaultMTU.
	MTU int

	// Logger, if nil uses the standard log package.
	Logger *log.Logger
}

func (p *Pipe) mtu() int {
	if p.MTU > 0 {
		return p.MTU
	}
	return DefaultMTU
}

func (p *Pipe) logf(format string, args ...any) {
	if p.Logger != nil {
		p.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Pump bridges a connected UDP socket and a byte stream bidirectionally.
//
// It blocks until either side closes, ctx is cancelled, or an unrecoverable
// error occurs.  Both directions are pumped concurrently; when one direction
// exits, the other is shut down.
//
//	udpConn  → stream  (goroutine)
//	stream   → udpConn  (caller goroutine, blocks)
func (p *Pipe) Pump(ctx context.Context, udpConn net.Conn, stream ReadWriteCloser) error {
	mtu := p.mtu()
	done := make(chan struct{})

	// udpConn → stream
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = udpConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := udpConn.Read(buf)
			if err != nil {
				return
			}
			payload := buf[:n]
			if len(payload) > mtu {
				p.logf("udppipe: truncating datagram %d→%d bytes", len(payload), mtu)
				payload = payload[:mtu]
			}
			if _, err := stream.Write(payload); err != nil {
				return
			}
		}
	}()

	// stream → udpConn
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			stream.Close()
			<-done
			return ctx.Err()
		case <-done:
			return nil
		default:
		}
		n, err := stream.Read(buf)
		if err != nil {
			stream.Close()
			<-done
			return err
		}
		if n > mtu {
			p.logf("udppipe: truncating datagram %d→%d bytes", n, mtu)
			n = mtu
		}
		if _, err := udpConn.Write(buf[:n]); err != nil {
			stream.Close()
			<-done
			return err
		}
	}
}

// PumpPacket bridges a PacketConn (connectionless UDP listener) and a
// bidirectional byte stream.  It is the client-side counterpart of Pump:
// incoming UDP datagrams are forwarded to the stream, and the sender address
// of the first datagram is remembered as the "peer" to which stream→UDP
// replies are sent.
//
//	udpConn  → stream  (goroutine, remembers peer)
//	stream   → lastPeer (caller goroutine, blocks)
func (p *Pipe) PumpPacket(ctx context.Context, udpConn net.PacketConn, stream ReadWriteCloser) error {
	mtu := p.mtu()
	done := make(chan struct{})

	// lastPeer is updated atomically by the UDP→stream goroutine and read
	// by the stream→UDP goroutine.
	var lastPeer atomic.Pointer[net.UDPAddr]

	// stream → UDP goroutine: receive from stream, write to last known peer.
	go func() {
		defer close(done)
		for {
			var msg [65535]byte
			n, err := stream.Read(msg[:])
			if err != nil {
				return
			}
			peer := lastPeer.Load()
			if peer == nil {
				continue // no peer yet; drop
			}
			if n > mtu {
				p.logf("udppipe: truncating stream→UDP datagram %d→%d bytes", n, mtu)
				n = mtu
			}
			// WriteTo with *net.UDPAddr
			if _, err := udpConn.(interface {
				WriteTo([]byte, net.Addr) (int, error)
			}).WriteTo(msg[:n], peer); err != nil {
				return
			}
		}
	}()

	// UDP → stream
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			stream.Close()
			<-done
			return ctx.Err()
		case <-done:
			return nil
		default:
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := udpConn.(interface {
			ReadFrom([]byte) (int, net.Addr, error)
		}).ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			stream.Close()
			<-done
			return err
		}
		if addr != nil {
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				lastPeer.Store(udpAddr)
			}
		}
		payload := buf[:n]
		if len(payload) > mtu {
			p.logf("udppipe: truncating UDP→stream datagram %d→%d bytes", len(payload), mtu)
			payload = payload[:mtu]
		}
		if _, err := stream.Write(payload); err != nil {
			stream.Close()
			<-done
			return err
		}
	}
}

// ReadWriteCloser is the minimal byte-stream interface required by Pump
// and PumpPacket.  io.ReadWriteCloser is a common Go interface; we define
// our own to avoid a dependency on a specific transport package.
type ReadWriteCloser interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}
