// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package udpws

import (
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

const (
	reconnectMin = 1 * time.Second
	reconnectMax = 30 * time.Second
)

// Client listens on a local UDP address and tunnels datagrams to/from a
// remote WebSocket endpoint.
//
// The data path is:
//
//	local app  →  UDPListenAddr  →  Client  →  ws://RemoteURL/udp  →  Server  →  target UDP
//
// The client reconnects automatically with exponential backoff (1s→30s) when
// the WebSocket connection is lost.
type Client struct {
	// UDPListenAddr is the local UDP address to listen on (e.g. "127.0.0.1:51820").
	UDPListenAddr string

	// RemoteURL is the WebSocket server URL (e.g. "ws://shiny-river-42.trycloudflare.com/udp").
	RemoteURL string

	// OriginURL is the WebSocket origin header.  Defaults to RemoteURL.
	OriginURL string

	// MTU caps outbound datagram size.  Zero uses DefaultMTU.
	MTU int

	// Logger, if nil uses the standard log package.
	Logger *log.Logger

	stop chan struct{}
}

func (c *Client) mtu() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return DefaultMTU
}

func (c *Client) logf(format string, args ...any) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (c *Client) origin() string {
	if c.OriginURL != "" {
		return c.OriginURL
	}
	return c.RemoteURL
}

// Start binds the local UDP socket and begins tunnelling.  It returns the
// actual listen address (useful when UDPListenAddr is "127.0.0.1:0") and a
// stop function.  Start is non-blocking; the reconnect loop runs in the
// background.
func (c *Client) Start() (listenAddr string, stop func(), err error) {
	udpAddr, err := net.ResolveUDPAddr("udp", c.UDPListenAddr)
	if err != nil {
		return "", nil, fmt.Errorf("udpws client: resolve local addr %s: %w", c.UDPListenAddr, err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", nil, fmt.Errorf("udpws client: listen %s: %w", c.UDPListenAddr, err)
	}

	c.stop = make(chan struct{})
	stopFn := func() {
		close(c.stop)
		_ = udpConn.Close()
	}

	go c.runLoop(udpConn)

	return udpConn.LocalAddr().String(), stopFn, nil
}

// runLoop manages reconnections and the bidirectional pump.
func (c *Client) runLoop(udpConn *net.UDPConn) {
	backoff := reconnectMin
	for {
		select {
		case <-c.stop:
			return
		default:
		}

		ws, err := websocket.Dial(c.RemoteURL, "", c.origin())
		if err != nil {
			c.logf("udpws client: connect %s: %v (retry in %v)", c.RemoteURL, err, backoff)
			select {
			case <-c.stop:
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, reconnectMax)
			continue
		}

		// Connected — reset backoff.
		backoff = reconnectMin
		c.logf("udpws client: connected to %s", c.RemoteURL)
		c.pump(udpConn, ws)
		ws.Close()
		c.logf("udpws client: connection lost, reconnecting in %v", backoff)
	}
}

// pump runs the bidirectional forward loop until either side errors.
func (c *Client) pump(udpConn *net.UDPConn, ws *websocket.Conn) {
	mtu := c.mtu()
	done := make(chan struct{})

	// lastPeer is updated atomically by the UDP→WS goroutine and read by the
	// WS→UDP goroutine.  atomic.Pointer eliminates the data race.
	var lastPeer atomic.Pointer[net.UDPAddr]

	// WS → UDP goroutine: receive from WebSocket, write to last known peer.
	go func() {
		defer close(done)
		for {
			var msg []byte
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				return
			}
			peer := lastPeer.Load()
			if peer == nil {
				continue // no peer yet; drop
			}
			if _, err := udpConn.WriteToUDP(msg, peer); err != nil {
				return
			}
		}
	}()

	// UDP → WS: receive from local UDP clients, remember the sender address.
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.stop:
			ws.Close()
			<-done
			return
		case <-done:
			return
		default:
		}

		_ = udpConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			ws.Close()
			<-done
			return
		}
		lastPeer.Store(addr)

		payload := buf[:n]
		if len(payload) > mtu {
			c.logf("udpws client: truncating datagram %d→%d bytes", len(payload), mtu)
			payload = payload[:mtu]
		}
		if err := websocket.Message.Send(ws, payload); err != nil {
			ws.Close()
			<-done
			return
		}
	}
}

// min returns the smaller of a and b.
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
