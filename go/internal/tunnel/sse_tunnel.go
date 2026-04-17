// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// Wave 22 technique #30 — SSE (Server-Sent Events) streaming tunnel.
//
// Uses Server-Sent Events (text/event-stream, RFC 8895 / W3C EventSource)
// as a covert downlink channel and HTTP POST requests as the uplink. From
// DPI's perspective, the downlink is an infinite chunked HTTP response
// identical to a news ticker, stock feed, or chat notification stream.
// The uplink is a series of ordinary HTTP POST requests.
//
// Key bypass properties:
//   - SSE is standard HTTP/1.1 or HTTP/2 — no exotic protocols.
//   - Every major captive portal allows chunked transfer encoding because
//     blocking it would break all streaming web applications.
//   - Data is base64-encoded in the `data:` field of SSE events, matching
//     the byte distribution of real event payloads.
//   - The Cloudflare Workers variant is serverless: the worker relays SSE
//     events to/from a target, requiring only a free CF account.
//
// Architecture:
//   Downlink: GET /stream → text/event-stream → data: <base64>\n\n
//   Uplink:   POST /send   → body: <base64>
//   Per SOCKS connection: target header in first SSE event, then data flow.
//
// This file implements the client side only.
// ----------------------------------------------------------------------------

// StartSSETunnel opens an SSE streaming connection to the relay server and
// starts a local SOCKS5-lite TCP listener. Each SOCKS connection gets a
// dedicated SSE stream (downlink) and POST channel (uplink).
func StartSSETunnel(serverURL string, localPort int, timeout time.Duration) (*Handle, error) {
	if serverURL == "" {
		return nil, errors.New("sse tunnel: serverURL required")
	}
	if localPort == 0 {
		localPort = 1091
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	// Normalize URL.
	baseURL := strings.TrimRight(serverURL, "/")

	// Probe: verify SSE endpoint responds with event-stream content type.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), timeout)
	defer probeCancel()

	req, err := http.NewRequestWithContext(probeCtx, "GET", baseURL+"/stream?probe=1", nil)
	if err != nil {
		return nil, fmt.Errorf("sse tunnel: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sse tunnel: probe %s: %w", baseURL, err)
	}
	_ = resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK || !strings.Contains(ct, "text/event-stream") {
		return nil, fmt.Errorf("sse tunnel: probe got HTTP %d content-type %q (want text/event-stream)", resp.StatusCode, ct)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("sse tunnel: listen %d: %w", localPort, err)
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "sse_tunnel",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go serveSSEForwarder(listener, baseURL, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
	}
	return h, nil
}

func serveSSEForwarder(l net.Listener, baseURL string, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}
		if tl, ok := l.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(1 * time.Second))
		}
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		go handleSSESocks(conn, baseURL)
	}
}

func handleSSESocks(client net.Conn, baseURL string) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 handshake — shared helper parses greeting + CONNECT request.
	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	// Open SSE downlink stream with target in query parameter.
	streamURL := fmt.Sprintf("%s/stream?target=%s", baseURL, target)
	req, err := http.NewRequest("GET", streamURL, nil)
	if err != nil {
		socks5SendFail(client)
		return
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		socks5SendFail(client)
		return
	}

	// Extract session ID from response header for uplink correlation.
	sessionID := resp.Header.Get("X-Session-Id")
	if sessionID == "" {
		// Fallback: use target as session key.
		sessionID = target
	}

	// SOCKS5 success.
	if err := socks5SendSuccess(client); err != nil {
		_ = resp.Body.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)

	// Downlink: SSE events → base64 decode → client.
	go func() {
		defer func() { done <- struct{}{} }()
		sseReadLoop(resp.Body, client)
	}()

	// Uplink: client → base64 encode → HTTP POST.
	go func() {
		defer func() { done <- struct{}{} }()
		sseWriteLoop(client, baseURL, sessionID)
	}()

	<-done
	_ = resp.Body.Close()
}

// sseReadLoop reads SSE events from the stream body, decodes the base64
// data field, and writes raw bytes to the client.
func sseReadLoop(body io.Reader, client net.Conn) {
	buf := make([]byte, 8192)
	var line strings.Builder

	for {
		n, err := body.Read(buf)
		if n > 0 {
			line.Write(buf[:n])
			// Process complete lines.
			for {
				text := line.String()
				idx := strings.Index(text, "\n")
				if idx < 0 {
					break
				}
				l := strings.TrimRight(text[:idx], "\r")
				line.Reset()
				line.WriteString(text[idx+1:])

				if strings.HasPrefix(l, "data: ") {
					payload := strings.TrimPrefix(l, "data: ")
					decoded, decErr := base64.StdEncoding.DecodeString(payload)
					if decErr == nil && len(decoded) > 0 {
						if _, wErr := client.Write(decoded); wErr != nil {
							return
						}
					}
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// sseWriteLoop reads from the client, base64-encodes chunks, and POSTs
// them to the relay server's uplink endpoint.
func sseWriteLoop(client net.Conn, baseURL, sessionID string) {
	buf := make([]byte, 4096)
	sendURL := fmt.Sprintf("%s/send?session=%s", baseURL, sessionID)

	for {
		n, err := client.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			postReq, _ := http.NewRequest("POST", sendURL, strings.NewReader(encoded))
			postReq.Header.Set("Content-Type", "text/plain")
			resp, postErr := http.DefaultClient.Do(postReq)
			if postErr != nil {
				return
			}
			_ = resp.Body.Close()
		}
		if err != nil {
			return
		}
	}
}
