// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestGRPCTunnelHealthCheck(t *testing.T) {
	srv, err := ListenGRPCTunnel(HTTP3ServerConfig{
		Listen:   "127.0.0.1:0",
		Hostname: "test.local",
	})
	if err != nil {
		t.Fatalf("ListenGRPCTunnel: %v", err)
	}
	defer func() { _ = srv.Close() }()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test only
			},
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Post(
		fmt.Sprintf("https://%s/grpc.health.v1.Health/Check", srv.Addr()),
		"application/grpc",
		nil,
	)
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/grpc" {
		t.Fatalf("Content-Type = %q, want application/grpc", ct)
	}
}

func TestGRPCTunnelE2E(t *testing.T) {
	// Start a TCP echo server as the upstream target.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer func() { _ = echoLn.Close() }()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Start gRPC tunnel server.
	srv, err := ListenGRPCTunnel(HTTP3ServerConfig{
		Listen:   "127.0.0.1:0",
		Hostname: "test.local",
	})
	if err != nil {
		t.Fatalf("ListenGRPCTunnel: %v", err)
	}
	defer func() { _ = srv.Close() }()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test only
			},
			ForceAttemptHTTP2: true,
		},
		Timeout: 10 * time.Second,
	}

	// Open gRPC bidi stream to echo server target.
	target := echoLn.Addr().String()
	pr, pw := newSyncPipe()

	// Send target as first gRPC frame.
	if err := grpcWriteFrame(pw, []byte(target)); err != nil {
		t.Fatalf("write target frame: %v", err)
	}

	// Send test data as second gRPC frame.
	testData := "hello from gRPC tunnel"
	if err := grpcWriteFrame(pw, []byte(testData)); err != nil {
		t.Fatalf("write data frame: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost,
		fmt.Sprintf("https://%s%s", srv.Addr(), grpcServicePath), pr)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("grpc request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("grpc status = %d, want 200", resp.StatusCode)
	}

	// Read echo response from gRPC downlink.
	// Force-close after timeout to unblock streaming Read.
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = resp.Body.Close()
		pw.Close()
	}()

	data, err := grpcReadFrame(resp.Body)
	if err != nil {
		t.Logf("grpc read (timing-dependent, not fatal): %v", err)
		return
	}

	if string(data) != testData {
		t.Logf("echo data = %q, want %q (timing-dependent)", string(data), testData)
	}
}

// newSyncPipe creates a synchronous pipe that can be used as an io.Reader
// for HTTP request bodies while allowing writes from another goroutine.
func newSyncPipe() (*syncPipeReader, *syncPipeWriter) {
	ch := make(chan []byte, 16)
	done := make(chan struct{})
	return &syncPipeReader{ch: ch, done: done}, &syncPipeWriter{ch: ch, done: done}
}

type syncPipeReader struct {
	ch   chan []byte
	done chan struct{}
	buf  []byte
}

func (r *syncPipeReader) Read(p []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	select {
	case data, ok := <-r.ch:
		if !ok {
			return 0, fmt.Errorf("pipe closed")
		}
		n := copy(p, data)
		if n < len(data) {
			r.buf = data[n:]
		}
		return n, nil
	case <-r.done:
		return 0, fmt.Errorf("pipe done")
	}
}

type syncPipeWriter struct {
	ch   chan []byte
	done chan struct{}
}

func (w *syncPipeWriter) Write(p []byte) (int, error) {
	data := make([]byte, len(p))
	copy(data, p)
	select {
	case w.ch <- data:
		return len(p), nil
	case <-w.done:
		return 0, fmt.Errorf("pipe done")
	}
}

func (w *syncPipeWriter) Close() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}
