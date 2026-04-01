// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package guard

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"
)

// mockCloser is a test double for io.Closer that tracks Close() calls.
type mockCloser struct {
	closed    bool
	closeErr  error
	mu        sync.Mutex
}

func (m *mockCloser) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeErr
}

func (m *mockCloser) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// Compile-time check.
var _ io.Closer = (*mockCloser)(nil)

func TestNew(t *testing.T) {
	// New captures the current MAC. On a test machine without en0 configured,
	// the MAC may be empty, but the guard should still be created.
	g := New("en0")
	if g == nil {
		t.Fatal("New returned nil")
	}
	if g.iface != "en0" {
		t.Errorf("iface = %q, want %q", g.iface, "en0")
	}
	if g.restored {
		t.Error("new guard should not be restored")
	}
}

func TestGuard_Interface(t *testing.T) {
	g := &Guard{iface: "en1"}
	if got := g.Interface(); got != "en1" {
		t.Errorf("Interface() = %q, want %q", got, "en1")
	}
}

func TestGuard_OriginalMAC(t *testing.T) {
	g := &Guard{originalMAC: "aa:bb:cc:dd:ee:ff"}
	if got := g.OriginalMAC(); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("OriginalMAC() = %q, want %q", got, "aa:bb:cc:dd:ee:ff")
	}
}

func TestRegisterTunnel(t *testing.T) {
	g := &Guard{
		iface: "en0",
		sigCh: make(chan os.Signal, 1),
	}

	t1 := &mockCloser{}
	t2 := &mockCloser{}

	g.RegisterTunnel(t1)
	g.RegisterTunnel(t2)

	g.mu.Lock()
	count := len(g.tunnels)
	g.mu.Unlock()

	if count != 2 {
		t.Errorf("tunnel count = %d, want 2", count)
	}
}

func TestRegisterTunnel_Concurrent(t *testing.T) {
	g := &Guard{
		iface: "en0",
		sigCh: make(chan os.Signal, 1),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.RegisterTunnel(&mockCloser{})
		}()
	}
	wg.Wait()

	g.mu.Lock()
	count := len(g.tunnels)
	g.mu.Unlock()

	if count != 100 {
		t.Errorf("tunnel count = %d, want 100", count)
	}
}

func TestRestore_Idempotent(t *testing.T) {
	// Create a guard with a known state. Use empty originalMAC so it
	// does not attempt actual MAC restore.
	g := &Guard{
		iface:       "en0",
		originalMAC: "",
		sigCh:       make(chan os.Signal, 1),
	}

	tunnel := &mockCloser{}
	g.RegisterTunnel(tunnel)

	// First restore.
	g.Restore()

	if !tunnel.isClosed() {
		t.Error("tunnel should be closed after first Restore()")
	}

	if !g.restored {
		t.Error("guard should be marked as restored")
	}

	// Register another tunnel after restore.
	t2 := &mockCloser{}
	g.RegisterTunnel(t2)

	// Second restore should be a no-op.
	g.Restore()

	if t2.isClosed() {
		t.Error("second tunnel should NOT be closed (Restore is idempotent)")
	}
}

func TestRestore_StopsAllTunnels(t *testing.T) {
	g := &Guard{
		iface:       "en0",
		originalMAC: "",
		sigCh:       make(chan os.Signal, 1),
	}

	tunnels := make([]*mockCloser, 5)
	for i := range tunnels {
		tunnels[i] = &mockCloser{}
		g.RegisterTunnel(tunnels[i])
	}

	g.Restore()

	for i, tun := range tunnels {
		if !tun.isClosed() {
			t.Errorf("tunnel[%d] not closed after Restore()", i)
		}
	}
}

func TestRestore_TunnelCloseError(t *testing.T) {
	g := &Guard{
		iface:       "en0",
		originalMAC: "",
		sigCh:       make(chan os.Signal, 1),
	}

	failing := &mockCloser{closeErr: errors.New("process already exited")}
	ok := &mockCloser{}

	g.RegisterTunnel(failing)
	g.RegisterTunnel(ok)

	// Restore should not panic even if a tunnel Close() fails.
	g.Restore()

	if !failing.isClosed() {
		t.Error("failing tunnel should have Close() called")
	}
	if !ok.isClosed() {
		t.Error("ok tunnel should have Close() called despite previous error")
	}
}

func TestRestore_ConcurrentCalls(t *testing.T) {
	g := &Guard{
		iface:       "en0",
		originalMAC: "",
		sigCh:       make(chan os.Signal, 1),
	}

	tunnel := &mockCloser{}
	g.RegisterTunnel(tunnel)

	// Call Restore from multiple goroutines simultaneously.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Restore()
		}()
	}
	wg.Wait()

	if !tunnel.isClosed() {
		t.Error("tunnel should be closed")
	}
	if !g.restored {
		t.Error("guard should be marked restored")
	}
}
