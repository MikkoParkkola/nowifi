// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package guard

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// mockCloser is a test double for io.Closer that tracks Close() calls.
type mockCloser struct {
	closed   bool
	closeErr error
	mu       sync.Mutex
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

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe(): %v", err)
	}

	os.Stderr = w
	fn()
	os.Stderr = origStderr

	if err := w.Close(); err != nil {
		t.Fatalf("Close(stderr writer): %v", err)
	}

	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll(stderr): %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close(stderr reader): %v", err)
	}

	return string(output)
}

func TestNew(t *testing.T) {
	// New captures the current MAC. On a test machine without en0 configured,
	// the MAC may be empty, but the guard should still be created.
	g, err := New("en0")
	if g == nil {
		t.Fatal("New returned nil")
	}
	if err != nil && g.originalMAC != "" {
		t.Fatalf("New returned originalMAC %q with error %v", g.originalMAC, err)
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

func TestRegisterStealth(t *testing.T) {
	g := &Guard{
		iface: "en0",
		sigCh: make(chan os.Signal, 1),
	}

	if g.stealthState != nil {
		t.Fatal("stealthState should be nil initially")
	}

	state := &platform.StealthState{
		OriginalTTL:  64,
		PFRulesAdded: true,
		PFWasEnabled: false,
	}
	g.RegisterStealth(state)

	g.mu.Lock()
	got := g.stealthState
	g.mu.Unlock()

	if got != state {
		t.Error("stealthState not stored")
	}
	if got.OriginalTTL != 64 {
		t.Errorf("OriginalTTL = %d, want 64", got.OriginalTTL)
	}
}

func TestRegisterStealth_Overwrite(t *testing.T) {
	g := &Guard{
		iface: "en0",
		sigCh: make(chan os.Signal, 1),
	}

	state1 := &platform.StealthState{OriginalTTL: 64}
	state2 := &platform.StealthState{OriginalTTL: 128}

	g.RegisterStealth(state1)
	g.RegisterStealth(state2)

	g.mu.Lock()
	got := g.stealthState
	g.mu.Unlock()

	if got != state2 {
		t.Error("stealthState should be overwritten to state2")
	}
}

func TestStartSignalHandler_NoPanic(t *testing.T) {
	g := &Guard{
		iface: "en0",
		sigCh: make(chan os.Signal, 1),
	}

	// StartSignalHandler should not panic.
	g.StartSignalHandler()

	// Clean up: stop signal notification and drain channel.
	signal.Stop(g.sigCh)
}

func TestNew_EmptyInterface(t *testing.T) {
	// New with empty interface should still create a guard.
	g, err := New("")
	if g == nil {
		t.Fatal("New('') returned nil")
	}
	if err != nil && g.originalMAC != "" {
		t.Fatalf("New returned originalMAC %q with error %v", g.originalMAC, err)
	}
	if g.iface != "" {
		t.Errorf("iface = %q, want empty", g.iface)
	}
	if g.sigCh == nil {
		t.Error("sigCh should be initialized")
	}
}

func TestNew_ReturnsGuardWhenMACCaptureFails(t *testing.T) {
	origGetCurrentMAC := getCurrentMAC
	getCurrentMAC = func(iface string) (string, error) {
		return "", errors.New("link unavailable")
	}
	t.Cleanup(func() {
		getCurrentMAC = origGetCurrentMAC
	})

	g, err := New("en0")
	if g == nil {
		t.Fatal("New returned nil guard on MAC capture error")
	}
	if err == nil {
		t.Fatal("expected MAC capture error")
	}
	if got := err.Error(); got != "failed to capture original MAC address: link unavailable" {
		t.Fatalf("unexpected error: %q", got)
	}
	if g.iface != "en0" {
		t.Errorf("iface = %q, want %q", g.iface, "en0")
	}
	if g.originalMAC != "" {
		t.Errorf("originalMAC = %q, want empty", g.originalMAC)
	}
	if g.sigCh == nil {
		t.Fatal("sigCh should be initialized")
	}
}

func TestGuard_RestoreWithoutTunnels(t *testing.T) {
	g := &Guard{
		iface:       "en0",
		originalMAC: "",
		sigCh:       make(chan os.Signal, 1),
	}

	// Restore with no tunnels should not panic.
	g.Restore()

	if !g.restored {
		t.Error("guard should be marked restored")
	}
}

func TestRestore_WarnsWhenFlushDNSFails(t *testing.T) {
	origFlushDNS := flushDNS
	origGeteuid := geteuid
	flushDNS = func() error {
		return errors.New("dns flush failed")
	}
	geteuid = func() int {
		return 0
	}
	t.Cleanup(func() {
		flushDNS = origFlushDNS
		geteuid = origGeteuid
	})

	g := &Guard{
		iface:       "en0",
		originalMAC: "",
		sigCh:       make(chan os.Signal, 1),
	}

	output := captureStderr(t, g.Restore)
	if !strings.Contains(output, "nowifi: warning: failed to flush DNS cache: dns flush failed") {
		t.Fatalf("expected DNS flush warning, got %q", output)
	}
}

func TestRegisterTunnel_AfterRestore(t *testing.T) {
	g := &Guard{
		iface:       "en0",
		originalMAC: "",
		sigCh:       make(chan os.Signal, 1),
	}

	g.Restore()

	// Registering after restore should still work (no panic),
	// but the tunnel won't be closed by a subsequent Restore.
	tunnel := &mockCloser{}
	g.RegisterTunnel(tunnel)

	g.mu.Lock()
	count := len(g.tunnels)
	g.mu.Unlock()

	if count != 1 {
		t.Errorf("tunnel count = %d, want 1", count)
	}
}

func TestRestore_MultipleTunnelsWithMixedErrors(t *testing.T) {
	g := &Guard{
		iface:       "en0",
		originalMAC: "",
		sigCh:       make(chan os.Signal, 1),
	}

	t1 := &mockCloser{}
	t2 := &mockCloser{closeErr: errors.New("err1")}
	t3 := &mockCloser{closeErr: errors.New("err2")}
	t4 := &mockCloser{}

	g.RegisterTunnel(t1)
	g.RegisterTunnel(t2)
	g.RegisterTunnel(t3)
	g.RegisterTunnel(t4)

	g.Restore()

	// All tunnels should have Close() called regardless of errors.
	for i, tun := range []*mockCloser{t1, t2, t3, t4} {
		if !tun.isClosed() {
			t.Errorf("tunnel[%d] not closed", i)
		}
	}
}
