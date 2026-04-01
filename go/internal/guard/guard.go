// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package guard provides the StateGuard, which saves and restores all
// network state (MAC address, system proxy, DNS cache, tunnel processes)
// on exit, ensuring the system returns to its pre-nowifi state.
//
// The Guard handles normal exit (via defer), SIGINT, SIGTERM, and panics.
// It is the Go equivalent of the Python StateGuard context manager.
package guard

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// Guard saves and restores network state. Create with New(), register
// tunnels with RegisterTunnel(), and call Restore() on exit (or use defer).
//
// Typical usage:
//
//	g := guard.New("en0")
//	defer g.Restore()
//	g.StartSignalHandler()
//	// ... run audit ...
type Guard struct {
	iface       string
	originalMAC string
	tunnels     []io.Closer
	restored    bool
	mu          sync.Mutex
	sigCh       chan os.Signal
}

// New creates a new Guard for the given interface.
// It captures the current MAC address as the restore target.
func New(iface string) *Guard {
	mac, _ := platform.GetCurrentMAC(iface)
	return &Guard{
		iface:       iface,
		originalMAC: mac,
		sigCh:       make(chan os.Signal, 1),
	}
}

// RegisterTunnel adds a tunnel (or any io.Closer) to be stopped on Restore().
func (g *Guard) RegisterTunnel(t io.Closer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tunnels = append(g.tunnels, t)
}

// StartSignalHandler spawns a goroutine that calls Restore() and exits
// on SIGINT or SIGTERM. Call this once from main().
func (g *Guard) StartSignalHandler() {
	signal.Notify(g.sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-g.sigCh
		fmt.Fprintf(os.Stderr, "\nnowifi: caught %s, restoring state...\n", sig)
		g.Restore()
		os.Exit(1)
	}()
}

// Restore reverts all network state to pre-nowifi conditions.
// It is safe to call multiple times; only the first call has effect.
//
// Restore order:
//  1. Stop all registered tunnel processes
//  2. Clear system SOCKS proxy
//  3. Restore original MAC address (+ DHCP renewal if changed)
//  4. Flush DNS cache
func (g *Guard) Restore() {
	g.mu.Lock()
	if g.restored {
		g.mu.Unlock()
		return
	}
	g.restored = true
	// Copy tunnels under lock, then release.
	tunnels := make([]io.Closer, len(g.tunnels))
	copy(tunnels, g.tunnels)
	g.mu.Unlock()

	// Stop signal forwarding.
	signal.Stop(g.sigCh)

	// 1. Stop all tunnel processes.
	for _, t := range tunnels {
		if err := t.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "nowifi: warning: failed to stop tunnel: %v\n", err)
		}
	}

	// 2. Clear system SOCKS proxy.
	if err := platform.ClearSystemProxy(g.iface); err != nil {
		fmt.Fprintf(os.Stderr, "nowifi: warning: failed to clear SOCKS proxy: %v\n", err)
	}

	// 3. Restore original MAC address if it was changed.
	if g.originalMAC != "" {
		current, err := platform.GetCurrentMAC(g.iface)
		if err == nil && current != g.originalMAC {
			if err := platform.SetMAC(g.iface, g.originalMAC); err != nil {
				fmt.Fprintf(os.Stderr, "nowifi: warning: failed to restore MAC address: %v\n", err)
			} else {
				// Renew DHCP after MAC change so the network sees the original address.
				if err := platform.RenewDHCP(g.iface); err != nil {
					fmt.Fprintf(os.Stderr, "nowifi: warning: failed to renew DHCP: %v\n", err)
				}
			}
		}
	}

	// 4. Flush DNS cache.
	_ = platform.FlushDNS()
}

// OriginalMAC returns the MAC address captured when the Guard was created.
func (g *Guard) OriginalMAC() string {
	return g.originalMAC
}

// Interface returns the network interface name this Guard manages.
func (g *Guard) Interface() string {
	return g.iface
}
