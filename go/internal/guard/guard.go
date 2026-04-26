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

var getCurrentMAC = platform.GetCurrentMAC
var flushDNS = platform.FlushDNS
var geteuid = os.Geteuid
var clearSystemProxy = platform.ClearSystemProxy

// Guard saves and restores network state. Create with New(), register
// tunnels with RegisterTunnel(), and call Restore() on exit (or use defer).
//
// Typical usage:
//
//	g, err := guard.New("en0")
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "nowifi: warning: %v\n", err)
//	}
//	defer g.Restore()
//	g.StartSignalHandler()
//	// ... run audit ...
type Guard struct {
	iface        string
	originalMAC  string
	tunnels      []io.Closer
	stealthState *platform.StealthState
	restored     bool
	report       RestoreReport
	mu           sync.Mutex
	sigCh        chan os.Signal
}

// RestoreReport captures best-effort cleanup verification for operator output
// and tests. A false Attempted field means that subsystem was not touched.
type RestoreReport struct {
	TunnelsStopped   int
	StealthAttempted bool
	StealthRestored  bool
	ProxyAttempted   bool
	ProxyCleared     bool
	MACAttempted     bool
	MACRestored      bool
	DNSAttempted     bool
	DNSFlushed       bool
	Warnings         []string
}

// New creates a new Guard for the given interface.
// It captures the current MAC address as the restore target.
//
// If MAC capture fails, the returned Guard still restores all other state,
// but the caller must surface the returned error because MAC restoration
// will be unavailable for that session.
func New(iface string) (*Guard, error) {
	mac, err := getCurrentMAC(iface)
	g := &Guard{
		iface:       iface,
		originalMAC: mac,
		sigCh:       make(chan os.Signal, 1),
	}
	if err != nil {
		return g, fmt.Errorf("failed to capture original MAC address: %w", err)
	}
	return g, nil
}

// RegisterTunnel adds a tunnel (or any io.Closer) to be stopped on Restore().
func (g *Guard) RegisterTunnel(t io.Closer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tunnels = append(g.tunnels, t)
}

// RegisterStealth records a StealthState for restoration on exit.
func (g *Guard) RegisterStealth(state *platform.StealthState) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stealthState = state
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
//  2. Disable traffic stealth (restore TTL, remove PF/iptables rules)
//  3. Clear system SOCKS proxy
//  4. Restore original MAC address (+ DHCP renewal if changed)
//  5. Flush DNS cache
func (g *Guard) Restore() {
	_ = g.RestoreWithReport()
}

// RestoreWithReport performs Restore and returns cleanup verification details.
// It is safe to call multiple times; later calls return the first report.
func (g *Guard) RestoreWithReport() RestoreReport {
	g.mu.Lock()
	if g.restored {
		report := g.report
		g.mu.Unlock()
		return report
	}
	g.restored = true
	// Copy tunnels under lock, then release.
	tunnels := make([]io.Closer, len(g.tunnels))
	copy(tunnels, g.tunnels)
	g.mu.Unlock()

	report := RestoreReport{}
	warn := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		report.Warnings = append(report.Warnings, msg)
		fmt.Fprintf(os.Stderr, "nowifi: warning: %s\n", msg)
	}

	// Stop signal forwarding.
	if g.sigCh != nil {
		signal.Stop(g.sigCh)
	}

	// 1. Stop all tunnel processes.
	for _, t := range tunnels {
		if err := t.Close(); err != nil {
			warn("failed to stop tunnel: %v", err)
		} else {
			report.TunnelsStopped++
		}
	}

	// 2. Disable traffic stealth (restore TTL, remove PF rules).
	if g.stealthState != nil {
		report.StealthAttempted = true
		platform.DisableStealth(g.stealthState)
		report.StealthRestored = true
	}

	// 3. Clear system SOCKS proxy (only if tunnels were registered — they set the proxy).
	if len(tunnels) > 0 {
		report.ProxyAttempted = true
		if err := clearSystemProxy(g.iface); err != nil {
			warn("failed to clear SOCKS proxy: %v", err)
		} else {
			report.ProxyCleared = true
		}
	}

	// 4. Restore original MAC address if it was changed (requires root).
	if g.originalMAC != "" && geteuid() == 0 {
		report.MACAttempted = true
		current, err := getCurrentMAC(g.iface)
		if err == nil && current != g.originalMAC {
			if err := platform.SetMAC(g.iface, g.originalMAC); err != nil {
				warn("failed to restore MAC address: %v", err)
			} else {
				report.MACRestored = true
				if err := platform.RenewDHCP(g.iface); err != nil {
					warn("failed to renew DHCP: %v", err)
				}
			}
		} else if err != nil {
			warn("failed to verify MAC address before restore: %v", err)
		} else {
			report.MACRestored = true
		}
	}

	// 5. Flush DNS cache (best-effort, may need root).
	if geteuid() == 0 {
		report.DNSAttempted = true
		if err := flushDNS(); err != nil {
			warn("failed to flush DNS cache: %v", err)
		} else {
			report.DNSFlushed = true
		}
	}

	g.mu.Lock()
	g.report = report
	g.mu.Unlock()
	return report
}

// OriginalMAC returns the MAC address captured when the Guard was created.
func (g *Guard) OriginalMAC() string {
	return g.originalMAC
}

// Interface returns the network interface name this Guard manages.
func (g *Guard) Interface() string {
	return g.iface
}
