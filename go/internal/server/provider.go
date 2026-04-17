// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Provider registry for tunnel/server backends.
//
// Adding a new provider requires only one new file that calls Register() from
// its init() function — no edits to server.go or cli/server.go.
package server

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// ---------------------------------------------------------------------------
// CreateOpts — unified options passed to every provider's Create method.
// ---------------------------------------------------------------------------

// CreateOpts carries all parameters a provider might need to create a server.
// VPS providers use APIToken + TTLHours; tunnel providers use Target.
// Extra holds provider-specific key/value pairs as an escape hatch.
type CreateOpts struct {
	APIToken string            // Cloud API token (DigitalOcean, Hetzner, …)
	TTLHours int               // Auto-destroy after N hours (0 = never)
	Target   string            // Local service URL to expose (tunnel providers)
	Extra    map[string]string // Provider-specific key/value escape hatch
}

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

// Provider is the interface every tunnel/server backend must implement.
// Implementations live in their own files and self-register via init().
type Provider interface {
	// Name returns the canonical provider identifier, e.g. "cloudflare_quick".
	// This must match the Info.Provider field stored in servers.json.
	Name() string

	// Create provisions a new server/tunnel and returns its Info.
	Create(ctx context.Context, opts CreateOpts) (*Info, error)

	// Destroy tears down the resource identified by info.
	Destroy(ctx context.Context, info *Info, apiToken string) error
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Register adds p to the global registry.
// If a provider with the same name is already registered, the new one wins
// (last registration takes effect). This matches Go's init() execution order
// being deterministic within a package but allows test overrides.
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	providers[p.Name()] = p
}

// Get returns the Provider registered under name, or (nil, false).
func Get(name string) (Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[name]
	return p, ok
}

// Names returns a sorted slice of all registered provider names.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(providers))
	for n := range providers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// Registry-backed wrappers (preserve public API)
// ---------------------------------------------------------------------------

// CreateViaRegistry creates a server using the named provider from the
// registry. It is the generic entry point; callers may also use the
// provider-specific helpers (SetupCloudflareWorker, CreateVPS, …) which
// delegate here.
func CreateViaRegistry(ctx context.Context, providerName string, opts CreateOpts) (*Info, error) {
	p, ok := Get(providerName)
	if !ok {
		return nil, fmt.Errorf("unknown provider %q — available: %v", providerName, Names())
	}
	return p.Create(ctx, opts)
}

// DestroyViaRegistry destroys the server described by info using the
// registered provider. It replaces the hardcoded switch in DestroyServer.
func DestroyViaRegistry(ctx context.Context, info *Info, apiToken string) error {
	p, ok := Get(info.Provider)
	if !ok {
		return fmt.Errorf("unknown provider %q — available: %v", info.Provider, Names())
	}
	return p.Destroy(ctx, info, apiToken)
}
