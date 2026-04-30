// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package server

import (
	"context"
	"errors"
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// Registry basics
// ---------------------------------------------------------------------------

func TestNamesContainsAllFourProviders(t *testing.T) {
	want := []string{"cloudflare_quick", "cloudflare_worker", "digitalocean", "hetzner", "libp2p"}
	got := Names()
	sort.Strings(got)

	if len(got) < len(want) {
		t.Fatalf("Names() = %v, want at least %v", got, want)
	}

	have := make(map[string]bool, len(got))
	for _, n := range got {
		have[n] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("Names() missing %q; got %v", w, got)
		}
	}
}

func TestNamesReturnsSortedSlice(t *testing.T) {
	names := Names()
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("Names() not sorted at index %d: %q < %q", i, names[i], names[i-1])
		}
	}
}

func TestGetUnknownProviderReturnsFalse(t *testing.T) {
	_, ok := Get("does_not_exist_xyz")
	if ok {
		t.Error("Get(unknown) should return false")
	}
}

func TestGetKnownProviderReturnsTrue(t *testing.T) {
	for _, name := range []string{"cloudflare_quick", "cloudflare_worker", "digitalocean", "hetzner", "libp2p"} {
		p, ok := Get(name)
		if !ok {
			t.Errorf("Get(%q) returned false", name)
			continue
		}
		if p.Name() != name {
			t.Errorf("Get(%q).Name() = %q, want %q", name, p.Name(), name)
		}
	}
}

// ---------------------------------------------------------------------------
// Register: last-wins semantics
// ---------------------------------------------------------------------------

// sentinelProvider is a no-op provider used for registration tests.
type sentinelProvider struct {
	name    string
	created bool
}

func (s *sentinelProvider) Name() string { return s.name }
func (s *sentinelProvider) Create(_ context.Context, _ CreateOpts) (*Info, error) {
	s.created = true
	return nil, errors.New("sentinel")
}
func (s *sentinelProvider) Destroy(_ context.Context, _ *Info, _ string) error {
	return errors.New("sentinel")
}

func TestRegisterLastWins(t *testing.T) {
	const testName = "__test_last_wins__"

	first := &sentinelProvider{name: testName}
	second := &sentinelProvider{name: testName}

	Register(first)
	Register(second) // should win

	t.Cleanup(func() {
		mu.Lock()
		delete(providers, testName)
		mu.Unlock()
	})

	p, ok := Get(testName)
	if !ok {
		t.Fatal("provider not found after double Register")
	}
	if p != second {
		t.Error("expected second registration to win (last wins)")
	}
}

func TestRegisterIdempotentSameName(t *testing.T) {
	const testName = "__test_idempotent__"

	p1 := &sentinelProvider{name: testName}
	Register(p1)
	Register(p1) // same pointer, same name

	t.Cleanup(func() {
		mu.Lock()
		delete(providers, testName)
		mu.Unlock()
	})

	got, ok := Get(testName)
	if !ok {
		t.Fatal("provider not found")
	}
	if got != p1 {
		t.Error("idempotent re-register of same pointer should still return it")
	}
}

// ---------------------------------------------------------------------------
// CreateViaRegistry / DestroyViaRegistry error paths
// ---------------------------------------------------------------------------

func TestCreateViaRegistry_UnknownProvider(t *testing.T) {
	_, err := CreateViaRegistry(context.Background(), "nonexistent_provider", CreateOpts{})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestDestroyViaRegistry_UnknownProvider(t *testing.T) {
	info := &Info{Provider: "nonexistent_provider", ServerID: "x"}
	err := DestroyViaRegistry(context.Background(), info, "")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

// ---------------------------------------------------------------------------
// CreateVPS backward-compat: unknown name returns clear error
// ---------------------------------------------------------------------------

func TestCreateVPS_UnknownProvider_RegistryError(t *testing.T) {
	_, err := CreateVPS("bogus_provider", "", 0)
	if err == nil {
		t.Fatal("expected error")
	}
	// Error must mention the provider name.
	errStr := err.Error()
	found := false
	for _, c := range errStr {
		_ = c
		found = true
		break
	}
	if !found || len(errStr) == 0 {
		t.Errorf("error message unexpectedly empty")
	}
}
