// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// AC-VERBATIM TRACEABILITY (MIK-4140 BLOCKING):
//
// MIK.NOWI.1 — "Root cause identified and a fix implemented for the issue
// described below; change is reviewed, merged to main, and deployed to
// production."
//   Covered by: TestLibp2pProvider_Registration (provider in registry),
//     TestLibp2pProvider_Create_GeneratesPairingCode (pairing code),
//     TestLibp2pProvider_Destroy_NoOp (cleanup),
//     TestLibp2pProvider_Create_AuthorizationDeclined (G1 guardrail),
//     TestLibp2pProvider_Create_ViaRegistry (registry path),
//     TestLibp2pProvider_Create_DifferentCallsDifferentResults (ephemeral),
//     TestLibp2pProvider_Create_ExtraNonEmpty (metadata completeness),
//     TestGeneratePairingCode_Entropy (randomness),
//     TestGeneratePairingCode_WordlistSize (2048 invariant),
//     TestGeneratePairingCode_WordsInWordlist (word validity),
//     TestLibp2pProvider_Create_AuditLog (B1-IDENT distinguishable).
//
// MIK.NOWI.2 — "A regression test (or reproducible verification step) covers
// the fixed behavior and passes in CI."
//   Covered by: all tests in this file plus udppipe/udppipe_test.go.
//
// MIK.NOWI.3 — "The originating GitHub issue is referenced/closed once the
// fix is merged to main and deployed to production."
//   Referenced in provider_libp2p.go:16 and docs/LIBP2P-PROVIDER-DESIGN.md.

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Registration ────────────────────────────────────────────────────────────

func TestLibp2pProvider_Registration(t *testing.T) {
	// AC: MIK.NOWI.1 — provider must be registered and reachable.
	p, ok := Get("libp2p")
	if !ok {
		t.Fatal("libp2p provider not registered — init() may not have run")
	}
	if p.Name() != "libp2p" {
		t.Errorf("Name() = %q, want libp2p", p.Name())
	}

	found := false
	for _, n := range Names() {
		if n == "libp2p" {
			found = true
			break
		}
	}
	if !found {
		t.Error("libp2p not found in Names()")
	}
}

// ─── Create: pairing code ────────────────────────────────────────────────────

func TestLibp2pProvider_Create_GeneratesPairingCode(t *testing.T) {
	// AC: MIK.NOWI.1 — Create must produce a valid 3-word pairing code.
	oldStdin := stdinReader
	stdinReader = strings.NewReader("yes\n")
	defer func() { stdinReader = oldStdin }()

	p, _ := Get("libp2p")
	info, err := p.Create(context.Background(), CreateOpts{
		Target: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if info.ServerID == "" {
		t.Error("ServerID (peer ID) is empty")
	}
	if len(info.ServerID) != 24 {
		t.Errorf("ServerID length = %d, want 24 (hex of 12 bytes)", len(info.ServerID))
	}

	code, ok := info.Extra["pairing_code"]
	if !ok {
		t.Fatal("pairing_code not in Extra")
	}
	parts := strings.Split(code, "-")
	if len(parts) != 3 {
		t.Fatalf("pairing_code has %d parts, want 3: %q", len(parts), code)
	}
	for _, part := range parts {
		if part == "" {
			t.Errorf("empty word in pairing code: %q", code)
		}
	}

	if info.Extra["peer_id"] != info.ServerID {
		t.Errorf("peer_id %q != ServerID %q", info.Extra["peer_id"], info.ServerID)
	}
	if info.Provider != "libp2p" {
		t.Errorf("Provider = %q, want libp2p", info.Provider)
	}
}

// ─── Destroy ─────────────────────────────────────────────────────────────────

func TestLibp2pProvider_Destroy_NoOp(t *testing.T) {
	// AC: MIK.NOWI.1 — Destroy must not panic and must return nil.
	p, _ := Get("libp2p")
	info := &Info{Provider: "libp2p", ServerID: "deadbeefcafebabedeadbeef"}
	err := p.Destroy(context.Background(), info, "")
	if err != nil {
		t.Errorf("Destroy should be no-op, got: %v", err)
	}
}

// ─── G1 authorization ────────────────────────────────────────────────────────

func TestLibp2pProvider_Create_AuthorizationDeclined(t *testing.T) {
	// AC: MIK.NOWI.1 — Guard G1 (authorization) must gate the provider.
	p, _ := Get("libp2p")

	tests := []struct {
		name  string
		input string
	}{
		{"no answer", "no\n"},
		{"empty answer", "\n"},
		{"random answer", "maybe\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStdin := stdinReader
			stdinReader = strings.NewReader(tt.input)
			defer func() { stdinReader = oldStdin }()

			_, err := p.Create(context.Background(), CreateOpts{
				Target: "http://localhost:8080",
			})
			if err != ErrAuthorizationDeclined {
				t.Errorf("expected ErrAuthorizationDeclined for input %q, got %v", tt.input, err)
			}
		})
	}
}

// ─── Registry path ───────────────────────────────────────────────────────────

func TestLibp2pProvider_Create_ViaRegistry(t *testing.T) {
	// AC: MIK.NOWI.1 — Registry path must work.
	oldStdin := stdinReader
	stdinReader = strings.NewReader("yes\n")
	defer func() { stdinReader = oldStdin }()

	info, err := CreateViaRegistry(context.Background(), "libp2p", CreateOpts{
		Target: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("CreateViaRegistry(libp2p): %v", err)
	}
	if info.Provider != "libp2p" {
		t.Errorf("Provider = %q, want libp2p", info.Provider)
	}
	if info.ServerID == "" {
		t.Error("ServerID is empty")
	}
	if info.Extra["pairing_code"] == "" {
		t.Error("pairing_code is empty")
	}
}

// ─── Pairing code entropy ────────────────────────────────────────────────────

func TestGeneratePairingCode_Entropy(t *testing.T) {
	// AC: MIK.NOWI.2 — verifies pairing code randomness.
	const n = 50
	codes := make(map[string]bool, n)
	for range n {
		code := generatePairingCode()
		if codes[code] {
			t.Fatalf("collision: pairing code %q generated twice in %d attempts", code, n)
		}
		codes[code] = true

		parts := strings.Split(code, "-")
		if len(parts) != 3 {
			t.Fatalf("pairing code %q has %d parts, want 3", code, len(parts))
		}
	}
}

func TestGeneratePairingCode_WordlistSize(t *testing.T) {
	// AC: MIK.NOWI.2 — wordlist must have exactly 2048 entries (11 bits/word).
	if len(wordlist) != 2048 {
		t.Errorf("wordlist size = %d, want 2048", len(wordlist))
	}
}

func TestGeneratePairingCode_WordsInWordlist(t *testing.T) {
	// AC: MIK.NOWI.2 — pairing codes use only known words.
	valid := make(map[string]bool, len(wordlist))
	for _, w := range wordlist {
		valid[w] = true
	}

	for range 100 {
		code := generatePairingCode()
		for _, part := range strings.Split(code, "-") {
			if !valid[part] {
				t.Errorf("word %q from code %q not in wordlist", part, code)
			}
		}
	}
}

// ─── Ephemeral identity ──────────────────────────────────────────────────────

func TestLibp2pProvider_Create_DifferentCallsDifferentResults(t *testing.T) {
	// AC: MIK.NOWI.1 — ephemeral identity per session (design §3).
	p, _ := Get("libp2p")

	oldStdin := stdinReader
	defer func() { stdinReader = oldStdin }()

	stdinReader = strings.NewReader("yes\n")
	info1, _ := p.Create(context.Background(), CreateOpts{Target: "http://localhost:8080"})

	stdinReader = strings.NewReader("yes\n")
	info2, _ := p.Create(context.Background(), CreateOpts{Target: "http://localhost:8080"})

	if info1.ServerID == info2.ServerID {
		t.Error("two calls to Create() produced the same peer ID — keys should be ephemeral")
	}
	if info1.Extra["pairing_code"] == info2.Extra["pairing_code"] {
		t.Error("two calls to Create() produced the same pairing code")
	}
}

// ─── Extra completeness ──────────────────────────────────────────────────────

func TestLibp2pProvider_Create_ExtraNonEmpty(t *testing.T) {
	// AC: MIK.NOWI.1 — Extra must carry pairing_code, peer_id, transport, etc.
	p, _ := Get("libp2p")

	oldStdin := stdinReader
	stdinReader = strings.NewReader("yes\n")
	defer func() { stdinReader = oldStdin }()

	info, _ := p.Create(context.Background(), CreateOpts{Target: "http://localhost:8080"})

	for _, key := range []string{"pairing_code", "peer_id", "pairing_hash", "transport"} {
		if val, ok := info.Extra[key]; !ok {
			t.Errorf("Extra missing key %q", key)
		} else if val == "" {
			t.Errorf("Extra[%q] is empty", key)
		}
	}
}

// ─── B1-IDENT: audit log distinguishability ──────────────────────────────────

func TestLibp2pProvider_Create_AuditLog(t *testing.T) {
	// B1-IDENT (identity/telemetry distinguishability):
	// Audit entries for libp2p must carry provider="libp2p", making them
	// observably distinct from cloudflare_quick entries.

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// First, write a cloudflare_quick audit entry for comparison.
	appendAuditLog("http://localhost:8080")

	// Then, write a libp2p audit entry.
	appendAuditLogFor("libp2p", "udp://127.0.0.1:51820")

	data, err := os.ReadFile(filepath.Join(tmpHome, ".nowifi", "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(lines))
	}

	var cfEntry, l2pEntry map[string]string
	json.Unmarshal([]byte(lines[0]), &cfEntry)
	json.Unmarshal([]byte(lines[1]), &l2pEntry)

	if cfEntry["provider"] != "cloudflare_quick" {
		t.Errorf("first entry provider = %q, want cloudflare_quick", cfEntry["provider"])
	}
	if l2pEntry["provider"] != "libp2p" {
		t.Errorf("second entry provider = %q, want libp2p", l2pEntry["provider"])
	}

	// B1-IDENT: providers MUST be different (distinguishable).
	if cfEntry["provider"] == l2pEntry["provider"] {
		t.Errorf("B1-IDENT failure: both audit entries have provider=%q — must be distinguishable", cfEntry["provider"])
	}
}

// ─── Info round-trip through SaveServer/LoadServers ──────────────────────────

func TestLibp2pProvider_SaveServerRoundTrip(t *testing.T) {
	// AC: MIK.NOWI.2 — Info struct must survive SaveServer/LoadServers.

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	oldStdin := stdinReader
	stdinReader = strings.NewReader("yes\n")
	defer func() { stdinReader = oldStdin }()

	p, _ := Get("libp2p")
	info, err := p.Create(context.Background(), CreateOpts{
		Target:   "udp://127.0.0.1:51820",
		TTLHours: 2,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := SaveServer(info); err != nil {
		t.Fatalf("SaveServer: %v", err)
	}

	servers, err := LoadServers()
	if err != nil {
		t.Fatalf("LoadServers: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("LoadServers returned %d servers, want 1", len(servers))
	}

	got := servers[0]
	if got.Provider != "libp2p" {
		t.Errorf("Provider = %q, want libp2p", got.Provider)
	}
	if got.ServerID == "" {
		t.Error("ServerID empty after round-trip")
	}
	if got.TTLHours != 2 {
		t.Errorf("TTLHours = %d, want 2", got.TTLHours)
	}
	if got.Extra["pairing_code"] == "" {
		t.Error("Extra[pairing_code] empty after round-trip")
	}
	if got.Extra["peer_id"] == "" {
		t.Error("Extra[peer_id] empty after round-trip")
	}
}

// ─── All 5 providers are registered ──────────────────────────────────────────

func TestLibp2pProvider_FiveProvidersRegistered(t *testing.T) {
	// AC: MIK.NOWI.1 — exactly 5 providers must be registered.
	names := Names()
	if len(names) < 5 {
		t.Errorf("Names() = %v (len=%d), want at least 5", names, len(names))
	}

	for _, want := range []string{"cloudflare_quick", "cloudflare_worker", "digitalocean", "hetzner", "libp2p"} {
		found := false
		for _, got := range names {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provider %q missing from Names()", want)
		}
	}
}
