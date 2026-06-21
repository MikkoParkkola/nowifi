// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// saveVerifierHooks restores internetVerifyProbes / internetVerifyQuorum /
// internetCheckURL after the test, so each test sees a clean verifier
// configuration.
func saveVerifierHooks(t *testing.T) func() {
	t.Helper()
	origProbes := internetVerifyProbes
	origQuorum := internetVerifyQuorum
	origCheckURL := internetCheckURL
	origHTTPSURL := internetVerifyHTTPSURL
	origTimeout := internetVerifyTimeout
	return func() {
		internetVerifyProbes = origProbes
		internetVerifyQuorum = origQuorum
		internetCheckURL = origCheckURL
		internetVerifyHTTPSURL = origHTTPSURL
		internetVerifyTimeout = origTimeout
	}
}

func stubProbe(result bool) internetProbeFunc {
	return func(ctx context.Context, dialer *net.Dialer) bool {
		return result
	}
}

func stubProbeAfter(delay time.Duration, result bool) internetProbeFunc {
	return func(ctx context.Context, dialer *net.Dialer) bool {
		select {
		case <-time.After(delay):
			return result
		case <-ctx.Done():
			return false
		}
	}
}

// ---------------------------------------------------------------------------
// Regression: issue #31 — captive-whitelist false-positive
//
// Reproduces the Finnair / Panasonic Avionics situation. The legacy
// gstatic /generate_204 probe answered 204 because that endpoint was
// whitelisted by the carrier's captive gateway pre-authentication. Real
// internet was not reachable: ping to www.google.com failed for ~5
// minutes after the user paid for a pass.
//
// The new quorum verifier rejects this case: even if the captive lets
// gstatic-style canaries through, the TLS-validated direct-IP probes
// and the random-token HTTPS probe cannot all be faked by a static
// whitelist, so quorum is not reached and HasInternet correctly returns
// false. This test pins that behavior so the bug cannot regress silently.
// ---------------------------------------------------------------------------

func TestHasInternet_CaptiveWhitelist_FalsePositiveBlocked(t *testing.T) {
	defer saveVerifierHooks(t)()

	// Production mode: no internetCheckURL override, full quorum verifier.
	internetCheckURL = ""
	internetVerifyQuorum = 2
	// Simulate a Panasonic-style whitelist: only the canary-equivalent
	// probe (e.g. gstatic) succeeds; the heterogeneous TLS/random-token
	// probes that defeat the whitelist all fail because the firewall is
	// closed to everything else.
	internetVerifyProbes = []internetProbeFunc{
		stubProbe(true),  // captive-whitelisted canary — passes
		stubProbe(false), // 1.1.1.1 TLS — blocked
		stubProbe(false), // 9.9.9.9 TLS — blocked
	}

	if HasInternet() {
		t.Fatal("HasInternet must return false when only the captive-whitelisted " +
			"canary passes — this is the issue #31 false-positive that lied to " +
			"the user on Finnair flight 2026-04-29")
	}
}

func TestHasInternet_QuorumPasses(t *testing.T) {
	defer saveVerifierHooks(t)()
	internetCheckURL = ""
	internetVerifyQuorum = 2
	internetVerifyProbes = []internetProbeFunc{
		stubProbe(true),
		stubProbe(true),
		stubProbe(false),
	}
	if !HasInternet() {
		t.Fatal("HasInternet must return true when quorum is reached " +
			"(2 of 3 probes succeed)")
	}
}

func TestHasInternet_QuorumNotReached(t *testing.T) {
	defer saveVerifierHooks(t)()
	internetCheckURL = ""
	internetVerifyQuorum = 2
	internetVerifyProbes = []internetProbeFunc{
		stubProbe(true),
		stubProbe(false),
		stubProbe(false),
	}
	if HasInternet() {
		t.Fatal("HasInternet must return false when only one probe succeeds " +
			"(quorum=2 not reached)")
	}
}

func TestHasInternet_AllProbesFail(t *testing.T) {
	defer saveVerifierHooks(t)()
	internetCheckURL = ""
	internetVerifyQuorum = 2
	internetVerifyProbes = []internetProbeFunc{
		stubProbe(false),
		stubProbe(false),
		stubProbe(false),
	}
	if HasInternet() {
		t.Fatal("HasInternet must return false when no probes succeed")
	}
}

// TestVerifyInternetReachable_EarlyExitOnQuorum ensures the verifier
// returns as soon as enough probes succeed — it does NOT wait for slow
// probes once quorum is locked in. Critical on satellite RTT where
// every probe carries 500-2500ms latency.
func TestVerifyInternetReachable_EarlyExitOnQuorum(t *testing.T) {
	defer saveVerifierHooks(t)()
	internetVerifyQuorum = 2
	internetVerifyTimeout = 5 * time.Second
	internetVerifyProbes = []internetProbeFunc{
		stubProbe(true),                      // immediate
		stubProbe(true),                      // immediate
		stubProbeAfter(4*time.Second, false), // would take 4s
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok := verifyInternetReachable(ctx, nil)
	elapsed := time.Since(start)
	if !ok {
		t.Fatal("expected verifier to return true once quorum reached")
	}
	if elapsed > 1*time.Second {
		t.Fatalf("verifier did not early-exit on quorum: took %v "+
			"(should be near-instant when 2 probes return true synchronously)", elapsed)
	}
}

// TestVerifyInternetReachable_EarlyExitOnImpossibleQuorum ensures the
// verifier short-circuits when remaining probes can no longer reach
// quorum — important when one slow probe is the last hope and we
// already know it can't matter.
func TestVerifyInternetReachable_EarlyExitOnImpossibleQuorum(t *testing.T) {
	defer saveVerifierHooks(t)()
	internetVerifyQuorum = 2
	internetVerifyTimeout = 5 * time.Second
	// Two fast failures, one slow probe — quorum is impossible after
	// the second failure regardless of the slow probe's eventual answer.
	internetVerifyProbes = []internetProbeFunc{
		stubProbe(false),
		stubProbe(false),
		stubProbeAfter(4*time.Second, true),
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok := verifyInternetReachable(ctx, nil)
	elapsed := time.Since(start)
	if ok {
		t.Fatal("expected verifier to return false when quorum is impossible")
	}
	if elapsed > 1*time.Second {
		t.Fatalf("verifier did not early-exit when quorum impossible: took %v", elapsed)
	}
}

// TestVerifyInternetReachable_ProbesRunConcurrently sanity-checks that
// the verifier fans probes out in parallel rather than serializing them.
// With three 200ms probes, total wall-clock should be ~200ms, not ~600ms.
func TestVerifyInternetReachable_ProbesRunConcurrently(t *testing.T) {
	defer saveVerifierHooks(t)()
	internetVerifyQuorum = 3
	internetVerifyTimeout = 5 * time.Second
	internetVerifyProbes = []internetProbeFunc{
		stubProbeAfter(200*time.Millisecond, true),
		stubProbeAfter(200*time.Millisecond, true),
		stubProbeAfter(200*time.Millisecond, true),
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok := verifyInternetReachable(ctx, nil)
	elapsed := time.Since(start)
	if !ok {
		t.Fatal("expected verifier to return true with all probes succeeding")
	}
	// Allow generous margin for CI scheduler jitter, but well below the
	// 600ms that serial execution would imply.
	if elapsed > 400*time.Millisecond {
		t.Fatalf("probes appear to be running serially: %v elapsed for "+
			"3x200ms concurrent probes", elapsed)
	}
}

// TestVerifyInternetReachable_PanicInProbeIsTreatedAsFailure ensures a
// buggy probe cannot crash the bypass loop — the probe runner recovers
// and treats the panic as a failed probe.
func TestVerifyInternetReachable_PanicInProbeIsTreatedAsFailure(t *testing.T) {
	defer saveVerifierHooks(t)()
	internetVerifyQuorum = 2
	internetVerifyProbes = []internetProbeFunc{
		stubProbe(true),
		func(ctx context.Context, dialer *net.Dialer) bool {
			panic("synthetic probe panic")
		},
		stubProbe(false),
	}
	// Must not panic; quorum=2 with one success and one panic-as-failure
	// and one explicit failure → returns false.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if verifyInternetReachable(ctx, nil) {
		t.Fatal("expected verifier to return false (only one probe succeeded)")
	}
}

// TestCertNameMatches covers the cert-name matching helper used by the
// TLS probes. Wildcards must match exactly one DNS label, and parent-
// domain matches must allow operator hostnames like dns.quad9.net to
// satisfy expected "quad9.net".
func TestCertNameMatches(t *testing.T) {
	cases := []struct {
		certName string
		want     string
		expect   bool
	}{
		{"one.one.one.one", "one.one.one.one", true},
		{"*.cloudflare-dns.com", "cloudflare-dns.com", false}, // wildcard requires a label
		{"*.cloudflare-dns.com", "www.cloudflare-dns.com", true},
		{"*.cloudflare-dns.com", "a.b.cloudflare-dns.com", false}, // wildcard is one label only
		{"dns.quad9.net", "quad9.net", true},                      // child matches parent operator
		{"quad9.net", "dns.quad9.net", false},                     // parent does not match child
		{"attacker.captive-portal-mitm.lan", "quad9.net", false},
		{"", "quad9.net", false},
		{"quad9.net", "", false},
	}
	for _, c := range cases {
		got := certNameMatches(c.certName, c.want)
		if got != c.expect {
			t.Errorf("certNameMatches(%q, %q) = %v, want %v",
				c.certName, c.want, got, c.expect)
		}
	}
}

// TestRandomToken verifies the random-query-string helper produces
// distinct tokens across calls (defeats exact-URL whitelists).
func TestRandomToken(t *testing.T) {
	const N = 64
	seen := make(map[string]struct{}, N)
	var mu sync.Mutex
	var wg sync.WaitGroup
	collisions := atomic.Int64{}
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok := randomToken(8)
			if len(tok) != 16 { // 8 bytes hex-encoded
				t.Errorf("randomToken length = %d, want 16", len(tok))
			}
			mu.Lock()
			if _, ok := seen[tok]; ok {
				collisions.Add(1)
			}
			seen[tok] = struct{}{}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if collisions.Load() > 0 {
		t.Errorf("randomToken produced %d collisions across %d calls",
			collisions.Load(), N)
	}
}
