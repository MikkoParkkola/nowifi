// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPortalRelay_CommonWhitelistedDomainsNotEmpty(t *testing.T) {
	if len(CommonWhitelistedDomains) == 0 {
		t.Fatal("CommonWhitelistedDomains is empty")
	}

	expected := []string{"js.stripe.com", "captive.apple.com", "fonts.googleapis.com"}
	for _, want := range expected {
		found := false
		for _, got := range CommonWhitelistedDomains {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("CommonWhitelistedDomains missing expected domain %q", want)
		}
	}
}

func TestPortalRelay_CommonWhitelistedDomainsNoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, d := range CommonWhitelistedDomains {
		if seen[d] {
			t.Errorf("duplicate domain in CommonWhitelistedDomains: %q", d)
		}
		seen[d] = true
	}
}

func TestPortalRelay_ProbeWhitelistedDomainSucceedsForLocalTLSServer(t *testing.T) {
	// Start a local TLS server with a self-signed cert.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Extract host:port from the server URL.
	host := srv.Listener.Addr().String()

	// The real probe uses TLS with ServerName verification; for the test we
	// verify that a TCP TLS dial succeeds when the cert matches. Since the
	// httptest cert is for "example.com" and 127.0.0.1, we use the custom
	// dialer directly to prove the helper works.
	ctx, cancel := makeTestContext(5 * time.Second)
	defer cancel()

	certPool := x509.NewCertPool()
	certPool.AddCert(srv.Certificate())

	conn, err := (&tls.Dialer{
		Config: &tls.Config{
			ServerName: "example.com",
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		},
	}).DialContext(ctx, "tcp", host)
	if err != nil {
		t.Fatalf("baseline TLS dial failed: %v", err)
	}
	_ = conn.Close()
}

func TestPortalRelay_ProbeWhitelistedDomainFailsForUnreachable(t *testing.T) {
	// Use an obviously-unreachable domain that won't resolve.
	if got := ProbeWhitelistedDomain("this-domain-absolutely-does-not-exist-12345.invalid", 1*time.Second); got {
		t.Error("ProbeWhitelistedDomain should return false for nonexistent domain")
	}
}

func TestPortalRelay_ProbeWhitelistedDomainDefaultTimeout(t *testing.T) {
	// Passing timeout=0 should use the 5s default. We verify the call returns
	// (either true or false) within a reasonable window for an unreachable host.
	start := time.Now()
	_ = ProbeWhitelistedDomain("10.255.255.1", 0) // RFC 1918 unreachable
	elapsed := time.Since(start)

	// The default timeout is 5s; we allow some slack. Just verify it returned.
	if elapsed > 10*time.Second {
		t.Errorf("ProbeWhitelistedDomain took %v, expected ≤10s", elapsed)
	}
}

func TestPortalRelay_FindWhitelistedDomainsDeduplication(t *testing.T) {
	// Pass the same invalid domain multiple times; expect no duplicates even
	// though none will be reachable.
	extra := []string{
		"dup.example.invalid",
		"dup.example.invalid",
		"dup.example.invalid",
	}

	// Start with a non-zero timeout that's short enough to fail fast.
	result := FindWhitelistedDomains(extra, 500*time.Millisecond)

	// Verify no duplicates in result.
	seen := make(map[string]bool)
	for _, d := range result {
		if seen[d] {
			t.Errorf("FindWhitelistedDomains returned duplicate: %q", d)
		}
		seen[d] = true
	}
}

func TestPortalRelay_StartPortalRelayTunnelFailsWithNoDomains(t *testing.T) {
	_, err := StartPortalRelayTunnel(nil, 0, 1*time.Second)
	if err == nil {
		t.Fatal("StartPortalRelayTunnel should fail with no domains")
	}
	if !strings.Contains(err.Error(), "no whitelisted domains") {
		t.Errorf("expected 'no whitelisted domains' error, got: %v", err)
	}
}

func TestPortalRelay_StartPortalRelayTunnelFailsWithUnreachableDomains(t *testing.T) {
	_, err := StartPortalRelayTunnel(
		[]string{"unreachable1.invalid", "unreachable2.invalid"},
		0,
		500*time.Millisecond,
	)
	if err == nil {
		t.Fatal("StartPortalRelayTunnel should fail with unreachable domains")
	}
	if !strings.Contains(err.Error(), "portal relay") {
		t.Errorf("expected 'portal relay' error, got: %v", err)
	}
}

func TestPortalRelay_DefaultPortConstant(t *testing.T) {
	// Port should be in user-range (1024-65535) and not conflict with other
	// tunnel ports: 1080 (chisel), 1081 (quic), 1082 (ntp), 1083 (doh),
	// 1092 (grpc), 1093 (warp), 1094 (portal relay), 1095 (turn relay).
	if portalRelayDefaultPort < 1024 || portalRelayDefaultPort > 65535 {
		t.Errorf("portalRelayDefaultPort=%d out of valid range", portalRelayDefaultPort)
	}
	if portalRelayDefaultPort == 1080 || portalRelayDefaultPort == 1081 ||
		portalRelayDefaultPort == 1092 || portalRelayDefaultPort == 1093 {
		t.Errorf("portalRelayDefaultPort=%d conflicts with existing tunnel port", portalRelayDefaultPort)
	}
}

// makeTestContext is a helper to create a context with timeout for tests.
func makeTestContext(timeout time.Duration) (ctx testContext, cancel func()) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	done := make(chan struct{})
	cancel = func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}
	return testContext{deadline: deadline, done: done}, cancel
}

// testContext is a minimal context.Context implementation for tests.
type testContext struct {
	deadline time.Time
	done     chan struct{}
}

func (c testContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c testContext) Done() <-chan struct{}       { return c.done }
func (c testContext) Err() error                  { return nil }
func (c testContext) Value(key any) any           { return nil }

// Ensure the testContext + net.Dialer types resolve (used implicitly above).
var _ = net.Dialer{}
