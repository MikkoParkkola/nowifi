// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

// Internet reachability verification — captive-portal-resistant.
//
// Background (issue #31): captive networks routinely whitelist canonical
// captive-detection probes (gstatic /generate_204, captive.apple.com,
// connecttest.txt) so iOS/Android/macOS see "internet" without paying.
// Probing only those endpoints, as the original HasInternet() did, returns
// 204 on a closed firewall and lies to the user. Reproduced 2026-04-29 on
// Finnair / Panasonic Avionics eXConnect: paid pass not yet activated by
// gateway, gstatic still answered 204, nowifi reported "successfully
// connected" while ping to www.google.com failed for ~5 minutes.
//
// Defense: quorum across heterogeneous, content-validated probes that a
// single whitelist entry cannot fake.
//   1. TLS handshake to 1.1.1.1:443 with certificate validation against
//      cloudflare-dns.com — direct IP defeats DNS-only whitelists; cert
//      validation defeats transparent MITM.
//   2. TLS handshake to 9.9.9.9:443 with certificate validation against
//      quad9.net — different operator from #1; whitelisting only one
//      operator (e.g. Cloudflare for the captive's own portal CDN) does
//      not satisfy the verifier.
//   3. Random-token HTTPS GET with body content check — random query
//      param defeats exact-URL whitelists; body content check defeats
//      "always 204" gateway responses.
// Quorum is 2 of 3 by default: tolerates one operator outage but rejects
// any single-whitelist captive.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// internetProbeFunc returns true iff its independent connectivity check
// passes. dialer, when non-nil, is used to bind probes to a specific
// network interface (used by the secondary-interface bypass).
type internetProbeFunc func(ctx context.Context, dialer *net.Dialer) bool

// internetVerifyProbes is the production probe set. Tests overwrite this
// (along with internetVerifyQuorum) to inject deterministic stubs.
var internetVerifyProbes = []internetProbeFunc{
	probeCloudflareDNSTLS,
	probeQuad9DNSTLS,
	probeRandomTokenHTTPS,
}

// internetVerifyQuorum is the minimum number of probes that must succeed
// for verifyInternetReachable to return true. Defaults to 2 — tolerates
// one operator outage, rejects single-whitelist captives.
var internetVerifyQuorum = 2

// internetVerifyTimeout caps the entire verification call, regardless of
// individual probe timeouts. Set conservatively for satellite RTT
// (Panasonic typical RTT ≈ 700ms; Ku/Ka 500-2500ms one-way).
var internetVerifyTimeout = 10 * time.Second

// internetVerifyEnabled toggles the captive-resistant verifier. Production
// always sets this to true (the default); tests that mock httptest servers
// for the technique-internal *CheckURL vars set it to false via saveHooks
// so the technique under test does not also need to mock TLS probes to
// 1.1.1.1 / 9.9.9.9.
//
// Bypassing the verifier is ONLY safe inside a test process. Production
// callers must never flip this — the verifier is the issue #31 fix.
var internetVerifyEnabled = true

// verifyInternetReachable runs the configured probes concurrently and
// returns true iff at least internetVerifyQuorum of them succeed within
// internetVerifyTimeout. Returns as soon as quorum is reached or every
// probe has reported.
//
// dialer, if non-nil, is propagated to each probe so callers can bind
// connectivity checks to a specific NIC (see probeInterfaceInternet).
// A nil dialer falls back to system routing.
//
// This is the canonical "do we have real internet?" check. Callers must
// not collapse it back into a single-URL probe — that's the regression
// this function exists to prevent. See issue #31.
func verifyInternetReachable(ctx context.Context, dialer *net.Dialer) bool {
	probes := internetVerifyProbes
	quorum := internetVerifyQuorum
	if quorum < 1 {
		quorum = 1
	}
	if quorum > len(probes) {
		quorum = len(probes)
	}
	if len(probes) == 0 {
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, internetVerifyTimeout)
	defer cancel()

	results := make(chan bool, len(probes))
	var wg sync.WaitGroup
	for _, p := range probes {
		wg.Add(1)
		go func(probe internetProbeFunc) {
			defer wg.Done()
			defer func() {
				// Probes must not panic, but if one does we treat it as
				// failure rather than crashing the bypass loop.
				if r := recover(); r != nil {
					select {
					case results <- false:
					case <-ctx.Done():
					}
				}
			}()
			ok := probe(ctx, dialer)
			select {
			case results <- ok:
			case <-ctx.Done():
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	successes := 0
	failures := 0
	for {
		select {
		case ok, more := <-results:
			if !more {
				return successes >= quorum
			}
			if ok {
				successes++
				if successes >= quorum {
					return true
				}
			} else {
				failures++
				// Early-exit if remaining probes can no longer reach quorum.
				if len(probes)-failures < quorum {
					return false
				}
			}
		case <-ctx.Done():
			return successes >= quorum
		}
	}
}

// ---------------------------------------------------------------------------
// Probe: TLS handshake to 1.1.1.1:443 with certificate validation
// ---------------------------------------------------------------------------

// probeCloudflareDNSTLS dials 1.1.1.1:443 directly (no DNS lookup), performs
// a full TLS handshake, and verifies the leaf certificate is issued for
// cloudflare-dns.com or one.one.one.one. A captive portal that whitelists
// 1.1.1.1 by IP and proxies the connection cannot satisfy this probe
// without breaking the certificate chain.
func probeCloudflareDNSTLS(ctx context.Context, dialer *net.Dialer) bool {
	return probeTLSReachable(ctx, dialer, "1.1.1.1:443", []string{
		"one.one.one.one",
		"cloudflare-dns.com",
	})
}

// probeQuad9DNSTLS dials 9.9.9.9:443 with the same approach. Quad9 is a
// different operator (Switzerland-based, IBM/PCH backed), so satisfying
// both this probe and probeCloudflareDNSTLS requires the captive to have
// whitelisted two unrelated operators — far less likely than whitelisting
// just gstatic.
func probeQuad9DNSTLS(ctx context.Context, dialer *net.Dialer) bool {
	return probeTLSReachable(ctx, dialer, "9.9.9.9:443", []string{
		"dns.quad9.net",
		"quad9.net",
	})
}

// probeTLSReachable establishes a TCP connection to addr and performs a
// TLS 1.2+ handshake, validating that the peer presents a certificate
// chaining to a system trust root AND that the leaf certificate's CN or
// SANs include at least one of expectedNames.
//
// Verification is left to crypto/tls (system roots). The expectedNames
// check is a defense-in-depth: even if a captive somehow presents a valid
// chain for a different host, the SAN match still has to hit one of the
// expected operator hostnames.
func probeTLSReachable(ctx context.Context, dialer *net.Dialer, addr string, expectedNames []string) bool {
	d := dialer
	if d == nil {
		d = &net.Dialer{Timeout: 5 * time.Second}
	}
	if d.Timeout == 0 {
		d.Timeout = 5 * time.Second
	}

	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = rawConn.Close() }()

	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr
	}

	// Use the first expected name as the SNI/ServerName so the cert is
	// presented for that host. crypto/tls then validates the chain
	// against system roots automatically.
	serverName := host
	if len(expectedNames) > 0 {
		serverName = expectedNames[0]
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]

	// Defense-in-depth name match: any expected name must appear in CN
	// or SANs, accounting for wildcard prefixes.
	for _, want := range expectedNames {
		if certNameMatches(leaf.Subject.CommonName, want) {
			return true
		}
		for _, san := range leaf.DNSNames {
			if certNameMatches(san, want) {
				return true
			}
		}
	}
	return false
}

// certNameMatches reports whether want satisfies certName. certName may
// be a wildcard like "*.cloudflare-dns.com"; the wildcard label matches a
// single DNS label of want.
func certNameMatches(certName, want string) bool {
	certName = strings.ToLower(strings.TrimSpace(certName))
	want = strings.ToLower(strings.TrimSpace(want))
	if certName == "" || want == "" {
		return false
	}
	if certName == want {
		return true
	}
	if strings.HasPrefix(certName, "*.") {
		suffix := certName[1:] // ".cloudflare-dns.com"
		// Wildcard matches exactly one label.
		if strings.HasSuffix(want, suffix) {
			prefix := want[:len(want)-len(suffix)]
			if prefix != "" && !strings.Contains(prefix, ".") {
				return true
			}
		}
		// A wildcard cert NEVER covers the bare apex domain by TLS spec
		// (RFC 6125 §6.4.3). Skip the parent-suffix heuristic below.
		return false
	}
	// Allow "want" to be a parent domain that the cert-name is a
	// subdomain of. E.g. cert SAN "dns.quad9.net" satisfies expected
	// "quad9.net" — same operator, different probe surface.
	if strings.HasSuffix(certName, "."+want) {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Probe: random-token HTTPS GET with body validation
// ---------------------------------------------------------------------------

// internetVerifyHTTPSURL is the HTTPS endpoint used by probeRandomTokenHTTPS.
// Overridable so future targets can be swapped without re-releasing.
var internetVerifyHTTPSURL = "https://www.google.com/generate_204"

// probeRandomTokenHTTPS issues an HTTPS GET to internetVerifyHTTPSURL with
// a random query parameter. Captive portals that whitelist exact URLs
// usually still pass query strings, but the probe also requires HTTPS
// (not just HTTP) and a 204-or-empty-body response — a portal that just
// returns 200/HTML on every URL fails the body check.
func probeRandomTokenHTTPS(ctx context.Context, dialer *net.Dialer) bool {
	tok := randomToken(8)
	url := internetVerifyHTTPSURL
	if strings.Contains(url, "?") {
		url = fmt.Sprintf("%s&n=%s", url, tok)
	} else {
		url = fmt.Sprintf("%s?n=%s", url, tok)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if dialer != nil {
		transport.DialContext = dialer.DialContext
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
		// Refuse redirects: captive portals redirect to portal pages,
		// which would otherwise confuse a naive 200/204 check.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "nowifi-internet-verify/1")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// google.com/generate_204 must return 204 with empty body. A captive
	// portal returning 200 + HTML, or a redirect, fails. A pure 204 from
	// a whitelist passes this single probe — quorum still rejects it
	// unless a second probe also passes.
	if resp.StatusCode != http.StatusNoContent {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return len(body) == 0
}

// randomToken returns a hex-encoded random string of n bytes (2*n chars).
// Used to defeat exact-URL whitelists; not cryptographic.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fallback to time-based token so the URL is still unique-ish.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
