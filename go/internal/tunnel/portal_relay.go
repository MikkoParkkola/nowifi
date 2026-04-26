// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// Portal Self-Relay — zero-config tunnel through portal-whitelisted domains.
//
// Captive portals whitelist certain domains (airline sites, payment processors,
// CDN endpoints) for pre-auth access. This technique leverages those whitelisted
// HTTPS endpoints to smuggle data:
//
//   1. Detect portal whitelisted domains (from inflight profiles or probing)
//   2. Establish HTTPS connection to whitelisted domain
//   3. HTTP/2 CONNECT or WebSocket upgrade to tunnel through
//   4. If the portal only validates SNI/DNS (not the full TLS handshake),
//      the tunnel passes transparently
//
// This is a generalization of domain fronting applied to captive portals.
// Key insight: most portals whitelist by DNS/SNI, not by inspecting the
// actual HTTP request within the TLS session.
//
// Airlines have specific whitelisted domains we already know about (see
// inflight package). This works even without airline detection — we probe
// common whitelisted domains (payment processors, CDNs, cloud APIs).
// ----------------------------------------------------------------------------

const portalRelayDefaultPort = 1094

// CommonWhitelistedDomains are domains frequently whitelisted by captive
// portals (payment, CDN, cloud APIs that portals need to function).
var CommonWhitelistedDomains = []string{
	// Payment processors (portals need these for paid WiFi)
	"js.stripe.com",
	"checkout.stripe.com",
	"api.stripe.com",
	"www.paypal.com",

	// CDNs and cloud (often whitelisted for portal assets)
	"cdn.cloudflare.com",
	"cdnjs.cloudflare.com",
	"ajax.googleapis.com",
	"fonts.googleapis.com",
	"fonts.gstatic.com",

	// Apple captive network (whitelisted so CNA works)
	"captive.apple.com",
	"www.apple.com",

	// Connectivity check endpoints (must pass for portal to function)
	"connectivitycheck.gstatic.com",
	"clients3.google.com",
	"www.msftconnecttest.com",
	"detectportal.firefox.com",
}

// ProbeWhitelistedDomain checks if a domain is reachable through the
// captive portal (i.e., whitelisted for pre-auth access).
func ProbeWhitelistedDomain(domain string, timeout time.Duration) bool {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: domain,
			MinVersion: tls.VersionTLS12,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", domain+":443")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// FindWhitelistedDomains probes common domains and returns those accessible
// through the captive portal.
func FindWhitelistedDomains(extraDomains []string, timeout time.Duration) []string {
	if timeout == 0 {
		timeout = 8 * time.Second
	}

	allDomains := make([]string, 0, len(CommonWhitelistedDomains)+len(extraDomains))
	allDomains = append(allDomains, extraDomains...)
	allDomains = append(allDomains, CommonWhitelistedDomains...)

	// Deduplicate.
	seen := make(map[string]bool, len(allDomains))
	unique := allDomains[:0]
	for _, d := range allDomains {
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}

	// Probe in parallel (up to 8 concurrent).
	type result struct {
		domain string
		ok     bool
	}

	results := make(chan result, len(unique))
	sem := make(chan struct{}, 8)

	for _, d := range unique {
		sem <- struct{}{}
		go func(domain string) {
			defer func() { <-sem }()
			results <- result{domain: domain, ok: ProbeWhitelistedDomain(domain, timeout)}
		}(d)
	}

	var reachable []string
	for range unique {
		r := <-results
		if r.ok {
			reachable = append(reachable, r.domain)
		}
	}
	return reachable
}

// StartPortalRelayTunnel attempts to relay traffic through a portal-whitelisted
// domain. The technique tries HTTP/2 CONNECT through each whitelisted domain
// in order, stopping at the first that allows tunneling.
//
// This is zero-config: no server needed. The "server" is the whitelisted
// domain's HTTPS endpoint, and we leverage the portal's trust in that domain.
func StartPortalRelayTunnel(whitelistedDomains []string, localPort int, timeout time.Duration) (*Handle, error) {
	if localPort == 0 {
		localPort = portalRelayDefaultPort
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if len(whitelistedDomains) == 0 {
		return nil, fmt.Errorf("portal relay: no whitelisted domains to try")
	}

	// Find a domain that allows HTTP/2 CONNECT tunneling.
	var workingDomain string
	for _, domain := range whitelistedDomains {
		if probeHTTP2Connect(domain, timeout) {
			workingDomain = domain
			break
		}
	}
	if workingDomain == "" {
		return nil, fmt.Errorf("portal relay: no whitelisted domain accepts HTTP/2 CONNECT")
	}

	// Start local SOCKS5 proxy that tunnels through the whitelisted domain.
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return nil, fmt.Errorf("portal relay: listen %d: %w", localPort, err)
	}

	tlsConf := &tls.Config{
		ServerName: workingDomain,
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsConf,
		ForceAttemptHTTP2: true,
	}

	h := &Handle{
		LocalPort: localPort,
		Method:    "portal_relay",
		Active:    true,
		stop:      make(chan struct{}),
		wg:        &sync.WaitGroup{},
	}
	h.wg.Add(1)
	go servePortalRelay(listener, transport, workingDomain, h.stop, h.wg)

	h.extraStop = func() {
		_ = listener.Close()
		transport.CloseIdleConnections()
	}
	return h, nil
}

// probeHTTP2Connect tests if a domain accepts HTTP/2 CONNECT requests.
// Many whitelisted domains are behind CDNs that support HTTP/2 but reject
// CONNECT. This probe verifies actual tunnel capability.
func probeHTTP2Connect(domain string, timeout time.Duration) bool {
	tlsConf := &tls.Config{
		ServerName: domain,
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := (&tls.Dialer{Config: tlsConf}).DialContext(ctx, "tcp", domain+":443")
	if err != nil {
		return false
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return false
	}
	_ = conn.Close()

	// Try an actual CONNECT request.
	transport := &http.Transport{
		TLSClientConfig:   tlsConf,
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()

	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+domain, pr)
	req.Host = "connectivitycheck.gstatic.com:443"

	resp, err := transport.RoundTrip(req)
	_ = pw.Close()
	if err != nil {
		return false
	}
	_ = resp.Body.Close()

	// 200 OK means CONNECT worked. 405/403/501 means domain rejects it.
	return resp.StatusCode == http.StatusOK
}

func servePortalRelay(l net.Listener, transport *http.Transport, domain string, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}
		if tl, ok := l.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(1 * time.Second))
		}
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		go handlePortalRelaySocks(conn, transport, domain)
	}
}

func handlePortalRelaySocks(client net.Conn, transport *http.Transport, domain string) {
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	// HTTP/2 CONNECT through the whitelisted domain.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+domain, pr)
	req.Host = target

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		socks5SendFail(client)
		return
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		socks5SendFail(client)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if err := socks5SendSuccess(client); err != nil {
		_ = resp.Body.Close()
		_ = pw.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(pw, client); _ = pw.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, resp.Body); _ = resp.Body.Close(); done <- struct{}{} }()
	<-done
}
