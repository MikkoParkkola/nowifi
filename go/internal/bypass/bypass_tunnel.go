// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/inflight"
	"github.com/MikkoParkkola/nowifi/internal/server"
	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

var (
	startDoHTunnelFn  = tunnel.StartDoHTunnel
	doHTunnelVerifyFn = tunnel.VerifyDirect
)

// ---------------------------------------------------------------------------
// Technique 8: DNS tunnel
// ---------------------------------------------------------------------------

func tryDNSTunnel(config *Config, probes *ProbeResults) Result {
	if !probes.DNS.IsOpen {
		return Result{Method: DNSTunnel, Success: false, Details: "DNS not open"}
	}
	if config.DNSDomain == "" {
		return Result{Method: DNSTunnel, Success: false, Details: "No DNS tunnel domain configured (use --dns-domain)"}
	}

	handle, err := tunnel.StartDNSTunnel(config.DNSDomain, "", 30*time.Second)
	if err != nil {
		return Result{Method: DNSTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if tunnel.VerifyDirect() {
		return successResult(
			DNSTunnel,
			fmt.Sprintf("IP-over-DNS through %s", config.DNSDomain),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{Method: DNSTunnel, Success: false, Details: "Tunnel connected but no internet"}
}

// ---------------------------------------------------------------------------
// Technique 9: ICMP tunnel
// ---------------------------------------------------------------------------

func tryICMPTunnel(config *Config, probes *ProbeResults) Result {
	if !probes.ICMP.IsOpen {
		return Result{Method: ICMPTunnel, Success: false, Details: "ICMP not open"}
	}
	if config.ICMPServer == "" {
		return Result{Method: ICMPTunnel, Success: false, Details: "No ICMP server configured (use --icmp-server)"}
	}

	handle, err := tunnel.StartICMPTunnel(config.ICMPServer, 15*time.Second)
	if err != nil {
		return Result{Method: ICMPTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if tunnel.VerifyDirect() {
		return successResult(
			ICMPTunnel,
			fmt.Sprintf("IP-over-ICMP to %s", config.ICMPServer),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{Method: ICMPTunnel, Success: false, Details: "Tunnel connected but no internet"}
}

// ---------------------------------------------------------------------------
// Technique 16: QUIC tunnel (Hysteria2)
// ---------------------------------------------------------------------------

func tryQUICTunnel(config *Config, probes *ProbeResults) Result {
	if !probes.QUIC.IsOpen {
		return Result{Method: QUICTunnel, Success: false, Details: "UDP/443 (QUIC) blocked"}
	}

	server := config.QUICServer
	if server == "" {
		server = config.TunnelServer
	}
	if server == "" {
		return Result{Method: QUICTunnel, Success: false, Details: "No QUIC server configured"}
	}

	handle, err := tunnel.StartQUICTunnel(server, 1081, 15*time.Second)
	if err != nil {
		return Result{Method: QUICTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			QUICTunnel,
			fmt.Sprintf("Hysteria2 QUIC tunnel to %s. Portal only filters TCP, UDP passes through.", server),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{Method: QUICTunnel, Success: false, Details: "QUIC tunnel connected but verification failed"}
}

// ---------------------------------------------------------------------------
// Technique 17: Cloudflare Workers proxy
// ---------------------------------------------------------------------------

func tryCFWorkers(config *Config, probes *ProbeResults) Result {
	workerURL := config.CFWorkersURL

	// Auto-discover: if no URL configured, check saved server config.
	if workerURL == "" {
		cfg := server.LoadConfig()
		if url, ok := cfg["cf_workers_url"]; ok && url != "" {
			workerURL = url
			logStatus("Found saved CF Workers URL: %s", workerURL)
		}
	}

	// Auto-deploy: if still no URL, try to deploy a free CF Worker.
	if workerURL == "" {
		logStatus("No CF Workers URL — attempting auto-deploy (free, ~30s)...")
		info, err := server.SetupCloudflareWorker()
		if err != nil {
			// Not an error — user just doesn't have wrangler/CF account set up.
			return Result{Method: CFWorkers, Success: false,
				Details: fmt.Sprintf("No CF Workers URL and auto-deploy unavailable: %v. Run `nowifi server create` to set up.", err)}
		}
		workerURL = info.URL
		logStatus("Auto-deployed CF Worker: %s", workerURL)
	}

	// Check if Cloudflare is reachable.
	cfOpen := probes.Cloudflare.IsOpen
	for _, w := range probes.Whitelists {
		if w.IsOpen && strings.Contains(strings.ToLower(w.Domain), "cloudflare") {
			cfOpen = true
			break
		}
	}
	if !cfOpen {
		return Result{Method: CFWorkers, Success: false, Details: "Cloudflare not reachable pre-auth"}
	}

	if tunnel.VerifyCFWorkersProxy(workerURL) {
		return successResult(CFWorkers, fmt.Sprintf("CF Worker at %s proxies requests. Traffic goes to trusted Cloudflare IPs.", workerURL))
	}

	return Result{Method: CFWorkers, Success: false, Details: "CF Workers proxy not functional"}
}

// ---------------------------------------------------------------------------
// Technique 18: NTP tunnel
// ---------------------------------------------------------------------------

func tryNTPTunnel(config *Config, probes *ProbeResults) Result {
	if !probes.NTP.IsOpen {
		return Result{Method: NTPTunnel, Success: false, Details: "NTP (UDP/123) blocked"}
	}

	if config.NTPServer == "" {
		return Result{Method: NTPTunnel, Success: false, Details: "No NTP tunnel server configured (use --ntp-server)"}
	}

	handle, err := tunnel.StartNTPTunnel(config.NTPServer, 1082, 20*time.Second)
	if err != nil {
		return Result{Method: NTPTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			NTPTunnel,
			fmt.Sprintf("Data encoded in NTP extension fields to %s. NTP is almost never blocked.", config.NTPServer),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{Method: NTPTunnel, Success: false, Details: "NTP tunnel connected but verification failed"}
}

// ---------------------------------------------------------------------------
// Technique 19: DoH tunnel
// ---------------------------------------------------------------------------

func tryDoHTunnel(probes *ProbeResults) Result {
	if !probes.DoH.IsOpen {
		return Result{Method: DoHTunnel, Success: false, Details: "DoH endpoints not reachable"}
	}

	handle, err := startDoHTunnelFn(1083, "", 15*time.Second)
	if err != nil {
		return Result{Method: DoHTunnel, Success: false, Details: fmt.Sprintf("Failed: %v", err)}
	}

	if doHTunnelVerifyFn() {
		handle.LocalPort = 0
		return successResult(
			DoHTunnel,
			"DNS-over-HTTPS to Cloudflare/Google. Bypasses DNS interception by portal.",
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{Method: DoHTunnel, Success: false, Details: "DoH tunnel connected but no internet access"}
}

// Wave 20 (2026-04): Modern portal/transport techniques.
//
// CAPPORTExtend  — queries the RFC 8908 API endpoint (discovered via DHCP
//                  option 114 or Config.CAPPORTURL) and reports session status.
// DoQTunnel      — pure-Go DNS-over-QUIC client (RFC 9250) speaking to a DoQ
//                  resolver over UDP/853. Runs a local UDP/53 proxy.
// HTTP3Tunnel    — pure-Go HTTP/3 CONNECT tunnel (quic-go) wrapped as a local
//                  SOCKS5-lite listener on TCP.

// tryCAPPORTExtend queries the RFC 8908 CAPPORT API and reports session status.
// Success means the API is reachable and returns a usable response; the Details
// field contains the user-portal-url for session extension if supported.
func tryCAPPORTExtend(config *Config, _ *ProbeResults) Result {
	if config == nil || config.CAPPORTURL == "" {
		return Result{
			Method:  CAPPORTExtend,
			Success: false,
			Details: "No CAPPORT URL available (not advertised via DHCP option 114 on this network).",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	resp, err := inflight.QueryCAPPORT(ctx, config.CAPPORTURL, 5*time.Second)
	if err != nil {
		return Result{
			Method:  CAPPORTExtend,
			Success: false,
			Details: fmt.Sprintf("CAPPORT API unreachable: %v", err),
		}
	}

	// Build human-readable status.
	var status string
	if resp.IsCaptive() {
		status = "CAPTIVE (not authenticated)"
	} else {
		status = "AUTHENTICATED"
	}

	details := fmt.Sprintf("RFC 8908 CAPPORT API reachable. Status: %s.", status)
	if remaining := resp.SessionRemaining(); remaining > 0 {
		details += fmt.Sprintf(" Session expires in %ds.", remaining)
	}
	if resp.CanExtend() && resp.UserPortalURL != "" {
		details += fmt.Sprintf(" Extend session at: %s", resp.UserPortalURL)
	} else if resp.UserPortalURL != "" {
		details += fmt.Sprintf(" User portal: %s", resp.UserPortalURL)
	}

	// Success when API is reachable and parseable. If we're captive, the user
	// still needs to authenticate -- but knowing the portal URL is a valuable
	// signal that saves guesswork.
	return Result{
		Method:  CAPPORTExtend,
		Success: !resp.IsCaptive(),
		Details: details,
	}
}

// tryDoQTunnel opens a DNS-over-QUIC channel to a public DoQ resolver
// (default dns.adguard.com:853) and starts a local UDP/53 proxy. Success
// means the QUIC handshake completed AND a test DNS query resolved through
// the tunnel. Bypass-relevant: DoQ is rarely filtered distinctly from
// generic QUIC/HTTP/3 and portals can no longer intercept DNS responses.
func tryDoQTunnel(config *Config, probes *ProbeResults) Result {
	if probes != nil && !probes.QUIC.IsOpen {
		return Result{
			Method:  DoQTunnel,
			Success: false,
			Details: "QUIC/UDP transport blocked; DoQ unreachable.",
		}
	}

	server := ""
	if config != nil {
		server = config.DoQServer
	}
	if server == "" {
		server = "dns.adguard.com:853"
	}

	handle, err := tunnel.StartDoQTunnel(server, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  DoQTunnel,
			Success: false,
			Details: fmt.Sprintf("DoQ dial failed (%s): %v", server, err),
		}
	}

	return successResult(
		DoQTunnel,
		fmt.Sprintf("DNS-over-QUIC (RFC 9250) to %s active on UDP/127.0.0.1:%d. Bypasses DNS interception.", server, handle.LocalPort),
		withTunnel(handle),
	)
}

// tryHTTP3Tunnel opens an HTTP/3 CONNECT channel to the configured tunnel
// server and exposes it locally as a SOCKS5-lite proxy (TCP). The transport
// is UDP/443 QUIC, which passes through TCP-only middleboxes.
func tryHTTP3Tunnel(config *Config, probes *ProbeResults) Result {
	if probes != nil && !probes.QUIC.IsOpen {
		return Result{
			Method:  HTTP3Tunnel,
			Success: false,
			Details: "UDP/443 (QUIC) blocked; HTTP/3 cannot reach server.",
		}
	}

	serverURL := ""
	if config != nil {
		serverURL = config.HTTP3Server
		if serverURL == "" {
			// Fall back to TunnelServer, rewriting ws/wss/http to https.
			serverURL = deriveHTTP3URL(config.TunnelServer)
		}
	}
	if serverURL == "" {
		return Result{
			Method:  HTTP3Tunnel,
			Success: false,
			Details: "No HTTP/3 server configured (--http3-server or --tunnel-server).",
		}
	}

	handle, err := tunnel.StartHTTP3Tunnel(serverURL, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  HTTP3Tunnel,
			Success: false,
			Details: fmt.Sprintf("HTTP/3 tunnel failed (%s): %v", serverURL, err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			HTTP3Tunnel,
			fmt.Sprintf("HTTP/3 CONNECT tunnel to %s over UDP/443 QUIC; SOCKS5 at 127.0.0.1:%d.", serverURL, handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  HTTP3Tunnel,
		Success: false,
		Details: "HTTP/3 tunnel connected but SOCKS verification failed (server may not support CONNECT).",
	}
}

// deriveHTTP3URL rewrites chisel-style ws/wss/http/https URLs to an https://
// URL suitable for HTTP/3. Returns "" when the input is unusable.
func deriveHTTP3URL(in string) string {
	if in == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(in, "https://"):
		return in
	case strings.HasPrefix(in, "http://"):
		return "https://" + strings.TrimPrefix(in, "http://")
	case strings.HasPrefix(in, "wss://"):
		return "https://" + strings.TrimPrefix(in, "wss://")
	case strings.HasPrefix(in, "ws://"):
		return "https://" + strings.TrimPrefix(in, "ws://")
	default:
		return "https://" + in
	}
}
