// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"strings"
	"time"

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
		return Result{
			Method:      DNSTunnel,
			Success:     true,
			Severity:    "high",
			Impact:      "Internet via DNS tunnel (50-500 Kbps)",
			Details:     fmt.Sprintf("IP-over-DNS through %s", config.DNSDomain),
			Remediation: "Restrict DNS to portal resolvers. Block UDP/53 to external IPs. Inspect DNS for tunnel signatures.",
			Tunnel:      handle,
		}
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
		return Result{
			Method:      ICMPTunnel,
			Success:     true,
			Severity:    "high",
			Impact:      "Internet via ICMP tunnel (100-300 Kbps)",
			Details:     fmt.Sprintf("IP-over-ICMP to %s", config.ICMPServer),
			Remediation: "Block/rate-limit ICMP to external hosts. Allow only to gateway.",
			Tunnel:      handle,
		}
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
		return Result{
			Method:      QUICTunnel,
			Success:     true,
			Severity:    "critical",
			Impact:      "Full internet via QUIC tunnel (UDP/443 -- looks like HTTP/3)",
			Details:     fmt.Sprintf("Hysteria2 QUIC tunnel to %s. Portal only filters TCP, UDP passes through.", server),
			Remediation: "Inspect UDP/443 traffic. Block non-HTTP/3 QUIC connections for unauthenticated clients. Deploy QUIC-aware DPI.",
			Tunnel:      handle,
		}
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
		return Result{
			Method:      CFWorkers,
			Success:     true,
			Severity:    "critical",
			Impact:      "Full internet via Cloudflare Workers proxy (serverless, free, no server needed)",
			Details:     fmt.Sprintf("CF Worker at %s proxies requests. Traffic goes to trusted Cloudflare IPs.", workerURL),
			Remediation: "Block access to *.workers.dev domains. Inspect HTTPS traffic to Cloudflare for proxy patterns. Consider blocking unknown Cloudflare subdomains.",
		}
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
		return Result{
			Method:      NTPTunnel,
			Success:     true,
			Severity:    "high",
			Impact:      "Internet via NTP tunnel (UDP/123, ~1-10 Kbps -- slow but stealthy)",
			Details:     fmt.Sprintf("Data encoded in NTP extension fields to %s. NTP is almost never blocked.", config.NTPServer),
			Remediation: "Restrict NTP to known time servers only. Inspect NTP packets for abnormal extension fields or payload sizes. Rate-limit NTP traffic per client.",
			Tunnel:      handle,
		}
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
		return Result{
			Method:      DoHTunnel,
			Success:     true,
			Severity:    "high",
			Impact:      "DNS resolution via encrypted DoH (enables further tunneling)",
			Details:     "DNS-over-HTTPS to Cloudflare/Google. Bypasses DNS interception by portal.",
			Remediation: "Block DoH endpoints (cloudflare-dns.com, dns.google) for unauthenticated clients. Deploy DoH-aware filtering.",
			Tunnel:      handle,
		}
	}

	handle.Stop()
	return Result{Method: DoHTunnel, Success: false, Details: "DoH tunnel connected but no internet access"}
}
