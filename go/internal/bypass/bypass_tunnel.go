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
