// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

// ---------------------------------------------------------------------------
// Technique 1: IPv6 bypass
// ---------------------------------------------------------------------------

func tryIPv6(probes *ProbeResults) Result {
	if !probes.IPv6.IsOpen {
		return Result{Method: IPv6Bypass, Success: false, Details: "No IPv6 connectivity"}
	}
	return successResult(IPv6Bypass, probes.IPv6.Details)
}

// ---------------------------------------------------------------------------
// Technique 2: HTTPS/WS tunnel (chisel)
// ---------------------------------------------------------------------------

func tryChisel(config *Config, probes *ProbeResults) Result {
	// Strategy 1: Via Cloudflare Tunnel (default URL, port 443)
	cfReachable := probes.Cloudflare.IsOpen
	for _, w := range probes.Whitelists {
		if w.IsOpen {
			cfReachable = true
			break
		}
	}

	if cfReachable && config.TunnelServer != "" {
		handle, err := tunnel.StartChisel(config.TunnelServer, 1080, 15*time.Second)
		if err == nil {
			if tunnel.VerifySOCKS(handle.LocalPort) {
				return successResult(
					ChiselTunnel,
					fmt.Sprintf("HTTPS/WebSocket tunnel through %s", config.TunnelServer),
					withTunnel(handle),
				)
			}
			handle.Stop()
		}
	}

	// Strategy 2: Direct to server on any open port found during stealth scan
	if config.TunnelServer != "" {
		serverHost := ""
		if u, err := url.Parse(config.TunnelServer); err == nil && u.Hostname() != "" {
			serverHost = u.Hostname()
		}

		var serverIP string
		if serverHost != "" {
			if addrs, err := net.LookupHost(serverHost); err == nil && len(addrs) > 0 {
				serverIP = addrs[0]
			}
		}

		if serverIP != "" {
			for _, pr := range probes.TunnelServerPorts {
				if !pr.IsOpen {
					continue
				}
				directURL := fmt.Sprintf("http://%s:%d", serverIP, pr.Port)
				logStatus("  Trying chisel direct: %s", directURL)
				handle, err := tunnel.StartChisel(directURL, 1080, 8*time.Second)
				if err != nil {
					continue
				}
				if tunnel.VerifySOCKS(handle.LocalPort) {
					return successResult(
						ChiselTunnel,
						fmt.Sprintf("Chisel direct to %s:%d (bypassed Cloudflare, portal allows port %d)", serverIP, pr.Port, pr.Port),
						withImpact(fmt.Sprintf("Full internet via direct tunnel on port %d", pr.Port)),
						withRemediation(fmt.Sprintf("Block outbound port %d for unauthenticated clients. Inspect non-standard port traffic.", pr.Port)),
						withTunnel(handle),
					)
				}
				handle.Stop()
			}
		}
	}

	return Result{Method: ChiselTunnel, Success: false, Details: "No route to tunnel server (CF blocked, no direct ports open)"}
}

// ---------------------------------------------------------------------------
// Technique 5: HTTP CONNECT abuse
// ---------------------------------------------------------------------------

func tryHTTPConnect(probes *ProbeResults, config *Config, plat PlatformOps) Result {
	gateway := plat.GetGateway(config.Interface)
	if gateway == "" {
		return Result{Method: HTTPConnect, Success: false, Details: "No gateway"}
	}
	// Validate gateway IP from system output before using in network calls.
	if ip := net.ParseIP(gateway); ip == nil {
		return Result{Method: HTTPConnect, Success: false, Details: "Invalid gateway IP"}
	}

	for _, proxyPort := range []int{80, 8080, 3128} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", gateway, proxyPort))
		if err != nil {
			cancel()
			continue
		}

		_, _ = conn.Write([]byte("CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"))
		buf := make([]byte, 4096)
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			conn.Close()
			cancel()
			continue
		}
		n, _ := conn.Read(buf)
		conn.Close()
		cancel()

		resp := string(buf[:n])
		if strings.Contains(resp, "200") {
			return successResult(
				HTTPConnect,
				"Portal's transparent proxy allows CONNECT to arbitrary hosts",
				withImpact(fmt.Sprintf("HTTP CONNECT tunnel via gateway %s:%d", gateway, proxyPort)),
			)
		}
	}

	return Result{Method: HTTPConnect, Success: false, Details: "CONNECT not available through gateway"}
}

// ---------------------------------------------------------------------------
// Technique 10: VPN on port 53
// ---------------------------------------------------------------------------

func tryVPNPort53(config *Config, probes *ProbeResults) Result {
	if config.VPNServer == "" {
		return Result{Method: VPNPort53, Success: false, Details: "No VPN server configured (use --vpn-server)"}
	}

	// Check if port 53 UDP is open.
	open53 := false
	for _, p := range probes.OpenPorts {
		if p.Port == 53 && p.IsOpen {
			open53 = true
			break
		}
	}
	if !open53 && !probes.DNS.IsOpen {
		return Result{Method: VPNPort53, Success: false, Details: "Port 53 not open"}
	}

	// Try WireGuard.
	if wg, err := exec.LookPath("wg-quick"); err == nil {
		_ = wg // use the found path
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := exec.CommandContext(ctx, "sudo", "wg-quick", "up", "wg-nowifi").Run()
		cancel()

		if err == nil {
			time.Sleep(3 * time.Second)
			if HasInternet() {
				return successResult(VPNPort53, fmt.Sprintf("WireGuard to %s:53 -- portal allows UDP/53", config.VPNServer))
			}
		}
	}

	return Result{Method: VPNPort53, Success: false, Details: "WireGuard not available or connection failed"}
}

// ---------------------------------------------------------------------------
// Technique 11: Whitelist domain abuse
// ---------------------------------------------------------------------------

func tryWhitelist(probes *ProbeResults) Result {
	var openDomains []string
	for _, w := range probes.Whitelists {
		if w.IsOpen {
			openDomains = append(openDomains, w.Domain)
		}
	}

	if len(openDomains) == 0 {
		return Result{Method: WhitelistDomain, Success: false, Details: "No whitelisted domains reachable"}
	}

	return findingResult(
		WhitelistDomain,
		fmt.Sprintf("Whitelisted domains found (%s) but no dedicated tunnel server on them. Chisel via CF is the primary exploit.", strings.Join(openDomains, ", ")),
	)
}
