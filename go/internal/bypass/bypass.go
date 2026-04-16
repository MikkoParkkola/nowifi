// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package bypass implements ordered captive portal bypass techniques.
//
// After a successful bypass, internet works system-wide (including browser)
// with zero manual steps. All changes are temporary and restored when nowifi
// exits via the guard package.
//
// Techniques ordered most-powerful-first:
//
//  1. IPv6 bypass          - portal only filters IPv4
//  2. HTTPS/WS tunnel      - chisel through Cloudflare to your server
//  3. CNA User-Agent spoof - portal auto-approves Apple CNA requests
//  4. JS-only bypass       - portal enforces auth only in JavaScript
//  5. HTTP CONNECT abuse   - tunnel through portal's transparent proxy
//  6. MAC clone (idle)     - steal an inactive authenticated device's session
//  7. MAC clone (any)      - steal any authenticated device's session
//  8. DNS tunnel           - IP-over-DNS through your server
//  9. ICMP tunnel          - IP-over-ping through your server
//  10. VPN on port 53       - WireGuard/OpenVPN on DNS port
//  11. Whitelist domain     - tunnel via whitelisted CDN domain
//  12. Session cookie replay- sniff and replay portal auth cookies
//  13. Portal default creds - try default admin passwords on portal
//  14. MAC rotate           - fresh random MAC for new session/quota
//  15. DHCP rotate          - new IP via DHCP release/renew cycle
//  16. QUIC tunnel          - Hysteria2 over UDP/443 (looks like HTTP/3)
//  17. CF Workers proxy     - serverless proxy via Cloudflare Workers
//  18. NTP tunnel           - data over UDP/123 (almost never blocked)
//  19. DoH tunnel           - DNS-over-HTTPS to bypass DNS interception
package bypass

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/techniques"
	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

var setSystemProxyFn = platform.SetSystemProxy

// Method identifies a specific bypass technique.
type Method = techniques.ID

const (
	IPv6Bypass      Method = techniques.IPv6Bypass
	ChiselTunnel    Method = techniques.ChiselTunnel
	CNASpoof        Method = techniques.CNASpoof
	JSBypass        Method = techniques.JSOnlyPortal //nolint:gosec // descriptive method name, not a secret
	HTTPConnect     Method = techniques.HTTPConnect
	MACCloneIdle    Method = techniques.MACCloneIdle
	MACClone        Method = techniques.MACClone
	DNSTunnel       Method = techniques.DNSTunnel
	ICMPTunnel      Method = techniques.ICMPTunnel
	VPNPort53       Method = techniques.VPNPort53
	WhitelistDomain Method = techniques.WhitelistDomain
	SessionReplay   Method = techniques.SessionReplay
	PortalCreds     Method = techniques.PortalCreds
	MACRotate       Method = techniques.MACRotate
	DHCPRotate      Method = techniques.DHCPRotate
	QUICTunnel      Method = techniques.QUICTunnel
	CFWorkers       Method = techniques.CFWorkers
	NTPTunnel       Method = techniques.NTPTunnel
	DoHTunnel       Method = techniques.DoHTunnel
	// Wave 20: Modern portal/transport techniques.
	CAPPORTExtend Method = techniques.CAPPORTExtend
	DoQTunnel     Method = techniques.DoQTunnel
	HTTP3Tunnel   Method = techniques.HTTP3Tunnel
	// Wave 21: serverless DHCP-advertised route injection.
	DHCPRouteBypass Method = techniques.DHCPRouteBypass
	// Wave 21: TLS 1.3 ECH (RFC 9147) domain fronting.
	ECHFronting Method = techniques.ECHFronting
	// Wave 21: WireGuard-over-WebSocket tunnel.
	WGOverWebSocket Method = techniques.WGOverWebSocket
	// Wave 21: Secondary interface (cellular/ethernet/tethered) bypass.
	SecondaryIfaceBypass Method = techniques.SecondaryIfaceBypass
	// Wave 21: MASQUE tunnel (HTTP/3 Extended CONNECT).
	MASQUETunnel Method = techniques.MASQUETunnel
	// Wave 21: WebTransport tunnel (RFC 9220).
	WebTransportTunnel Method = techniques.WebTransportTunnel
)

// Config holds user-specified settings for the bypass engine.
type Config struct {
	Interface    string
	TunnelServer string
	DNSDomain    string
	ICMPServer   string
	QUICServer   string
	NTPServer    string
	CFWorkersURL string
	VPNServer    string
	Stealth      bool
	// CAPPORTURL is the RFC 8908 captive-portal API endpoint, typically
	// discovered via DHCP option 114 or router advertisement option 37.
	// Empty string means CAPPORT API is unavailable for this network.
	CAPPORTURL string
	// HTTP3Server is the URL (scheme+host) of a tunnel-server speaking
	// HTTP/3 CONNECT. If empty, the HTTP3Tunnel technique attempts to derive
	// one from TunnelServer (by rewriting chisel http/https schemes to https).
	HTTP3Server string
	// DoQServer is a DNS-over-QUIC endpoint in host:port form.
	// Defaults to dns.adguard.com:853 when empty.
	DoQServer string
	// DHCPClasslessRoutes holds RFC 3442 option 121 routes advertised by
	// the DHCP server on Interface. Populated by the audit pipeline from
	// platform.GetDHCPClasslessRoutes at probe time. Non-default routes
	// here enable the Wave 21 #23 DHCPRouteBypass technique.
	DHCPClasslessRoutes []platform.DHCPRoute
	// WSServerURL is a WebSocket tunnel endpoint (wss://...). Powers #25.
	WSServerURL string
	// ECHServerURL is the HTTPS endpoint of an ECH-capable bypass proxy
	// (typically a Cloudflare Worker or custom reverse proxy whose domain
	// has ECH enabled in its HTTPS DNS RR).
	ECHServerURL string
	// ECHConfigListBase64 is the base64-encoded ECHConfigList value from
	// the server's HTTPS DNS RR ech= field. Operator-provided for now;
	// future work may fetch it via DoH.
	ECHConfigListBase64 string
	// MASQUEServerURL is the MASQUE proxy endpoint (https://...). Powers #27.
	MASQUEServerURL string
	// WTServerURL is the WebTransport tunnel endpoint (https://...). Powers #28.
	WTServerURL string
}

// Result records the outcome of a single bypass attempt.
type Result struct {
	Method      Method
	Success     bool
	Severity    string // critical, high, medium, low, info
	Impact      string
	Details     string
	Remediation string
	Tunnel      *tunnel.Handle
}

type resultOption func(*Result)

func withImpact(impact string) resultOption {
	return func(result *Result) {
		result.Impact = impact
	}
}

func withRemediation(remediation string) resultOption {
	return func(result *Result) {
		result.Remediation = remediation
	}
}

func withTunnel(handle *tunnel.Handle) resultOption {
	return func(result *Result) {
		result.Tunnel = handle
	}
}

func buildTechniqueResult(method Method, success bool, details string, metadata techniques.BypassTechniqueResultMetadata, opts ...resultOption) Result {
	result := Result{
		Method:      method,
		Success:     success,
		Severity:    metadata.Severity,
		Impact:      metadata.Impact,
		Details:     details,
		Remediation: metadata.Remediation,
	}
	for _, opt := range opts {
		opt(&result)
	}
	return result
}

func successResult(method Method, details string, opts ...resultOption) Result {
	metadata, _ := techniques.SuccessResultMetadataByID(techniques.ID(method))
	return buildTechniqueResult(method, true, details, metadata, opts...)
}

func findingResult(method Method, details string, opts ...resultOption) Result {
	metadata, _ := techniques.FindingResultMetadataByID(techniques.ID(method))
	return buildTechniqueResult(method, false, details, metadata, opts...)
}

// ---------------------------------------------------------------------------
// Probe result interfaces -- minimal types needed from the probe package.
// The actual probe package implements these; we define them here so bypass
// can compile independently.
// ---------------------------------------------------------------------------

// ProbeResult holds the status of a single protocol probe.
type ProbeResult struct {
	IsOpen  bool
	Details string
}

// WhitelistResult holds a probed whitelisted domain.
type WhitelistResult struct {
	Domain  string
	IsOpen  bool
	Details string
}

// PortResult holds a probed TCP port.
type PortResult struct {
	Port    int
	Service string
	IsOpen  bool
}

// ProbeResults is the full set of probe outcomes consumed by the bypass engine.
// This mirrors the probe.Results struct; the caller maps from probe.Results to this.
type ProbeResults struct {
	DNS        ProbeResult
	ICMP       ProbeResult
	IPv6       ProbeResult
	Cloudflare ProbeResult
	QUIC       ProbeResult
	NTP        ProbeResult
	DoH        ProbeResult

	Whitelists        []WhitelistResult
	OpenPorts         []PortResult
	TunnelServerPorts []PortResult
}

// PlatformOps abstracts the platform-specific operations needed by bypass
// techniques. This allows testing with mocks and decouples from the concrete
// platform package's build-tag-gated functions.
type PlatformOps interface {
	GetGateway(iface string) string
	GetCurrentMAC(iface string) string
	GetArpTable() []platform.ArpEntry
	SetMAC(iface, mac string) bool
	RenewDHCP(iface string)
	GenerateRandomMAC() string
}

// RunBypasses tries every registered bypass technique in order, stopping on
// the first success. Returns the list of all attempted results.
func RunBypasses(probes *ProbeResults, config *Config, plat PlatformOps) []Result {
	if plat == nil {
		plat = &defaultPlatformOps{}
	}

	hasServer := config.TunnelServer != ""
	if !hasServer {
		logStatus("No tunnel server configured -- trying serverless techniques first.")
		logStatus("Tip: `nowifi server create` deploys a free Cloudflare Worker (~30s).")
	}

	var results []Result
	for _, t := range orderedTechniqueRunners() {
		tName := t.runName // capture for panic recovery
		logStatus("Trying: %s...", tName)
		r := func() (result Result) {
			defer func() {
				if rec := recover(); rec != nil {
					result = Result{Success: false, Details: fmt.Sprintf("panic in %s: %v", tName, rec)}
				}
			}()
			return t.run(probes, config, plat)
		}()

		r = finalizeSuccessfulTunnelResult(config.Interface, r)

		results = append(results, r)
		if r.Success {
			logStatus("SUCCESS: %s", t.runName)
			return results
		}
		logStatus("Failed: %s", t.runName)
	}

	return results
}

type techniqueRunner struct {
	runName string
	run     func(*ProbeResults, *Config, PlatformOps) Result
}

func missingTechniqueRunner(info techniques.BypassTechniqueInfo) techniqueRunner {
	method := Method(info.ID)
	details := fmt.Sprintf("internal error: missing runner for technique %s", info.ID)
	return techniqueRunner{
		runName: info.Name,
		run: func(_ *ProbeResults, _ *Config, _ PlatformOps) Result {
			return Result{
				Method:      method,
				Success:     false,
				Severity:    "critical",
				Details:     details,
				Remediation: "Update internal bypass runner registry to match canonical technique metadata",
			}
		},
	}
}

var techniqueRunnerByMethod = map[Method]techniqueRunner{
	IPv6Bypass: {
		run: func(probes *ProbeResults, _ *Config, _ PlatformOps) Result { return tryIPv6(probes) },
	},
	ChiselTunnel: {
		runName: "HTTPS tunnel (chisel)",
		run:     func(probes *ProbeResults, config *Config, _ PlatformOps) Result { return tryChisel(config, probes) },
	},
	CNASpoof: {
		run: func(_ *ProbeResults, _ *Config, _ PlatformOps) Result { return tryCNASpoof() },
	},
	JSBypass: {
		run: func(_ *ProbeResults, _ *Config, _ PlatformOps) Result { return tryJSBypass() },
	},
	HTTPConnect: {
		run: func(probes *ProbeResults, config *Config, plat PlatformOps) Result {
			return tryHTTPConnect(probes, config, plat)
		},
	},
	MACCloneIdle: {
		run: func(_ *ProbeResults, config *Config, plat PlatformOps) Result {
			return tryMACClone(config.Interface, true, plat)
		},
	},
	MACClone: {
		run: func(_ *ProbeResults, config *Config, plat PlatformOps) Result {
			return tryMACClone(config.Interface, false, plat)
		},
	},
	DNSTunnel: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result { return tryDNSTunnel(config, probes) },
	},
	ICMPTunnel: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result { return tryICMPTunnel(config, probes) },
	},
	VPNPort53: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result { return tryVPNPort53(config, probes) },
	},
	WhitelistDomain: {
		run: func(probes *ProbeResults, _ *Config, _ PlatformOps) Result { return tryWhitelist(probes) },
	},
	SessionReplay: {
		run: func(_ *ProbeResults, config *Config, plat PlatformOps) Result {
			return trySessionReplay(config.Interface, plat)
		},
	},
	PortalCreds: {
		run: func(_ *ProbeResults, config *Config, plat PlatformOps) Result {
			return tryDefaultCreds(config.Interface, plat)
		},
	},
	MACRotate: {
		run: func(_ *ProbeResults, config *Config, plat PlatformOps) Result {
			return tryMACRotate(config.Interface, plat)
		},
	},
	DHCPRotate: {
		run: func(_ *ProbeResults, config *Config, plat PlatformOps) Result {
			return tryDHCPRotate(config.Interface, plat)
		},
	},
	QUICTunnel: {
		runName: "QUIC tunnel (Hysteria2)",
		run:     func(probes *ProbeResults, config *Config, _ PlatformOps) Result { return tryQUICTunnel(config, probes) },
	},
	CFWorkers: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result { return tryCFWorkers(config, probes) },
	},
	NTPTunnel: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result { return tryNTPTunnel(config, probes) },
	},
	DoHTunnel: {
		run: func(probes *ProbeResults, _ *Config, _ PlatformOps) Result { return tryDoHTunnel(probes) },
	},
	// Wave 20: Modern portal/transport techniques (detection-only stubs for now;
	// execution runners pending implementation in follow-up PRs).
	CAPPORTExtend: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result {
			return tryCAPPORTExtend(config, probes)
		},
	},
	DoQTunnel: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result { return tryDoQTunnel(config, probes) },
	},
	HTTP3Tunnel: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result {
			return tryHTTP3Tunnel(config, probes)
		},
	},
	// Wave 21: DHCP-advertised static route injection.
	DHCPRouteBypass: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result {
			return tryDHCPRouteBypass(config, probes)
		},
	},
	// Wave 21: TLS 1.3 ECH domain fronting.
	ECHFronting: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result {
			return tryECHFronting(config, probes)
		},
	},
	// Wave 21: WireGuard-over-WebSocket tunnel.
	WGOverWebSocket: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result {
			return tryWGOverWebSocket(config, probes)
		},
	},
	// Wave 21: Secondary interface bypass.
	SecondaryIfaceBypass: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result {
			return trySecondaryIfaceBypass(config, probes)
		},
	},
	// Wave 21: MASQUE tunnel (HTTP/3 Extended CONNECT).
	MASQUETunnel: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result {
			return tryMASQUETunnel(config, probes)
		},
	},
	// Wave 21: WebTransport tunnel (RFC 9220).
	WebTransportTunnel: {
		run: func(probes *ProbeResults, config *Config, _ PlatformOps) Result {
			return tryWebTransportTunnel(config, probes)
		},
	},
}

func orderedTechniqueRunners() []techniqueRunner {
	infos := techniques.BypassTechniqueInfos()
	runners := make([]techniqueRunner, 0, len(infos))
	for _, info := range infos {
		runner, ok := techniqueRunnerByMethod[Method(info.ID)]
		if !ok {
			runners = append(runners, missingTechniqueRunner(info))
			continue
		}
		if runner.runName == "" {
			runner.runName = info.Name
		}
		runners = append(runners, runner)
	}
	return runners
}

// ClearSystemSOCKSProxy removes the system-wide SOCKS proxy.
// Called by the guard package on cleanup.
func ClearSystemSOCKSProxy(iface string) {
	_ = platform.ClearSystemProxy(iface)
}

// ---------------------------------------------------------------------------
// System proxy management
// ---------------------------------------------------------------------------

func setSystemSOCKSProxy(iface string, port int) error {
	return setSystemProxyFn(iface, port)
}

func finalizeSuccessfulTunnelResult(iface string, result Result) Result {
	if !result.Success || result.Tunnel == nil || !result.Tunnel.Active || result.Tunnel.LocalPort <= 0 {
		return result
	}

	if err := setSystemSOCKSProxy(iface, result.Tunnel.LocalPort); err != nil {
		port := result.Tunnel.LocalPort
		result.Tunnel.Stop()
		result.Tunnel = nil
		result.Success = false
		result.Severity = ""
		result.Impact = ""
		result.Remediation = "Fix local proxy configuration permissions and retry."
		proxyErr := fmt.Sprintf("failed to configure system SOCKS proxy on port %d: %v", port, err)
		if result.Details == "" {
			result.Details = proxyErr
		} else {
			result.Details = result.Details + "; " + proxyErr
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Internet connectivity check
// ---------------------------------------------------------------------------

// internetCheckURL is the URL used by HasInternet(). Tests override this
// to point at httptest servers so no real network call is made.
var internetCheckURL = "http://connectivitycheck.gstatic.com/generate_204"
var internetCheckClient = &http.Client{Timeout: 10 * time.Second}

// HasInternet checks if we have real internet connectivity by hitting
// Google's connectivity check URL (HTTP 204 = connected).
func HasInternet() bool {
	// Use 10s timeout to accommodate satellite links (RTT 500-2500ms).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", internetCheckURL, nil)
	resp, err := internetCheckClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 204
}

// ---------------------------------------------------------------------------
// Default platform ops -- delegates to the platform package.
// The actual implementations are in platform_darwin.go / platform_linux.go.
// These stubs allow bypass to compile on any platform; the caller should
// inject a real PlatformOps at runtime.
// ---------------------------------------------------------------------------

type defaultPlatformOps struct{}

func (d *defaultPlatformOps) GetGateway(iface string) string    { return "" }
func (d *defaultPlatformOps) GetCurrentMAC(iface string) string { return "" }
func (d *defaultPlatformOps) GetArpTable() []platform.ArpEntry  { return nil }
func (d *defaultPlatformOps) SetMAC(iface, mac string) bool     { return false }
func (d *defaultPlatformOps) RenewDHCP(iface string)            {}
func (d *defaultPlatformOps) GenerateRandomMAC() string         { return platform.GenerateRandomMAC() }

// suppressLog controls whether bypass log output is suppressed (TUI mode).
var suppressLog atomic.Bool

// SetSuppressLog sets whether bypass log output is suppressed.
func SetSuppressLog(v bool) { suppressLog.Store(v) }

func logStatus(format string, args ...any) {
	if !suppressLog.Load() {
		log.Printf("  "+format, args...)
	}
}
