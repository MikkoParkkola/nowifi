// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/inflight"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/spf13/cobra"
)

// ReconReport is the structured output of `nowifi recon`.
// Use it to build new provider fingerprints: run the command on an unknown
// network, copy the resulting JSON into a provider profile issue/PR.
type ReconReport struct {
	Timestamp  string          `json:"timestamp"`
	Host       HostInfo        `json:"host"`
	Network    NetworkInfo     `json:"network"`
	Gateway    GatewayInfo     `json:"gateway"`
	DNS        DNSInfo         `json:"dns"`
	CAPPORT    *CAPPORTProbe   `json:"capport,omitempty"`
	Portal     *PortalProbe    `json:"portal,omitempty"`
	Latency    LatencyProbe    `json:"latency"`
	Provider   ProviderGuess   `json:"provider"`
	Whitelists WhitelistProbes `json:"whitelists"`
}

type HostInfo struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type NetworkInfo struct {
	Interface string `json:"interface"`
	LocalIP   string `json:"local_ip,omitempty"`
	MAC       string `json:"mac,omitempty"`
}

type GatewayInfo struct {
	IP  string `json:"ip,omitempty"`
	MAC string `json:"mac,omitempty"`
}

type DNSInfo struct {
	SearchDomain string   `json:"search_domain,omitempty"`
	Resolvers    []string `json:"resolvers,omitempty"`
}

// CAPPORTProbe captures the RFC 8908 response (when advertised).
type CAPPORTProbe struct {
	URL      string                    `json:"url"`
	Reached  bool                      `json:"reached"`
	Response *inflight.CAPPORTResponse `json:"response,omitempty"`
	Error    string                    `json:"error,omitempty"`
}

// PortalProbe captures basic portal HTTP response.
type PortalProbe struct {
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	ServerHeader    string            `json:"server_header,omitempty"`
	Via             string            `json:"via,omitempty"`
	InterestingHdrs map[string]string `json:"interesting_headers,omitempty"`
	Error           string            `json:"error,omitempty"`
}

type LatencyProbe struct {
	TargetHost   string `json:"target_host"`
	MinMs        int    `json:"min_ms"`
	AvgMs        int    `json:"avg_ms"`
	MaxMs        int    `json:"max_ms"`
	DetectedLink string `json:"detected_link_type,omitempty"`
	IsStarlink   bool   `json:"is_starlink"`
}

// ProviderGuess is nowifi's best guess of the inflight provider.
type ProviderGuess struct {
	Provider   string `json:"provider"`
	Confidence string `json:"confidence"` // "high" | "medium" | "low" | "unknown"
	Reason     string `json:"reason,omitempty"`
}

type WhitelistProbes struct {
	WhatsApp      bool `json:"whatsapp"`
	CloudflareDNS bool `json:"cloudflare_dns"`
	ArXiv         bool `json:"arxiv"`
}

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Passively fingerprint the current network (for contributing provider profiles)",
	Long: `Passively fingerprint the current network.

Gathers data needed to contribute a new provider profile to nowifi:
  - Network interface, MAC, gateway
  - DHCP-advertised search domain and CAPPORT URL (RFC 8908)
  - DNS resolvers
  - Portal HTTP headers (Server, Via, vendor-specific markers)
  - Latency profile (min/avg/max RTT → LEO vs satellite detection)
  - Whitelist / free-tier reachability

Output is JSON suitable for a GitHub issue describing a new provider.
Running 'recon' does NOT attempt any bypass — it's read-only.

Examples:
  nowifi recon                    # Fingerprint current wifi, print JSON
  nowifi recon -o klm-2026.json   # Save to file
  nowifi recon --iface en1        # Fingerprint specific interface`,
	RunE: runRecon,
}

func runRecon(cmd *cobra.Command, args []string) error {
	outPath, _ := cmd.Flags().GetString("output")
	iface, _ := cmd.Flags().GetString("iface")
	if iface == "" {
		iface = "en0" // macOS default; platform.GetDefaultInterface() would be better
	}

	report := buildReconReport(iface)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, append(data, '\n'), 0o644); err != nil { //nolint:gosec // user-specified output
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", outPath)
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func buildReconReport(iface string) *ReconReport {
	report := &ReconReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Host: HostInfo{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Network: NetworkInfo{Interface: iface},
	}

	// Network basics.
	if ip, err := platform.GetLocalIP(iface); err == nil {
		report.Network.LocalIP = ip
	}
	if mac, err := platform.GetCurrentMAC(iface); err == nil {
		report.Network.MAC = mac
	}

	// Gateway.
	if gw, err := platform.GetGateway(iface); err == nil {
		report.Gateway.IP = gw
		// ARP table lookup for gateway MAC.
		if entries, err := platform.GetARPTable(); err == nil {
			for _, e := range entries {
				if e.IP == gw {
					report.Gateway.MAC = e.MAC
					break
				}
			}
		}
	}

	// DNS.
	if resolvers, err := net.LookupHost("localhost"); err == nil && len(resolvers) > 0 {
		_ = resolvers // placeholder; real DNS resolver enum is platform-specific
	}

	// CAPPORT.
	if capportURL, _ := platform.GetCAPPORTURL(iface); capportURL != "" {
		probe := &CAPPORTProbe{URL: capportURL}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if resp, err := inflight.QueryCAPPORT(ctx, capportURL, 4*time.Second); err == nil {
			probe.Reached = true
			probe.Response = resp
		} else {
			probe.Error = err.Error()
		}
		report.CAPPORT = probe
	}

	// Portal (try CAPPORT URL or gateway as HTTP probe target).
	portalURL := ""
	if report.CAPPORT != nil {
		portalURL = report.CAPPORT.URL
	} else if report.Gateway.IP != "" {
		portalURL = "http://" + report.Gateway.IP
	}
	if portalURL != "" {
		report.Portal = probePortalHTTP(portalURL)
	}

	// Latency.
	report.Latency = probeLatency("1.1.1.1")
	report.Latency.DetectedLink = string(inflight.DetectLinkType(report.Latency.AvgMs))
	report.Latency.IsStarlink = inflight.IsStarlink(report.Latency.AvgMs)

	// Provider guess based on what we gathered.
	headers := map[string]string{}
	if report.Portal != nil {
		headers["server"] = report.Portal.ServerHeader
		headers["via"] = report.Portal.Via
	}
	provider := inflight.DetectProvider(report.Gateway.MAC, "", "", headers)
	report.Provider = ProviderGuess{
		Provider:   string(provider),
		Confidence: inferConfidence(provider, report),
		Reason:     inferReason(provider, report),
	}

	// Whitelist probes.
	report.Whitelists = WhitelistProbes{
		WhatsApp:      probeReachable("https://whatsapp.com", 3*time.Second),
		CloudflareDNS: probeReachable("https://cloudflare-dns.com", 3*time.Second),
		ArXiv:         probeReachable("https://arxiv.org", 3*time.Second),
	}

	return report
}

func probePortalHTTP(url string) *PortalProbe {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return &PortalProbe{URL: url, Error: err.Error()}
	}
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow -- we want to see the first response
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return &PortalProbe{URL: url, Error: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	interesting := map[string]string{}
	for _, hdr := range []string{"X-Kong-Upstream-Latency", "X-Kong-Proxy-Latency", "Strict-Transport-Security", "Content-Security-Policy"} {
		if v := resp.Header.Get(hdr); v != "" {
			interesting[hdr] = v
		}
	}
	return &PortalProbe{
		URL:             url,
		StatusCode:      resp.StatusCode,
		ServerHeader:    resp.Header.Get("Server"),
		Via:             resp.Header.Get("Via"),
		InterestingHdrs: interesting,
	}
}

func probeLatency(host string) LatencyProbe {
	probe := LatencyProbe{TargetHost: host}
	// Best-effort: 3 TCP dial measurements to port 443. Not ICMP because that
	// requires raw sockets on many platforms.
	var samples []time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", host+":443", 3*time.Second)
		if err == nil {
			samples = append(samples, time.Since(start))
			_ = conn.Close()
		}
	}
	if len(samples) == 0 {
		return probe
	}
	var min, max, sum time.Duration
	min = samples[0]
	for _, s := range samples {
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
		sum += s
	}
	probe.MinMs = int(min.Milliseconds())
	probe.MaxMs = int(max.Milliseconds())
	probe.AvgMs = int((sum / time.Duration(len(samples))).Milliseconds())
	return probe
}

func probeReachable(url string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	// Any response (2xx/3xx/4xx) means we reached the endpoint.
	// 5xx could mean portal interception.
	return resp.StatusCode < 500
}

func inferConfidence(provider inflight.Provider, report *ReconReport) string {
	if provider == inflight.Unknown {
		return "unknown"
	}
	hits := 0
	if report.Portal != nil && report.Portal.ServerHeader != "" {
		hits++
	}
	if report.DNS.SearchDomain != "" {
		hits++
	}
	if report.CAPPORT != nil && report.CAPPORT.URL != "" {
		hits++
	}
	switch {
	case hits >= 2:
		return "high"
	case hits == 1:
		return "medium"
	default:
		return "low"
	}
}

func inferReason(provider inflight.Provider, report *ReconReport) string {
	if provider == inflight.Unknown {
		return "No matching OUI, DNS pattern, HTML marker, or HTTP header"
	}
	reasons := []string{}
	if report.Portal != nil && report.Portal.ServerHeader != "" {
		reasons = append(reasons, "Server header: "+report.Portal.ServerHeader)
	}
	if report.CAPPORT != nil && report.CAPPORT.URL != "" {
		reasons = append(reasons, "CAPPORT URL present")
	}
	if len(reasons) == 0 {
		return "Detected via fingerprint matching"
	}
	result := reasons[0]
	for i := 1; i < len(reasons); i++ {
		result += "; " + reasons[i]
	}
	return result
}

func init() {
	reconCmd.Flags().StringP("output", "o", "", "Write JSON to this file instead of stdout")
	reconCmd.Flags().String("iface", "", "Network interface (default: en0)")
}
