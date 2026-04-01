// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/bypass"
	"github.com/MikkoParkkola/nowifi/internal/capture"
	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/probe"
	"github.com/MikkoParkkola/nowifi/internal/report"
	"github.com/spf13/cobra"
)

var flagAutoBypass bool

// runAudit is the default command — the full audit pipeline.
// Flow: WiFi info -> portal detection -> leak probing -> interactive choice -> bypass -> report.
func runAudit(cmd *cobra.Command, args []string) {
	startTime := time.Now()

	// When --fast is set, disable stealth.
	stealth := flagStealth
	if flagFast {
		stealth = false
	}

	fmt.Printf("\nnowifi v%s — No WiFi? Now WiFi.\n\n", version)

	// Check for root — many techniques need it.
	if os.Geteuid() != 0 && !flagProbeOnly {
		fmt.Println("Warning: Running without sudo. MAC spoofing and tunnels won't work.")
		fmt.Println("  For full capability: sudo nowifi")
		fmt.Println("  For read-only scan:  nowifi diagnose")
		fmt.Println()
	}

	// --- Phase 1: WiFi info ---
	fmt.Printf("1. WiFi  ")
	wifi, wifiErr := platform.GetWifiInfo(flagInterface)
	if wifiErr != nil {
		fmt.Printf("(interface: %s — %v)\n", flagInterface, wifiErr)
	} else {
		fmt.Printf("%s on %s (ch %s, %ddBm)\n", wifi.SSID, flagInterface, wifi.Channel, wifi.RSSI)
	}

	// --- Phase 2: Portal detection ---
	fmt.Printf("2. Portal  ")
	portalInfo := detect.DetectPortal(flagInterface)
	if portalInfo.IsCaptive {
		fmt.Printf("%s portal detected", string(portalInfo.Type))
		if portalInfo.Vendor != "" {
			fmt.Printf(" (%s)", portalInfo.Vendor)
		}
		fmt.Println()
	} else {
		fmt.Println("no captive portal detected")
	}

	// --- Phase 3: Leak enumeration ---
	fmt.Printf("3. Probing  ")
	tunnelIP := extractHost(flagTunnelServer)
	probes := probe.ProbeAll(flagInterface, stealth, tunnelIP)
	openCount := countOpenPorts(probes)
	fmt.Printf("done (%d open ports", openCount)
	if probes.DNS.IsOpen {
		fmt.Print(", DNS open")
	}
	if probes.IPv6.IsOpen {
		fmt.Print(", IPv6 open")
	}
	fmt.Println(")")

	// --- Phase 4: Interactive choice (when portal detected) ---
	if !flagProbeOnly && portalInfo.IsCaptive && !flagAutoBypass {
		choice := promptBypassChoice()
		switch choice {
		case 2:
			// Diagnose only.
			fmt.Println("4. Bypass  skipped (diagnose only)")
			fmt.Println()
			return
		case 4:
			// Quit.
			fmt.Println()
			return
		case 3:
			// Pick specific technique — fall through to auto for now.
			fmt.Printf("4. Bypass  ")
		default:
			// 1 = auto-bypass, fall through.
			fmt.Printf("4. Bypass  ")
		}
	}

	// --- Phase 4: Bypass ---
	var bypassResults []bypass.Result
	if !flagProbeOnly {
		if !portalInfo.IsCaptive || flagAutoBypass {
			fmt.Printf("4. Bypass  ")
		}

		bpConfig := &bypass.Config{
			Interface:    flagInterface,
			TunnelServer: flagTunnelServer,
			DNSDomain:    flagDNSDomain,
			ICMPServer:   flagICMPServer,
			QUICServer:   flagQUICServer,
			NTPServer:    flagNTPServer,
			CFWorkersURL: flagCFWorkers,
			Stealth:      stealth,
		}

		bpProbes := mapProbeResults(probes)
		bypassResults = bypass.RunBypasses(bpProbes, bpConfig, nil)

		successCount := 0
		for _, r := range bypassResults {
			if r.Success {
				successCount++
			}
		}
		if successCount > 0 {
			fmt.Printf("%d technique(s) succeeded\n", successCount)
		} else {
			fmt.Println("no bypass succeeded")
		}
	} else {
		fmt.Println("4. Bypass  skipped (--probe-only)")
	}

	// --- Phase 5: Report ---
	rPortal := mapPortalInfo(portalInfo, wifi)
	rProbes := mapReportProbes(probes)
	report.PrintTerminal(rPortal, rProbes, bypassResults)

	// --- Phase 6: Save audit record ---
	record := &capture.AuditRecord{
		ID:        time.Now().Format("20060102-150405"),
		Timestamp: startTime,
		Portal:    portalInfo.IsCaptive,
		Vendor:    portalInfo.Vendor,
		Duration:  time.Since(startTime).Round(time.Second).String(),
		Probes: map[string]bool{
			"dns":  probes.DNS.IsOpen,
			"icmp": probes.ICMP.IsOpen,
			"ipv6": probes.IPv6.IsOpen,
			"quic": probes.QUIC.IsOpen,
			"ntp":  probes.NTP.IsOpen,
			"doh":  probes.DoH.IsOpen,
		},
	}
	if wifi != nil {
		record.SSID = wifi.SSID
	}
	for _, r := range bypassResults {
		if r.Success {
			record.BypassUsed = string(r.Method)
			record.Success = true
			break
		}
	}
	if err := capture.SaveAudit(record); err != nil {
		fmt.Printf("  (warning: failed to save audit record: %v)\n", err)
	}

	fmt.Println()
}

// extractHost extracts the hostname or IP from a URL string.
func extractHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

// countOpenPorts counts the number of open ports in probe results.
func countOpenPorts(probes *probe.ProbeResults) int {
	count := 0
	for _, p := range probes.OpenPorts {
		if p.IsOpen {
			count++
		}
	}
	return count
}

// mapProbeResults converts probe.ProbeResults to bypass.ProbeResults.
func mapProbeResults(p *probe.ProbeResults) *bypass.ProbeResults {
	bp := &bypass.ProbeResults{
		DNS:        bypass.ProbeResult{IsOpen: p.DNS.IsOpen, Details: p.DNS.Details},
		ICMP:       bypass.ProbeResult{IsOpen: p.ICMP.IsOpen, Details: p.ICMP.Details},
		IPv6:       bypass.ProbeResult{IsOpen: p.IPv6.IsOpen, Details: p.IPv6.Details},
		Cloudflare: bypass.ProbeResult{IsOpen: p.Cloudflare.IsOpen, Details: p.Cloudflare.Details},
		QUIC:       bypass.ProbeResult{IsOpen: p.QUIC.IsOpen, Details: p.QUIC.Details},
		NTP:        bypass.ProbeResult{IsOpen: p.NTP.IsOpen, Details: p.NTP.Details},
		DoH:        bypass.ProbeResult{IsOpen: p.DoH.IsOpen, Details: p.DoH.Details},
	}
	for _, wl := range p.Whitelists {
		bp.Whitelists = append(bp.Whitelists, bypass.WhitelistResult{
			Domain: wl.Domain, IsOpen: wl.IsOpen, Details: wl.Details,
		})
	}
	for _, pp := range p.OpenPorts {
		bp.OpenPorts = append(bp.OpenPorts, bypass.PortResult{
			Port: pp.Port, Service: pp.Service, IsOpen: pp.IsOpen,
		})
	}
	for _, tp := range p.TunnelServerPorts {
		bp.TunnelServerPorts = append(bp.TunnelServerPorts, bypass.PortResult{
			Port: tp.Port, Service: tp.Service, IsOpen: tp.IsOpen,
		})
	}
	return bp
}

// mapPortalInfo converts detect.PortalInfo to report.PortalInfo.
func mapPortalInfo(p *detect.PortalInfo, wifi *platform.WifiInfo) report.PortalInfo {
	rp := report.PortalInfo{
		IsCaptive:   p.IsCaptive,
		PortalType:  string(p.Type),
		Vendor:      p.Vendor,
		PortalURL:   p.PortalURL,
		AuthMethods: p.AuthMethods,
		Gateway:     p.Gateway,
	}
	if wifi != nil {
		rp.SSID = wifi.SSID
	}
	return rp
}

// mapReportProbes converts probe.ProbeResults to report.ProbeResults.
func mapReportProbes(p *probe.ProbeResults) report.ProbeResults {
	rp := report.ProbeResults{
		DNS:        report.ProbeResult{IsOpen: p.DNS.IsOpen, Details: p.DNS.Details},
		ICMP:       report.ProbeResult{IsOpen: p.ICMP.IsOpen, Details: p.ICMP.Details},
		IPv6:       report.ProbeResult{IsOpen: p.IPv6.IsOpen, Details: p.IPv6.Details},
		Cloudflare: report.ProbeResult{IsOpen: p.Cloudflare.IsOpen, Details: p.Cloudflare.Details},
		QUIC:       report.ProbeResult{IsOpen: p.QUIC.IsOpen, Details: p.QUIC.Details},
		NTP:        report.ProbeResult{IsOpen: p.NTP.IsOpen, Details: p.NTP.Details},
		DoH:        report.ProbeResult{IsOpen: p.DoH.IsOpen, Details: p.DoH.Details},
	}
	for _, wl := range p.Whitelists {
		rp.Whitelists = append(rp.Whitelists, report.WhitelistResult{
			Domain: wl.Domain, IsOpen: wl.IsOpen, Details: wl.Details,
		})
	}
	for _, pp := range p.OpenPorts {
		rp.OpenPorts = append(rp.OpenPorts, report.PortResult{
			Port: pp.Port, Service: pp.Service, IsOpen: pp.IsOpen,
		})
	}
	return rp
}

// promptBypassChoice displays the interactive portal menu and returns the user's choice.
func promptBypassChoice() int {
	fmt.Println()
	fmt.Println(bold("Portal detected. What would you like to do?"))
	fmt.Println()
	fmt.Println("  [1] Auto-bypass (try all techniques, stop on first success)")
	fmt.Println("  [2] Diagnose only (read-only assessment)")
	fmt.Println("  [3] Pick a specific technique")
	fmt.Println("  [4] Quit")
	fmt.Println()
	fmt.Print("Choice [1]: ")

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			return 1
		}
		switch line {
		case "1":
			return 1
		case "2":
			return 2
		case "3":
			return 3
		case "4":
			return 4
		default:
			return 1
		}
	}

	// Default on read error (e.g. piped input).
	return 1
}
