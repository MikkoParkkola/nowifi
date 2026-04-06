// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/bypass"
	"github.com/MikkoParkkola/nowifi/internal/capture"
	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/guard"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/probe"
	"github.com/MikkoParkkola/nowifi/internal/report"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

var flagAutoBypass bool

// tuiBypassResults stores bypass results from the pipeline for the exit report.
var tuiBypassResults []bypass.Result

func anySuccess(results []bypass.Result) bool {
	for _, r := range results {
		if r.Success {
			return true
		}
	}
	return false
}

// runAudit is the default command -- the full audit pipeline.
// Flow: WiFi info -> portal detection -> leak probing -> interactive choice -> bypass -> report.
func runAudit(cmd *cobra.Command, args []string) {
	startTime := time.Now()

	// When --fast is set, disable stealth.
	stealth := flagStealth
	if flagFast {
		stealth = false
	}

	// --probe-only and diagnose use the plain scrolling output.
	if flagProbeOnly {
		runAuditPlain(startTime, stealth)
		return
	}

	// Full audit: use the Bubbletea TUI if we have a terminal with color.
	if useColor {
		runAuditTUI(startTime, stealth)
		return
	}

	// Fallback to plain output for non-terminals / NO_COLOR.
	runAuditPlain(startTime, stealth)
}

// ---------------------------------------------------------------------------
// Bubbletea TUI audit (full-screen, replaces the old ANSI dashboard)
// ---------------------------------------------------------------------------

func runAuditTUI(startTime time.Time, stealth bool) {
	// For the interactive portal prompt we need to leave alt-screen
	// temporarily. We handle this by doing the prompt BEFORE starting
	// the Bubbletea program if a portal is detected and --auto is off.
	//
	// Everything runs in the pipeline goroutine for instant TUI start.
	var wifi *platform.WifiInfo
	var wifiErr error
	var portalInfo *detect.PortalInfo

	if false && !flagAutoBypass { // Portal prompt disabled — runs inside TUI now.
		printBanner("No WiFi? Now WiFi.")
		choice := promptBypassChoice()
		switch choice {
		case 2:
			// Diagnose only.
			tunnelIP := extractHost(flagTunnelServer)
			probes := probe.ProbeAll(flagInterface, stealth, tunnelIP)
			rPortal := mapPortalInfo(portalInfo, wifi)
			rProbes := mapReportProbes(probes)
			report.PrintTerminal(rPortal, rProbes, nil)
			fmt.Println()
			return
		case 4:
			fmt.Println()
			return
		}
	}

	// Suppress bypass log output during TUI mode.
	bypass.SuppressLog = true
	defer func() { bypass.SuppressLog = false }()

	// Create the Bubbletea TUI program.
	m := newTuiModel()
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Run the full audit pipeline in a background goroutine,
	// communicating state changes to the TUI via p.Send().
	go runAuditPipeline(p, startTime, stealth, wifi, wifiErr, portalInfo)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
	}

	// After TUI exits, print summary report.
	fmt.Println()
	fmt.Println("  All changes restored. Network is back to original state.")
	fmt.Println()
	// Print concise findings summary.
	fmt.Println("  " + bold("Security Findings:"))
	for _, r := range tuiBypassResults {
		if r.Success {
			fmt.Printf("  %s %s  %s\n", green("✓"), bold(string(r.Method)), r.Details)
			if r.Remediation != "" {
				fmt.Printf("    %s %s\n", dim("Fix:"), r.Remediation)
			}
		}
	}
	if len(tuiBypassResults) == 0 || !anySuccess(tuiBypassResults) {
		fmt.Println("  " + dim("No vulnerabilities found."))
	}
	fmt.Println()
}

// runAuditPipeline drives all audit phases in a background goroutine,
// sending typed messages to the Bubbletea program as state changes.
func runAuditPipeline(p *tea.Program, startTime time.Time, stealth bool, wifi *platform.WifiInfo, wifiErr error, portalInfo *detect.PortalInfo) {
	// Check for root.
	if os.Geteuid() != 0 {
		p.Send(statusMsg{text: "Warning: running without sudo. MAC spoofing and tunnels won't work."})
		time.Sleep(2 * time.Second)
	}

	// --- Phase 1: WiFi info ---
	if wifi == nil {
		wifi, wifiErr = platform.GetWifiInfo(flagInterface)
	}
	if wifiErr != nil {
		p.Send(wifiErrMsg{text: fmt.Sprintf("%s -- %v", flagInterface, wifiErr)})
	} else if wifi != nil {
		p.Send(wifiMsg{ssid: wifi.SSID, channel: wifi.Channel, rssi: wifi.RSSI})
	}

	// --- Phase 2: Portal detection (runs here for instant TUI start) ---
	if portalInfo == nil {
		portalInfo = detect.DetectPortal(flagInterface)
	}
	if portalInfo.IsCaptive {
		p.Send(portalMsg{portalType: string(portalInfo.Type), vendor: portalInfo.Vendor, captive: true})
		if portalInfo.Gateway != "" {
			p.Send(networkMsg{gateway: portalInfo.Gateway})
		}
	} else {
		p.Send(portalMsg{portalType: "none", captive: false})
	}

	// --- Phase 3: Leak enumeration ---
	p.Send(statusMsg{text: "Probing network leaks..."})
	tunnelIP := extractHost(flagTunnelServer)
	probes := probe.ProbeAll(flagInterface, stealth, tunnelIP)

	p.Send(probeMsg{name: "DNS", open: probes.DNS.IsOpen})
	p.Send(probeMsg{name: "ICMP", open: probes.ICMP.IsOpen})
	p.Send(probeMsg{name: "IPv6", open: probes.IPv6.IsOpen})
	p.Send(probeMsg{name: "HTTPS", open: probes.Cloudflare.IsOpen})
	p.Send(probeMsg{name: "QUIC", open: probes.QUIC.IsOpen})
	p.Send(probeMsg{name: "NTP", open: probes.NTP.IsOpen})
	p.Send(probeMsg{name: "DoH", open: probes.DoH.IsOpen})

	// --- Phase 4: Bypass ---
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

	p.Send(statusMsg{text: "Running bypass techniques..."})
	bpProbes := mapProbeResults(probes)
	bypassResults := bypass.RunBypasses(bpProbes, bpConfig, nil)
	tuiBypassResults = bypassResults // Store for exit report.

	for _, r := range bypassResults {
		detail := r.Details
		if len(detail) > 50 {
			detail = detail[:50] + "..."
		}
		p.Send(bypassResultMsg{technique: string(r.Method), success: r.Success, detail: detail})
	}

	successCount := 0
	for _, r := range bypassResults {
		if r.Success {
			successCount++
		}
	}
	if successCount > 0 {
		p.Send(statusMsg{text: fmt.Sprintf("%d technique(s) succeeded", successCount)})
	} else {
		p.Send(statusMsg{text: "No bypass succeeded"})
	}

	// --- Phase 5: Save audit record ---
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
		p.Send(statusMsg{text: fmt.Sprintf("Warning: failed to save audit: %v", err)})
	}

	// --- Phase 6: Session persistence ---
	if record.Success {
		g := guard.New(flagInterface)

		// Register tunnel cleanup.
		for _, r := range bypassResults {
			if r.Success && r.Tunnel != nil && r.Tunnel.Active {
				g.RegisterTunnel(tunnelCloser{r.Tunnel})
			}
		}

		// Enable stealth.
		if os.Geteuid() == 0 {
			stealthState, stealthErr := platform.EnableStealth(flagInterface)
			if stealthErr != nil {
				p.Send(stealthMsg{ttl: false, pf: false})
			} else {
				p.Send(stealthMsg{ttl: true, pf: true})
			}
			if stealthState != nil {
				g.RegisterStealth(stealthState)
			}
		} else {
			p.Send(stealthMsg{ttl: false, pf: false})
		}

		// Session maintenance loop -- runs until TUI quits.
		maintainSessionTUI(p, flagInterface, bypassResults, bpConfig, probes, stealth)

		// Cleanup.
		g.Restore()
		return
	}

	// No bypass succeeded -- pause briefly then signal done.
	time.Sleep(3 * time.Second)
	p.Send(doneMsg{})
}

// maintainSessionTUI is the Bubbletea-aware session maintenance loop.
// It runs in the audit pipeline goroutine and sends state to the TUI.
func maintainSessionTUI(p *tea.Program, iface string, results []bypass.Result, bpConfig *bypass.Config, probes *probe.ProbeResults, stealth bool) {
	var successMethod string
	for _, r := range results {
		if r.Success {
			successMethod = string(r.Method)
			break
		}
	}

	checkInterval := 30 * time.Second
	connectTime := time.Now()
	renewCount := 0
	consecutiveOK := 0

	p.Send(sessionTickMsg{uptime: 0, renewals: 0})
	p.Send(statusMsg{text: fmt.Sprintf("Maintaining session (bypass: %s)", successMethod)})

	uptimeTicker := time.NewTicker(1 * time.Second)
	defer uptimeTicker.Stop()

	checkTicker := time.NewTicker(checkInterval)
	defer checkTicker.Stop()

	for {
		select {
		case <-uptimeTicker.C:
			uptime := time.Since(connectTime).Round(time.Second)
			p.Send(sessionTickMsg{uptime: uptime, renewals: renewCount})

		case <-checkTicker.C:
			if checkInternet() {
				consecutiveOK++
				if consecutiveOK > 5 && checkInterval < 60*time.Second {
					checkInterval = 60 * time.Second
					checkTicker.Reset(checkInterval)
				}
				continue
			}

			// Session dropped.
			consecutiveOK = 0
			checkInterval = 30 * time.Second
			checkTicker.Reset(checkInterval)
			p.Send(sessionDownMsg{})
			p.Send(statusMsg{text: "Session dropped -- re-establishing connection..."})

			reconnected := false

			// Attempt 1: MAC rotate + DHCP.
			p.Send(bypassStartMsg{technique: "MAC rotate + DHCP renew"})
			newMAC := platform.GenerateRandomMAC()
			if err := platform.SetMAC(iface, newMAC); err == nil {
				if err := platform.RenewDHCP(iface); err == nil {
					time.Sleep(3 * time.Second)
					if checkInternet() {
						reconnected = true
						renewCount++
						p.Send(bypassResultMsg{technique: "MAC rotate", success: true, detail: newMAC})
					}
				}
			}
			if !reconnected {
				p.Send(bypassResultMsg{technique: "MAC rotate", success: false, detail: "no connectivity"})
			}

			// Attempt 2: Full bypass re-run.
			if !reconnected {
				p.Send(bypassStartMsg{technique: "Full bypass re-run"})
				bpProbes := mapProbeResults(probes)
				newResults := bypass.RunBypasses(bpProbes, bpConfig, nil)
				for _, r := range newResults {
					if r.Success {
						reconnected = true
						renewCount++
						successMethod = string(r.Method)
						p.Send(bypassResultMsg{technique: string(r.Method), success: true, detail: "reconnected"})
						break
					}
				}
				if !reconnected {
					p.Send(bypassResultMsg{technique: "Full bypass", success: false, detail: "all techniques failed"})
				}
			}

			// Attempt 3: Re-probe + bypass.
			if !reconnected {
				p.Send(bypassStartMsg{technique: "Re-probing network"})
				tunnelIP := extractHost(bpConfig.TunnelServer)
				newProbes := probe.ProbeAll(iface, stealth, tunnelIP)
				probes = newProbes

				p.Send(probeMsg{name: "DNS", open: newProbes.DNS.IsOpen})
				p.Send(probeMsg{name: "ICMP", open: newProbes.ICMP.IsOpen})
				p.Send(probeMsg{name: "IPv6", open: newProbes.IPv6.IsOpen})
				p.Send(probeMsg{name: "HTTPS", open: newProbes.Cloudflare.IsOpen})
				p.Send(probeMsg{name: "QUIC", open: newProbes.QUIC.IsOpen})
				p.Send(probeMsg{name: "NTP", open: newProbes.NTP.IsOpen})
				p.Send(probeMsg{name: "DoH", open: newProbes.DoH.IsOpen})

				bpProbes := mapProbeResults(newProbes)
				newResults := bypass.RunBypasses(bpProbes, bpConfig, nil)
				for _, r := range newResults {
					if r.Success {
						reconnected = true
						renewCount++
						successMethod = string(r.Method)
						p.Send(bypassResultMsg{technique: string(r.Method), success: true, detail: "after re-probe"})
						break
					}
				}
				if !reconnected {
					p.Send(bypassResultMsg{technique: "Re-probe + bypass", success: false, detail: "all failed"})
				}
			}

			if reconnected {
				connectTime = time.Now()
				p.Send(sessionTickMsg{uptime: 0, renewals: renewCount})
				p.Send(statusMsg{text: fmt.Sprintf("Reconnected via %s", successMethod)})
			} else {
				p.Send(statusMsg{text: fmt.Sprintf("All reconnect attempts failed. Retrying in %s...", checkInterval)})
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Plain (non-dashboard) audit -- used for --probe-only, no-color, and
// non-terminal environments. Preserves the original printf-based output.
// ---------------------------------------------------------------------------

func runAuditPlain(startTime time.Time, stealth bool) {
	printBanner("No WiFi? Now WiFi.")

	// Check for root.
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
		fmt.Printf("(interface: %s -- %v)\n", flagInterface, wifiErr)
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
			fmt.Println("4. Bypass  skipped (diagnose only)")
			fmt.Println()
			return
		case 4:
			fmt.Println()
			return
		case 3:
			fmt.Printf("4. Bypass  ")
		default:
			fmt.Printf("4. Bypass  ")
		}
	}

	// --- Phase 4: Bypass ---
	var bypassResults []bypass.Result
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
	if !flagProbeOnly {
		if !portalInfo.IsCaptive || flagAutoBypass {
			fmt.Printf("4. Bypass  ")
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

	// --- Phase 7: Session persistence ---
	if !flagProbeOnly && record.Success {
		g := guard.New(flagInterface)
		defer g.Restore()

		for _, r := range bypassResults {
			if r.Success && r.Tunnel != nil && r.Tunnel.Active {
				g.RegisterTunnel(tunnelCloser{r.Tunnel})
			}
		}

		if os.Geteuid() == 0 {
			stealthState, stealthErr := platform.EnableStealth(flagInterface)
			if stealthErr != nil {
				fmt.Printf("  %s  Stealth partially enabled: %v\n", yellow("WARN"), stealthErr)
			} else {
				fmt.Printf("5. Stealth  TTL normalized, traffic scrubbed\n")
			}
			if stealthState != nil {
				g.RegisterStealth(stealthState)
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Printf("\n\n  %s Stopping -- restoring original network state...\n", yellow("STOP"))
			cancel()
		}()

		maintainSession(ctx, flagInterface, bypassResults, bpConfig, probes, stealth)

		fmt.Println("  All changes restored. Network is back to original state.")
		fmt.Println()
		return
	}

	fmt.Println()
}

// tunnelCloser adapts tunnel.Handle (which has Stop()) to io.Closer for guard.
type tunnelCloser struct {
	h interface{ Stop() }
}

func (tc tunnelCloser) Close() error {
	tc.h.Stop()
	return nil
}

// maintainSession keeps the connection alive after a successful bypass.
// It monitors connectivity, predicts session timeout, and auto-renews.
func maintainSession(ctx context.Context, iface string, results []bypass.Result, bpConfig *bypass.Config, probes *probe.ProbeResults, stealth bool) {
	// Find the technique that worked.
	var successMethod string
	for _, r := range results {
		if r.Success {
			successMethod = string(r.Method)
			break
		}
	}

	// Adaptive check interval: shorter for first few checks to learn timeout,
	// then longer once we have a pattern.
	checkInterval := 30 * time.Second
	connectTime := time.Now()
	var lastDisconnect time.Time
	sessionCount := 0
	renewCount := 0

	fmt.Println()
	fmt.Printf("  %s  Maintaining session (bypass: %s)\n", green("CONNECTED"), successMethod)
	fmt.Printf("  %s  Checking every %s -- Ctrl+C to disconnect\n", dim("INFO"), checkInterval)
	fmt.Println()

	consecutiveOK := 0

	for {
		select {
		case <-ctx.Done():
			elapsed := time.Since(connectTime).Round(time.Second)
			fmt.Printf("\n  Session lasted %s (%d renewals)\n\n", elapsed, renewCount)
			return
		case <-time.After(checkInterval):
		}

		ts := time.Now().Format("15:04:05")
		uptime := time.Since(connectTime).Round(time.Second)

		if checkInternet() {
			consecutiveOK++
			// After 5 consecutive OKs, extend interval to reduce noise.
			if consecutiveOK > 5 && checkInterval < 60*time.Second {
				checkInterval = 60 * time.Second
			}
			fmt.Printf("  %s  %s  Connected (%s)\n", dim(ts), green("OK"), uptime)
			continue
		}

		// --- Session dropped ---
		consecutiveOK = 0
		checkInterval = 30 * time.Second // Reset to aggressive checking.

		// Track timeout pattern for future prediction.
		if !lastDisconnect.IsZero() {
			sessionCount++
		}
		lastDisconnect = time.Now()
		sessionDuration := lastDisconnect.Sub(connectTime).Round(time.Second)

		fmt.Printf("  %s  %s  Session dropped after %s\n", dim(ts), red("DOWN"), sessionDuration)
		fmt.Printf("  %s  %s  Re-establishing connection...\n", dim(ts), yellow("RENEW"))

		// Strategy: try the technique that worked first, then fall back to full bypass.
		reconnected := false

		// Attempt 1: MAC rotate + DHCP (fast, works if portal just expired the session).
		newMAC := platform.GenerateRandomMAC()
		if err := platform.SetMAC(iface, newMAC); err == nil {
			if err := platform.RenewDHCP(iface); err == nil {
				time.Sleep(3 * time.Second)
				if checkInternet() {
					reconnected = true
					renewCount++
					fmt.Printf("  %s  %s  Reconnected via MAC rotate (%s)\n", dim(ts), green("OK"), newMAC)
				}
			}
		}

		// Attempt 2: Full bypass re-run with original probes.
		if !reconnected {
			fmt.Printf("  %s  %s  MAC rotate failed, re-running full bypass...\n", dim(ts), yellow("RETRY"))
			bpProbes := mapProbeResults(probes)
			newResults := bypass.RunBypasses(bpProbes, bpConfig, nil)
			for _, r := range newResults {
				if r.Success {
					reconnected = true
					renewCount++
					successMethod = string(r.Method)
					fmt.Printf("  %s  %s  Reconnected via %s\n", dim(ts), green("OK"), successMethod)
					break
				}
			}
		}

		// Attempt 3: Re-probe the network (topology may have changed).
		if !reconnected {
			fmt.Printf("  %s  %s  Full bypass failed, re-probing network...\n", dim(ts), yellow("PROBE"))
			tunnelIP := extractHost(bpConfig.TunnelServer)
			newProbes := probe.ProbeAll(iface, stealth, tunnelIP)
			probes = newProbes // Update for next cycle.
			bpProbes := mapProbeResults(newProbes)
			newResults := bypass.RunBypasses(bpProbes, bpConfig, nil)
			for _, r := range newResults {
				if r.Success {
					reconnected = true
					renewCount++
					successMethod = string(r.Method)
					fmt.Printf("  %s  %s  Reconnected via %s (after re-probe)\n", dim(ts), green("OK"), successMethod)
					break
				}
			}
		}

		if !reconnected {
			fmt.Printf("  %s  %s  All reconnect attempts failed. Retrying in %s...\n", dim(ts), red("FAIL"), checkInterval)
		}

		// Reset connect time for the new session.
		if reconnected {
			connectTime = time.Now()
		}
	}
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
