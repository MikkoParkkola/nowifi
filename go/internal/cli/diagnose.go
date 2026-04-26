// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"os"

	"github.com/MikkoParkkola/nowifi/internal/bypass"
	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/probe"
	"github.com/MikkoParkkola/nowifi/internal/report"
	"github.com/MikkoParkkola/nowifi/internal/techniques"
	"github.com/spf13/cobra"
)

var (
	diagnoseReportFormat string
	diagnoseOutput       string
)

var diagnoseCmd = &cobra.Command{
	Use:   "diagnose",
	Short: "Read-only network security assessment",
	Long: `Diagnose network security without exploiting anything.

Scans protocols, detects portal, checks which portal bypass
methods WOULD work — without changing any network settings.
No MAC changes. No tunnels. No proxy. Pure read-only assessment.`,
	Run: runDiagnose,
}

func init() {
	diagnoseCmd.Flags().StringVarP(&diagnoseReportFormat, "report", "r", "terminal",
		"Report format: terminal, markdown, json")
	diagnoseCmd.Flags().StringVarP(&diagnoseOutput, "output", "o", "",
		"Write report to file (default: stdout)")
}

func runDiagnose(cmd *cobra.Command, args []string) {
	printBanner("Diagnosis Mode (read-only)")

	// Validate interface.
	iface := flagInterface
	fmt.Printf("  Interface: %s\n", iface)

	// --- WiFi info ---
	fmt.Print("  Detecting WiFi connection... ")
	wifi, wifiErr := platform.GetWifiInfo(iface)
	if wifiErr != nil {
		fmt.Printf("(%v)\n", wifiErr)
	} else {
		fmt.Printf("%s (%ddBm)\n", wifi.SSID, wifi.RSSI)
	}

	// --- Portal detection ---
	fmt.Print("  Detecting portal... ")
	portalInfo := detect.DetectPortal(iface)
	if portalInfo.IsCaptive {
		fmt.Printf("%s", string(portalInfo.Type))
		if portalInfo.Vendor != "" {
			fmt.Printf(" (%s)", portalInfo.Vendor)
		}
		fmt.Println()
	} else {
		fmt.Println("no captive portal")
	}

	// --- Probe ---
	fmt.Print("  Probing protocols... ")
	probes := probe.ProbeAll(iface, flagStealth, "")
	fmt.Println("done")

	// --- Assess bypass methods ---
	fmt.Print("  Assessing bypass methods... ")
	bpConfig := buildBypassConfig(portalInfo, flagStealth)
	feasible := assessMethodsForConfig(probes, portalInfo, bpConfig)
	fmt.Printf("%d of %d portal bypass techniques feasible\n", feasible, techniques.BypassTechniqueCount())

	// --- Build report data ---
	rPortal := mapPortalInfo(portalInfo, wifi)
	rProbes := mapReportProbes(probes)
	// Empty bypass results — diagnose mode does not attempt bypasses.
	var bypassResults []bypass.Result

	// --- Output ---
	switch diagnoseReportFormat {
	case "terminal":
		report.PrintTerminal(rPortal, rProbes, bypassResults)
	case "markdown":
		md := report.GenerateMarkdown(rPortal, rProbes, bypassResults)
		writeOutput(md)
	case "json":
		js := report.GenerateJSON(rPortal, rProbes, bypassResults)
		writeOutput(js)
	default:
		fmt.Printf("\n  Unknown report format: %s\n", diagnoseReportFormat)
	}

	if diagnoseOutput != "" && diagnoseReportFormat == "terminal" {
		fmt.Printf("  (terminal format cannot be written to file; use -r markdown or -r json)\n")
	}
	fmt.Println()
}

// assessMethods counts how many bypass techniques would be feasible
// based on probe results. This is a read-only assessment.
func assessMethods(probes *probe.ProbeResults, portal *detect.PortalInfo) int {
	return assessMethodsForConfig(probes, portal, nil)
}

func assessMethodsForConfig(probes *probe.ProbeResults, portal *detect.PortalInfo, config *bypass.Config) int {
	return techniques.CountFeasibleBypassTechniques(diagnoseSignalsForConfig(probes, portal, config))
}

func diagnoseSignals(probes *probe.ProbeResults, portal *detect.PortalInfo) techniques.BypassTechniqueSignals {
	return diagnoseSignalsForConfig(probes, portal, nil)
}

func diagnoseSignalsForConfig(probes *probe.ProbeResults, portal *detect.PortalInfo, config *bypass.Config) techniques.BypassTechniqueSignals {
	whitelistReachable := false
	for _, wl := range probes.Whitelists {
		if wl.IsOpen {
			whitelistReachable = true
			break
		}
	}

	signals := techniques.BypassTechniqueSignals{
		PortalDetected:     portal != nil && portal.IsCaptive,
		IPv6Open:           probes.IPv6.IsOpen,
		DNSOpen:            probes.DNS.IsOpen,
		ICMPOpen:           probes.ICMP.IsOpen,
		CloudflareOpen:     probes.Cloudflare.IsOpen,
		QUICOpen:           probes.QUIC.IsOpen,
		NTPOpen:            probes.NTP.IsOpen,
		DoHOpen:            probes.DoH.IsOpen,
		WhitelistReachable: whitelistReachable,
		HTTP443Open:        portOpen(probes, 443),
		HTTP8080Open:       portOpen(probes, 8080),
	}
	signals.DoQOpen = probes.QUIC.IsOpen
	if config != nil {
		signals.CAPPORTAvailable = config.CAPPORTURL != ""
		signals.DHCPClasslessRoutesAvailable = len(config.DHCPClasslessRoutes) > 0
		signals.ECHServerConfigured = config.ECHServerURL != "" && config.ECHConfigListBase64 != ""
		signals.WSServerConfigured = config.WSServerURL != ""
		signals.MASQUEServerConfigured = config.MASQUEServerURL != ""
		signals.WTServerConfigured = config.WTServerURL != ""
		signals.H2ProxyConfigured = config.H2ProxyURL != ""
		signals.SSEServerConfigured = config.SSEServerURL != ""
		signals.GRPCServerConfigured = config.GRPCServerURL != ""
		signals.ConnectIPServerConfigured = config.ConnectIPServerURL != ""
		signals.HTTP3Open = probes.QUIC.IsOpen && (config.HTTP3Server != "" || config.TunnelServer != "")
	}
	return signals
}

// portOpen checks if a specific TCP port was found open in probe results.
func portOpen(probes *probe.ProbeResults, port int) bool {
	for _, p := range probes.OpenPorts {
		if p.Port == port && p.IsOpen {
			return true
		}
	}
	return false
}

// writeOutput writes content to diagnoseOutput file or stdout.
func writeOutput(content string) {
	if diagnoseOutput != "" {
		if err := os.WriteFile(diagnoseOutput, []byte(content), 0o600); err != nil {
			fmt.Printf("  Error writing to %s: %v\n", diagnoseOutput, err)
			return
		}
		fmt.Printf("  Report saved to %s\n", diagnoseOutput)
	} else {
		fmt.Println(content)
	}
}
