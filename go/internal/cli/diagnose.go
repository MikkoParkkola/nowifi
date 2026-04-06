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

Scans all protocols, detects portal, checks which of the 27 bypass
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
	feasible := assessMethods(probes, portalInfo)
	fmt.Printf("%d of 27 techniques feasible\n", feasible)

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
	feasible := 0

	// IPv6 bypass — feasible if IPv6 is open.
	if probes.IPv6.IsOpen {
		feasible++
	}
	// HTTPS tunnel — feasible if TCP/443 is open.
	if portOpen(probes, 443) {
		feasible++
	}
	// CNA spoof — always worth trying if portal detected.
	if portal.IsCaptive {
		feasible++
	}
	// JS-only bypass — always worth trying if portal detected.
	if portal.IsCaptive {
		feasible++
	}
	// HTTP CONNECT — feasible if TCP/443 or TCP/8080 is open.
	if portOpen(probes, 443) || portOpen(probes, 8080) {
		feasible++
	}
	// MAC clone (idle) — always feasible with sudo.
	feasible++
	// MAC clone (any) — always feasible with sudo.
	feasible++
	// DNS tunnel — feasible if DNS (UDP/53) is open.
	if probes.DNS.IsOpen {
		feasible++
	}
	// ICMP tunnel — feasible if ICMP is open.
	if probes.ICMP.IsOpen {
		feasible++
	}
	// VPN on port 53 — feasible if DNS port is open.
	if probes.DNS.IsOpen {
		feasible++
	}
	// Whitelist domain — feasible if any whitelisted domain is open.
	for _, wl := range probes.Whitelists {
		if wl.IsOpen {
			feasible++
			break
		}
	}
	// Session cookie replay — always feasible if portal detected.
	if portal.IsCaptive {
		feasible++
	}
	// Portal default creds — always feasible if portal detected.
	if portal.IsCaptive {
		feasible++
	}
	// MAC rotate — always feasible with sudo.
	feasible++
	// DHCP rotate — always feasible.
	feasible++
	// QUIC tunnel — feasible if QUIC (UDP/443) is open.
	if probes.QUIC.IsOpen {
		feasible++
	}
	// CF Workers proxy — feasible if HTTPS is open.
	if probes.Cloudflare.IsOpen {
		feasible++
	}
	// NTP tunnel — feasible if NTP (UDP/123) is open.
	if probes.NTP.IsOpen {
		feasible++
	}
	// DoH tunnel — feasible if DoH is reachable.
	if probes.DoH.IsOpen {
		feasible++
	}

	return feasible
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
