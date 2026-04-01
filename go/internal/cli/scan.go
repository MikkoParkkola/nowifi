// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"strings"

	"github.com/MikkoParkkola/nowifi/internal/discover"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan nearby WiFi networks",
	Long: `Shows all nearby WiFi networks with security type, signal strength,
WPS status, and portal likelihood.

Open networks with many clients likely have captive portals.
WPS-enabled networks may be vulnerable to Pixie-Dust or PIN brute-force.`,
	Run: runScan,
}

func runScan(cmd *cobra.Command, args []string) {
	fmt.Printf("\nnowifi v%s — WiFi Scanner\n\n", version)

	iface := flagInterface
	fmt.Printf("  Scanning on %s...\n\n", iface)

	networks, err := discover.ScanNetworks(iface)
	if err != nil {
		fmt.Printf("  %s Scan failed: %v\n\n", red("ERROR"), err)
		return
	}

	if len(networks) == 0 {
		fmt.Println("  No networks found.")
		fmt.Println()
		return
	}

	// Table header.
	fmt.Printf("  %-28s  %s  %-6s  %-18s  %-3s  %-7s  %s\n",
		bold("SSID"), bold("Signal"), bold("Ch"), bold("Security"), bold("WPS"), bold("Portal"), bold("BSSID"))
	fmt.Printf("  %s\n", dim(strings.Repeat("-", 95)))

	for _, n := range networks {
		ssidDisplay := n.SSID
		if ssidDisplay == "" {
			ssidDisplay = dim("<hidden>")
		}
		if len(ssidDisplay) > 28 {
			ssidDisplay = ssidDisplay[:25] + "..."
		}

		bars := discover.SignalBars(n.Signal)
		signalStr := fmt.Sprintf("%s %4ddBm", bars, n.Signal)

		securityStr := colorSecurity(n.Security)

		wpsStr := dim("-")
		if n.WPS {
			wpsStr = yellow("YES")
		}

		portalStr := dim("-")
		if n.PortalLikely {
			portalStr = yellow("likely")
		}

		bssidStr := dim(n.BSSID)

		fmt.Printf("  %-28s  %s  %-6d  %-18s  %-3s  %-7s  %s\n",
			ssidDisplay, signalStr, n.Channel, securityStr, wpsStr, portalStr, bssidStr)
	}

	// Summary.
	openCount := 0
	wpsCount := 0
	for _, n := range networks {
		if n.Security == "Open" {
			openCount++
		}
		if n.WPS {
			wpsCount++
		}
	}

	fmt.Println()
	fmt.Printf("  %s networks found", bold(fmt.Sprintf("%d", len(networks))))
	if openCount > 0 {
		fmt.Printf(", %s open", yellow(fmt.Sprintf("%d", openCount)))
	}
	if wpsCount > 0 {
		fmt.Printf(", %s with WPS", yellow(fmt.Sprintf("%d", wpsCount)))
	}
	fmt.Println()

	if openCount > 0 {
		hint("Open networks with many clients likely have captive portals.",
			"Run: sudo nowifi  -- to auto-detect and bypass the portal.")
	} else if wpsCount > 0 {
		hint("WPS-enabled networks may be vulnerable to Pixie-Dust attack.",
			"Run: sudo nowifi crack --wps <BSSID>  -- to test WPS security.")
	} else {
		fmt.Println()
	}
}

// colorSecurity applies color to the security type label.
func colorSecurity(sec string) string {
	switch sec {
	case "Open":
		return yellow("Open")
	case "WEP":
		return red("WEP")
	case "WPA":
		return yellow("WPA")
	case "WPA2":
		return green("WPA2")
	case "WPA3":
		return green("WPA3")
	case "WPA2-Enterprise":
		return green("WPA2-Enterprise")
	default:
		return sec
	}
}
