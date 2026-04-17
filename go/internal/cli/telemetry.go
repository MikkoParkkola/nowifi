// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"

	"github.com/MikkoParkkola/nowifi/internal/telemetry"
	"github.com/spf13/cobra"
)

var telemetryCmd = &cobra.Command{
	Use:   "telemetry",
	Short: "Manage anonymous opt-in telemetry",
	Long:  buildTelemetryLongDescription(),
}

var telemetryEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Opt in to anonymous telemetry",
	Long: `Opt in to sending anonymous usage data to nowifi's community endpoint.

The purpose is security research: track which captive-portal bypass
techniques actually work against which inflight WiFi providers. Aggregate
data is used to publish security findings and to improve technique
ordering in future client updates.

What's collected (per bypass attempt):
  - Technique ID (e.g., "warp_tunnel")
  - Success true/false
  - Provider ID (e.g., "panasonic_avionics")
  - Duration in milliseconds
  - nowifi version + OS/arch
  - Country code (from the Cloudflare edge; your IP is never logged)

What's NEVER collected:
  - Your IP address
  - Your MAC address
  - The WiFi SSID
  - The captive portal URL or any DNS names
  - Any personal identifier

Disable any time: nowifi telemetry disable`,
	Run: runTelemetryEnable,
}

var telemetryDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Opt out of telemetry",
	Run:   runTelemetryDisable,
}

var telemetryStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show telemetry opt-in state",
	Run:   runTelemetryStatus,
}

func buildTelemetryLongDescription() string {
	return `Manage anonymous opt-in telemetry.

Disabled by default. Sending telemetry is always the user's explicit choice.

Purpose: track which bypass techniques succeed against which captive-portal
providers, to improve security research and future client updates.

Never collects: IP, MAC, SSID, portal URL, DNS names, or any identifier.

Commands:
  nowifi telemetry enable   Opt in
  nowifi telemetry disable  Opt out
  nowifi telemetry status   Show current state`
}

func init() {
	telemetryCmd.AddCommand(telemetryEnableCmd)
	telemetryCmd.AddCommand(telemetryDisableCmd)
	telemetryCmd.AddCommand(telemetryStatusCmd)
	rootCmd.AddCommand(telemetryCmd)
}

func runTelemetryEnable(cmd *cobra.Command, args []string) {
	if err := telemetry.Enable(); err != nil {
		fmt.Printf("  %s %v\n", red("ERROR"), err)
		return
	}
	fmt.Println()
	fmt.Println("  " + green("✓") + " Telemetry enabled.")
	fmt.Println()
	fmt.Println("  Data sent per bypass attempt:")
	fmt.Println("    • technique ID, success, provider, duration, version, OS/arch, country")
	fmt.Println()
	fmt.Println("  Never sent:")
	fmt.Println("    • IP, MAC, SSID, portal URL, DNS names, personal identifiers")
	fmt.Println()
	fmt.Println("  Endpoint: " + telemetry.DefaultEndpoint)
	fmt.Println("  Disable any time: nowifi telemetry disable")
	fmt.Println()
}

func runTelemetryDisable(cmd *cobra.Command, args []string) {
	if err := telemetry.Disable(); err != nil {
		fmt.Printf("  %s %v\n", red("ERROR"), err)
		return
	}
	fmt.Println()
	fmt.Println("  " + green("✓") + " Telemetry disabled.")
	fmt.Println("  No further data will be sent.")
	fmt.Println()
}

func runTelemetryStatus(cmd *cobra.Command, args []string) {
	fmt.Println()
	fmt.Println("  " + bold("Telemetry Status"))
	fmt.Println()
	for _, line := range splitLines(telemetry.Status()) {
		fmt.Println("  " + line)
	}
	fmt.Println()
}

// splitLines splits text into lines without trailing empty strings.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
