// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"strings"

	"github.com/MikkoParkkola/nowifi/internal/capture"
	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show past audit sessions",
	Long: `Display a table of past nowifi audit sessions.

Each row shows the SSID, gateway, portal vendor, bypass used,
whether it succeeded, and the session duration.`,
	Run: runHistory,
}

func runHistory(cmd *cobra.Command, args []string) {
	printBanner("Audit History")

	records, err := capture.ListAudits()
	if err != nil {
		fmt.Printf("  %s Failed to load history: %v\n\n", red("ERROR"), err)
		return
	}

	if len(records) == 0 {
		fmt.Println("  No audit records found.")
		fmt.Println()
		fmt.Println(dim("  Run 'sudo nowifi' to perform an audit. Results are saved automatically."))
		fmt.Println()
		return
	}

	// Table header.
	fmt.Printf("  %-19s  %-20s  %-15s  %-14s  %-20s  %-7s  %s\n",
		bold("Date"), bold("SSID"), bold("Gateway"), bold("Vendor"), bold("Bypass"), bold("Result"), bold("Duration"))
	fmt.Printf("  %s\n", dim(strings.Repeat("-", 110)))

	for _, r := range records {
		ts := r.Timestamp.Local().Format("2006-01-02 15:04")

		ssid := r.SSID
		if ssid == "" {
			ssid = dim("<unknown>")
		}
		if len(ssid) > 20 {
			ssid = ssid[:17] + "..."
		}

		gw := r.Gateway
		if gw == "" {
			gw = dim("-")
		}

		vendor := r.Vendor
		if vendor == "" {
			vendor = dim("-")
		}
		if len(vendor) > 14 {
			vendor = vendor[:11] + "..."
		}

		bypass := r.BypassUsed
		if bypass == "" {
			bypass = dim("none")
		}
		if len(bypass) > 20 {
			bypass = bypass[:17] + "..."
		}

		result := red("FAIL")
		if r.Success {
			result = green("OK")
		}

		duration := r.Duration
		if duration == "" {
			duration = dim("-")
		}

		fmt.Printf("  %-19s  %-20s  %-15s  %-14s  %-20s  %-7s  %s\n",
			ts, ssid, gw, vendor, bypass, result, duration)
	}

	// Summary.
	successCount := 0
	for _, r := range records {
		if r.Success {
			successCount++
		}
	}

	fmt.Println()
	fmt.Printf("  %s sessions, %s successful\n",
		bold(fmt.Sprintf("%d", len(records))),
		green(fmt.Sprintf("%d", successCount)))
	fmt.Println()
}
