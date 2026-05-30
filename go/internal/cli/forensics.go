// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/forensics"
	"github.com/spf13/cobra"
)

var (
	forensicsOutput       string
	forensicsFormat       string
	forensicsBaseline     bool
	forensicsBaselineFile string
	forensicsTimeout      int
	forensicsPortalBase   string
)

var forensicsCmd = &cobra.Command{
	Use:   "forensics",
	Short: "Capture a portable, read-only diagnostic package (offline analysis)",
	Long: `Capture a portable forensic package of which egress channels survive
captive-portal enforcement, so an unsolved environment can be analyzed
later to build a working bypass.

This is a Go port of forensics/captive-forensics.sh (sections 1-10 plus the
pax-api enforcement control-plane sweep). It is collection-only:

  - READ-ONLY: no MAC changes, no tunnels, no proxy, no network mutation.
  - NO SUDO: runs without root; privilege-gated probes degrade gracefully and
    the limitation is recorded in the package.
  - LOCAL-ONLY: writes to disk and prints the saved paths. Never uploads,
    never phones home.

Output: two sibling files in the current directory (or --output dir),
holes-<UTC-timestamp>.txt (human) and holes-<UTC-timestamp>.json (machine).

Baseline diff (section 10): run with --baseline at full access to write a
baseline file, then later run with --baseline-file <path> under enforcement —
channels open in BOTH runs are the reliable holes.`,
	Run: runForensics,
}

func init() {
	forensicsCmd.Flags().StringVarP(&forensicsOutput, "output", "o", "",
		"Output directory for the package (default: current directory)")
	forensicsCmd.Flags().StringVarP(&forensicsFormat, "format", "f", "both",
		"Output format: both, json, txt")
	forensicsCmd.Flags().BoolVar(&forensicsBaseline, "baseline", false,
		"Capture-at-full-access mode: also write a baseline-<ts>.txt for later diff")
	forensicsCmd.Flags().StringVar(&forensicsBaselineFile, "baseline-file", "",
		"Path to a prior baseline file; include a section-10 diff (open in both = reliable holes)")
	forensicsCmd.Flags().IntVar(&forensicsTimeout, "timeout", 90,
		"Hard total time cap in seconds for live collection")
	forensicsCmd.Flags().StringVar(&forensicsPortalBase, "portal-base", "",
		"Override the pax-api base URL (derived from detected portal otherwise)")
}

func runForensics(cmd *cobra.Command, args []string) {
	printBanner("Forensics Mode (read-only, local-only)")

	iface := flagInterface
	fmt.Printf("  Interface: %s\n", iface)

	// Forensics defaults to the fast path so the total time cap is a backstop,
	// not the common case (stealth sweeps self-sleep and can approach the cap).
	stealth := false
	if cmd.Flags().Changed("stealth") {
		stealth = flagStealth && !flagFast
	}

	fmt.Print("  Capturing forensic package (read-only)... ")
	pkg := forensics.Collect(forensics.Options{
		Iface:        iface,
		Stealth:      stealth,
		PortalBase:   forensicsPortalBase,
		TotalTimeout: time.Duration(forensicsTimeout) * time.Second,
	})
	fmt.Println("done")

	fmt.Printf("  Provider: %s | Gateway: %s\n", pkg.Provider, pkg.GW)
	fmt.Printf("  Holes found: %d\n", len(pkg.Holes))

	// Optional section-10 baseline diff.
	if forensicsBaselineFile != "" {
		baseHoles, err := forensics.ReadBaselineFile(forensicsBaselineFile)
		if err != nil {
			fmt.Printf("  (baseline diff skipped: %v)\n", err)
		} else {
			reliable := forensics.DiffBaseline(pkg.Holes, baseHoles)
			fmt.Printf("  Reliable holes (open in both runs): %d\n", len(reliable))
			for _, h := range reliable {
				fmt.Printf("    [%s] %s\n", h.Severity, h.Technique)
			}
		}
	}

	res, err := writeForensicsPackage(pkg)
	if err != nil {
		fmt.Printf("  Error writing package: %v\n", err)
		return
	}
	if res.TextPath != "" {
		fmt.Printf("  Saved: %s\n", res.TextPath)
	}
	if res.JSONPath != "" {
		fmt.Printf("  Saved: %s\n", res.JSONPath)
	}
	if res.BaselinePath != "" {
		fmt.Printf("  Saved baseline: %s\n", res.BaselinePath)
	}
	fmt.Println()
}

// writeForensicsPackage writes the package honoring the --format flag.
// "both" (default) writes .txt + .json; "json"/"txt" select one. A baseline is
// written when --baseline is set, regardless of format.
func writeForensicsPackage(pkg *forensics.Package) (forensics.WriteResult, error) {
	return pkg.Write(forensicsOutput, forensics.WriteOptions{
		Format:   forensicsFormat,
		Baseline: forensicsBaseline,
	})
}
