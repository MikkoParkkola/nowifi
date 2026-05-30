// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"os"

	"github.com/MikkoParkkola/nowifi/internal/failreport"
	"github.com/spf13/cobra"
)

var (
	reportList   bool
	reportDryRun bool
	reportYes    bool
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Review and submit queued unsolved-network forensic reports",
	Long: `Review and submit forensic reports captured when nowifi could not bypass a
captive portal.

When bypass fails you are offline, so the forensic package is queued locally.
The next time nowifi runs with internet it automatically offers to file a
GitHub issue (with your consent) — you normally never need this command. Use it
to review pending reports, preview exactly what would be posted, or submit
non-interactively.

  nowifi report             # interactive: preview + consent prompt per report
  nowifi report --list      # list pending reports (no submit)
  nowifi report --dry-run   # print the sanitized issue body (no submit)
  nowifi report --yes       # submit all pending without prompting (scripted)

Privacy: nearby device MACs and your own MAC are redacted to vendor IDs before
anything is posted. Filing uses your own authenticated 'gh' CLI; nothing is
ever uploaded without an explicit confirmation.`,
	Run: runReport,
}

func init() {
	reportCmd.Flags().BoolVar(&reportList, "list", false, "List pending reports without submitting")
	reportCmd.Flags().BoolVar(&reportDryRun, "dry-run", false, "Print the sanitized issue body without submitting")
	reportCmd.Flags().BoolVarP(&reportYes, "yes", "y", false, "Submit all pending reports without prompting")
}

func runReport(cmd *cobra.Command, args []string) {
	entries, err := failreport.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "report: %v\n", err)
		os.Exit(1)
	}
	var pending []failreport.Entry
	for _, e := range entries {
		if !e.Submitted {
			pending = append(pending, e)
		}
	}

	if len(pending) == 0 {
		fmt.Println("No pending unsolved-network reports.")
		return
	}

	switch {
	case reportList:
		fmt.Printf("%d pending report(s):\n", len(pending))
		for _, e := range pending {
			fmt.Printf("  %s  provider=%s ssid=%s  %d open channels\n",
				e.TS, dash(e.Provider), dash(e.SSID), e.HolesCount)
		}
	case reportDryRun:
		for _, e := range pending {
			pkg, ent, lerr := failreport.Load(e.ID)
			if lerr != nil {
				continue
			}
			san := failreport.Sanitize(pkg)
			fmt.Printf("===== %s =====\nTitle: %s\n\n%s\n",
				e.TS, failreport.IssueTitle(san, ent.SSID), failreport.IssueBody(san, ent.SSID))
		}
	case reportYes:
		for _, e := range pending {
			url, body, serr := failreport.SubmitEntry(e.ID)
			if serr != nil {
				fmt.Printf("%s: could not file (%v). Create manually at https://github.com/MikkoParkkola/nowifi/issues/new\n\n%s\n", e.TS, serr, body)
				continue
			}
			fmt.Printf("Filed: %s\n", url)
		}
	default:
		// Interactive: the same consent flow used automatically on a connected run.
		if err := failreport.MaybeOfferPending(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
			os.Exit(1)
		}
	}
}

func dash(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
