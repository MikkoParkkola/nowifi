// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/MikkoParkkola/nowifi/internal/score"
	"github.com/spf13/cobra"
)

var scoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Security score all nearby WiFi networks (A-F grade)",
	Long: `Scan nearby WiFi networks and produce a security posture report.

Each network gets a letter grade (A-F) based on:
  - Encryption type (WPA3 > WPA2 > WEP > Open)
  - WPS status (enabled = -25 points)
  - Portal security (open + portal = vulnerable)
  - Protocol leaks (DNS, ICMP, IPv6 pre-auth)

Use --deep to also analyze the currently connected network
with full probe-based vulnerability assessment.`,
	Run: runScore,
}

var (
	scoreDeep   bool
	scoreFormat string
	scoreOutput string
)

func init() {
	scoreCmd.Flags().BoolVar(&scoreDeep, "deep", false, "Deep analysis of connected network (probes)")
	scoreCmd.Flags().StringVarP(&scoreFormat, "format", "f", "terminal", "Output format: terminal, json, markdown")
	scoreCmd.Flags().StringVarP(&scoreOutput, "output", "o", "", "Write report to file")
}

func runScore(cmd *cobra.Command, args []string) {
	iface := flagInterface
	fmt.Printf("\n%s — WiFi Security Score\n\n", bold("nowifi"))

	// Scan all nearby networks
	fmt.Println("Scanning nearby networks...")
	report, err := score.ScoreAll(iface)
	if err != nil {
		fmt.Printf("%s %v\n", red("Error:"), err)
		hint("Make sure WiFi is enabled", "Try: sudo nowifi score")
		return
	}

	if len(report.Networks) == 0 {
		fmt.Println("No networks found.")
		return
	}

	// Deep analysis of connected network
	var connectedScore *score.NetworkScore
	if scoreDeep {
		fmt.Println("Running deep analysis on connected network...")
		connectedScore, err = score.ScoreConnected(iface)
		if err != nil {
			fmt.Printf("%s Deep analysis failed: %v\n", yellow("Warning:"), err)
		}
	}

	// Output
	switch scoreFormat {
	case "json":
		out := map[string]interface{}{
			"report":    report,
			"connected": connectedScore,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		if err := writeOrPrint(string(data), scoreOutput); err != nil {
			fmt.Printf("%s %v\n", red("Error:"), err)
		}

	case "markdown":
		md := generateScoreMarkdown(report, connectedScore)
		if err := writeOrPrint(md, scoreOutput); err != nil {
			fmt.Printf("%s %v\n", red("Error:"), err)
		}

	default:
		printScoreTerminal(report, connectedScore)
	}
}

func printScoreTerminal(report *score.ScanReport, connected *score.NetworkScore) {
	// Header
	fmt.Printf("  Found %d networks\n\n", len(report.Networks))

	// Network table
	fmt.Printf("  %-24s %-6s %5s  %-14s %-4s  %s\n",
		"SSID", "Grade", "Score", "Security", "WPS", "Findings")
	fmt.Printf("  %-24s %-6s %5s  %-14s %-4s  %s\n",
		strings.Repeat("-", 24), "-----", "-----", strings.Repeat("-", 14), "---", strings.Repeat("-", 20))

	for _, n := range report.Networks {
		grade := colorGrade(n.Grade)
		wps := ""
		if n.WPS {
			wps = yellow("YES")
		}
		ssid := n.SSID
		if len(ssid) > 24 {
			ssid = ssid[:21] + "..."
		}
		if ssid == "" {
			ssid = dim("<hidden>")
		}

		critCount := 0
		highCount := 0
		for _, f := range n.Findings {
			if f.Severity == "critical" {
				critCount++
			} else if f.Severity == "high" {
				highCount++
			}
		}

		findingSummary := ""
		if critCount > 0 {
			findingSummary += red(fmt.Sprintf("%d critical", critCount))
		}
		if highCount > 0 {
			if findingSummary != "" {
				findingSummary += ", "
			}
			findingSummary += yellow(fmt.Sprintf("%d high", highCount))
		}
		if findingSummary == "" {
			findingSummary = green("clean")
		}

		fmt.Printf("  %-24s %-6s %5d  %-14s %-4s  %s\n",
			ssid, grade, n.Score, n.Security, wps, findingSummary)
	}

	// Summary
	s := report.Summary
	fmt.Printf("\n  %s\n", bold("Summary"))
	fmt.Printf("  %s: %d  %s: %d  %s: %d  %s: %d  %s: %d\n",
		green("A"), s.GradeA, green("B"), s.GradeB,
		yellow("C"), s.GradeC, yellow("D"), s.GradeD,
		red("F"), s.GradeF)

	if s.CriticalFindings > 0 || s.HighFindings > 0 {
		fmt.Printf("  %s: %s critical, %s high\n",
			bold("Findings"),
			red(fmt.Sprintf("%d", s.CriticalFindings)),
			yellow(fmt.Sprintf("%d", s.HighFindings)))
	}

	if s.WorstNetwork != "" {
		fmt.Printf("  Weakest: %s  Strongest: %s\n", red(s.WorstNetwork), green(s.BestNetwork))
	}

	// Deep analysis
	if connected != nil {
		fmt.Printf("\n  %s — Connected Network Deep Analysis\n\n", bold(connected.SSID))
		fmt.Printf("  Grade: %s  Score: %d/100\n\n", colorGrade(connected.Grade), connected.Score)

		for _, f := range connected.Findings {
			sev := colorSeverity(f.Severity)
			fmt.Printf("  %s  %s\n", sev, bold(f.Title))
			fmt.Printf("         %s\n", f.Description)
			fmt.Printf("         %s %s\n\n", dim("Fix:"), f.Remediation)
		}
	}

	fmt.Println()
}

func generateScoreMarkdown(report *score.ScanReport, connected *score.NetworkScore) string {
	var b strings.Builder
	b.WriteString("# WiFi Security Score Report\n\n")
	b.WriteString(fmt.Sprintf("**Date:** %s\n\n", report.Timestamp.Format("2006-01-02 15:04 MST")))

	b.WriteString("## Nearby Networks\n\n")
	b.WriteString("| SSID | Grade | Score | Security | WPS | Critical | High |\n")
	b.WriteString("|------|-------|-------|----------|-----|----------|------|\n")

	for _, n := range report.Networks {
		crit, high := 0, 0
		for _, f := range n.Findings {
			if f.Severity == "critical" {
				crit++
			} else if f.Severity == "high" {
				high++
			}
		}
		wps := ""
		if n.WPS {
			wps = "YES"
		}
		ssid := n.SSID
		if ssid == "" {
			ssid = "(hidden)"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %d | %d |\n",
			ssid, string(n.Grade), n.Score, n.Security, wps, crit, high))
	}

	if connected != nil {
		b.WriteString(fmt.Sprintf("\n## Deep Analysis: %s\n\n", connected.SSID))
		b.WriteString(fmt.Sprintf("**Grade:** %s  **Score:** %d/100\n\n", string(connected.Grade), connected.Score))

		b.WriteString("| Severity | Finding | Remediation |\n")
		b.WriteString("|----------|---------|-------------|\n")
		for _, f := range connected.Findings {
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", f.Severity, f.Title, f.Remediation))
		}
	}

	b.WriteString("\n*Generated by nowifi — https://github.com/MikkoParkkola/nowifi*\n")
	return b.String()
}

func colorGrade(g score.Grade) string {
	switch g {
	case score.GradeA:
		return green(string(g))
	case score.GradeB:
		return green(string(g))
	case score.GradeC:
		return yellow(string(g))
	case score.GradeD:
		return yellow(string(g))
	case score.GradeF:
		return red(string(g))
	default:
		return string(g)
	}
}

func colorSeverity(s string) string {
	switch s {
	case "critical":
		return red("[CRIT]")
	case "high":
		return red("[HIGH]")
	case "medium":
		return yellow("[MED] ")
	case "low":
		return dim("[LOW] ")
	default:
		return dim("[INFO]")
	}
}

func writeOrPrint(content, path string) error {
	if path != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return fmt.Errorf("write report %s: %w", path, err)
		}
		fmt.Printf("Report written to %s\n", path)
	} else {
		fmt.Println(content)
	}
	return nil
}
