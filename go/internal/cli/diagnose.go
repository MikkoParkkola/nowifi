package cli

import (
	"fmt"

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

Scans all protocols, detects portal, checks which of the 23 bypass
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
	fmt.Printf("\nnowifi v%s — Diagnosis Mode (read-only)\n\n", version)

	// Validate interface.
	iface := flagInterface
	fmt.Printf("  Interface: %s\n", iface)

	// --- WiFi info ---
	// TODO: wifi := platform.GetWifiInfo(iface)
	fmt.Println("  Detecting WiFi connection...")

	// --- Portal detection ---
	// TODO: portal := detect.DetectPortal(iface)
	fmt.Println("  Detecting portal...")

	// --- Probe ---
	// TODO: probes := probe.ProbeAll(iface, flagStealth, "")
	fmt.Println("  Probing protocols...")

	// --- Assess bypass methods ---
	// TODO: methods := diagnose.AssessMethods(portal, probes, tools)
	fmt.Println("  Assessing bypass methods...")

	// --- Output ---
	switch diagnoseReportFormat {
	case "terminal":
		// TODO: diagnose.PrintDiagnosis(portal, probes, methods, tools)
		fmt.Println("\n  (terminal report not yet implemented)")
	case "markdown":
		// TODO: generate markdown report
		fmt.Println("\n  (markdown report not yet implemented)")
	case "json":
		// TODO: generate JSON report
		fmt.Println("\n  (JSON report not yet implemented)")
	default:
		fmt.Printf("\n  Unknown report format: %s\n", diagnoseReportFormat)
	}

	if diagnoseOutput != "" {
		fmt.Printf("  (would write to %s)\n", diagnoseOutput)
	}
	fmt.Println()
}
