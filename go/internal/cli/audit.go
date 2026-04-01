package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// runAudit is the default command — the full audit pipeline.
// Flow: WiFi info -> portal detection -> leak probing -> bypass -> report.
func runAudit(cmd *cobra.Command, args []string) {
	// When --fast is set, disable stealth.
	stealth := flagStealth
	if flagFast {
		stealth = false
	}

	fmt.Printf("\nnowifi v%s — No WiFi? Now WiFi.\n\n", version)

	// Check for root — many techniques need it.
	if os.Geteuid() != 0 && !flagProbeOnly {
		fmt.Println("Warning: Running without sudo. MAC spoofing and tunnels won't work.")
		fmt.Println("  For full capability: sudo nowifi")
		fmt.Println("  For read-only scan:  nowifi diagnose")
		fmt.Println()
	}

	// --- Phase 1: WiFi info ---
	fmt.Printf("1. WiFi  ")
	// TODO: wifi := platform.GetWifiInfo(flagInterface)
	fmt.Printf("(interface: %s)\n", flagInterface)

	// --- Phase 2: Portal detection ---
	fmt.Printf("2. Portal  ")
	// TODO: portal := detect.DetectPortal(flagInterface)
	fmt.Println("(detection not yet implemented)")

	// --- Phase 3: Leak enumeration ---
	fmt.Printf("3. Probing  ")
	_ = stealth // will be passed to probe.ProbeAll
	// TODO: probes := probe.ProbeAll(flagInterface, stealth, tunnelIP)
	fmt.Println("(probing not yet implemented)")

	// --- Phase 4: Bypass ---
	if !flagProbeOnly {
		fmt.Printf("4. Bypass  ")
		_ = flagTunnelServer
		_ = flagDNSDomain
		_ = flagICMPServer
		_ = flagCFWorkers
		_ = flagQUICServer
		_ = flagNTPServer
		// TODO: config := bypass.AuditConfig{...}
		// TODO: results := bypass.RunBypasses(probes, config)
		fmt.Println("(bypass not yet implemented)")
	} else {
		fmt.Println("4. Bypass  skipped (--probe-only)")
	}

	// --- Phase 5: Report ---
	// TODO: report.PrintTerminalReport(portal, probes, results)
	fmt.Println()
}
