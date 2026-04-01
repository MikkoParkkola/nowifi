package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var flagAutoBypass bool

// runAudit is the default command — the full audit pipeline.
// Flow: WiFi info -> portal detection -> leak probing -> interactive choice -> bypass -> report.
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
	portalDetected := false // placeholder until detection is wired
	fmt.Println("(detection not yet implemented)")

	// --- Phase 3: Leak enumeration ---
	fmt.Printf("3. Probing  ")
	_ = stealth // will be passed to probe.ProbeAll
	// TODO: probes := probe.ProbeAll(flagInterface, stealth, tunnelIP)
	fmt.Println("(probing not yet implemented)")

	// --- Phase 4: Interactive choice (when portal detected) ---
	if !flagProbeOnly && portalDetected && !flagAutoBypass {
		choice := promptBypassChoice()
		switch choice {
		case 2:
			// Diagnose only.
			fmt.Println("4. Bypass  skipped (diagnose only)")
			fmt.Println()
			return
		case 4:
			// Quit.
			fmt.Println()
			return
		case 3:
			// Pick specific technique.
			fmt.Println("4. Bypass  (specific technique selection not yet implemented)")
		default:
			// 1 = auto-bypass, fall through.
			fmt.Printf("4. Bypass  ")
		}
	}

	// --- Phase 4: Bypass ---
	if !flagProbeOnly {
		if !portalDetected || flagAutoBypass {
			fmt.Printf("4. Bypass  ")
		}
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

// promptBypassChoice displays the interactive portal menu and returns the user's choice.
func promptBypassChoice() int {
	fmt.Println()
	fmt.Println(bold("Portal detected. What would you like to do?"))
	fmt.Println()
	fmt.Println("  [1] Auto-bypass (try all techniques, stop on first success)")
	fmt.Println("  [2] Diagnose only (read-only assessment)")
	fmt.Println("  [3] Pick a specific technique")
	fmt.Println("  [4] Quit")
	fmt.Println()
	fmt.Print("Choice [1]: ")

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			return 1
		}
		switch line {
		case "1":
			return 1
		case "2":
			return 2
		case "3":
			return 3
		case "4":
			return 4
		default:
			return 1
		}
	}

	// Default on read error (e.g. piped input).
	return 1
}
