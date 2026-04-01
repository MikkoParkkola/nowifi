package cli

import (
	"fmt"

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
	// TODO: targets := crack.ScanTargets(iface)
	fmt.Println("   (scanning not yet implemented)")

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
	fmt.Printf("   Timeout: %ds\n", crackTimeout)
	// TODO: results := crack.RunCrack(iface, crackTarget, crackTimeout, crackWordlist)
	fmt.Println("   (cracking not yet implemented)")

	// --- Results ---
	fmt.Println("\n3. Results")
	// TODO: display results table
	fmt.Println("   (results display not yet implemented)")
	fmt.Println()
}
