// Package cli implements the nowifi command-line interface using cobra.
//
// The root command (bare `nowifi`) runs the full audit pipeline:
// detect portal -> probe leaks -> attempt bypass -> report.
// Subcommands provide targeted functionality (diagnose, crack, tools, etc.).
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

// SetVersion sets the version string (called from main with ldflags value).
func SetVersion(v string) {
	version = v
}

var rootCmd = &cobra.Command{
	Use:   "nowifi",
	Short: "No WiFi? Now WiFi.",
	Long: `nowifi — WiFi security assessment tool.

Just run: sudo nowifi
Detects portal, probes leaks, tries 23 bypass techniques.
Browser works immediately. Ctrl+C restores everything.

23 techniques (in order):
   1. IPv6 bypass        9. ICMP tunnel       17. CF Workers
   2. HTTPS tunnel      10. VPN port 53       18. NTP tunnel
   3. CNA UA spoof      11. Whitelist         19. DoH tunnel
   4. JS-only bypass    12. Session cookie    20. PMKID capture
   5. HTTP CONNECT      13. Portal creds      21. WPS Pixie-Dust
   6. MAC clone idle    14. MAC rotate        22. WPA handshake
   7. MAC clone any     15. DHCP rotate       23. WPS PIN brute
   8. DNS tunnel        16. QUIC tunnel`,
	Version: version,
	Run:     runAudit,
}

// Flags shared across commands or used by the root audit command.
var (
	flagInterface    string
	flagTunnelServer string
	flagDNSDomain    string
	flagICMPServer   string
	flagCFWorkers    string
	flagQUICServer   string
	flagNTPServer    string
	flagStealth      bool
	flagFast         bool
	flagProbeOnly    bool
)

func init() {
	// Persistent flags (available to all subcommands).
	rootCmd.PersistentFlags().StringVarP(&flagInterface, "interface", "i", "en0", "WiFi interface")

	// Root-only flags for the audit pipeline.
	rootCmd.Flags().StringVarP(&flagTunnelServer, "tunnel-server", "t", "", "Chisel tunnel endpoint URL")
	rootCmd.Flags().StringVarP(&flagDNSDomain, "dns-domain", "d", "", "DNS tunnel domain")
	rootCmd.Flags().StringVar(&flagICMPServer, "icmp-server", "", "ICMP tunnel server IP")
	rootCmd.Flags().StringVar(&flagCFWorkers, "cf-workers", "", "Cloudflare Workers proxy URL")
	rootCmd.Flags().StringVar(&flagQUICServer, "quic-server", "", "QUIC/Hysteria2 server address")
	rootCmd.Flags().StringVar(&flagNTPServer, "ntp-server", "", "NTP tunnel server IP")
	rootCmd.Flags().BoolVar(&flagStealth, "stealth", true, "Randomized probe timing (default)")
	rootCmd.Flags().BoolVar(&flagFast, "fast", false, "Skip stealth delays")
	rootCmd.Flags().BoolVarP(&flagProbeOnly, "probe-only", "p", false, "Probe only, don't exploit")
	rootCmd.Flags().BoolVarP(&flagAutoBypass, "auto", "y", false, "Skip interactive prompt, auto-bypass immediately")

	// Register subcommands.
	rootCmd.AddCommand(diagnoseCmd)
	rootCmd.AddCommand(crackCmd)
	rootCmd.AddCommand(toolsCmd)
	rootCmd.AddCommand(resetCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(ecosystemCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(uiCmd)
	rootCmd.AddCommand(menubarCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(watchCmd)
}

// Execute runs the root command. Called from main.
func Execute() {
	// Override version template to match the style: "nowifi v0.2.0".
	rootCmd.SetVersionTemplate(fmt.Sprintf("nowifi v%s\n", version))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
