// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package cli implements the nowifi command-line interface using cobra.
//
// The root command (bare `nowifi`) runs the full audit pipeline:
// detect portal -> probe leaks -> attempt bypass -> report.
// Subcommands provide targeted functionality (diagnose, crack, tools, etc.).
package cli

import (
	"fmt"
	"os"

	"github.com/MikkoParkkola/nowifi/internal/platform"
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
Detects portal, probes leaks, tries 19 portal bypass techniques.
Browser works immediately. Ctrl+C restores everything.

27 techniques overall:
  Portal bypass (19): nowifi
  WPA cracking (4):   nowifi crack
  Smart cracking (4): nowifi crack

Portal bypass techniques (in order):
   1. IPv6 bypass        9. ICMP tunnel       17. CF Workers
   2. HTTPS tunnel      10. VPN port 53       18. NTP tunnel
   3. CNA UA spoof      11. Whitelist         19. DoH tunnel
   4. JS-only bypass    12. Session cookie
   5. HTTP CONNECT      13. Portal creds
   6. MAC clone idle    14. MAC rotate
   7. MAC clone any     15. DHCP rotate
   8. DNS tunnel        16. QUIC tunnel`,
	Version:           version,
	PersistentPreRunE: validateFlags,
	Run:               runAudit,
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
	flagVPNServer    string
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
	rootCmd.Flags().StringVar(&flagVPNServer, "vpn-server", "", "VPN server (host:port) for VPN-on-port-53 technique")
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
	rootCmd.AddCommand(scoreCmd)
}

// validateFlags validates all user-provided CLI flags at the boundary
// before they can reach any exec.Command call. Rejects invalid input early.
func validateFlags(cmd *cobra.Command, args []string) error {
	// Interface name: must be a valid network interface identifier.
	if _, err := platform.ValidateInterface(flagInterface); err != nil {
		return fmt.Errorf("--interface: %w", err)
	}

	// Tunnel server: must be a valid URL if provided.
	if flagTunnelServer != "" {
		if _, err := platform.ValidateURL(flagTunnelServer); err != nil {
			return fmt.Errorf("--tunnel-server: %w", err)
		}
	}

	// DNS domain: must be a valid domain name if provided.
	if flagDNSDomain != "" {
		if _, err := platform.ValidateDomain(flagDNSDomain); err != nil {
			return fmt.Errorf("--dns-domain: %w", err)
		}
	}

	// ICMP server: must be a valid IP address if provided.
	if flagICMPServer != "" {
		if _, err := platform.ValidateIP(flagICMPServer); err != nil {
			return fmt.Errorf("--icmp-server: %w", err)
		}
	}

	// CF Workers URL: must be a valid URL if provided.
	if flagCFWorkers != "" {
		if _, err := platform.ValidateURL(flagCFWorkers); err != nil {
			return fmt.Errorf("--cf-workers: %w", err)
		}
	}

	// QUIC server: must be a valid server address if provided.
	if flagQUICServer != "" {
		if _, err := platform.ValidateServerAddr(flagQUICServer); err != nil {
			return fmt.Errorf("--quic-server: %w", err)
		}
	}

	// NTP server: must be a valid IP address if provided.
	if flagNTPServer != "" {
		if _, err := platform.ValidateIP(flagNTPServer); err != nil {
			return fmt.Errorf("--ntp-server: %w", err)
		}
	}

	return nil
}

// Execute runs the root command. Called from main.
func Execute() {
	// Override version template to match the style: "nowifi v0.2.0".
	rootCmd.SetVersionTemplate(fmt.Sprintf("nowifi v%s\n", version))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
