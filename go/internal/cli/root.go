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
	"strings"

	"github.com/MikkoParkkola/nowifi/internal/crack"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/techniques"
	"github.com/spf13/cobra"
)

var version = "dev"

// SetVersion sets the version string (called from main with ldflags value).
func SetVersion(v string) {
	version = v
}

var rootCmd = &cobra.Command{
	Use:               "nowifi",
	Short:             "No WiFi? Now WiFi.",
	Long:              buildRootLongDescription(),
	Version:           version,
	PersistentPreRunE: validateFlags,
	Run:               runAudit,
}

func buildRootLongDescription() string {
	var b strings.Builder
	totalTechniqueCount := techniques.BypassTechniqueCount() + crack.UserVisibleTechniqueCount

	fmt.Fprintln(&b, "nowifi — WiFi security assessment tool.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Just run: sudo nowifi")
	fmt.Fprintf(&b, "Detects portal, probes leaks, tries %d portal bypass techniques.\n", techniques.BypassTechniqueCount())
	fmt.Fprintln(&b, "Browser works immediately. Ctrl+C restores everything.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "%d techniques overall:\n", totalTechniqueCount)
	fmt.Fprintf(&b, "  Portal bypass (%d): nowifi\n", techniques.BypassTechniqueCount())
	fmt.Fprintf(&b, "  WPA cracking (%d):   nowifi crack\n", crack.WPAGroupTechniqueCount)
	fmt.Fprintf(&b, "  Smart cracking (%d): nowifi crack\n", crack.SmartGroupTechniqueCount)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Portal bypass techniques (in order):")
	for _, info := range techniques.BypassTechniqueInfos() {
		fmt.Fprintf(&b, "  %2d. %s\n", info.Number, info.HelpName)
	}

	return strings.TrimRight(b.String(), "\n")
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
	flagHTTP3Server  string
	flagDoQServer    string
	flagStealth      bool
	flagFast         bool
	flagProbeOnly    bool
	flagAutoBypass   bool
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
	rootCmd.Flags().StringVar(&flagHTTP3Server, "http3-server", "", "HTTP/3-ALPN tunnel server URL or host:port (Wave 20)")
	rootCmd.Flags().StringVar(&flagDoQServer, "doq-server", "", "DNS-over-QUIC resolver host:port (default: dns.adguard.com:853)")
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
	rootCmd.AddCommand(reconCmd)
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

	// VPN server: must be a valid server address if provided.
	if flagVPNServer != "" {
		if _, err := platform.ValidateServerAddr(flagVPNServer); err != nil {
			return fmt.Errorf("--vpn-server: %w", err)
		}
	}

	// HTTP/3 server: must be a valid URL or server address if provided.
	if flagHTTP3Server != "" {
		// Accept either URL form or host:port form.
		if _, urlErr := platform.ValidateURL(flagHTTP3Server); urlErr != nil {
			if _, addrErr := platform.ValidateServerAddr(flagHTTP3Server); addrErr != nil {
				return fmt.Errorf("--http3-server: invalid URL or host:port: %w", urlErr)
			}
		}
	}

	// DoQ server: must be a valid server address if provided.
	if flagDoQServer != "" {
		if _, err := platform.ValidateServerAddr(flagDoQServer); err != nil {
			return fmt.Errorf("--doq-server: %w", err)
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
