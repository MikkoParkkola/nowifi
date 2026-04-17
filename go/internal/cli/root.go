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

	"time"

	"github.com/MikkoParkkola/nowifi/internal/config"
	"github.com/MikkoParkkola/nowifi/internal/crack"
	"github.com/MikkoParkkola/nowifi/internal/tunnel"
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
	flagWSServer     string
	flagMASQUEServer string
	flagWTServer     string
	flagH2Proxy      string
	flagSSEServer    string
	flagGRPCServer      string
	flagConnectIPServer string
	flagECHServer       string
	flagECHConfigB64 string
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
	rootCmd.Flags().StringVar(&flagWSServer, "ws-server", "", "WebSocket tunnel server URL (wss://...) (Wave 21 #25)")
	rootCmd.Flags().StringVar(&flagMASQUEServer, "masque-server", "", "MASQUE proxy URL (https://...) for HTTP/3 Extended CONNECT (Wave 21 #27)")
	rootCmd.Flags().StringVar(&flagWTServer, "wt-server", "", "WebTransport tunnel server URL (https://...) (Wave 21 #28)")
	rootCmd.Flags().StringVar(&flagH2Proxy, "h2-proxy", "", "HTTP/2 CONNECT proxy URL (https://...) (Wave 22 #29)")
	rootCmd.Flags().StringVar(&flagSSEServer, "sse-server", "", "SSE relay server URL (https://...) (Wave 22 #30)")
	rootCmd.Flags().StringVar(&flagGRPCServer, "grpc-server", "", "gRPC tunnel server URL (https://...) (Wave 22 #31)")
	rootCmd.Flags().StringVar(&flagConnectIPServer, "connectip-server", "", "CONNECT-IP proxy URL (https://...) (Wave 22 #32)")
	rootCmd.Flags().StringVar(&flagECHServer, "ech-server", "", "HTTPS URL of ECH-capable bypass proxy (Wave 21 #24)")
	rootCmd.Flags().StringVar(&flagECHConfigB64, "ech-config-list", "", "Base64 ECHConfigList from the server's HTTPS DNS RR")
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

// loadConfigDefaults fills unset CLI flags from ~/.nowifi/config.json.
// This is the "configure once, use forever" mechanism: any flag the user
// has previously set is automatically reused in subsequent runs.
func loadConfigDefaults(cmd *cobra.Command) {
	cfg, err := config.Load()
	if err != nil {
		return // silently use flag defaults on config error
	}

	// Helper: set flag value from config if the flag wasn't explicitly provided.
	fill := func(name, val string) {
		if val != "" && !cmd.Flags().Changed(name) {
			_ = cmd.Flags().Set(name, val)
		}
	}

	fill("tunnel-server", cfg.TunnelServer)
	fill("dns-domain", cfg.DNSDomain)
	fill("icmp-server", cfg.ICMPServer)
	fill("cf-workers", cfg.CFWorkers)
	fill("quic-server", cfg.QUICServer)
	fill("ntp-server", cfg.NTPServer)
	fill("vpn-server", cfg.VPNServer)
	fill("http3-server", cfg.HTTP3Server)
	fill("doq-server", cfg.DoQServer)
	fill("ws-server", cfg.WSServer)
	fill("masque-server", cfg.MASQUEServer)
	fill("wt-server", cfg.WTServer)
	fill("h2-proxy", cfg.H2Proxy)
	fill("sse-server", cfg.SSEServer)
	fill("grpc-server", cfg.GRPCServer)
	fill("connectip-server", cfg.ConnectIPServer)
	fill("ech-server", cfg.ECHServer)
	fill("ech-config-list", cfg.ECHConfigList)
}

// saveConfigFromFlags persists any newly-set server flags to config.
// Only saves fields that were explicitly set via CLI (cmd.Flags().Changed).
func saveConfigFromFlags(cmd *cobra.Command) {
	cfg, err := config.Load()
	if err != nil {
		return
	}

	changed := false
	save := func(name string, target *string, val string) {
		if cmd.Flags().Changed(name) && val != "" && val != *target {
			*target = val
			changed = true
		}
	}

	save("tunnel-server", &cfg.TunnelServer, flagTunnelServer)
	save("dns-domain", &cfg.DNSDomain, flagDNSDomain)
	save("icmp-server", &cfg.ICMPServer, flagICMPServer)
	save("cf-workers", &cfg.CFWorkers, flagCFWorkers)
	save("quic-server", &cfg.QUICServer, flagQUICServer)
	save("ntp-server", &cfg.NTPServer, flagNTPServer)
	save("vpn-server", &cfg.VPNServer, flagVPNServer)
	save("http3-server", &cfg.HTTP3Server, flagHTTP3Server)
	save("doq-server", &cfg.DoQServer, flagDoQServer)
	save("ws-server", &cfg.WSServer, flagWSServer)
	save("masque-server", &cfg.MASQUEServer, flagMASQUEServer)
	save("wt-server", &cfg.WTServer, flagWTServer)
	save("h2-proxy", &cfg.H2Proxy, flagH2Proxy)
	save("sse-server", &cfg.SSEServer, flagSSEServer)
	save("grpc-server", &cfg.GRPCServer, flagGRPCServer)
	save("connectip-server", &cfg.ConnectIPServer, flagConnectIPServer)
	save("ech-server", &cfg.ECHServer, flagECHServer)
	save("ech-config-list", &cfg.ECHConfigList, flagECHConfigB64)

	if changed {
		_ = config.Save(cfg)
	}
}

// autoDiscoverServers tries mDNS discovery for nowifi tunnel servers on the
// local network. Only runs when no server flags are set (neither CLI nor config).
func autoDiscoverServers(cmd *cobra.Command) {
	// Only discover if no server flags are set at all.
	serverFlags := []string{
		"tunnel-server", "masque-server", "wt-server", "h2-proxy",
		"sse-server", "grpc-server", "connectip-server", "http3-server",
		"ws-server", "ech-server",
	}
	for _, name := range serverFlags {
		if f := cmd.Flags().Lookup(name); f != nil && f.Value.String() != "" {
			return // at least one server configured, skip discovery
		}
	}

	servers, err := tunnel.DiscoverServers(2 * time.Second)
	if err != nil || len(servers) == 0 {
		return
	}

	// Map discovered servers to the appropriate flags.
	flagMap := map[string]string{
		"quic":      "http3-server",
		"h3":        "masque-server",
		"h2":        "h2-proxy",
		"sse":       "sse-server",
		"grpc":      "grpc-server",
		"connectip": "connectip-server",
	}

	for _, srv := range servers {
		if flagName, ok := flagMap[srv.Mode]; ok {
			if f := cmd.Flags().Lookup(flagName); f != nil && f.Value.String() == "" {
				_ = cmd.Flags().Set(flagName, srv.URL)
				fmt.Fprintf(cmd.OutOrStdout(), "  Auto-discovered %s server: %s\n", srv.Mode, srv.URL)
			}
		}
	}
}

// validateFlags validates all user-provided CLI flags at the boundary
// before they can reach any exec.Command call. Rejects invalid input early.
func validateFlags(cmd *cobra.Command, args []string) error {
	// Load saved config as defaults for unset flags.
	loadConfigDefaults(cmd)
	// Save any new flag values for future runs.
	saveConfigFromFlags(cmd)
	// Try mDNS discovery if no servers configured.
	autoDiscoverServers(cmd)
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

	// MASQUE server: must be a valid URL if provided.
	if flagMASQUEServer != "" {
		if _, err := platform.ValidateURL(flagMASQUEServer); err != nil {
			return fmt.Errorf("--masque-server: %w", err)
		}
	}

	// H2 proxy: must be a valid URL if provided.
	if flagH2Proxy != "" {
		if _, err := platform.ValidateURL(flagH2Proxy); err != nil {
			return fmt.Errorf("--h2-proxy: %w", err)
		}
	}

	// SSE server: must be a valid URL if provided.
	if flagSSEServer != "" {
		if _, err := platform.ValidateURL(flagSSEServer); err != nil {
			return fmt.Errorf("--sse-server: %w", err)
		}
	}

	// gRPC server: must be a valid URL if provided.
	if flagGRPCServer != "" {
		if _, err := platform.ValidateURL(flagGRPCServer); err != nil {
			return fmt.Errorf("--grpc-server: %w", err)
		}
	}

	// CONNECT-IP server: must be a valid URL if provided.
	if flagConnectIPServer != "" {
		if _, err := platform.ValidateURL(flagConnectIPServer); err != nil {
			return fmt.Errorf("--connectip-server: %w", err)
		}
	}

	// WebTransport server: must be a valid URL if provided.
	if flagWTServer != "" {
		if _, err := platform.ValidateURL(flagWTServer); err != nil {
			return fmt.Errorf("--wt-server: %w", err)
		}
	}

	// ECH server: must be a valid URL if provided.
	if flagECHServer != "" {
		if _, err := platform.ValidateURL(flagECHServer); err != nil {
			return fmt.Errorf("--ech-server: %w", err)
		}
	}
	// ECH config list: non-empty strings should be plausibly base64. Deep
	// decoding happens at dial time.

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
