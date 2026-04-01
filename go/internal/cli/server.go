package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// --- server group ---

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Manage tunnel server infrastructure",
	Long: `Manage your tunnel server infrastructure.

Three options for getting a tunnel endpoint:
  A. Cloudflare Workers (FREE) — HTTPS proxy on CF edge, 100K req/day
  B. Ephemeral VPS            — DigitalOcean ($0.007/hr) or Hetzner ($0.005/hr)
  C. No server at all         — 10 of 23 techniques need no server`,
}

// --- server create ---

var (
	serverProvider string
	serverToken    string
	serverTTL      int
)

var serverCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a tunnel server (CF Worker or VPS)",
	Long: `Create a tunnel server (CF Worker or VPS).

Examples:
  nowifi server create                                  # Free CF Worker
  nowifi server create -p digitalocean -t do_xxx        # DO droplet
  nowifi server create -p hetzner -t htz_xxx --ttl 6    # Hetzner, 6h TTL`,
	Run: runServerCreate,
}

// --- server list ---

var serverListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active tunnel servers",
	Run:   runServerList,
}

// --- server destroy ---

var (
	serverDestroyAll bool
)

var serverDestroyCmd = &cobra.Command{
	Use:   "destroy [server-id]",
	Short: "Destroy a tunnel server",
	Long: `Destroy a tunnel server.

Examples:
  nowifi server destroy 12345678          # Destroy specific server
  nowifi server destroy nowifi-proxy      # Destroy CF Worker
  nowifi server destroy --all             # Destroy everything`,
	Run: runServerDestroy,
}

// --- server info ---

var serverInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show which techniques need a server and which don't",
	Long: `Show which techniques need a server and which don't.

10 of 23 bypass techniques work without any server infrastructure.
The other 13 need a tunnel endpoint you control.`,
	Run: runServerInfo,
}

func init() {
	// server create flags.
	serverCreateCmd.Flags().StringVarP(&serverProvider, "provider", "p", "cloudflare",
		"Infrastructure provider: cloudflare, digitalocean, hetzner")
	serverCreateCmd.Flags().StringVarP(&serverToken, "token", "t", "",
		"API token for cloud provider")
	serverCreateCmd.Flags().IntVar(&serverTTL, "ttl", 24,
		"Auto-destroy after N hours (VPS only)")

	// server destroy flags.
	serverDestroyCmd.Flags().BoolVar(&serverDestroyAll, "all", false,
		"Destroy all active servers")

	// Register subcommands under server.
	serverCmd.AddCommand(serverCreateCmd)
	serverCmd.AddCommand(serverListCmd)
	serverCmd.AddCommand(serverDestroyCmd)
	serverCmd.AddCommand(serverInfoCmd)
}

func runServerCreate(cmd *cobra.Command, args []string) {
	switch serverProvider {
	case "cloudflare":
		fmt.Println("\nnowifi — Deploying Cloudflare Worker")
		fmt.Println()
		// TODO: url := server.SetupCloudflareWorker()
		fmt.Println("  (Cloudflare Worker deployment not yet implemented)")
		fmt.Println("  Free tier: 100,000 requests/day")
	case "digitalocean", "hetzner":
		fmt.Printf("\nnowifi — Creating %s VPS\n\n", serverProvider)
		// TODO: info := server.CreateVPS(serverProvider, serverToken, serverTTL)
		fmt.Printf("  (VPS creation not yet implemented for %s)\n", serverProvider)
		fmt.Printf("  TTL: %dh\n", serverTTL)
	default:
		fmt.Printf("  Unknown provider: %s\n", serverProvider)
		os.Exit(1)
	}
	fmt.Println()
}

func runServerList(cmd *cobra.Command, args []string) {
	fmt.Println("\nnowifi — Tunnel Servers")
	fmt.Println()
	// TODO: servers := server.ListServers()
	fmt.Println("  No active servers.")
	fmt.Println("  Create one: nowifi server create")
	fmt.Println()
}

func runServerDestroy(cmd *cobra.Command, args []string) {
	serverID := ""
	if len(args) > 0 {
		serverID = args[0]
	}

	if serverID == "" && !serverDestroyAll {
		fmt.Println("\n  Specify a server ID or use --all.")
		fmt.Println("  List servers: nowifi server list")
		fmt.Println()
		os.Exit(1)
	}

	fmt.Println("\nnowifi — Destroying Server(s)")
	fmt.Println()

	if serverDestroyAll {
		// TODO: destroy all servers.
		fmt.Println("  (destroy all not yet implemented)")
	} else {
		// TODO: destroy specific server.
		fmt.Printf("  (destroy %s not yet implemented)\n", serverID)
	}
	fmt.Println()
}

func runServerInfo(cmd *cobra.Command, args []string) {
	fmt.Println("\nnowifi — Server Requirements")
	fmt.Println()

	serverless := []string{
		"IPv6 bypass",
		"CNA User-Agent spoof",
		"JS-only bypass",
		"HTTP CONNECT abuse",
		"MAC clone (idle station)",
		"MAC clone (any station)",
		"Whitelist domain abuse",
		"Session cookie replay",
		"Portal default credentials",
		"MAC rotate (fresh identity)",
		"DHCP rotate",
		"PMKID capture",
		"WPS Pixie-Dust",
		"WPA handshake capture",
		"WPS PIN brute force",
	}

	serverRequired := []string{
		"HTTPS/WS tunnel (chisel)",
		"DNS tunnel (iodine)",
		"ICMP tunnel (hans)",
		"VPN on port 53",
		"QUIC tunnel (Hysteria2)",
		"Cloudflare Workers proxy",
		"NTP tunnel",
		"DoH tunnel",
	}

	fmt.Printf("  %d techniques need NO server:\n", len(serverless))
	for _, t := range serverless {
		fmt.Printf("    o  %s\n", t)
	}

	fmt.Printf("\n  %d techniques NEED a server:\n", len(serverRequired))
	for _, t := range serverRequired {
		fmt.Printf("    *  %s\n", t)
	}

	fmt.Println()
	fmt.Println("  Get a free server: nowifi server create")
	fmt.Println("  Or use your own:   sudo nowifi -t https://your-server.example.com")
	fmt.Println()
}
