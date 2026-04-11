// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"os"

	"github.com/MikkoParkkola/nowifi/internal/crack"
	"github.com/MikkoParkkola/nowifi/internal/server"
	"github.com/MikkoParkkola/nowifi/internal/techniques"
	"github.com/spf13/cobra"
)

// --- server group ---

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Manage tunnel server infrastructure",
	Long:  buildServerCommandLongDescription(),
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
	Long:  buildServerInfoLongDescription(),
	Run:   runServerInfo,
}

var localCrackingTechniqueNames = []string{
	"PMKID capture",
	"WPS Pixie-Dust",
	"WPA handshake capture",
	"WPS PIN brute force",
	"Smart common passwords",
	"Smart numeric masks",
	"Smart word+number rules",
	"Online brute force",
}

func buildServerCommandLongDescription() string {
	totalTechniqueCount := techniques.BypassTechniqueCount() + crack.UserVisibleTechniqueCount
	return fmt.Sprintf(`Manage your tunnel server infrastructure.

Three options for getting a tunnel endpoint:
  A. Cloudflare Workers (FREE) — HTTPS proxy on CF edge, 100K req/day
  B. Ephemeral VPS            — DigitalOcean ($0.007/hr) or Hetzner ($0.005/hr)
  C. No server at all         — %d of %d techniques are local/serverless`,
		len(serverlessTechniqueNames()),
		totalTechniqueCount,
	)
}

func buildServerInfoLongDescription() string {
	totalTechniqueCount := techniques.BypassTechniqueCount() + crack.UserVisibleTechniqueCount
	return fmt.Sprintf(`Show which techniques need a server and which don't.

%d of %d techniques work without any server infrastructure.
The remaining %d portal bypass techniques need an external endpoint you control.
WPA cracking techniques are all local.`,
		len(serverlessTechniqueNames()),
		totalTechniqueCount,
		len(serverRequiredTechniqueNames()),
	)
}

func serverlessTechniqueNames() []string {
	names := make([]string, 0, len(techniques.ServerlessBypassTechniqueInfos())+len(localCrackingTechniqueNames))
	for _, info := range techniques.ServerlessBypassTechniqueInfos() {
		names = append(names, info.Name)
	}
	names = append(names, localCrackingTechniqueNames...)
	return names
}

func serverRequiredTechniqueNames() []string {
	names := make([]string, 0, len(techniques.ServerRequiredBypassTechniqueInfos()))
	for _, info := range techniques.ServerRequiredBypassTechniqueInfos() {
		names = append(names, info.Name)
	}
	return names
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
		info, err := server.SetupCloudflareWorker()
		if err != nil {
			fmt.Printf("  %s %v\n", red("ERROR"), err)
			fmt.Println()
			os.Exit(1)
		}
		fmt.Printf("  %s Worker deployed: %s\n", green("OK"), info.URL)
		fmt.Println("  Free tier: 100,000 requests/day")
		fmt.Printf("  Use: sudo nowifi --cf-workers %s\n", info.URL)
	case "digitalocean", "hetzner":
		fmt.Printf("\nnowifi — Creating %s VPS\n\n", serverProvider)
		info, err := server.CreateVPS(serverProvider, serverToken, serverTTL)
		if err != nil {
			fmt.Printf("  %s %v\n", red("ERROR"), err)
			fmt.Println()
			os.Exit(1)
		}
		fmt.Printf("  %s Server created: %s\n", green("OK"), info.IP)
		fmt.Printf("  Tunnel URL: %s\n", info.URL)
		fmt.Printf("  TTL: %dh (auto-destroy)\n", serverTTL)
		fmt.Printf("  Use: sudo nowifi -t %s\n", info.URL)
	default:
		fmt.Printf("  Unknown provider: %s\n", serverProvider)
		os.Exit(1)
	}
	fmt.Println()
}

func runServerList(cmd *cobra.Command, args []string) {
	fmt.Println("\nnowifi — Tunnel Servers")
	fmt.Println()

	servers, err := server.ListServers()
	if err != nil {
		fmt.Printf("  %s %v\n", red("ERROR"), err)
		fmt.Println()
		return
	}

	if len(servers) == 0 {
		fmt.Println("  No active servers.")
		fmt.Println("  Create one: nowifi server create")
		fmt.Println()
		return
	}

	fmt.Printf("  %-20s  %-16s  %-20s  %-8s  %s\n",
		bold("Provider"), bold("IP"), bold("URL"), bold("TTL"), bold("Created"))
	for _, s := range servers {
		ip := s.IP
		if ip == "" {
			ip = dim("(edge)")
		}
		ttl := "-"
		if s.TTLHours > 0 {
			ttl = fmt.Sprintf("%dh", s.TTLHours)
		}
		created := s.CreatedAt
		if len(created) > 19 {
			created = created[:19]
		}
		fmt.Printf("  %-20s  %-16s  %-20s  %-8s  %s\n",
			s.Provider, ip, s.URL, ttl, dim(created))
	}

	// Check for expired servers.
	expired := server.CheckExpiredServers()
	if len(expired) > 0 {
		fmt.Println()
		fmt.Printf("  %s %d server(s) past TTL — consider destroying them.\n",
			yellow("WARN"), len(expired))
	}

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
		servers, err := server.ListServers()
		if err != nil {
			fmt.Printf("  %s %v\n", red("ERROR"), err)
			fmt.Println()
			return
		}
		if len(servers) == 0 {
			fmt.Println("  No active servers to destroy.")
			fmt.Println()
			return
		}
		for _, s := range servers {
			if err := server.DestroyServer(&s, serverToken); err != nil {
				fmt.Printf("  %s %s (%s): %v\n", red("FAIL"), s.ServerID, s.Provider, err)
			} else {
				fmt.Printf("  %s %s (%s) destroyed\n", green("OK"), s.ServerID, s.Provider)
			}
		}
	} else {
		// Find the specific server.
		servers, _ := server.LoadServers()
		var target *server.Info
		for i := range servers {
			if servers[i].ServerID == serverID {
				target = &servers[i]
				break
			}
		}
		if target == nil {
			fmt.Printf("  Server %s not found. Run: nowifi server list\n", serverID)
			fmt.Println()
			os.Exit(1)
		}
		if err := server.DestroyServer(target, serverToken); err != nil {
			fmt.Printf("  %s %v\n", red("ERROR"), err)
		} else {
			fmt.Printf("  %s %s (%s) destroyed\n", green("OK"), target.ServerID, target.Provider)
		}
	}
	fmt.Println()
}

func runServerInfo(cmd *cobra.Command, args []string) {
	fmt.Println("\nnowifi — Server Requirements")
	fmt.Println()

	serverless := serverlessTechniqueNames()
	serverRequired := serverRequiredTechniqueNames()

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
