// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/MikkoParkkola/nowifi/internal/crack"
	"github.com/MikkoParkkola/nowifi/internal/server"
	"github.com/MikkoParkkola/nowifi/internal/server/udpws"
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
	serverProvider  string
	serverToken     string
	serverTTL       int
	serverTarget    string
	serverUDP       bool
	serverUDPTarget string
)

var serverCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a tunnel server (CF Worker, VPS, or libp2p peer)",
	Long: `Create a tunnel server (CF Worker, VPS, or libp2p P2P peer).

Examples:
  nowifi server create                                  # Free CF Worker
  nowifi server create -p digitalocean -t do_xxx        # DO droplet
  nowifi server create -p hetzner -t htz_xxx --ttl 6    # Hetzner, 6h TTL
  nowifi server create -p libp2p                        # P2P peer (prints pairing code)`,
	Run: runServerCreate,
}

// --- server list ---

var serverListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active tunnel servers",
	Run:   runServerList,
}

// --- server rotate-token ---

var serverRotateTokenCmd = &cobra.Command{
	Use:   "rotate-token",
	Short: "Rotate the Cloudflare Worker authentication token",
	Long: `Rotate the Cloudflare Worker authentication token.

This redeploys the managed Worker with a new nowifi_token and persists the new
token-bearing URL in ~/.nowifi/config.json.`,
	Run: runServerRotateToken,
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

// --- server client ---

var (
	serverClientURL      string
	serverClientUDPLocal string
	serverClientPair     string
)

var serverClientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start UDP-over-WebSocket client (peer side of --udp tunnel)",
	Long: `Start the UDP-over-WebSocket client on the remote peer.

The client listens on a local UDP port and tunnels all datagrams to the
Quick Tunnel WebSocket endpoint opened by 'nowifi server create --udp'.

Examples:
  # Peer connects WireGuard via the Quick Tunnel (printed by server create):
  nowifi server client --url wss://shiny-river-42.trycloudflare.com --udp-local 127.0.0.1:51820

  # Custom local bind (e.g. to avoid conflicts):
  nowifi server client --url wss://... --udp-local 0.0.0.0:5182`,
	Run: runServerClient,
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
		"Infrastructure provider: cloudflare, cloudflare-quick, github-codespace, digitalocean, hetzner, libp2p")
	serverCreateCmd.Flags().StringVarP(&serverToken, "token", "t", "",
		"API token for cloud provider")
	serverCreateCmd.Flags().IntVar(&serverTTL, "ttl", 24,
		"Auto-destroy after N hours (VPS only)")
	serverCreateCmd.Flags().StringVar(&serverTarget, "target", "http://localhost:8080",
		"Local service URL to expose (cloudflare-quick only)")
	serverCreateCmd.Flags().BoolVar(&serverUDP, "udp", false,
		"Enable UDP-over-WebSocket mode (cloudflare-quick only); starts in-process udpws bridge")
	serverCreateCmd.Flags().StringVar(&serverUDPTarget, "udp-target", "127.0.0.1:51820",
		"Local UDP target to bridge (libp2p provider)")

	// server destroy flags.
	serverDestroyCmd.Flags().BoolVar(&serverDestroyAll, "all", false,
		"Destroy all active servers")

	// server client flags.
	serverClientCmd.Flags().StringVar(&serverClientURL, "url", "",
		"Quick Tunnel URL (wss://... or https://...) printed by server create --udp")
	serverClientCmd.Flags().StringVar(&serverClientUDPLocal, "udp-local", "127.0.0.1:51820",
		"Local UDP address to listen on (WireGuard/VPN peer endpoint)")
	serverClientCmd.Flags().StringVar(&serverClientPair, "pair", "",
		"libp2p 3-word pairing code (alternative to --url)")

	// Register subcommands under server.
	serverCmd.AddCommand(serverCreateCmd)
	serverCmd.AddCommand(serverListCmd)
	serverCmd.AddCommand(serverRotateTokenCmd)
	serverCmd.AddCommand(serverDestroyCmd)
	serverCmd.AddCommand(serverInfoCmd)
	serverCmd.AddCommand(serverClientCmd)
}

func runServerCreate(cmd *cobra.Command, args []string) {
	switch serverProvider {
	case "github-codespace":
		fmt.Println("\nnowifi — GitHub Codespace Relay")
		fmt.Println()
		p, ok := server.Get("github_codespace")
		if !ok {
			fmt.Printf("  %s provider not registered\n", red("ERROR"))
			os.Exit(1)
		}
		extra := map[string]string{"repo": serverTarget}
		if repo := os.Getenv("NOWIFI_CODESPACE_REPO"); repo != "" {
			extra["repo"] = repo
		}
		info, err := p.Create(context.Background(), server.CreateOpts{
			TTLHours: serverTTL,
			Extra:    extra,
		})
		if err != nil {
			fmt.Printf("  %s %v\n", red("ERROR"), err)
			fmt.Println()
			os.Exit(1)
		}
		fmt.Printf("  %s Codespace: %s\n", green("OK"), info.ServerID)
		fmt.Printf("  URL: %s\n", info.URL)
	case "cloudflare-quick":
		fmt.Println("\nnowifi — Cloudflare Quick Tunnel")
		fmt.Printf("  Target: %s\n", serverTarget)
		if serverUDP {
			fmt.Println("  Mode: UDP-over-WebSocket")
		}
		fmt.Println()
		extra := map[string]string{}
		if serverUDP {
			extra["udp"] = "true"
		}
		// Use a cancellable context so cloudflared (launched via exec.CommandContext)
		// is killed when the context is cancelled on Ctrl-C / SIGTERM.
		tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
		defer tunnelCancel()

		info, stop, err := server.SetupCloudflareQuickTunnelWithOpts(tunnelCtx, server.CreateOpts{
			Target:   serverTarget,
			TTLHours: serverTTL,
			Extra:    extra,
		})
		if err != nil {
			fmt.Printf("  %s %v\n", red("ERROR"), err)
			fmt.Println()
			os.Exit(1)
		}
		fmt.Printf("  %s Tunnel active: %s\n", green("OK"), info.URL)
		fmt.Printf("  Tunnel name: %s\n", info.ServerID)
		if info.Extra["udp_mode"] == "true" {
			fmt.Printf("  UDP bridge: ws://%s/udp\n", info.Extra["udp_listen"])
			fmt.Printf("  Client cmd: nowifi server client --url %s --udp-local 127.0.0.1:51820\n", info.URL)
		}
		fmt.Println()
		fmt.Println("  Press Ctrl-C to stop tunnel.")

		// Block until SIGINT or SIGTERM.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		fmt.Println("\n  Stopping tunnel…")
		tunnelCancel() // cancels exec.CommandContext → cloudflared exits
		stop()         // SIGTERM/SIGKILL + udpws shutdown
		_ = server.DestroyServer(info, "")
		fmt.Println("  Tunnel stopped.")
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
	case "libp2p":
		fmt.Println("\nnowifi — libp2p P2P Peer (native UDP)")
		fmt.Printf("  UDP target: %s\n", serverUDPTarget)
		fmt.Println()
		p, ok := server.Get("libp2p")
		if !ok {
			fmt.Printf("  %s provider not registered\n", red("ERROR"))
			os.Exit(1)
		}
		tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
		defer tunnelCancel()
		info, err := p.Create(tunnelCtx, server.CreateOpts{
			Extra: map[string]string{"udp_target": serverUDPTarget},
		})
		if err != nil {
			fmt.Printf("  %s %v\n", red("ERROR"), err)
			fmt.Println()
			os.Exit(1)
		}
		fmt.Printf("  %s libp2p peer active: %s\n", green("OK"), info.ServerID)
		if code := info.Extra["pairing_code"]; code != "" {
			fmt.Printf("  Pairing code: %s\n", code)
		}
		fmt.Println("  Ctrl+C to stop.")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\n  Stopping libp2p peer…")
		tunnelCancel()
		_ = server.DestroyServer(info, "")
		fmt.Println("  Stopped.")
	default:
		fmt.Printf("  Unknown provider %q. Available: %v\n", serverProvider, server.Names())
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
			s.Provider, ip, server.RedactURLSecrets(s.URL), ttl, dim(created))
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

func runServerRotateToken(cmd *cobra.Command, args []string) {
	fmt.Println("\nnowifi — Rotating Cloudflare Worker Token")
	fmt.Println()
	info, err := server.SetupCloudflareWorker()
	if err != nil {
		fmt.Printf("  %s %v\n", red("ERROR"), err)
		fmt.Println()
		os.Exit(1)
	}
	fmt.Printf("  %s Worker token rotated: %s\n", green("OK"), info.URL)
	fmt.Printf("  Use: sudo nowifi --cf-workers %s\n", info.URL)
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

func runServerClient(cmd *cobra.Command, args []string) {
	// Exactly one connection mode is required. The --url required-flag guard was
	// dropped when --pair was added, so validate here: without this, invoking
	// with neither flag builds "wss:///udp" from an empty URL and fails obscurely.
	if serverClientPair == "" && serverClientURL == "" {
		fmt.Printf("\n  %s provide --url <server-url> or --pair <3-word-code>\n\n", red("ERROR"))
		os.Exit(1)
	}
	if serverClientPair != "" && serverClientURL != "" {
		fmt.Printf("\n  %s --url and --pair are mutually exclusive; use one\n\n", red("ERROR"))
		os.Exit(1)
	}
	if serverClientPair != "" {
		fmt.Println("\nnowifi — libp2p P2P Client")
		fmt.Printf("  Pairing code: %s\n", serverClientPair)
		fmt.Printf("  Local UDP: %s\n\n", serverClientUDPLocal)
		if err := server.ConnectLibp2pClientPair(context.Background(), serverClientPair, serverClientUDPLocal); err != nil {
			fmt.Printf("  %s %v\n\n", red("ERROR"), err)
			os.Exit(1)
		}
		fmt.Printf("  %s libp2p client connected\n", green("OK"))
		fmt.Println("  Ctrl+C to stop.")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\n  Stopping libp2p client.")
		return
	}

	fmt.Println("\nnowifi — UDP-over-WebSocket Client")
	fmt.Println()

	// Normalise URL: accept https:// or wss:// or bare hostname.
	// The udpws client needs a ws:// or wss:// URL.
	wsURL := serverClientURL
	switch {
	case strings.HasPrefix(wsURL, "https://"):
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	case strings.HasPrefix(wsURL, "http://"):
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	case !strings.HasPrefix(wsURL, "ws://") && !strings.HasPrefix(wsURL, "wss://"):
		wsURL = "wss://" + wsURL
	}

	// Append /udp path if not already present.
	if !strings.HasSuffix(wsURL, "/udp") {
		wsURL = strings.TrimRight(wsURL, "/") + "/udp"
	}

	fmt.Printf("  WebSocket: %s\n", wsURL)
	fmt.Printf("  Local UDP: %s\n\n", serverClientUDPLocal)

	cli := &udpws.Client{
		UDPListenAddr: serverClientUDPLocal,
		RemoteURL:     wsURL,
		OriginURL:     wsURL,
	}

	listenAddr, stop, err := cli.Start()
	if err != nil {
		fmt.Printf("  %s %v\n\n", red("ERROR"), err)
		os.Exit(1)
	}
	defer stop()

	fmt.Printf("  %s Listening on %s\n", green("OK"), listenAddr)
	fmt.Println("  Ctrl+C to stop.")
	fmt.Println()

	// Block until SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n  Stopping UDP client.")
	fmt.Println()
	_ = context.Background() // keep context import used
}
