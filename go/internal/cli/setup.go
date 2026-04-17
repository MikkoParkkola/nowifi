// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/server"
	"github.com/MikkoParkkola/nowifi/internal/telemetry"
	"github.com/MikkoParkkola/nowifi/internal/toolchain"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive first-time setup wizard",
	Long: `Interactive first-time setup wizard.

Checks your system, installs missing tools, and configures nowifi.
Run this once after installing nowifi.`,
	Run: runSetup,
}

// telemetryIsEnabled is a thin wrapper so setup.go doesn't import the
// telemetry package at the top level (avoids circular import risk).
func telemetryIsEnabled() bool { return telemetry.IsEnabled() }

func runSetup(cmd *cobra.Command, args []string) {
	fmt.Println("\nnowifi — Setup Wizard")
	fmt.Println()

	// 1. System check.
	fmt.Println("1. System check")
	fmt.Printf("   Go %s  %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		fmt.Printf("   Unsupported OS: %s. nowifi supports macOS and Linux.\n", runtime.GOOS)
		return
	}
	fmt.Println("   OK")

	// 2. WiFi interface.
	fmt.Println("\n2. WiFi interface")
	iface := "en0"
	if runtime.GOOS == "linux" {
		iface = "wlan0"
	}
	fmt.Printf("   Interface: %s\n", iface)
	wifi, wifiErr := platform.GetWifiInfo(iface)
	if wifiErr == nil && wifi != nil {
		fmt.Printf("   SSID: %s  Signal: %d dBm\n", wifi.SSID, wifi.RSSI)
	} else {
		fmt.Println("   Not connected (run setup after connecting to WiFi)")
	}

	// 3. External tools.
	fmt.Println("\n3. External tools")
	toolNames := []string{"chisel", "hysteria", "iodine", "hans", "hcxdumptool", "hashcat", "aircrack-ng", "cloudflared"}
	for _, t := range toolNames {
		path := toolchain.FindTool(t)
		if path != "" {
			fmt.Printf("   %s  %-18s %s\n", green("OK"), t, path)
		} else {
			fmt.Printf("   %s  %-18s not installed\n", dim("--"), t)
		}
	}

	// 4. Quick test.
	fmt.Println("\n4. Quick test")
	fmt.Println("   Running portal detection (read-only)...")
	portalInfo := detect.DetectPortal(iface)
	if portalInfo.IsCaptive {
		fmt.Printf("   Captive portal detected: %s\n", string(portalInfo.Type))
		if portalInfo.Vendor != "" {
			fmt.Printf("   Vendor: %s\n", portalInfo.Vendor)
		}
	} else {
		fmt.Println("   No captive portal (network appears open)")
	}

	// 5. Offline readiness check.
	fmt.Println("\n5. Offline readiness")
	fmt.Println("   nowifi often runs WITHOUT internet (behind a portal or cracking WiFi).")
	fmt.Println("   Make sure you have everything BEFORE going to the target location:")
	fmt.Println()

	allReady := true
	// Check downloadable tools.
	for _, t := range []string{"chisel", "hysteria"} {
		if toolchain.FindTool(t) == "" {
			fmt.Printf("   %s  %s — run: nowifi tools -d (requires internet)\n", yellow("MISSING"), t)
			allReady = false
		}
	}
	// Check for wordlists (for WPA cracking).
	wordlistPaths := []string{
		"/usr/share/wordlists/rockyou.txt",
		"/usr/share/wordlists/rockyou.txt.gz",
		"/opt/homebrew/share/wordlists/rockyou.txt",
	}
	hasWordlist := false
	for _, p := range wordlistPaths {
		if _, statErr := os.Stat(p); statErr == nil {
			hasWordlist = true
			break
		}
	}
	if !hasWordlist {
		fmt.Println("   NOTE    No wordlist found (rockyou.txt). For WPA cracking:")
		fmt.Println("           On Kali: already included")
		fmt.Println("           On macOS: brew install seclists")
		fmt.Println("           The top 1000 WiFi passwords are embedded in the binary.")
	} else {
		fmt.Println("   OK     Wordlist available for WPA cracking")
	}

	if allReady {
		fmt.Println("   OK     All tools ready for offline use")
	}

	// 6. Public endpoint (auto cascade).
	//
	// G3 – mandatory disclosure printed immediately before cascade attempt.
	fmt.Println("\n6. Public endpoint (auto)")
	fmt.Println()
	fmt.Println("   Note: Cloudflare logs the source IP of any tunnel you open. Tunnels are")
	fmt.Println("   not anonymous. Use only against networks you are authorized to assess.")
	fmt.Println()
	fmt.Println("   Trying providers in order (free, no account):")
	setupPublicEndpointCascade()

	// 7. Anonymous telemetry (opt-in).
	fmt.Println("\n7. Anonymous telemetry")
	fmt.Println("   nowifi can send anonymous data about which bypass techniques")
	fmt.Println("   succeed on which captive portals. Purpose: security research")
	fmt.Println("   and better technique ordering in future releases.")
	fmt.Println()
	fmt.Println("   Collected: technique, success, provider, duration, version, country")
	fmt.Println("   Never collected: IP, MAC, SSID, portal URL, DNS names")
	fmt.Println()
	if telemetryIsEnabled() {
		fmt.Println("   OK     Telemetry already enabled")
	} else {
		fmt.Println("   Enable later: nowifi telemetry enable")
		fmt.Println("   Details:      nowifi telemetry enable --help")
	}

	// 8. Summary.
	fmt.Println("\n8. Ready!")
	fmt.Println("   Available commands:")
	fmt.Println()
	fmt.Println("   sudo nowifi          Auto-detect and bypass (works offline)")
	fmt.Println("   nowifi diagnose      Read-only network assessment (works offline)")
	fmt.Println("   nowifi crack         WPA password cracking (works offline)")
	fmt.Println("   nowifi tools -d      Download tools (run NOW while online)")
	fmt.Println("   nowifi server create Set up tunnel server (run NOW while online)")
	fmt.Println("   nowifi doctor        System health check")
	fmt.Println("   nowifi reset         Restore network after crash")
	fmt.Println()
	fmt.Println("   TIP: Run 'nowifi tools -d' and 'nowifi server create' BEFORE")
	fmt.Println("        going to a location where you'll need nowifi.")
	fmt.Println()
}

// setupPublicEndpointCascade tries providers in priority order:
//
//  1. cloudflare_quick   — ephemeral trycloudflare.com, zero-config, no account
//  2. github_codespace   — GitHub Codespace relay (opt-in via NOWIFI_CODESPACE_REPO)
//  3. cloudflare_worker  — wrangler-deployed Worker, requires CF account
//
// Short-circuits if any tunnel endpoint is already active.
// [2/3] is silently skipped when NOWIFI_CODESPACE_REPO is unset — users opt in
// by setting the env var; we never prompt for it during setup.
func setupPublicEndpointCascade() {
	// Short-circuit: already active.
	servers, _ := server.ListServers()
	for _, s := range servers {
		if s.Provider == "cloudflare_quick" || s.Provider == "cloudflare_worker" ||
			s.Provider == "github_codespace" {
			fmt.Printf("   %s Endpoint already active: %s\n", green("OK"), s.URL)
			return
		}
	}

	// [1/3] cloudflare_quick — fastest, zero-config.
	fmt.Print("     [1/3] cloudflared quick tunnel ....... ")
	if toolchain.FindTool("cloudflared") != "" {
		info, err := server.SetupCloudflareQuickTunnel(context.Background(), "http://localhost:8080", 0)
		if err != nil {
			fmt.Printf("%s (%v)\n", dim("SKIP"), err)
		} else {
			fmt.Printf("%s %s\n", green("OK"), info.URL)
			return
		}
	} else {
		fmt.Printf("%s (cloudflared not installed)\n", dim("SKIP"))
	}

	// [2/3] github_codespace — opt-in via NOWIFI_CODESPACE_REPO env var.
	if repo := os.Getenv("NOWIFI_CODESPACE_REPO"); repo != "" {
		fmt.Print("     [2/3] github codespace relay ......... ")
		p, ok := server.Get("github_codespace")
		if ok {
			info, err := p.Create(context.Background(), server.CreateOpts{
				Extra: map[string]string{"repo": repo},
			})
			if err != nil {
				fmt.Printf("%s (%v)\n", dim("SKIP"), err)
			} else {
				fmt.Printf("%s %s\n", green("OK"), info.URL)
				return
			}
		} else {
			fmt.Printf("%s (provider not registered)\n", dim("SKIP"))
		}
	}

	// [3/3] cloudflare_worker — needs wrangler + CF account.
	fmt.Print("     [3/3] cloudflared worker (wrangler) .. ")
	if toolchain.FindTool("wrangler") != "" {
		info, err := server.SetupCloudflareWorker()
		if err != nil {
			fmt.Printf("%s (%v)\n", dim("SKIP"), err)
		} else {
			fmt.Printf("%s %s\n", green("OK"), info.URL)
			fmt.Println("   Free tier: 100,000 requests/day")
			return
		}
	} else {
		fmt.Printf("%s (wrangler not installed)\n", dim("SKIP"))
	}

	fmt.Println()
	fmt.Println("   No public endpoint configured (optional).")
	fmt.Println("   Install cloudflared: brew install cloudflared")
	fmt.Println("   Then: nowifi server create -p cloudflare-quick")
}
