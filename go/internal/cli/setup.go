// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/platform"
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

	// 6. Summary.
	fmt.Println("\n6. Ready!")
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
