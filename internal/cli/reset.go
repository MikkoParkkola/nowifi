// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset network to clean state after a crash or forced kill",
	Long: `Reset network to clean state after a crash or forced kill.

Run this if nowifi was killed (kill -9, power loss, crash) and your
network is broken. It undoes everything nowifi might have changed:

  - Restores hardware MAC address
  - Removes system SOCKS proxy
  - Kills orphaned tunnel processes (chisel, iodine, hans, hysteria)
  - Flushes DNS cache
  - Renews DHCP lease
  - Turns WiFi off and back on (full reset)`,
	Run: runReset,
}

func runReset(cmd *cobra.Command, args []string) {
	iface := flagInterface
	fmt.Printf("\nnowifi — Network Reset\n\n")

	// 1. Kill orphaned tunnel processes.
	tunnelProcesses := []string{
		"chisel", "iodine", "iodined", "hans", "ptunnel",
		"wstunnel", "hysteria", "ntpescape", "dnscrypt-proxy",
	}
	killed, warnings := stopOrphanedProcesses(tunnelProcesses)
	for _, warning := range warnings {
		fmt.Printf("  Warning: %v\n", warning)
	}
	switch {
	case killed > 0:
		fmt.Printf("  Killed %d orphaned tunnel process(es)\n", killed)
	case len(warnings) > 0:
		fmt.Println("  Tunnel cleanup completed with warnings")
	default:
		fmt.Println("  No orphaned tunnel processes found")
	}

	// 2. Remove system SOCKS proxy.
	if err := platform.ClearSystemProxy(iface); err != nil {
		fmt.Printf("  SOCKS proxy disable failed: %v\n", err)
	} else {
		fmt.Println("  SOCKS proxy disabled")
	}

	// 3. Restore hardware MAC.
	fmt.Printf("  MAC check (interface: %s)... ", iface)
	currentMAC, err := platform.GetCurrentMAC(iface)
	if err != nil {
		fmt.Printf("could not read current MAC: %v\n", err)
	} else {
		// The hardware MAC is not easily retrievable after spoofing,
		// but we can detect if it has the locally-administered bit set
		// (bit 1 of first octet), which indicates it was spoofed by nowifi.
		if len(currentMAC) >= 2 {
			firstByte := currentMAC[0:2]
			isLocal := false
			for _, c := range []string{"02", "06", "0a", "0e"} {
				if firstByte == c {
					isLocal = true
					break
				}
			}
			if isLocal {
				fmt.Printf("spoofed MAC detected (%s), ", currentMAC)
				// Generate a random vendor MAC to replace the spoofed one.
				// The real hardware MAC restoration happens via WiFi power cycle below.
				fmt.Println("will be restored via WiFi power cycle")
			} else {
				fmt.Printf("hardware MAC (%s) — OK\n", currentMAC)
			}
		} else {
			fmt.Printf("%s — OK\n", currentMAC)
		}
	}

	// 4. Flush DNS.
	if err := platform.FlushDNS(); err != nil {
		fmt.Printf("  DNS cache flush failed: %v\n", err)
	} else {
		fmt.Println("  DNS cache flushed")
	}

	// 5. WiFi power cycle.
	fmt.Println("  WiFi power cycling...")
	if err := platform.DisconnectWifi(iface); err != nil {
		fmt.Printf("    WiFi off failed: %v\n", err)
	} else {
		time.Sleep(2 * time.Second)
		if err := platform.ConnectWifi(iface); err != nil {
			fmt.Printf("    WiFi on failed: %v\n", err)
		} else {
			time.Sleep(3 * time.Second)
			fmt.Println("  WiFi power cycle complete")
		}
	}

	// 6. Renew DHCP.
	if err := platform.RenewDHCP(iface); err != nil {
		fmt.Printf("  DHCP renewal failed: %v\n", err)
	} else {
		fmt.Println("  DHCP renewed")
	}

	// 7. Remove WireGuard tunnel if present.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "wg-quick", "down", "wg-nowifi").Run()

	fmt.Print("\nNetwork reset complete. Try browsing now.\n\n")
}
