// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/bypass"
	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/guard"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/portal"
	"github.com/spf13/cobra"
)

var (
	watchInterval int
)

var detectPortal = detect.DetectPortal

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Maintain persistent access -- auto-reconnect on session expiry",
	Long: `Monitors connection and automatically rotates MAC and re-authenticates
when kicked by the captive portal.

Loop:
  1. Check internet (canary URL)
  2. If connected: sleep, repeat
  3. If disconnected: rotate MAC, DHCP renew, try auto-login
  4. Ctrl+C to stop (StateGuard restores original MAC)`,
	Run: runWatch,
}

func init() {
	watchCmd.Flags().IntVar(&watchInterval, "interval", 60, "Check interval in seconds")
}

func resolveWatchPortalURL(iface string) string {
	if flagPortalURL != "" {
		return flagPortalURL
	}
	portalInfo := detectPortal(iface)
	if portalInfo == nil || portalInfo.PortalURL == "" {
		return ""
	}
	flagPortalURL = portalInfo.PortalURL
	return flagPortalURL
}

func runWatch(cmd *cobra.Command, args []string) {
	iface := flagInterface

	printBanner("Watch Mode")

	if os.Geteuid() != 0 {
		fmt.Println("  Warning: Running without sudo. MAC rotation will not work.")
		fmt.Println("  For full capability: sudo nowifi watch")
		fmt.Println()
	}

	// Create state guard to restore on exit.
	g, err := guard.New(iface)
	if err != nil {
		fmt.Printf("  Warning: %v\n\n", err)
	}
	defer g.Restore()

	// Handle Ctrl+C gracefully.
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n  %s Caught signal, restoring state...\n", yellow("STOP"))
		cancel()
	}()

	interval := time.Duration(watchInterval) * time.Second
	disconnectCount := 0

	fmt.Printf("  Interface: %s\n", bold(iface))
	fmt.Printf("  Interval:  %s\n", bold(fmt.Sprintf("%ds", watchInterval)))
	fmt.Printf("  Press Ctrl+C to stop.\n\n")

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			fmt.Println("  Watch mode stopped. Original state restored.")
			fmt.Println()
			return
		default:
		}

		ts := time.Now().Format("15:04:05")

		if bypass.HasInternet() {
			fmt.Printf("  %s  %s  Connected\n", dim(ts), green("OK"))
			disconnectCount = 0
		} else {
			disconnectCount++
			fmt.Printf("  %s  %s  Session expired (attempt %d)\n", dim(ts), red("DOWN"), disconnectCount)

			// Rotate MAC.
			newMAC := platform.GenerateRandomMAC()
			fmt.Printf("  %s  %s  Rotating MAC to %s\n", dim(ts), yellow("MAC"), newMAC)

			if err := platform.SetMAC(iface, newMAC); err != nil {
				fmt.Printf("  %s  %s  MAC set failed: %v\n", dim(ts), red("ERR"), err)
			} else {
				// DHCP renew.
				fmt.Printf("  %s  %s  Renewing DHCP...\n", dim(ts), yellow("DHCP"))
				if err := platform.RenewDHCP(iface); err != nil {
					fmt.Printf("  %s  %s  DHCP renew failed: %v\n", dim(ts), red("ERR"), err)
				}

				// Wait for network to stabilize.
				time.Sleep(3 * time.Second)

				// Try auto-login.
				if !bypass.HasInternet() {
					portalURL := flagPortalURL
					if portalURL == "" {
						fmt.Printf("  %s  %s  Detecting portal URL...\n", dim(ts), yellow("DETECT"))
						portalURL = resolveWatchPortalURL(iface)
					}
					if portalURL == "" {
						fmt.Printf("  %s  %s  No portal URL detected; manual login may be required\n", dim(ts), yellow("INFO"))
						continue
					}

					fmt.Printf("  %s  %s  Trying auto-login...\n", dim(ts), yellow("LOGIN"))
					result, err := portal.AutoLogin(portalURL)
					if err != nil {
						fmt.Printf("  %s  %s  Auto-login error: %v\n", dim(ts), red("ERR"), err)
					} else if result.Success {
						fmt.Printf("  %s  %s  %s\n", dim(ts), green("OK"), result.Details)
					} else {
						fmt.Printf("  %s  %s  %s\n", dim(ts), yellow("INFO"), result.Details)
					}
				}

				// Final connectivity check.
				time.Sleep(2 * time.Second)
				if bypass.HasInternet() {
					fmt.Printf("  %s  %s  Reconnected!\n", dim(ts), green("OK"))
				} else {
					fmt.Printf("  %s  %s  Still disconnected\n", dim(ts), red("FAIL"))
				}
			}
		}

		// Sleep with cancellation support.
		select {
		case <-ctx.Done():
			fmt.Println()
			fmt.Println("  Watch mode stopped. Original state restored.")
			fmt.Println()
			return
		case <-time.After(interval):
		}
	}
}

// flagPortalURL is used by watch mode to remember the portal URL for auto-login.
var flagPortalURL string
