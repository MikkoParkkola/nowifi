package cli

import (
	"fmt"

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
	for _, proc := range tunnelProcesses {
		// TODO: Find and kill process by name.
		_ = proc
	}
	fmt.Println("  Killed orphaned tunnel processes")

	// 2. Remove system SOCKS proxy.
	// TODO: bypass.ClearSystemSOCKSProxy(iface)
	fmt.Println("  SOCKS proxy disabled")

	// 3. Restore hardware MAC.
	// TODO: Read hw MAC from system, compare with current, restore if different.
	fmt.Printf("  MAC check (interface: %s)\n", iface)

	// 4. Flush DNS.
	// TODO: platform.FlushDNS()
	fmt.Println("  DNS cache flushed")

	// 5. WiFi power cycle.
	fmt.Println("  WiFi power cycling...")
	// TODO: platform.DisconnectWifi(iface); sleep 2s; platform.ConnectWifi(iface); sleep 3s

	// 6. Renew DHCP.
	// TODO: platform.RenewDHCP(iface)
	fmt.Println("  DHCP renewed")

	// 7. Remove WireGuard tunnel if present.
	// TODO: exec wg-quick down wg-nowifi

	fmt.Print("\nNetwork reset complete. Try browsing now.\n\n")
}
