package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var ecosystemCmd = &cobra.Command{
	Use:   "ecosystem",
	Short: "Show complementary tools for deeper WiFi assessment",
	Long: `Show complementary tools for capabilities beyond nowifi's scope.

nowifi focuses on automated bypass + cracking. For deeper assessment,
use these proven tools alongside nowifi.`,
	Run: runEcosystem,
}

type ecosystemTool struct {
	name    string
	what    string
	when    string
	install string
}

func runEcosystem(cmd *cobra.Command, args []string) {
	fmt.Println("\nnowifi — Complementary Tool Ecosystem")
	fmt.Println()
	fmt.Println("nowifi doesn't reimplement these — they're SOTA for their niche.")
	fmt.Println()

	tools := []ecosystemTool{
		{
			"bettercap",
			"MITM, ARP spoofing, network topology, BLE/HID",
			"After nowifi gets you on the network — deep MITM assessment",
			"brew install bettercap",
		},
		{
			"wifiphisher",
			"Evil twin, rogue AP, credential phishing portals",
			"When you need to clone a portal or create a fake AP",
			"pip install wifiphisher (Linux only)",
		},
		{
			"eaphammer",
			"WPA2-Enterprise, 802.1X, GTC downgrade, RADIUS relay",
			"Enterprise WiFi with RADIUS/EAP authentication",
			"github.com/s0lst1c3/eaphammer",
		},
		{
			"kismet",
			"Passive WiFi/BT/Zigbee/SDR reconnaissance",
			"Full spectrum passive monitoring without transmitting",
			"brew install kismet",
		},
		{
			"Wireshark",
			"Deep packet capture and protocol analysis",
			"Analyzing captured traffic after getting network access",
			"brew install wireshark",
		},
		{
			"Responder",
			"LLMNR/NBT-NS/mDNS poisoning, NTLMv2 hash capture",
			"On open/corporate WiFi to harvest Windows credentials",
			"pip install Responder",
		},
		{
			"mitm6",
			"IPv6 RA attacks, DHCPv6 poisoning, WPAD abuse",
			"When IPv6 is enabled — MITM via forged router advertisements",
			"pip install mitm6",
		},
		{
			"Nmap",
			"Network scanning, service detection, NSE scripts",
			"Mapping the network after gaining access",
			"brew install nmap",
		},
	}

	// Print as a formatted table.
	fmt.Printf("  %-14s %-55s %-55s %s\n", "Tool", "What it does", "When to use", "Install")
	fmt.Printf("  %-14s %-55s %-55s %s\n", "----", "------------", "-----------", "-------")
	for _, t := range tools {
		fmt.Printf("  %-14s %-55s %-55s %s\n", t.name, t.what, t.when, t.install)
	}

	fmt.Println()
	fmt.Println("Typical workflow: nowifi (get access) -> nmap (map network) -> bettercap (MITM) -> Wireshark (analyze)")
	fmt.Println()
}
