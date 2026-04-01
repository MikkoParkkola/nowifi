package cli

import (
	"fmt"
	"os/exec"
	"runtime"

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
	// TODO: wifi := platform.GetWifiInfo(iface)
	fmt.Println("   (WiFi check not yet implemented)")

	// 3. External tools.
	fmt.Println("\n3. External tools")
	tools := []string{"chisel", "hysteria", "iodine", "hans", "hcxdumptool", "hashcat", "aircrack-ng", "cloudflared"}
	for _, t := range tools {
		path, err := exec.LookPath(t)
		if err == nil {
			fmt.Printf("   OK  %-18s %s\n", t, path)
		} else {
			fmt.Printf("   --  %-18s not installed\n", t)
		}
	}

	// 4. Quick test.
	fmt.Println("\n4. Quick test")
	fmt.Println("   Running portal detection (read-only)...")
	// TODO: portal := detect.DetectPortal(iface)
	fmt.Println("   (portal detection not yet implemented)")

	// 5. Summary.
	fmt.Println("\n5. Ready!")
	fmt.Println("   Available commands:")
	fmt.Println()
	fmt.Println("   sudo nowifi          Auto-detect and bypass captive portal")
	fmt.Println("   nowifi diagnose      Read-only network assessment")
	fmt.Println("   nowifi crack         WPA password cracking")
	fmt.Println("   nowifi tools -d      Download missing tools")
	fmt.Println("   nowifi doctor        System health check")
	fmt.Println("   nowifi reset         Restore network after crash")
	fmt.Println()
}
