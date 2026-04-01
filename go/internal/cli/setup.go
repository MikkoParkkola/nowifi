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

	// 5. Offline readiness check.
	fmt.Println("\n5. Offline readiness")
	fmt.Println("   nowifi often runs WITHOUT internet (behind a portal or cracking WiFi).")
	fmt.Println("   Make sure you have everything BEFORE going to the target location:")
	fmt.Println()

	allReady := true
	// Check downloadable tools
	for _, t := range []string{"chisel", "hysteria"} {
		if _, err := exec.LookPath(t); err != nil {
			fmt.Printf("   MISSING  %s — run: nowifi tools -d (requires internet)\n", t)
			allReady = false
		}
	}
	// Check for wordlists (for WPA cracking)
	wordlistPaths := []string{
		"/usr/share/wordlists/rockyou.txt",
		"/usr/share/wordlists/rockyou.txt.gz",
		"/opt/homebrew/share/wordlists/rockyou.txt",
	}
	hasWordlist := false
	for _, p := range wordlistPaths {
		if _, err := exec.LookPath("test"); err == nil {
			// Just check file exists
			if out, _ := exec.Command("test", "-f", p).CombinedOutput(); len(out) == 0 {
				hasWordlist = true
				break
			}
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
