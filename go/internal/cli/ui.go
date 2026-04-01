package cli

import (
	"fmt"

	"github.com/MikkoParkkola/nowifi/internal/ui"
	"github.com/spf13/cobra"
)

var uiPort int

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Launch the web dashboard",
	Long: `Launch the embedded web dashboard.

Opens a real-time dark-themed dashboard in your browser at
http://127.0.0.1:8321 (default port). The dashboard shows:

  - Network overview (SSID, gateway, MAC)
  - Captive portal detection
  - Protocol probe results (live updates)
  - Bypass method feasibility table
  - Action buttons (Audit, Diagnose, Probe, Reset)
  - Active tunnel status
  - Live log stream

The dashboard binds to 127.0.0.1 only (not exposed to the network).`,
	Run: runUI,
}

func init() {
	uiCmd.Flags().IntVar(&uiPort, "port", 8321, "Dashboard listen port")
}

func runUI(cmd *cobra.Command, args []string) {
	fmt.Printf("\nnowifi v%s -- Web Dashboard\n\n", version)
	if err := ui.Serve(uiPort); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
