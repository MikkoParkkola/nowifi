//go:build darwin

package cli

import (
	"fmt"

	"github.com/MikkoParkkola/nowifi/internal/ui"
	"github.com/spf13/cobra"
)

var menubarPort int

var menubarCmd = &cobra.Command{
	Use:   "menubar",
	Short: "Launch macOS menubar app with web dashboard",
	Long: `Launch the macOS system tray (menubar) application.

Shows a "NW" icon in the macOS menu bar with quick actions:
  - Run Audit
  - Diagnose
  - Probe Only
  - Open Dashboard (web browser)
  - Reset Network
  - Quit

The web dashboard also starts on the configured port.
Both the menubar and dashboard run until you choose Quit.`,
	Run: runMenubar,
}

func init() {
	menubarCmd.Flags().IntVar(&menubarPort, "port", 8321, "Dashboard listen port")
}

func runMenubar(cmd *cobra.Command, args []string) {
	fmt.Printf("\nnowifi v%s -- Menubar + Dashboard\n\n", version)

	// Start the web dashboard in the background.
	go func() {
		if err := ui.Serve(menubarPort); err != nil {
			fmt.Printf("Dashboard error: %v\n", err)
		}
	}()

	// Run the system tray (blocks until quit).
	ui.RunTray(menubarPort)
}
