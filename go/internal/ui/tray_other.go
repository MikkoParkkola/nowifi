//go:build !darwin

package ui

import "fmt"

// RunTray is a no-op on non-darwin platforms.
func RunTray(dashboardPort int) {
	fmt.Println("System tray is only supported on macOS.")
	fmt.Println("Use 'nowifi ui' for the web dashboard instead.")
}
