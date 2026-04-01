//go:build !darwin

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package ui

import "fmt"

// RunTray is a no-op on non-darwin platforms.
func RunTray(dashboardPort int) {
	fmt.Println("System tray is only supported on macOS.")
	fmt.Println("Use 'nowifi ui' for the web dashboard instead.")
}
