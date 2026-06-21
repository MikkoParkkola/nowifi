//go:build !darwin || !cgo

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var menubarCmd = &cobra.Command{
	Use:   "menubar",
	Short: "Launch macOS menubar app (macOS CGO only)",
	Long:  `The menubar command is only available on macOS builds with CGO enabled. Use 'nowifi ui' for the web dashboard on other platforms.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("The menubar command is only available on macOS builds with CGO enabled.")
		fmt.Println("Use 'nowifi ui' for the web dashboard instead.")
	},
}
