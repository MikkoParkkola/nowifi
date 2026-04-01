//go:build !darwin

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var menubarCmd = &cobra.Command{
	Use:   "menubar",
	Short: "Launch macOS menubar app (macOS only)",
	Long:  `The menubar command is only available on macOS. Use 'nowifi ui' for the web dashboard on other platforms.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("The menubar command is only available on macOS.")
		fmt.Println("Use 'nowifi ui' for the web dashboard instead.")
	},
}
