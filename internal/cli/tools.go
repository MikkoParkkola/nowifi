// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"sort"

	"github.com/MikkoParkkola/nowifi/internal/toolchain"
	"github.com/spf13/cobra"
)

var toolsDownload bool

var toolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "List required external tools and their install status",
	Long: `List required external tools and their install status.

Shows which tools are installed, missing, or auto-downloadable.
Use -d to automatically download missing tools that support it.`,
	Run: runTools,
}

func init() {
	toolsCmd.Flags().BoolVarP(&toolsDownload, "download", "d", false,
		"Auto-download missing tools that support it")
}

func runTools(cmd *cobra.Command, args []string) {
	fmt.Printf("\nnowifi — External Tools\n\n")

	allTools := toolchain.ListTools()

	// Sort tool names for consistent output.
	names := make([]string, 0, len(allTools))
	for name := range allTools {
		names = append(names, name)
	}
	sort.Strings(names)

	installedCount := 0
	missingCount := 0
	downloadedCount := 0

	for _, name := range names {
		ts := allTools[name]

		if ts.Installed {
			installedCount++
			fmt.Printf("  %s  %-18s %s\n", green("OK"), name, dim(ts.Path))
			if ts.Description != "" {
				fmt.Printf("  %s  %-18s   %s\n", "  ", "", dim(ts.Description))
			}
		} else if toolsDownload && ts.Downloadable {
			// Attempt auto-download.
			fmt.Printf("  %s  %-18s downloading...\n", yellow("DL"), name)
			path, err := toolchain.DownloadTool(name)
			if err != nil {
				fmt.Printf("  %s  %-18s %v\n", red("!!"), name, err)
				missingCount++
			} else {
				fmt.Printf("  %s  %-18s %s\n", green("OK"), name, path)
				downloadedCount++
			}
		} else {
			missingCount++
			hint := ts.InstallHint
			if hint == "" && ts.Downloadable {
				hint = "nowifi tools -d"
			}
			fmt.Printf("  %s  %-18s %s\n", red("--"), name, dim("install: "+hint))
			if ts.Description != "" {
				fmt.Printf("  %s  %-18s   %s\n", "  ", "", dim(ts.Description))
			}
		}
	}

	// Summary.
	fmt.Println()
	fmt.Printf("  %d installed", installedCount)
	if downloadedCount > 0 {
		fmt.Printf(", %s downloaded", green(fmt.Sprintf("%d", downloadedCount)))
	}
	if missingCount > 0 {
		fmt.Printf(", %s missing", yellow(fmt.Sprintf("%d", missingCount)))
	}
	fmt.Println()

	if missingCount > 0 && !toolsDownload {
		fmt.Println()
		fmt.Println(dim("  Run 'nowifi tools -d' to auto-download chisel, hysteria, and cloudflared."))
		fmt.Println(dim("  Other tools require manual installation (see hints above)."))
	}
	fmt.Println()
}
