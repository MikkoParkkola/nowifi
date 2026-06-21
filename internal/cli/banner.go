// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import "fmt"

// Banner lines — the final revealed state.
var bannerLines = []string{
	"  _ __   _____      _(_)/ _(_)",
	" | '_ \\ / _ \\ \\ /\\ / / | |_| |",
	" | | | | (_) \\ V  V /| |  _| |",
	" |_| |_|\\___/ \\_/\\_/ |_|_| |_|",
}

// printBanner displays the styled startup banner.
func printBanner(subtitle string) {
	if !useColor {
		fmt.Printf("\nnowifi v%s — %s\n\n", version, subtitle)
		return
	}

	fmt.Println()
	for _, line := range bannerLines {
		fmt.Printf("\033[1;36m%s\033[0m\n", line)
	}
	fmt.Printf("\n  \033[2m%s\033[0m  \033[1;37mv%s\033[0m\n\n", subtitle, version)
}
