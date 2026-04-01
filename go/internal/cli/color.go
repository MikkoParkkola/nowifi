// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

var useColor = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}()

func green(s string) string {
	if !useColor {
		return s
	}
	return "\033[32m" + s + "\033[0m"
}

func red(s string) string {
	if !useColor {
		return s
	}
	return "\033[31m" + s + "\033[0m"
}

func yellow(s string) string {
	if !useColor {
		return s
	}
	return "\033[33m" + s + "\033[0m"
}

func bold(s string) string {
	if !useColor {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

func dim(s string) string {
	if !useColor {
		return s
	}
	return "\033[2m" + s + "\033[0m"
}

func status(ok bool) string {
	if ok {
		return green("OPEN")
	}
	return red("CLOSED")
}

func hint(lines ...string) {
	fmt.Println()
	fmt.Println(yellow("  What to do:"))
	for _, l := range lines {
		fmt.Println("  " + l)
	}
	fmt.Println()
}
