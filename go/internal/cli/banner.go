// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// ASCII art banner using block character style.
const banner = `
 ░█▀█░█▀█░█░█░▀█▀░█▀▀░▀█▀
 ░█░█░█░█░█▄█░░█░░█▀▀░░█░
 ░▀░▀░▀▀▀░▀░▀░▀▀▀░▀░░░▀▀▀
`

// printBanner displays the styled startup banner.
func printBanner(subtitle string) {
	if !useColor {
		fmt.Printf("\nnowifi v%s — %s\n\n", version, subtitle)
		return
	}

	// Cyan banner
	lines := strings.Split(banner, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			fmt.Printf("\033[1;36m%s\033[0m\n", line)
		}
	}

	// Version + subtitle
	fmt.Printf("  \033[2m%s\033[0m  \033[1mv%s\033[0m\n", subtitle, version)
	fmt.Println()
}

// matrixRain displays a brief matrix-style animation.
// Duration is ~1 second, 12 frames. Only runs if stdout is a terminal.
func matrixRain() {
	// Skip animation if not a terminal or NO_COLOR is set.
	if !useColor {
		return
	}
	if fi, err := os.Stdout.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return // Not a terminal (piped output).
	}

	cols := 60
	rows := 8
	chars := "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
	runeChars := []rune(chars)

	// Each column has a "drop" position.
	drops := make([]int, cols)
	for i := range drops {
		drops[i] = -rand.Intn(rows * 2)
	}

	// Hide cursor.
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h") // Restore cursor.

	grid := make([][]rune, rows)
	for r := range grid {
		grid[r] = make([]rune, cols)
		for c := range grid[r] {
			grid[r][c] = ' '
		}
	}

	for frame := 0; frame < 12; frame++ {
		// Advance drops.
		for c := range drops {
			drops[c]++
			row := drops[c]
			if row >= 0 && row < rows {
				grid[row][c] = runeChars[rand.Intn(len(runeChars))]
			}
			// Fade old positions.
			fadeRow := row - 3
			if fadeRow >= 0 && fadeRow < rows {
				grid[fadeRow][c] = ' '
			}
			// Reset drop when it goes past the screen.
			if drops[c] > rows+5 {
				drops[c] = -rand.Intn(rows)
			}
		}

		// Render frame.
		var buf strings.Builder
		buf.WriteString("\033[H") // Move cursor to top.
		for r := 0; r < rows; r++ {
			for c := 0; c < cols; c++ {
				ch := grid[r][c]
				dropRow := drops[c]
				if ch == ' ' {
					buf.WriteByte(' ')
				} else if r == dropRow {
					// Head of drop: bright white.
					buf.WriteString("\033[1;37m")
					buf.WriteRune(ch)
					buf.WriteString("\033[0m")
				} else if r == dropRow-1 {
					// Just behind head: bright green.
					buf.WriteString("\033[1;32m")
					buf.WriteRune(ch)
					buf.WriteString("\033[0m")
				} else {
					// Trail: dim green.
					buf.WriteString("\033[0;32m")
					buf.WriteRune(ch)
					buf.WriteString("\033[0m")
				}
			}
			buf.WriteByte('\n')
		}
		fmt.Print(buf.String())
		time.Sleep(80 * time.Millisecond)
	}

	// Clear the animation area.
	fmt.Printf("\033[H\033[J")
}
