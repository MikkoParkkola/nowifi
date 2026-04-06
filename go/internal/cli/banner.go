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

// Banner lines — the final revealed state.
var bannerLines = []string{
	"  ░█▀█░█▀█░█░█░▀█▀░█▀▀░▀█▀",
	"  ░█░█░█░█░█▄█░░█░░█▀▀░░█░",
	"  ░▀░▀░▀▀▀░▀░▀░▀▀▀░▀░░░▀▀▀",
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

// matrixRain displays a signal-scan animation unique to nowifi.
//
// The concept: a WiFi signal sweep searches for connectivity.
// Signal bars scan left to right, probing for an opening.
// When found, the banner crystallizes from the interference pattern.
//
// Three phases:
//  1. SCAN — A signal probe sweeps across, leaving interference patterns
//  2. LOCK — The probe finds a signal; interference patterns freeze
//  3. DECODE — Frozen patterns resolve into the banner text
//
// Total: ~1.5 seconds. Terminal-only, respects NO_COLOR.
func matrixRain() {
	if !useColor {
		return
	}
	if fi, err := os.Stdout.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return
	}

	const (
		cols = 40
		rows = 5 // 1 blank + 3 banner + 1 blank
		fps  = 50 * time.Millisecond
	)

	// Signal/interference characters — WiFi themed.
	signalChars := []rune("·∙•○◦◌◎●◉⦿⊙⊚░▒▓")
	probeChars := []rune("▸▹►▻⟩›»→⟶⇢")

	// Build target from banner lines.
	target := make([][]rune, rows)
	for r := 0; r < rows; r++ {
		bannerIdx := r - 1 // offset: row 0 is blank, rows 1-3 are banner
		if bannerIdx >= 0 && bannerIdx < len(bannerLines) {
			line := bannerLines[bannerIdx]
			runes := []rune(line)
			target[r] = make([]rune, cols)
			copy(target[r], runes)
			for c := len(runes); c < cols; c++ {
				target[r][c] = ' '
			}
		} else {
			target[r] = make([]rune, cols)
			for c := range target[r] {
				target[r][c] = ' '
			}
		}
	}

	// Working grid.
	grid := make([][]rune, rows)
	for r := range grid {
		grid[r] = make([]rune, cols)
		for c := range grid[r] {
			grid[r][c] = ' '
		}
	}

	decoded := make([][]bool, rows)
	for r := range decoded {
		decoded[r] = make([]bool, cols)
	}

	// Reserve screen space.
	fmt.Print("\033[?25l") // Hide cursor.
	defer fmt.Print("\033[?25h")

	for i := 0; i < rows+1; i++ {
		fmt.Println()
	}
	fmt.Printf("\033[%dA\033[s", rows+1)

	render := func() {
		var buf strings.Builder
		buf.WriteString("\033[u")
		for r := 0; r < rows; r++ {
			for c := 0; c < cols; c++ {
				ch := grid[r][c]
				if ch == ' ' {
					buf.WriteByte(' ')
				} else if decoded[r][c] {
					buf.WriteString("\033[1;36m") // Cyan — final banner.
					buf.WriteRune(ch)
					buf.WriteString("\033[0m")
				} else {
					// Interference: dim cyan with occasional bright flickers.
					if rand.Float32() < 0.15 {
						buf.WriteString("\033[1;37m") // Bright white flash.
					} else if rand.Float32() < 0.4 {
						buf.WriteString("\033[0;36m") // Dim cyan.
					} else {
						buf.WriteString("\033[2;36m") // Very dim cyan.
					}
					buf.WriteRune(ch)
					buf.WriteString("\033[0m")
				}
			}
			buf.WriteByte('\n')
		}
		// Signal strength indicator below banner.
		buf.WriteString("\033[0m")
		fmt.Print(buf.String())
	}

	// Phase 1: SCAN — Signal probe sweeps left to right.
	// A vertical bar moves across, leaving interference in its wake.
	for probeCol := 0; probeCol < cols+5; probeCol += 2 {
		for r := 0; r < rows; r++ {
			for c := 0; c < cols; c++ {
				if c == probeCol {
					// Probe head.
					grid[r][c] = probeChars[rand.Intn(len(probeChars))]
				} else if c == probeCol-1 || c == probeCol-2 {
					// Probe trail — interference.
					if target[r][c] != ' ' {
						// Where banner text will be: leave denser interference.
						grid[r][c] = signalChars[rand.Intn(len(signalChars))]
					} else if rand.Float32() < 0.2 {
						grid[r][c] = signalChars[rand.Intn(4)] // Light scatter.
					}
				} else if c < probeCol-2 && grid[r][c] != ' ' {
					// Old interference fades.
					if rand.Float32() < 0.15 {
						grid[r][c] = ' '
					}
				}
			}
		}
		render()
		time.Sleep(fps)
	}

	// Phase 2: LOCK — Interference freezes, signal strength pulses.
	for frame := 0; frame < 4; frame++ {
		for r := 0; r < rows; r++ {
			for c := 0; c < cols; c++ {
				if target[r][c] != ' ' && !decoded[r][c] {
					// Replace interference with banner-adjacent chars.
					grid[r][c] = signalChars[rand.Intn(len(signalChars))]
				}
			}
		}
		render()
		time.Sleep(fps)
	}

	// Phase 3: DECODE — Banner text resolves from interference.
	// Decode column by column, left to right (like a signal lock).
	for c := 0; c < cols; c++ {
		for r := 0; r < rows; r++ {
			if target[r][c] != ' ' {
				grid[r][c] = target[r][c]
				decoded[r][c] = true
			} else {
				grid[r][c] = ' '
			}
		}
		if c%2 == 0 {
			render()
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Final clean render.
	render()
	time.Sleep(150 * time.Millisecond)

	// Move cursor below.
	fmt.Printf("\033[u\033[%dB", rows+1)
}
