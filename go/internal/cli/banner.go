// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

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

// ── ANSI helpers ────────────────────────────────────────────────────

const (
	esc        = "\033["
	clearScr   = esc + "2J" + esc + "H"
	hideCursor = esc + "?25l"
	showCursor = esc + "?25h"
	reset      = esc + "0m"
)

func moveTo(row, col int) string { return fmt.Sprintf("%s%d;%dH", esc, row, col) }
func fg(code int) string         { return fmt.Sprintf("%s38;5;%dm", esc, code) }
func boldANSI() string           { return esc + "1m" }
func dimANSI() string            { return esc + "2m" }

// ── Boot text pools ─────────────────────────────────────────────────

var bootMessages = []string{
	"loading bypass engine",
	"initializing probe matrix",
	"arming MAC rotation",
	"calibrating DNS tunnels",
	"building ARP poison table",
	"mapping portal fingerprints",
	"seeding entropy pool",
	"compiling evasion ruleset",
	"mounting covert channel",
	"hashing portal signatures",
	"warming ICMP echo chain",
	"linking protocol analyzers",
	"indexing captive signatures",
	"engaging stealth subsystem",
	"allocating spoof buffers",
}

var ifaceLines = []string{
	"wlan0     UP  802.11ac  ch36",
	"en0       UP  802.11ax  ch149",
	"wlan1     DOWN scanning...",
	"mon0      UP  monitor mode",
	"tun0      INIT  dns-tunnel",
	"tap0      WAIT  icmp-echo",
	"br0       UP  bridge-mode",
	"veth1     UP  spoof-ready",
}

// ── WiFi signal art ─────────────────────────────────────────────────

// Each row is one horizontal slice; drawn from inner (index 0) to outer.
var wifiArcs = []string{
	"     ( . )",
	"    (  .  )",
	"   (   .   )",
	"  (    .    )",
	" (     .     )",
}

// ── matrixRain: cinematic boot sequence ─────────────────────────────
//
// Five-phase startup animation that takes over the terminal for ~3 s.
// Pure ANSI escape codes + Unicode block characters. No external deps.
//
//   Phase 0  BLACKOUT        200 ms   blank screen, tension
//   Phase 1  SYSTEM BOOT     800 ms   hex scrolling, progress bar, iface data
//   Phase 2  SIGNAL ACQUIRE  600 ms   WiFi arcs pulse inward-out
//   Phase 3  TARGET LOCK     400 ms   flash + shake + "SIGNAL ACQUIRED"
//   Phase 4  BANNER REVEAL   600 ms   wipe + letter-spark reveal
//   Phase 5  READY           200 ms   settle, restore cursor
//
// Skipped when: NO_COLOR set, not a real terminal, or useColor == false.
func matrixRain() {
	if !useColor {
		return
	}
	fd := int(os.Stdout.Fd())
	if !term.IsTerminal(fd) {
		return
	}

	// Terminal dimensions — fallback to 80x24.
	width, height, err := term.GetSize(fd)
	if err != nil || width < 40 || height < 12 {
		width, height = 80, 24
	}

	// Hide cursor for the entire sequence.
	fmt.Print(hideCursor)
	defer fmt.Print(showCursor)

	// ─── Phase 0: BLACKOUT ──────────────────────────────────────────
	fmt.Print(clearScr)
	time.Sleep(400 * time.Millisecond)

	// ─── Phase 1: SYSTEM BOOT ───────────────────────────────────────
	// Three concurrent visual streams:
	//   Left column  : hex address + boot message
	//   Right column : network interface data
	//   Bottom row   : progress bar

	barRow := height - 2
	barWidth := width - 4
	if barWidth > 72 {
		barWidth = 72
	}
	barCol := (width - barWidth) / 2

	ifaceCol := width - 36
	if ifaceCol < 44 {
		ifaceCol = 44
	}

	const bootFrames = 14
	for frame := 0; frame < bootFrames; frame++ {
		var buf strings.Builder

		// -- hex boot lines (left column, rows 2..frame+2) --
		hexRow := 2 + frame
		if hexRow < barRow-1 {
			addr := 0x7F00 + rand.Intn(0x0FFF)
			msg := bootMessages[frame%len(bootMessages)]
			line := fmt.Sprintf("[0x%04X] %s...", addr, msg)
			if len(line) > ifaceCol-4 {
				line = line[:ifaceCol-4]
			}
			buf.WriteString(moveTo(hexRow, 3))
			buf.WriteString(dimANSI())
			buf.WriteString(fg(34)) // dim green (256-color)
			buf.WriteString(line)
			buf.WriteString(reset)
		}

		// -- right-side iface data (every other frame) --
		if frame%2 == 0 && ifaceCol+30 < width {
			ifRow := 2 + frame/2
			if ifRow < barRow-1 && frame/2 < len(ifaceLines) {
				buf.WriteString(moveTo(ifRow, ifaceCol))
				buf.WriteString(dimANSI())
				buf.WriteString(fg(22)) // darker green
				buf.WriteString(ifaceLines[frame/2])
				buf.WriteString(reset)
			}
		}

		// -- progress bar --
		progress := float64(frame+1) / float64(bootFrames)
		filled := int(progress * float64(barWidth))
		pctText := fmt.Sprintf(" %3d%%", int(progress*100))

		buf.WriteString(moveTo(barRow, barCol))
		buf.WriteString(fg(34))
		for i := 0; i < barWidth; i++ {
			if i < filled {
				buf.WriteString("\033[1m") // bright
				buf.WriteRune('\u2588')    // full block
			} else {
				buf.WriteString(dimANSI())
				buf.WriteRune('\u2591') // light shade
			}
		}
		buf.WriteString(reset)
		buf.WriteString(fg(34))
		buf.WriteString(pctText)
		buf.WriteString(reset)

		// -- techniques counter (below bar, centered) --
		if frame >= bootFrames/2 {
			armed := (frame - bootFrames/2 + 1) * 3
			if armed > 19 {
				armed = 19
			}
			counter := fmt.Sprintf("%d techniques armed", armed)
			buf.WriteString(moveTo(barRow+1, (width-len(counter))/2))
			buf.WriteString(fg(34))
			buf.WriteString(counter)
			buf.WriteString(reset)
		}

		fmt.Print(buf.String())
		time.Sleep(90 * time.Millisecond) // ~11 fps, ~1.3s total
	}

	// ─── Phase 2: SIGNAL ACQUISITION ────────────────────────────────
	// WiFi arcs appear one at a time from center outward, pulsing.

	arcHeight := len(wifiArcs)
	arcStartRow := height/2 - arcHeight/2 - 1
	scanDots := [4]string{"   ", ".  ", ".. ", "..."}

	for arcIdx := 0; arcIdx < arcHeight; arcIdx++ {
		var buf strings.Builder

		// Draw all arcs up to current index.
		for a := 0; a <= arcIdx; a++ {
			row := arcStartRow + (arcHeight - 1 - a)
			arc := wifiArcs[a]
			col := (width - len(arc)) / 2
			buf.WriteString(moveTo(row, col))

			if a == arcIdx {
				// Newest arc: bright cyan.
				buf.WriteString(boldANSI())
				buf.WriteString(fg(51)) // bright cyan
			} else {
				// Older arcs: dim cyan.
				buf.WriteString(dimANSI())
				buf.WriteString(fg(37)) // medium cyan
			}
			buf.WriteString(arc)
			buf.WriteString(reset)
		}

		// SCANNING... text below the arcs.
		scanText := "SCANNING" + scanDots[arcIdx%4]
		scanCol := (width - len(scanText)) / 2
		scanRow := arcStartRow + arcHeight + 1
		buf.WriteString(moveTo(scanRow, scanCol))
		buf.WriteString(dimANSI())
		buf.WriteString(fg(37))
		buf.WriteString(scanText)
		buf.WriteString(reset)

		fmt.Print(buf.String())
		time.Sleep(120 * time.Millisecond) // 5 arcs * 120ms = 600ms
	}

	// ─── Phase 3: TARGET LOCK ───────────────────────────────────────
	// Flash all arcs bright white, then shake, then "SIGNAL ACQUIRED".

	// Flash white.
	{
		var buf strings.Builder
		for a := 0; a < arcHeight; a++ {
			row := arcStartRow + (arcHeight - 1 - a)
			arc := wifiArcs[a]
			col := (width - len(arc)) / 2
			buf.WriteString(moveTo(row, col))
			buf.WriteString(boldANSI())
			buf.WriteString(fg(231)) // bright white
			buf.WriteString(arc)
			buf.WriteString(reset)
		}
		fmt.Print(buf.String())
		time.Sleep(100 * time.Millisecond)
	}

	// Screen shake: shift arcs left by 1, then right by 2, then back.
	shakeOffsets := []int{-1, 2, -1}
	for _, offset := range shakeOffsets {
		var buf strings.Builder
		for a := 0; a < arcHeight; a++ {
			row := arcStartRow + (arcHeight - 1 - a)
			arc := wifiArcs[a]
			col := (width-len(arc))/2 + offset

			// Clear old position.
			buf.WriteString(moveTo(row, 1))
			buf.WriteString(strings.Repeat(" ", width))

			buf.WriteString(moveTo(row, col))
			buf.WriteString(boldANSI())
			buf.WriteString(fg(46)) // bright green
			buf.WriteString(arc)
			buf.WriteString(reset)
		}
		fmt.Print(buf.String())
		time.Sleep(50 * time.Millisecond)
	}

	// "SIGNAL ACQUIRED" replaces "SCANNING".
	{
		acquired := "\u2593\u2593\u2593 SIGNAL ACQUIRED \u2593\u2593\u2593"
		acqCol := (width - len(acquired)) / 2
		acqRow := arcStartRow + arcHeight + 1

		// Clear scanning text.
		var buf strings.Builder
		buf.WriteString(moveTo(acqRow, 1))
		buf.WriteString(strings.Repeat(" ", width))

		buf.WriteString(moveTo(acqRow, acqCol))
		buf.WriteString(boldANSI())
		buf.WriteString(fg(46)) // bright green
		buf.WriteString(acquired)
		buf.WriteString(reset)
		fmt.Print(buf.String())
		time.Sleep(150 * time.Millisecond)
	}

	// ─── Phase 4: BANNER REVEAL ─────────────────────────────────────
	// Center-out wipe clears the screen, then banner chars spark in.

	// Wipe: clear columns from center outward.
	mid := width / 2
	for spread := 0; spread <= mid+1; spread += 3 {
		var buf strings.Builder
		for row := 1; row <= height; row++ {
			left := mid - spread
			right := mid + spread
			if left >= 1 {
				buf.WriteString(moveTo(row, left))
				buf.WriteString("   ")
			}
			if right <= width {
				buf.WriteString(moveTo(row, right))
				buf.WriteString("   ")
			}
		}
		fmt.Print(buf.String())
		time.Sleep(15 * time.Millisecond)
	}

	// Full clear after wipe.
	fmt.Print(clearScr)
	time.Sleep(50 * time.Millisecond)

	// Banner dimensions.
	bannerWidth := 0
	for _, line := range bannerLines {
		if len([]rune(line)) > bannerWidth {
			bannerWidth = len([]rune(line))
		}
	}
	bannerStartRow := height/2 - 2
	bannerStartCol := (width - bannerWidth) / 2
	if bannerStartCol < 1 {
		bannerStartCol = 1
	}

	// Convert banner to rune grid for per-character reveal.
	type cell struct {
		r    rune
		row  int
		col  int
		bRow int // banner line index
	}
	var cells []cell
	for bRow, line := range bannerLines {
		runes := []rune(line)
		for i, r := range runes {
			if r != ' ' {
				cells = append(cells, cell{r: r, row: bannerStartRow + bRow, col: bannerStartCol + i, bRow: bRow})
			}
		}
	}

	// Shuffle for staggered reveal.
	rand.Shuffle(len(cells), func(i, j int) { cells[i], cells[j] = cells[j], cells[i] })

	// Reveal in bursts: each burst shows a few characters.
	burstSize := len(cells) / 10
	if burstSize < 3 {
		burstSize = 3
	}

	// Track which cells are already revealed (for dimming).
	revealed := make([]bool, len(cells))

	for i := 0; i < len(cells); i += burstSize {
		var buf strings.Builder
		end := i + burstSize
		if end > len(cells) {
			end = len(cells)
		}

		// Dim all previously revealed cells to final cyan.
		for j := 0; j < i; j++ {
			if revealed[j] {
				c := cells[j]
				buf.WriteString(moveTo(c.row, c.col))
				buf.WriteString(boldANSI())
				buf.WriteString(fg(51)) // cyan
				buf.WriteRune(c.r)
				buf.WriteString(reset)
			}
		}

		// New cells spark bright white.
		for j := i; j < end; j++ {
			c := cells[j]
			revealed[j] = true
			buf.WriteString(moveTo(c.row, c.col))
			buf.WriteString(boldANSI())
			buf.WriteString(fg(231)) // bright white spark
			buf.WriteRune(c.r)
			buf.WriteString(reset)
		}

		fmt.Print(buf.String())
		time.Sleep(50 * time.Millisecond)
	}

	// Final pass: all cells settle to bold cyan.
	{
		var buf strings.Builder
		for _, c := range cells {
			buf.WriteString(moveTo(c.row, c.col))
			buf.WriteString(boldANSI())
			buf.WriteString(fg(51))
			buf.WriteRune(c.r)
			buf.WriteString(reset)
		}
		fmt.Print(buf.String())
	}

	// Subtitle fades in below banner.
	subtitle := fmt.Sprintf("No WiFi? Now WiFi.  v%s", version)
	subRow := bannerStartRow + len(bannerLines) + 1
	subCol := (width - len(subtitle)) / 2

	// Three-step fade: dim -> normal -> bright.
	fadeLevels := []string{
		dimANSI() + fg(240), // very dim grey
		fg(245),             // medium grey
		fg(252),             // near-white
	}
	for _, style := range fadeLevels {
		var buf strings.Builder
		buf.WriteString(moveTo(subRow, subCol))
		buf.WriteString(style)
		buf.WriteString(subtitle)
		buf.WriteString(reset)
		fmt.Print(buf.String())
		time.Sleep(70 * time.Millisecond)
	}

	// ─── Phase 5: READY ─────────────────────────────────────────────
	time.Sleep(200 * time.Millisecond)

	// Clear screen and reposition cursor at top for normal CLI output.
	fmt.Print(clearScr)
}
