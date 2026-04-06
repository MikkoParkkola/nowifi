// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// ---------------------------------------------------------------------------
// Dashboard — full-screen TUI for the audit pipeline.
//
// Pure ANSI escape codes + Unicode box drawing. No external TUI libraries.
// Single strings.Builder + one fmt.Print per frame = zero flicker.
// ---------------------------------------------------------------------------

// BypassEntry records one bypass attempt for the scrolling log.
type BypassEntry struct {
	Name    string
	Success bool
	Detail  string
}

// Dashboard manages a persistent full-screen view that the audit phases
// update in-place instead of scrolling text.
type Dashboard struct {
	mu sync.Mutex

	width  int
	height int

	// Phase 1: WiFi
	ssid    string
	channel string
	rssi    int
	wifiErr string

	// Phase 2: Portal
	portalType string
	vendor     string
	isCaptive  bool

	// Network panel
	gateway     string
	clientCount int
	rttMs       int

	// Phase 3: Probes
	probes    map[string]probeState
	openPorts int

	// Phase 4: Bypass
	bypassLog    []BypassEntry
	activeBypass string
	spinnerTick  int

	// Phase 5: Session
	connected  bool
	uptime     time.Duration
	renewals   int
	stealthTTL bool
	stealthPF  bool

	// Status line
	statusMsg string

	// Lifecycle
	closed bool
}

type probeState int

const (
	probeUnknown probeState = iota
	probeRunning
	probeOpen
	probeClosed
)

// Braille spinner frames.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Probe names in display order.
var probeNames = []string{"DNS", "ICMP", "IPv6", "HTTPS", "QUIC", "NTP", "DoH"}

// ANSI escape sequences for dashboard rendering.
const (
	dAltScreenOn  = "\033[?1049h"
	dAltScreenOff = "\033[?1049l"
	dHideCursor   = "\033[?25l"
	dShowCursor   = "\033[?25h"
	dClearScreen  = "\033[2J\033[H"
	dReset        = "\033[0m"
)

// Color helpers that return raw ANSI (no reset suffix).
func dBoldCyan() string   { return "\033[1;36m" }
func dBold() string       { return "\033[1m" }
func dDim() string        { return "\033[2m" }
func dGreen() string      { return "\033[32m" }
func dBrightGreen() string { return "\033[1;32m" }
func dRed() string        { return "\033[31m" }
func dBrightRed() string  { return "\033[1;31m" }
func dYellow() string     { return "\033[33m" }
func dWhite() string      { return "\033[37m" }
func dBrightWhite() string { return "\033[1;37m" }
func dGray() string       { return "\033[90m" }

// NewDashboard creates the dashboard, switches to the alternate screen,
// hides the cursor, and renders the initial empty frame.
func NewDashboard() *Dashboard {
	d := &Dashboard{
		probes: make(map[string]probeState),
	}

	// Terminal size with sane fallback.
	fd := int(os.Stdout.Fd())
	w, h, err := term.GetSize(fd)
	if err != nil || w < 60 || h < 20 {
		w, h = 80, 24
	}
	d.width = w
	d.height = h

	// Enter alternate screen buffer.
	fmt.Print(dAltScreenOn + dHideCursor + dClearScreen)

	d.Render()
	return d
}

// Close exits the alternate screen and restores the cursor.
func (d *Dashboard) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	fmt.Print(dShowCursor + dAltScreenOff)
}

// ---------------------------------------------------------------------------
// State setters — each updates fields and triggers a full re-render.
// ---------------------------------------------------------------------------

// SetWifi updates the WiFi info panel.
func (d *Dashboard) SetWifi(ssid, channel string, rssi int) {
	d.mu.Lock()
	d.ssid = ssid
	d.channel = channel
	d.rssi = rssi
	d.wifiErr = ""
	d.mu.Unlock()
	d.Render()
}

// SetWifiError shows an error in the WiFi panel.
func (d *Dashboard) SetWifiError(msg string) {
	d.mu.Lock()
	d.wifiErr = msg
	d.mu.Unlock()
	d.Render()
}

// SetPortal updates the portal detection panel.
func (d *Dashboard) SetPortal(portalType, vendor string, isCaptive bool) {
	d.mu.Lock()
	d.portalType = portalType
	d.vendor = vendor
	d.isCaptive = isCaptive
	d.mu.Unlock()
	d.Render()
}

// SetNetwork updates the right-hand network panel.
func (d *Dashboard) SetNetwork(gateway string, clients, rttMs int) {
	d.mu.Lock()
	d.gateway = gateway
	d.clientCount = clients
	d.rttMs = rttMs
	d.mu.Unlock()
	d.Render()
}

// SetProbeRunning marks a probe as currently executing.
func (d *Dashboard) SetProbeRunning(name string) {
	d.mu.Lock()
	d.probes[name] = probeRunning
	d.mu.Unlock()
	d.Render()
}

// SetProbe updates a single probe result indicator.
func (d *Dashboard) SetProbe(name string, open bool) {
	d.mu.Lock()
	if open {
		d.probes[name] = probeOpen
		d.openPorts++
	} else {
		d.probes[name] = probeClosed
	}
	d.mu.Unlock()
	d.Render()
}

// SetBypassing shows the spinner + current technique being tried.
func (d *Dashboard) SetBypassing(technique string) {
	d.mu.Lock()
	d.activeBypass = technique
	d.spinnerTick++
	d.mu.Unlock()
	d.Render()
}

// AddBypass adds a completed attempt to the scrolling bypass log.
func (d *Dashboard) AddBypass(name string, success bool, detail string) {
	d.mu.Lock()
	d.activeBypass = ""
	d.bypassLog = append(d.bypassLog, BypassEntry{
		Name:    name,
		Success: success,
		Detail:  detail,
	})
	d.mu.Unlock()
	d.Render()
}

// SetConnected updates the session panel with uptime and renewal count.
func (d *Dashboard) SetConnected(uptime time.Duration, renewals int) {
	d.mu.Lock()
	d.connected = true
	d.uptime = uptime
	d.renewals = renewals
	d.mu.Unlock()
	d.Render()
}

// SetDisconnected marks the session as down.
func (d *Dashboard) SetDisconnected() {
	d.mu.Lock()
	d.connected = false
	d.mu.Unlock()
	d.Render()
}

// SetStealth updates the stealth indicators.
func (d *Dashboard) SetStealth(ttl, pf bool) {
	d.mu.Lock()
	d.stealthTTL = ttl
	d.stealthPF = pf
	d.mu.Unlock()
	d.Render()
}

// SetStatus updates the bottom status message.
func (d *Dashboard) SetStatus(msg string) {
	d.mu.Lock()
	d.statusMsg = msg
	d.mu.Unlock()
	d.Render()
}

// TickSpinner advances the spinner by one frame without changing state.
func (d *Dashboard) TickSpinner() {
	d.mu.Lock()
	d.spinnerTick++
	d.mu.Unlock()
	d.Render()
}

// ---------------------------------------------------------------------------
// Render — redraws the entire screen in a single write.
// ---------------------------------------------------------------------------

// Render builds the full frame into a strings.Builder and prints it in one
// atomic write. This prevents flicker on every redraw.
func (d *Dashboard) Render() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}

	w := d.width
	if w < 60 {
		w = 60
	}

	var b strings.Builder
	b.Grow(w * d.height * 4) // Pre-allocate generously for ANSI sequences.

	// Home cursor.
	b.WriteString("\033[H")

	inner := w - 2 // Usable width inside the double-line border.

	// ── Row 1: Top border ──────────────────────────────────────────
	b.WriteString(d.borderTop(w))
	b.WriteByte('\n')

	// ── Rows 2-4: Banner ──────────────────────────────────────────
	for i, line := range bannerLines {
		right := ""
		switch i {
		case 0:
			// Empty right side.
		case 1:
			right = "No WiFi? Now WiFi."
		case 2:
			right = "v" + version
		}
		b.WriteString(d.bannerRow(inner, line, right))
		b.WriteByte('\n')
	}

	// ── Row 5: Header separator with T-junctions ──────────────────
	midCol := d.midColumn(inner)
	b.WriteString(d.headerSep(w, midCol))
	b.WriteByte('\n')

	// ── Rows 6-9: System + Network dual-pane ──────────────────────
	leftW := midCol - 1
	rightW := inner - midCol - 1

	// Row 6: Section headers.
	b.WriteString(d.dualPaneRow(leftW, rightW,
		dBoldCyan()+"  SYSTEM"+dReset,
		dBoldCyan()+"  NETWORK"+dReset,
		8, 9))
	b.WriteByte('\n')

	// Row 7: WiFi / Gateway.
	wifiVal := d.wifiDisplay()
	gwVal := d.gatewayDisplay()
	b.WriteString(d.dualPaneRow(leftW, rightW,
		"  "+d.indicator(d.ssid != "" || d.wifiErr != "")+" WiFi  "+wifiVal,
		"  Gateway  "+gwVal,
		d.visLen("  "+d.indicator(d.ssid != "" || d.wifiErr != "")+" WiFi  "+wifiVal),
		d.visLen("  Gateway  "+gwVal)))
	b.WriteByte('\n')

	// Row 8: Portal / Clients.
	portalVal := d.portalDisplay()
	clientVal := d.clientDisplay()
	b.WriteString(d.dualPaneRow(leftW, rightW,
		"  "+d.indicator(d.portalType != "")+" Portal "+portalVal,
		"  Clients  "+clientVal,
		d.visLen("  "+d.indicator(d.portalType != "")+" Portal "+portalVal),
		d.visLen("  Clients  "+clientVal)))
	b.WriteByte('\n')

	// Row 9: Vendor / RTT.
	vendorVal := d.vendorDisplay()
	rttVal := d.rttDisplay()
	b.WriteString(d.dualPaneRow(leftW, rightW,
		"  "+d.indicator(d.vendor != "")+" Vendor "+vendorVal,
		"  RTT      "+rttVal,
		d.visLen("  "+d.indicator(d.vendor != "")+" Vendor "+vendorVal),
		d.visLen("  RTT      "+rttVal)))
	b.WriteByte('\n')

	// ── Row 10: Probe section separator ───────────────────────────
	b.WriteString(d.fullSep(w, '╠', '╣'))
	b.WriteByte('\n')

	// ── Row 11: PROBES header ─────────────────────────────────────
	b.WriteString(d.contentRow(inner, dBoldCyan()+"  PROBES"+dReset, 8))
	b.WriteByte('\n')

	// ── Row 12: Probe indicators ──────────────────────────────────
	b.WriteString(d.probeRow(inner))
	b.WriteByte('\n')

	// ── Row 13: Bypass section separator ──────────────────────────
	b.WriteString(d.fullSep(w, '╠', '╣'))
	b.WriteByte('\n')

	// ── Row 14: BYPASS header ─────────────────────────────────────
	b.WriteString(d.contentRow(inner, dBoldCyan()+"  BYPASS"+dReset, 8))
	b.WriteByte('\n')

	// ── Rows 15-19: Bypass log (5 visible lines) ─────────────────
	bypassLines := d.bypassLines()
	for i := 0; i < 5; i++ {
		if i < len(bypassLines) {
			b.WriteString(d.contentRow(inner, bypassLines[i].text, bypassLines[i].visLen))
		} else {
			b.WriteString(d.contentRow(inner, "", 0))
		}
		b.WriteByte('\n')
	}

	// ── Row 20: Session section separator ─────────────────────────
	b.WriteString(d.fullSep(w, '╠', '╣'))
	b.WriteByte('\n')

	// ── Row 21: SESSION line ──────────────────────────────────────
	b.WriteString(d.sessionRow(inner))
	b.WriteByte('\n')

	// ── Row 22: Progress bar + stealth ────────────────────────────
	b.WriteString(d.stealthRow(inner))
	b.WriteByte('\n')

	// ── Row 23: Footer separator ──────────────────────────────────
	b.WriteString(d.fullSep(w, '╠', '╣'))
	b.WriteByte('\n')

	// ── Row 24: Status/help line ──────────────────────────────────
	statusText := d.statusDisplay()
	b.WriteString(d.contentRow(inner, statusText.text, statusText.visLen))
	b.WriteByte('\n')

	// ── Row 25: Bottom border ─────────────────────────────────────
	b.WriteString(d.borderBottom(w))

	// Clear any leftover lines below the dashboard.
	remaining := d.height - 25
	if remaining > 0 {
		for i := 0; i < remaining; i++ {
			b.WriteString("\n\033[2K")
		}
	}

	d.mu.Unlock()

	// Single atomic write.
	fmt.Print(b.String())
}

// ---------------------------------------------------------------------------
// Display value formatters
// ---------------------------------------------------------------------------

func (d *Dashboard) wifiDisplay() string {
	if d.wifiErr != "" {
		return dRed() + d.wifiErr + dReset
	}
	if d.ssid == "" {
		return dGray() + "scanning..." + dReset
	}
	rssiColor := dGreen()
	if d.rssi < -70 {
		rssiColor = dRed()
	} else if d.rssi < -50 {
		rssiColor = dYellow()
	}
	return dBrightWhite() + d.ssid + dReset + dGray() + " ch" + d.channel + " " + rssiColor + fmt.Sprintf("%ddBm", d.rssi) + dReset
}

func (d *Dashboard) gatewayDisplay() string {
	if d.gateway == "" {
		return dGray() + "---" + dReset
	}
	return dWhite() + d.gateway + dReset
}

func (d *Dashboard) portalDisplay() string {
	if d.portalType == "" {
		return dGray() + "detecting..." + dReset
	}
	if !d.isCaptive {
		return dGreen() + "none (open)" + dReset
	}
	return dYellow() + d.portalType + dReset
}

func (d *Dashboard) vendorDisplay() string {
	if d.vendor == "" {
		if d.portalType != "" && !d.isCaptive {
			return dGray() + "n/a" + dReset
		}
		return dGray() + "---" + dReset
	}
	return dWhite() + d.vendor + dReset
}

func (d *Dashboard) clientDisplay() string {
	if d.clientCount == 0 {
		return dGray() + "---" + dReset
	}
	return dWhite() + fmt.Sprintf("%d", d.clientCount) + dReset
}

func (d *Dashboard) rttDisplay() string {
	if d.rttMs == 0 {
		return dGray() + "---" + dReset
	}
	color := dGreen()
	if d.rttMs > 100 {
		color = dRed()
	} else if d.rttMs > 30 {
		color = dYellow()
	}
	return color + fmt.Sprintf("%dms", d.rttMs) + dReset
}

func (d *Dashboard) indicator(active bool) string {
	if active {
		return dBrightGreen() + "\u25C9" + dReset // ◉
	}
	return dGray() + "\u25CB" + dReset // ○
}

// ---------------------------------------------------------------------------
// Probe row builder
// ---------------------------------------------------------------------------

type styledText struct {
	text   string
	visLen int
}

func (d *Dashboard) probeRow(inner int) string {
	var parts []string
	for _, name := range probeNames {
		state, ok := d.probes[name]
		if !ok {
			state = probeUnknown
		}
		var indicator string
		switch state {
		case probeUnknown:
			indicator = dGray() + "\u00B7" + dReset // middle dot
		case probeRunning:
			frame := spinnerFrames[d.spinnerTick%len(spinnerFrames)]
			indicator = dYellow() + frame + dReset
		case probeOpen:
			indicator = dBrightGreen() + "\u2713" + dReset // checkmark
		case probeClosed:
			indicator = dBrightRed() + "\u2717" + dReset // cross
		}
		parts = append(parts, indicator+" "+name)
	}
	line := "  " + strings.Join(parts, "   ")
	// Visual length: 2 (indent) + for each probe: 1 (indicator) + 1 (space) + len(name) + 3 (sep).
	vl := 2
	for i, name := range probeNames {
		vl += 1 + 1 + len(name)
		if i < len(probeNames)-1 {
			vl += 3
		}
	}
	return d.contentRow(inner, line, vl)
}

// ---------------------------------------------------------------------------
// Bypass log builder
// ---------------------------------------------------------------------------

func (d *Dashboard) bypassLines() []styledText {
	var lines []styledText

	// Show last 4 completed entries + active spinner line.
	entries := d.bypassLog
	start := 0
	maxShow := 4
	if d.activeBypass != "" {
		maxShow = 4 // Reserve one line for active.
	}
	if len(entries) > maxShow {
		start = len(entries) - maxShow
	}

	for i := start; i < len(entries); i++ {
		e := entries[i]
		var prefix string
		var vl int
		if e.Success {
			prefix = "  " + dBrightGreen() + "\u2713" + dReset + " "
		} else {
			prefix = "  " + dBrightRed() + "\u2717" + dReset + " "
		}
		detail := ""
		if e.Detail != "" {
			detail = dGray() + " -- " + e.Detail + dReset
		}
		text := prefix + dWhite() + e.Name + dReset + detail
		vl = 2 + 1 + 1 + len(e.Name)
		if e.Detail != "" {
			vl += 4 + len(e.Detail)
		}
		lines = append(lines, styledText{text: text, visLen: vl})
	}

	// Active bypass with spinner.
	if d.activeBypass != "" {
		frame := spinnerFrames[d.spinnerTick%len(spinnerFrames)]
		text := "  " + dYellow() + frame + dReset + " " + dYellow() + d.activeBypass + dReset + dGray() + "..." + dReset
		vl := 2 + 1 + 1 + len(d.activeBypass) + 3
		lines = append(lines, styledText{text: text, visLen: vl})
	}

	// Fill with empty hint lines if nothing yet.
	if len(lines) == 0 {
		lines = append(lines, styledText{
			text:   dGray() + "  waiting for probe results..." + dReset,
			visLen: 31,
		})
	}

	return lines
}

// ---------------------------------------------------------------------------
// Session row
// ---------------------------------------------------------------------------

func (d *Dashboard) sessionRow(inner int) string {
	label := dBoldCyan() + "  SESSION" + dReset
	labelVL := 9

	if !d.connected && d.uptime == 0 {
		// Not yet connected.
		text := label + dGray() + "        waiting..." + dReset
		return d.contentRow(inner, text, labelVL+18)
	}

	var statusBadge string
	var badgeVL int
	if d.connected {
		statusBadge = dBrightGreen() + " \u25C9 CONNECTED" + dReset
		badgeVL = 12
	} else {
		statusBadge = dBrightRed() + " \u25C9 RECONNECTING" + dReset
		badgeVL = 15
	}

	uptimeStr := formatUptime(d.uptime)
	renewStr := ""
	renewVL := 0
	if d.renewals > 0 {
		renewStr = dGray() + fmt.Sprintf("  (%d renewals)", d.renewals) + dReset
		renewVL = 4 + len(fmt.Sprintf("%d", d.renewals)) + 10
	}

	text := label + "  " + statusBadge + "  " + dBrightWhite() + uptimeStr + dReset + renewStr
	vl := labelVL + 2 + badgeVL + 2 + len(uptimeStr) + renewVL
	return d.contentRow(inner, text, vl)
}

// ---------------------------------------------------------------------------
// Stealth / progress row
// ---------------------------------------------------------------------------

func (d *Dashboard) stealthRow(inner int) string {
	// Progress bar portion.
	barWidth := inner / 3
	if barWidth > 30 {
		barWidth = 30
	}
	if barWidth < 10 {
		barWidth = 10
	}

	var bar strings.Builder
	bar.WriteString("  ")
	if d.connected {
		// Full green bar.
		bar.WriteString(dBrightGreen())
		for i := 0; i < barWidth; i++ {
			bar.WriteString("\u2588") // Full block.
		}
		bar.WriteString(dReset)
	} else if d.uptime > 0 {
		// Partial bar (reconnecting).
		half := barWidth / 2
		bar.WriteString(dYellow())
		for i := 0; i < half; i++ {
			bar.WriteString("\u2588")
		}
		bar.WriteString(dGray())
		for i := half; i < barWidth; i++ {
			bar.WriteString("\u2591") // Light shade.
		}
		bar.WriteString(dReset)
	} else {
		// Empty bar.
		bar.WriteString(dGray())
		for i := 0; i < barWidth; i++ {
			bar.WriteString("\u2591")
		}
		bar.WriteString(dReset)
	}

	// Stealth indicators.
	stealthText := ""
	stealthVL := 0
	if d.stealthTTL || d.stealthPF {
		stealthText = "  Stealth:"
		stealthVL = 10
		if d.stealthTTL {
			stealthText += " TTL " + dBrightGreen() + "\u2713" + dReset
			stealthVL += 6
		} else {
			stealthText += " TTL " + dGray() + "-" + dReset
			stealthVL += 6
		}
		if d.stealthPF {
			stealthText += "  PF " + dBrightGreen() + "\u2713" + dReset
			stealthVL += 6
		} else {
			stealthText += "  PF " + dGray() + "-" + dReset
			stealthVL += 6
		}
	}

	text := bar.String() + stealthText
	vl := 2 + barWidth + stealthVL
	return d.contentRow(inner, text, vl)
}

// ---------------------------------------------------------------------------
// Status line
// ---------------------------------------------------------------------------

func (d *Dashboard) statusDisplay() styledText {
	if d.statusMsg != "" {
		return styledText{
			text:   dGray() + "  " + d.statusMsg + dReset,
			visLen: 2 + len(d.statusMsg),
		}
	}
	msg := "Ctrl+C to disconnect  \u00B7  All changes restored on exit"
	return styledText{
		text:   dGray() + "  " + msg + dReset,
		visLen: 2 + len(msg),
	}
}

// ---------------------------------------------------------------------------
// Box drawing primitives
// ---------------------------------------------------------------------------

func (d *Dashboard) borderTop(w int) string {
	return dDim() + "\u2554" + strings.Repeat("\u2550", w-2) + "\u2557" + dReset
}

func (d *Dashboard) borderBottom(w int) string {
	return dDim() + "\u255A" + strings.Repeat("\u2550", w-2) + "\u255D" + dReset
}

func (d *Dashboard) fullSep(w int, left, right rune) string {
	return dDim() + string(left) + strings.Repeat("\u2550", w-2) + string(right) + dReset
}

func (d *Dashboard) headerSep(w, midCol int) string {
	var b strings.Builder
	b.WriteString(dDim())
	b.WriteRune('\u2560') // ╠
	for i := 1; i < w-1; i++ {
		if i == midCol+1 {
			b.WriteRune('\u2566') // ╦
		} else {
			b.WriteRune('\u2550') // ═
		}
	}
	b.WriteRune('\u2563') // ╣
	b.WriteString(dReset)
	return b.String()
}

// midColumn returns the column position for the vertical divider between
// SYSTEM and NETWORK panels. Roughly 45% of inner width.
func (d *Dashboard) midColumn(inner int) int {
	mid := inner * 45 / 100
	if mid < 26 {
		mid = 26
	}
	return mid
}

func (d *Dashboard) bannerRow(inner int, bannerLine, rightText string) string {
	var b strings.Builder
	b.WriteString(dDim())
	b.WriteRune('\u2551') // ║
	b.WriteString(dReset)

	// Banner portion (bold cyan).
	bl := len([]rune(bannerLine))
	b.WriteString(dBoldCyan())
	b.WriteString(bannerLine)
	b.WriteString(dReset)

	// Right-aligned text.
	rtLen := len(rightText)
	gap := inner - bl - rtLen
	if gap < 1 {
		gap = 1
	}
	b.WriteString(strings.Repeat(" ", gap))
	if rightText != "" {
		b.WriteString(dGray())
		b.WriteString(rightText)
		b.WriteString(dReset)
	}

	// Right border.
	b.WriteString(dDim())
	b.WriteRune('\u2551')
	b.WriteString(dReset)
	return b.String()
}

func (d *Dashboard) dualPaneRow(leftW, rightW int, leftText, rightText string, leftVL, rightVL int) string {
	var b strings.Builder

	// Left border.
	b.WriteString(dDim())
	b.WriteRune('\u2551')
	b.WriteString(dReset)

	// Left pane content.
	b.WriteString(leftText)
	leftPad := leftW - leftVL
	if leftPad < 0 {
		leftPad = 0
	}
	b.WriteString(strings.Repeat(" ", leftPad))

	// Middle divider.
	b.WriteString(dDim())
	b.WriteRune('\u2551')
	b.WriteString(dReset)

	// Right pane content.
	b.WriteString(rightText)
	rightPad := rightW - rightVL
	if rightPad < 0 {
		rightPad = 0
	}
	b.WriteString(strings.Repeat(" ", rightPad))

	// Right border.
	b.WriteString(dDim())
	b.WriteRune('\u2551')
	b.WriteString(dReset)

	return b.String()
}

func (d *Dashboard) contentRow(inner int, text string, visLen int) string {
	var b strings.Builder

	// Left border.
	b.WriteString(dDim())
	b.WriteRune('\u2551')
	b.WriteString(dReset)

	b.WriteString(text)
	pad := inner - visLen
	if pad < 0 {
		pad = 0
	}
	b.WriteString(strings.Repeat(" ", pad))

	// Right border.
	b.WriteString(dDim())
	b.WriteRune('\u2551')
	b.WriteString(dReset)

	return b.String()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// visLen estimates the visible character length of a string that may contain
// ANSI escape sequences. It strips sequences like \033[...m.
func (d *Dashboard) visLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

func formatUptime(dur time.Duration) string {
	h := int(dur.Hours())
	m := int(dur.Minutes()) % 60
	s := int(dur.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
