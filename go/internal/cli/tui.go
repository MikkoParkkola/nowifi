// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Color palette -- cyberpunk/hacker aesthetic
// ---------------------------------------------------------------------------

var (
	cCyan      = lipgloss.Color("#00e5ff")
	cGreen     = lipgloss.Color("#00ff9f")
	cRed       = lipgloss.Color("#ff3366")
	cYellow    = lipgloss.Color("#ffd000")
	cDimGray   = lipgloss.Color("#7a7a8e") // Brighter for readability on dark bg
	cWhite     = lipgloss.Color("#e8e8f8")
	cBorder    = lipgloss.Color("#3a3a55") // Slightly brighter borders
	cBorderHot = lipgloss.Color("#00e5ff") // Glowing border for active panels
)

// ---------------------------------------------------------------------------
// Lipgloss styles
// ---------------------------------------------------------------------------

var (
	// Panel: rounded border with subtle color
	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(cBorder).
			Padding(0, 1)

	// Panel with glowing border (active/connected section)
	activePanelStyle = lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(cBorderHot).
				Padding(0, 1)

	// Panel with success glow
	successPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(cGreen).
				Padding(0, 1)

	// Header labels inside panels
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cCyan)

	// Success / open indicators
	okStyle = lipgloss.NewStyle().
		Foreground(cGreen).
		Bold(true)

	// Error / closed indicators
	failStyle = lipgloss.NewStyle().
			Foreground(cRed)

	// Warning / in-progress indicators
	warnStyle = lipgloss.NewStyle().
			Foreground(cYellow)

	// Dimmed secondary text
	dimStyle = lipgloss.NewStyle().
			Foreground(cDimGray)

	// Value text (white)
	valStyle = lipgloss.NewStyle().
			Foreground(cWhite)

	// Bold value
	boldValStyle = lipgloss.NewStyle().
			Foreground(cWhite).
			Bold(true)

	// Banner text
	bannerStyle = lipgloss.NewStyle().
			Foreground(cCyan).
			Bold(true)

	// Footer hint
	footerStyle = lipgloss.NewStyle().
			Foreground(cDimGray).
			Align(lipgloss.Center)
)

// ---------------------------------------------------------------------------
// TUI message types -- sent from audit goroutine via p.Send()
// ---------------------------------------------------------------------------

type wifiMsg struct {
	ssid, channel string
	rssi          int
}

type wifiErrMsg struct{ text string }

type portalMsg struct {
	portalType, vendor string
	captive            bool
}

type networkMsg struct {
	gateway string
	clients int
	rttMs   int
}

type probeRunningMsg struct{ name string }

type probeMsg struct {
	name string
	open bool
}

type bypassStartMsg struct{ technique string }

type bypassResultMsg struct {
	technique string
	success   bool
	detail    string
}

type sessionTickMsg struct {
	uptime   time.Duration
	renewals int
}

type sessionDownMsg struct{}

type stealthMsg struct{ ttl, pf bool }

type statusMsg struct{ text string }

type doneMsg struct{}

// sessionPulseMsg drives the progress bar animation in session mode.
type sessionPulseMsg struct{}

// ---------------------------------------------------------------------------
// TUI model
// ---------------------------------------------------------------------------

type tuiModel struct {
	width, height int

	// Phase tracking
	phase string // "boot", "wifi", "portal", "probe", "bypass", "session", "done"

	// WiFi data
	ssid, channel string
	rssi          int
	wifiErr       string

	// Portal data
	portalType, vendor string
	isCaptive          bool

	// Network
	gateway     string
	clientCount int
	rttMs       int

	// Probes
	probes       map[string]string // name -> "open" | "closed" | "running" | ""
	probeRunning string

	// Bypass log
	bypassLog       []tuiBypassEntry
	activeTechnique string

	// Session
	connected    bool
	uptime       time.Duration
	renewals     int
	stealthTTL   bool
	stealthPF    bool
	sessionPulse float64

	// Status
	statusText string

	// Components
	spinner  spinner.Model
	progress progress.Model

	// Control
	quitting bool
}

type tuiBypassEntry struct {
	name    string
	success bool
	detail  string
}

// Probe display order.
var tuiProbeOrder = []string{"DNS", "ICMP", "IPv6", "HTTPS", "QUIC", "NTP", "DoH"}

// Braille spinner for bypass activity.
var brailleSpinner = spinner.Spinner{
	Frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	FPS:    80 * time.Millisecond,
}

func newTuiModel() tuiModel {
	s := spinner.New(spinner.WithSpinner(brailleSpinner))
	s.Style = lipgloss.NewStyle().Foreground(cYellow)

	p := progress.New(
		progress.WithScaledGradient("#00d4ff", "#00ff88"),
		progress.WithoutPercentage(),
	)

	return tuiModel{
		phase:    "boot",
		probes:   make(map[string]string),
		spinner:  s,
		progress: p,
	}
}

// ---------------------------------------------------------------------------
// Bubbletea interface: Init, Update, View
// ---------------------------------------------------------------------------

func (m tuiModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Resize progress bar to fit session panel.
		barW := m.width - 12
		if barW > 60 {
			barW = 60
		}
		if barW < 20 {
			barW = 20
		}
		m.progress = progress.New(
			progress.WithScaledGradient("#00d4ff", "#00ff88"),
			progress.WithoutPercentage(),
			progress.WithWidth(barW),
		)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		}

	// -- Audit messages --

	case wifiMsg:
		m.phase = "wifi"
		m.ssid = msg.ssid
		m.channel = msg.channel
		m.rssi = msg.rssi
		m.wifiErr = ""
		return m, nil

	case wifiErrMsg:
		m.phase = "wifi"
		m.wifiErr = msg.text
		return m, nil

	case portalMsg:
		m.phase = "portal"
		m.portalType = msg.portalType
		m.vendor = msg.vendor
		m.isCaptive = msg.captive
		return m, nil

	case networkMsg:
		m.gateway = msg.gateway
		m.clientCount = msg.clients
		m.rttMs = msg.rttMs
		return m, nil

	case probeRunningMsg:
		m.phase = "probe"
		m.probeRunning = msg.name
		m.probes[msg.name] = "running"
		return m, nil

	case probeMsg:
		m.phase = "probe"
		if msg.open {
			m.probes[msg.name] = "open"
		} else {
			m.probes[msg.name] = "closed"
		}
		if m.probeRunning == msg.name {
			m.probeRunning = ""
		}
		return m, nil

	case bypassStartMsg:
		m.phase = "bypass"
		m.activeTechnique = msg.technique
		return m, nil

	case bypassResultMsg:
		m.phase = "bypass"
		m.activeTechnique = ""
		m.bypassLog = append(m.bypassLog, tuiBypassEntry{
			name:    msg.technique,
			success: msg.success,
			detail:  msg.detail,
		})
		return m, nil

	case sessionTickMsg:
		m.phase = "session"
		m.connected = true
		m.uptime = msg.uptime
		m.renewals = msg.renewals
		// Pulse the progress bar based on uptime.
		secs := msg.uptime.Seconds()
		// Cycle every 60 seconds for a breathing effect.
		pulse := (secs - float64(int(secs/60)*60)) / 60.0
		m.sessionPulse = pulse
		return m, nil

	case sessionDownMsg:
		m.connected = false
		return m, nil

	case stealthMsg:
		m.stealthTTL = msg.ttl
		m.stealthPF = msg.pf
		return m, nil

	case statusMsg:
		m.statusText = msg.text
		return m, nil

	case doneMsg:
		m.phase = "done"
		return m, nil

	case sessionPulseMsg:
		return m, nil

	// Spinner tick
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

// ---------------------------------------------------------------------------
// View -- the heart of the TUI
// ---------------------------------------------------------------------------

func (m tuiModel) View() string {
	if m.quitting {
		return ""
	}

	w := m.width
	if w < 60 {
		w = 60
	}
	if w > 100 {
		w = 100
	}

	// Inner width available for panel content.
	innerW := w - 4

	// Build all sections.
	// The two half-panels (SYSTEM + NETWORK) define the total rendered width.
	// Full-width panels add +2 to innerW to match: each half-panel adds
	// its own border+padding (4 chars), so two halves = innerW + 5 outer,
	// while a single panel at innerW is innerW + 4 outer. The +2 closes that.
	header := m.viewHeader(innerW + 1)
	sysNet := m.viewSystemNetwork(innerW)
	probes := m.viewProbes(innerW + 1)
	bypass := m.viewBypass(innerW + 1)
	session := m.viewSession(innerW + 1)
	footer := m.viewFooter(innerW + 1)

	// Stack everything vertically.
	full := lipgloss.JoinVertical(lipgloss.Left,
		header,
		sysNet,
		probes,
		bypass,
		session,
		footer,
	)

	// Place in the terminal — top-left for clean alignment.
	if m.width > 0 && m.height > 0 {
		return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, full)
	}
	return full
}

// ---------------------------------------------------------------------------
// Header panel -- ASCII banner + tagline
// ---------------------------------------------------------------------------

func (m tuiModel) viewHeader(w int) string {
	banner := strings.Join([]string{
		"  _ __   _____      _(_)/ _(_)",
		" | '_ \\ / _ \\ \\ /\\ / / | |_| |",
		" | | | | (_) \\ V  V /| |  _| |",
		" |_| |_|\\___/ \\_/\\_/ |_|_| |_|",
	}, "\n")

	bannerRendered := bannerStyle.Render(banner)

	tagline := dimStyle.Render("No WiFi? Now WiFi.") +
		"  " + dimStyle.Render("v"+version)

	content := lipgloss.JoinVertical(lipgloss.Left,
		bannerRendered,
		tagline,
	)

	return panelStyle.
		Width(w).
		BorderForeground(cCyan).
		Render(content)
}

// ---------------------------------------------------------------------------
// SYSTEM + NETWORK side-by-side panels
// ---------------------------------------------------------------------------

func (m tuiModel) viewSystemNetwork(totalW int) string {
	// Full-width panel renders at totalW + 4 (2 border + 2 padding).
	// Two half panels: each (halfW + 4) + 1 gap = totalW + 4.
	// So: 2*halfW + 9 = totalW + 4 → halfW = (totalW - 5) / 2.
	halfW := (totalW - 1) / 2

	sys := m.viewSystem(halfW)
	net := m.viewNetwork(halfW)

	return lipgloss.JoinHorizontal(lipgloss.Top, sys, " ", net)
}

func (m tuiModel) viewSystem(w int) string {
	title := headerStyle.Render("SYSTEM")

	// WiFi line
	var wifiLine string
	if m.wifiErr != "" {
		wifiLine = indicatorDot(false) + " WiFi   " + failStyle.Render(m.wifiErr)
	} else if m.ssid != "" {
		rssiStr := fmt.Sprintf("%ddBm", m.rssi)
		rssiStyled := okStyle.Render(rssiStr)
		if m.rssi < -70 {
			rssiStyled = failStyle.Render(rssiStr)
		} else if m.rssi < -50 {
			rssiStyled = warnStyle.Render(rssiStr)
		}
		// Truncate SSID to fit in half-width panel.
		ssid := m.ssid
		if len(ssid) > 22 {
			ssid = ssid[:19] + "..."
		}
		wifiLine = indicatorDot(true) + " WiFi   " +
			boldValStyle.Render(ssid) + " " + rssiStyled
	} else {
		wifiLine = indicatorDot(false) + " WiFi   " + dimStyle.Render("scanning...")
	}

	// Portal line
	var portalLine string
	if m.portalType == "" {
		portalLine = indicatorDot(false) + " Portal " + dimStyle.Render("detecting...")
	} else if !m.isCaptive {
		portalLine = indicatorDot(true) + " Portal " + okStyle.Render("none (open)")
	} else {
		portalLine = indicatorDot(true) + " Portal " + warnStyle.Render(m.portalType)
		if m.vendor != "" {
			portalLine += dimStyle.Render(" (" + m.vendor + ")")
		}
	}

	// Vendor line
	var vendorLine string
	if m.vendor != "" {
		vendorLine = indicatorDot(true) + " Vendor " + valStyle.Render(m.vendor)
	} else if m.portalType != "" && !m.isCaptive {
		vendorLine = indicatorDot(false) + " Vendor " + dimStyle.Render("n/a")
	} else {
		vendorLine = indicatorDot(false) + " Vendor " + dimStyle.Render("---")
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		title,
		wifiLine,
		portalLine,
		vendorLine,
	)

	return panelStyle.Width(w).Render(content)
}

func (m tuiModel) viewNetwork(w int) string {
	title := headerStyle.Render("NETWORK")

	// Gateway
	gwVal := dimStyle.Render("---")
	if m.gateway != "" {
		gwVal = valStyle.Render(m.gateway)
	}
	gwLine := dimStyle.Render("Gateway  ") + gwVal

	// Clients
	clVal := dimStyle.Render("---")
	if m.clientCount > 0 {
		clVal = valStyle.Render(fmt.Sprintf("%d devices", m.clientCount))
	}
	clLine := dimStyle.Render("Clients  ") + clVal

	// RTT
	rttVal := dimStyle.Render("---")
	if m.rttMs > 0 {
		rttStr := fmt.Sprintf("%dms", m.rttMs)
		if m.rttMs > 100 {
			rttVal = failStyle.Render(rttStr)
		} else if m.rttMs > 30 {
			rttVal = warnStyle.Render(rttStr)
		} else {
			rttVal = okStyle.Render(rttStr)
		}
	}
	rttLine := dimStyle.Render("RTT      ") + rttVal

	content := lipgloss.JoinVertical(lipgloss.Left,
		title,
		gwLine,
		clLine,
		rttLine,
	)

	return panelStyle.Width(w).Render(content)
}

// ---------------------------------------------------------------------------
// PROBES panel
// ---------------------------------------------------------------------------

func (m tuiModel) viewProbes(w int) string {
	title := headerStyle.Render("PROBES")

	var parts []string
	for _, name := range tuiProbeOrder {
		state := m.probes[name]
		var indicator string
		switch state {
		case "open":
			indicator = okStyle.Render("\u2713") // checkmark
		case "closed":
			indicator = failStyle.Render("\u2717") // cross
		case "running":
			indicator = m.spinner.View()
		default:
			indicator = dimStyle.Render("\u00B7") // middle dot
		}
		parts = append(parts, indicator+" "+valStyle.Render(name))
	}

	probeLine := strings.Join(parts, "   ")

	content := lipgloss.JoinVertical(lipgloss.Left,
		title,
		probeLine,
	)

	return panelStyle.Width(w).Render(content)
}

// ---------------------------------------------------------------------------
// BYPASS panel
// ---------------------------------------------------------------------------

func (m tuiModel) viewBypass(w int) string {
	title := headerStyle.Render("BYPASS")

	var lines []string

	// Show the last entries from the log.
	maxShow := 6
	start := 0
	if len(m.bypassLog) > maxShow {
		start = len(m.bypassLog) - maxShow
	}

	for i := start; i < len(m.bypassLog); i++ {
		e := m.bypassLog[i]
		var line string
		if e.success {
			line = okStyle.Render("\u2713") + " " + okStyle.Render(e.name)
		} else {
			line = failStyle.Render("\u2717") + " " + valStyle.Render(e.name)
		}
		if e.detail != "" {
			detail := e.detail
			if len(detail) > 50 {
				detail = detail[:47] + "..."
			}
			line += dimStyle.Render(" -- " + detail)
		}
		lines = append(lines, line)
	}

	// Active technique with spinner.
	if m.activeTechnique != "" {
		active := m.spinner.View() + " " +
			warnStyle.Render(m.activeTechnique) +
			dimStyle.Render("...")
		lines = append(lines, active)
	}

	// Empty state.
	if len(lines) == 0 {
		lines = append(lines, dimStyle.Render("waiting for probe results..."))
	}

	// Pad to minimum height for visual stability.
	for len(lines) < 3 {
		lines = append(lines, "")
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		append([]string{title}, lines...)...,
	)

	style := panelStyle
	if m.activeTechnique != "" {
		style = activePanelStyle // Glowing double border during bypass.
	}

	return style.
		Width(w).
		Render(content)
}

// ---------------------------------------------------------------------------
// SESSION panel
// ---------------------------------------------------------------------------

func (m tuiModel) viewSession(w int) string {
	title := headerStyle.Render("SESSION")

	// Session status badge.
	var statusBadge string
	if m.connected {
		statusBadge = okStyle.Render("\u25C9 CONNECTED")
	} else if m.uptime > 0 {
		statusBadge = warnStyle.Render("\u25C9 RECONNECTING")
	} else {
		statusBadge = dimStyle.Render("\u25CB waiting...")
	}

	// Uptime.
	uptimeStr := ""
	if m.uptime > 0 {
		uptimeStr = "  " + boldValStyle.Render(formatUptime(m.uptime))
	}

	// Renewals.
	renewStr := ""
	if m.renewals > 0 {
		renewStr = "  " + dimStyle.Render(fmt.Sprintf("(%d renewals)", m.renewals))
	}

	statusLine := statusBadge + uptimeStr + renewStr

	// Progress bar for session duration.
	var barLine string
	if m.connected {
		barLine = m.progress.ViewAs(m.sessionPulse)
	} else if m.uptime > 0 {
		barLine = m.progress.ViewAs(0.5)
	} else {
		barLine = m.progress.ViewAs(0.0)
	}

	// Stealth indicators.
	var stealthLine string
	if m.stealthTTL || m.stealthPF {
		stealthParts := []string{dimStyle.Render("Stealth:")}
		if m.stealthTTL {
			stealthParts = append(stealthParts, "TTL "+okStyle.Render("\u2713"))
		} else {
			stealthParts = append(stealthParts, "TTL "+dimStyle.Render("-"))
		}
		if m.stealthPF {
			stealthParts = append(stealthParts, "PF "+okStyle.Render("\u2713"))
		} else {
			stealthParts = append(stealthParts, "PF "+dimStyle.Render("-"))
		}
		stealthLine = strings.Join(stealthParts, "  ")
	}

	// Active bypass technique label.
	var bypassLabel string
	for i := len(m.bypassLog) - 1; i >= 0; i-- {
		if m.bypassLog[i].success {
			bypassLabel = dimStyle.Render("Bypass: ") +
				valStyle.Render(m.bypassLog[i].name)
			break
		}
	}

	// Second line: progress bar + stealth + bypass technique.
	secondLine := barLine
	if stealthLine != "" {
		secondLine += "  " + stealthLine
	}
	if bypassLabel != "" {
		secondLine += "  " + bypassLabel
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		title,
		statusLine,
		secondLine,
	)

	style := panelStyle
	if m.connected {
		style = successPanelStyle // Green double border when connected.
	}

	return style.
		Width(w).
		Render(content)
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

func (m tuiModel) viewFooter(w int) string {
	status := m.statusText
	if status == "" {
		status = "Ctrl+C to disconnect  \u00B7  All changes restored on exit"
	}
	return footerStyle.Width(w + 4).Render(status)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// indicatorDot returns a colored circle indicator.
func indicatorDot(active bool) string {
	if active {
		return okStyle.Render("\u25C9") // ◉
	}
	return dimStyle.Render("\u25CB") // ○
}
