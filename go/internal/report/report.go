// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package report generates terminal, markdown, and JSON output for
// captive portal security audit results.
//
// Terminal output uses fatih/color for colored text. The format closely
// mirrors the Python Rich-based output: header panel, leak enumeration
// table, bypass results table, findings summary, and active tunnel info.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/bypass"
	"golang.org/x/term"
)

// ---------------------------------------------------------------------------
// Types consumed by the report generators. These mirror the detect and
// probe packages' types so report can compile independently. The caller
// maps from the concrete types to these.
// ---------------------------------------------------------------------------

// PortalInfo summarizes the detected captive portal.
type PortalInfo struct {
	IsCaptive   bool
	PortalType  string // e.g. "http_redirect", "dns_hijack", "firewall_block"
	Vendor      string
	SSID        string
	Gateway     string
	PortalURL   string
	AuthMethods []string
}

// ProbeResult holds the status of a single protocol probe.
type ProbeResult struct {
	IsOpen  bool
	Details string
}

// WhitelistResult holds a probed whitelisted domain.
type WhitelistResult struct {
	Domain  string
	IsOpen  bool
	Details string
}

// PortResult holds a probed TCP port.
type PortResult struct {
	Port    int
	Service string
	IsOpen  bool
}

// ProbeResults is the full set of probe outcomes for reporting.
type ProbeResults struct {
	DNS        ProbeResult
	ICMP       ProbeResult
	IPv6       ProbeResult
	Cloudflare ProbeResult
	QUIC       ProbeResult
	NTP        ProbeResult
	DoH        ProbeResult

	Whitelists []WhitelistResult
	OpenPorts  []PortResult
}

// ---------------------------------------------------------------------------
// Color helpers (ANSI escape codes)
// ---------------------------------------------------------------------------

const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	red       = "\033[31m"
	green     = "\033[32m"
	yellow    = "\033[33m"
	cyan      = "\033[36m"
	boldRed   = "\033[1;31m"
	boldGreen = "\033[1;32m"
	boldCyan  = "\033[1;36m"
)

var colorEnabled = os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd()))

func renderTerminalOutput(s string) string {
	if colorEnabled {
		return s
	}
	return stripANSI(s)
}

func severityColor(sev string) string {
	switch sev {
	case "critical":
		return boldRed
	case "high":
		return red
	case "medium":
		return yellow
	case "low":
		return cyan
	case "info":
		return dim
	default:
		return dim
	}
}

func severityTag(sev string) string {
	switch sev {
	case "critical":
		return boldRed + "CRIT" + reset
	case "high":
		return red + "HIGH" + reset
	case "medium":
		return yellow + "MED" + reset
	case "low":
		return cyan + "LOW" + reset
	case "info":
		return dim + "INFO" + reset
	default:
		return dim + "?" + reset
	}
}

func boolIcon(val bool) string {
	if val {
		return green + "OPEN" + reset
	}
	return red + "CLOSED" + reset
}

func successIcon(val bool) string {
	if val {
		return boldGreen + "SUCCESS" + reset
	}
	return dim + "failed" + reset
}

// ---------------------------------------------------------------------------
// Box-drawing helpers for terminal panels
// ---------------------------------------------------------------------------

func drawBox(title string, borderColor string, content string) string {
	lines := strings.Split(content, "\n")
	maxWidth := len(title) + 4
	for _, l := range lines {
		// Approximate visible length (strip ANSI codes).
		vis := stripANSI(l)
		if len(vis) > maxWidth {
			maxWidth = len(vis)
		}
	}
	if maxWidth > 100 {
		maxWidth = 100
	}

	var sb strings.Builder
	topLeft := borderColor + "+" + strings.Repeat("-", maxWidth+2) + "+" + reset
	sb.WriteString(topLeft + "\n")

	// Title line.
	titlePad := maxWidth - len(stripANSI(title))
	if titlePad < 0 {
		titlePad = 0
	}
	sb.WriteString(borderColor + "| " + reset + title + strings.Repeat(" ", titlePad) + borderColor + " |" + reset + "\n")
	sb.WriteString(borderColor + "+" + strings.Repeat("-", maxWidth+2) + "+" + reset + "\n")

	// Content lines.
	for _, l := range lines {
		vis := stripANSI(l)
		pad := maxWidth - len(vis)
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(borderColor + "| " + reset + l + strings.Repeat(" ", pad) + borderColor + " |" + reset + "\n")
	}

	sb.WriteString(borderColor + "+" + strings.Repeat("-", maxWidth+2) + "+" + reset + "\n")
	return renderTerminalOutput(sb.String())
}

// stripANSI removes ANSI escape sequences for length calculation.
func stripANSI(s string) string {
	var result strings.Builder
	inEscape := false
	for _, c := range s {
		if c == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				inEscape = false
			}
			continue
		}
		result.WriteRune(c)
	}
	return result.String()
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

// simpleTable renders an ASCII table with headers and rows.
func simpleTable(title string, borderColor string, headers []string, rows [][]string) string {
	// Compute column widths.
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(stripANSI(h))
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				vis := len(stripANSI(cell))
				if vis > widths[i] {
					widths[i] = vis
				}
			}
		}
	}

	sep := borderColor + "+"
	for _, w := range widths {
		sep += strings.Repeat("-", w+2) + "+"
	}
	sep += reset

	var sb strings.Builder

	// Title.
	if title != "" {
		sb.WriteString("\n" + bold + title + reset + "\n")
	}

	sb.WriteString(sep + "\n")

	// Header row.
	sb.WriteString(borderColor + "|" + reset)
	for i, h := range headers {
		pad := widths[i] - len(stripANSI(h))
		sb.WriteString(" " + bold + h + reset + strings.Repeat(" ", pad) + " " + borderColor + "|" + reset)
	}
	sb.WriteString("\n" + sep + "\n")

	// Data rows.
	for _, row := range rows {
		sb.WriteString(borderColor + "|" + reset)
		for i := 0; i < len(headers); i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			vis := len(stripANSI(cell))
			pad := widths[i] - vis
			if pad < 0 {
				pad = 0
			}
			sb.WriteString(" " + cell + strings.Repeat(" ", pad) + " " + borderColor + "|" + reset)
		}
		sb.WriteString("\n")
	}

	sb.WriteString(sep + "\n")
	return renderTerminalOutput(sb.String())
}

// ---------------------------------------------------------------------------
// Terminal report
// ---------------------------------------------------------------------------

// PrintTerminal prints a colored terminal report to stdout.
func PrintTerminal(portal PortalInfo, probes ProbeResults, bypasses []bypass.Result) {
	// Header panel.
	vendorStr := portal.Vendor
	if vendorStr == "" {
		vendorStr = "Unknown"
	}
	captiveStr := boldRed + "YES" + reset
	if !portal.IsCaptive {
		captiveStr = boldGreen + "NO" + reset
	}
	authStr := "N/A"
	if len(portal.AuthMethods) > 0 {
		authStr = strings.Join(portal.AuthMethods, ", ")
	}
	portalURLStr := portal.PortalURL
	if portalURLStr == "" {
		portalURLStr = "N/A"
	}

	header := fmt.Sprintf(
		"%sSSID:%s %s\n%sGateway:%s %s\n%sCaptive Portal:%s %s\n%sPortal Type:%s %s\n%sVendor:%s %s\n%sAuth Methods:%s %s\n%sPortal URL:%s %s",
		bold, reset, nvl(portal.SSID, "N/A"),
		bold, reset, nvl(portal.Gateway, "N/A"),
		bold, reset, captiveStr,
		bold, reset, portal.PortalType,
		bold, reset, vendorStr,
		bold, reset, authStr,
		bold, reset, portalURLStr,
	)
	fmt.Println()
	fmt.Print(drawBox(boldCyan+"nowifi -- WiFi Security Audit"+reset, cyan, header))

	// Probe results table.
	probeRows := [][]string{
		{"DNS (UDP/53)", boolIcon(probes.DNS.IsOpen), probes.DNS.Details},
		{"ICMP (ping)", boolIcon(probes.ICMP.IsOpen), probes.ICMP.Details},
		{"IPv6", boolIcon(probes.IPv6.IsOpen), probes.IPv6.Details},
		{"HTTPS (Cloudflare)", boolIcon(probes.Cloudflare.IsOpen), probes.Cloudflare.Details},
		{"QUIC (UDP/443)", boolIcon(probes.QUIC.IsOpen), probes.QUIC.Details},
		{"NTP (UDP/123)", boolIcon(probes.NTP.IsOpen), probes.NTP.Details},
		{"DoH (HTTPS)", boolIcon(probes.DoH.IsOpen), probes.DoH.Details},
	}

	for _, wl := range probes.Whitelists {
		probeRows = append(probeRows, []string{"  " + wl.Domain, boolIcon(wl.IsOpen), wl.Details})
	}

	var openPorts []PortResult
	for _, p := range probes.OpenPorts {
		if p.IsOpen {
			openPorts = append(openPorts, p)
		}
	}
	if len(openPorts) > 0 {
		var portStrs []string
		for _, p := range openPorts {
			portStrs = append(portStrs, fmt.Sprintf("%d/%s", p.Port, p.Service))
		}
		probeRows = append(probeRows, []string{
			"Open Ports",
			green + fmt.Sprintf("%d", len(openPorts)) + reset,
			strings.Join(portStrs, ", "),
		})
	} else {
		probeRows = append(probeRows, []string{
			"Open Ports",
			red + "0" + reset,
			"All scanned ports blocked",
		})
	}

	fmt.Print(simpleTable("Leak Enumeration", "\033[34m", []string{"Protocol", "Status", "Details"}, probeRows))

	// Bypass results table.
	var bypassRows [][]string
	for _, r := range bypasses {
		resultStr := successIcon(r.Success)
		sevStr := dim + "-" + reset
		if r.Success {
			sevStr = severityTag(r.Severity)
		}
		detail := r.Details
		if r.Success {
			detail = r.Impact
		}
		bypassRows = append(bypassRows, []string{string(r.Method), resultStr, sevStr, detail})
	}

	fmt.Print(simpleTable("Bypass Attempts", red, []string{"Technique", "Result", "Severity", "Impact / Details"}, bypassRows))
	fmt.Println()

	// Findings summary.
	var successful []bypass.Result
	for _, r := range bypasses {
		if r.Success {
			successful = append(successful, r)
		}
	}

	if len(successful) > 0 {
		var findings strings.Builder
		for _, r := range successful {
			sc := severityColor(r.Severity)
			findings.WriteString(fmt.Sprintf(
				"%s%s%s: %s -- %s\n  %sRemediation: %s%s\n",
				sc, strings.ToUpper(r.Severity), reset,
				string(r.Method), r.Impact,
				dim, r.Remediation, reset,
			))
		}
		fmt.Print(drawBox(
			boldRed+fmt.Sprintf("Findings (%d vulnerabilities)", len(successful))+reset,
			red, findings.String(),
		))
	} else {
		fmt.Print(drawBox(
			boldGreen+"No Findings"+reset,
			green,
			green+"No bypass techniques succeeded. Portal appears well-configured."+reset,
		))
	}

	// Active tunnel info.
	for _, r := range bypasses {
		if r.Tunnel != nil && r.Tunnel.Active {
			tunnelInfo := fmt.Sprintf(
				"%sTunnel active:%s %s\nSOCKS5 proxy: %slocalhost:%d%s\nUse: %sexport ALL_PROXY=socks5://127.0.0.1:%d%s",
				boldGreen, reset, string(r.Method),
				bold, r.Tunnel.LocalPort, reset,
				bold, r.Tunnel.LocalPort, reset,
			)
			fmt.Print(drawBox(boldGreen+"Active Tunnel"+reset, green, tunnelInfo))
			break
		}
	}

	fmt.Println()
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

// GenerateMarkdown produces a markdown pentest report as a string.
func GenerateMarkdown(portal PortalInfo, probes ProbeResults, bypasses []bypass.Result) string {
	ts := time.Now().UTC().Format("2006-01-02 15:04 UTC")

	var b strings.Builder
	b.WriteString("# Captive Portal Security Assessment Report\n\n")
	b.WriteString(fmt.Sprintf("**Date:** %s\n", ts))
	b.WriteString(fmt.Sprintf("**SSID:** %s\n", nvl(portal.SSID, "N/A")))
	b.WriteString(fmt.Sprintf("**Gateway:** %s\n", nvl(portal.Gateway, "N/A")))
	b.WriteString(fmt.Sprintf("**Portal Vendor:** %s\n", nvl(portal.Vendor, "Unknown")))
	b.WriteString(fmt.Sprintf("**Portal Type:** %s\n", portal.PortalType))
	b.WriteString("\n## Leak Enumeration\n\n")
	b.WriteString("| Protocol | Status | Details |\n")
	b.WriteString("|----------|--------|--------|\n")

	writeProbeRow := func(name string, pr ProbeResult) {
		status := "CLOSED"
		if pr.IsOpen {
			status = "OPEN"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", name, status, pr.Details))
	}

	writeProbeRow("DNS (UDP/53)", probes.DNS)
	writeProbeRow("ICMP", probes.ICMP)
	writeProbeRow("IPv6", probes.IPv6)
	writeProbeRow("HTTPS (CF)", probes.Cloudflare)
	writeProbeRow("QUIC (UDP/443)", probes.QUIC)
	writeProbeRow("NTP (UDP/123)", probes.NTP)
	writeProbeRow("DoH (HTTPS)", probes.DoH)

	for _, wl := range probes.Whitelists {
		status := "CLOSED"
		if wl.IsOpen {
			status = "OPEN"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", wl.Domain, status, wl.Details))
	}

	b.WriteString("\n## Bypass Results\n\n")
	b.WriteString("| Technique | Result | Severity | Impact |\n")
	b.WriteString("|-----------|--------|----------|--------|\n")

	for _, r := range bypasses {
		result := "failed"
		if r.Success {
			result = "SUCCESS"
		}
		sev := "-"
		if r.Success {
			sev = strings.ToUpper(r.Severity)
		}
		detail := r.Details
		if r.Success {
			detail = r.Impact
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", string(r.Method), result, sev, detail))
	}

	var successful []bypass.Result
	for _, r := range bypasses {
		if r.Success {
			successful = append(successful, r)
		}
	}

	if len(successful) > 0 {
		b.WriteString("\n## Findings & Remediation\n\n")
		for i, r := range successful {
			b.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, string(r.Method), strings.ToUpper(r.Severity)))
			b.WriteString(fmt.Sprintf("**Impact:** %s\n\n", r.Impact))
			b.WriteString(fmt.Sprintf("**Details:** %s\n\n", r.Details))
			b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", r.Remediation))
		}
	}

	b.WriteString("---\n*Generated by nowifi v0.1.0*\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// JSON report
// ---------------------------------------------------------------------------

// jsonReport is the serialization structure for JSON output.
type jsonReport struct {
	Timestamp string       `json:"timestamp"`
	Portal    jsonPortal   `json:"portal"`
	Probes    jsonProbes   `json:"probes"`
	Bypasses  []jsonBypass `json:"bypasses"`
}

type jsonPortal struct {
	IsCaptive   bool     `json:"is_captive"`
	Type        string   `json:"type"`
	Vendor      string   `json:"vendor"`
	SSID        string   `json:"ssid"`
	Gateway     string   `json:"gateway"`
	URL         string   `json:"url"`
	AuthMethods []string `json:"auth_methods"`
}

type jsonProbeEntry struct {
	Open    bool   `json:"open"`
	Details string `json:"details"`
}

type jsonWhitelist struct {
	Domain string `json:"domain"`
	Open   bool   `json:"open"`
}

type jsonOpenPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

type jsonProbes struct {
	DNS        jsonProbeEntry  `json:"dns"`
	ICMP       jsonProbeEntry  `json:"icmp"`
	IPv6       jsonProbeEntry  `json:"ipv6"`
	Cloudflare jsonProbeEntry  `json:"cloudflare"`
	QUIC       jsonProbeEntry  `json:"quic"`
	NTP        jsonProbeEntry  `json:"ntp"`
	DoH        jsonProbeEntry  `json:"doh"`
	Whitelists []jsonWhitelist `json:"whitelists"`
	OpenPorts  []jsonOpenPort  `json:"open_ports"`
}

type jsonBypass struct {
	Method      string `json:"method"`
	Success     bool   `json:"success"`
	Severity    string `json:"severity"`
	Impact      string `json:"impact"`
	Details     string `json:"details"`
	Remediation string `json:"remediation"`
}

// GenerateJSON produces a JSON report as a formatted string.
func GenerateJSON(portal PortalInfo, probes ProbeResults, bypasses []bypass.Result) string {
	report := jsonReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Portal: jsonPortal{
			IsCaptive:   portal.IsCaptive,
			Type:        portal.PortalType,
			Vendor:      portal.Vendor,
			SSID:        portal.SSID,
			Gateway:     portal.Gateway,
			URL:         portal.PortalURL,
			AuthMethods: portal.AuthMethods,
		},
		Probes: jsonProbes{
			DNS:        jsonProbeEntry{Open: probes.DNS.IsOpen, Details: probes.DNS.Details},
			ICMP:       jsonProbeEntry{Open: probes.ICMP.IsOpen, Details: probes.ICMP.Details},
			IPv6:       jsonProbeEntry{Open: probes.IPv6.IsOpen, Details: probes.IPv6.Details},
			Cloudflare: jsonProbeEntry{Open: probes.Cloudflare.IsOpen, Details: probes.Cloudflare.Details},
			QUIC:       jsonProbeEntry{Open: probes.QUIC.IsOpen, Details: probes.QUIC.Details},
			NTP:        jsonProbeEntry{Open: probes.NTP.IsOpen, Details: probes.NTP.Details},
			DoH:        jsonProbeEntry{Open: probes.DoH.IsOpen, Details: probes.DoH.Details},
		},
	}

	for _, wl := range probes.Whitelists {
		report.Probes.Whitelists = append(report.Probes.Whitelists, jsonWhitelist{
			Domain: wl.Domain,
			Open:   wl.IsOpen,
		})
	}

	for _, p := range probes.OpenPorts {
		if p.IsOpen {
			report.Probes.OpenPorts = append(report.Probes.OpenPorts, jsonOpenPort{
				Port:    p.Port,
				Service: p.Service,
			})
		}
	}

	for _, r := range bypasses {
		report.Bypasses = append(report.Bypasses, jsonBypass{
			Method:      string(r.Method),
			Success:     r.Success,
			Severity:    r.Severity,
			Impact:      r.Impact,
			Details:     r.Details,
			Remediation: r.Remediation,
		})
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "%s"}`, err.Error())
	}
	return string(data)
}

// nvl returns val if non-empty, otherwise fallback.
func nvl(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}
