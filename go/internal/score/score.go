// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package score provides WiFi network security scoring and reporting.
// Scans nearby networks and produces a security posture assessment
// with letter grades (A-F) and specific vulnerability findings.
package score

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/discover"
	"github.com/MikkoParkkola/nowifi/internal/probe"
)

// Grade represents a security letter grade.
type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeF Grade = "F"
)

// Finding represents a specific security issue found.
type Finding struct {
	Severity    string // critical, high, medium, low, info
	Title       string
	Description string
	Remediation string
}

// NetworkScore is the security assessment for a single WiFi network.
type NetworkScore struct {
	SSID        string
	BSSID       string
	Channel     int
	Signal      int
	Security    string
	WPS         bool
	Grade       Grade
	Score       int // 0-100
	Findings    []Finding
	ClientCount int
	PortalType  string
	Timestamp   time.Time
}

// ScanReport is the complete security report for all nearby networks.
type ScanReport struct {
	Timestamp time.Time
	Interface string
	Location  string // user-provided or auto-detected
	Networks  []NetworkScore
	Summary   ReportSummary
}

// ReportSummary aggregates findings across all networks.
type ReportSummary struct {
	TotalNetworks    int
	GradeA           int
	GradeB           int
	GradeC           int
	GradeD           int
	GradeF           int
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	WorstNetwork     string
	BestNetwork      string
}

// ScoreNetwork assesses the security posture of a single WiFi network.
func ScoreNetwork(net discover.ScannedNetwork) NetworkScore {
	ns := NetworkScore{
		SSID:      net.SSID,
		BSSID:     net.BSSID,
		Channel:   net.Channel,
		Signal:    net.Signal,
		Security:  net.Security,
		WPS:       net.WPS,
		Timestamp: time.Now(),
	}

	score := 100
	findings := []Finding{}

	// --- Encryption assessment ---
	switch {
	case net.Security == "Open" || net.Security == "":
		score -= 50
		findings = append(findings, Finding{
			Severity:    "critical",
			Title:       "No encryption",
			Description: "Network transmits all data in cleartext. Anyone nearby can intercept traffic.",
			Remediation: "Enable WPA3-Personal or WPA2-Personal with a strong passphrase.",
		})

	case strings.Contains(net.Security, "WEP"):
		score -= 45
		findings = append(findings, Finding{
			Severity:    "critical",
			Title:       "WEP encryption (broken)",
			Description: "WEP can be cracked in minutes. Equivalent to no encryption.",
			Remediation: "Upgrade to WPA3-Personal or WPA2-Personal immediately.",
		})

	case net.Security == "WPA":
		// WPA1/TKIP: deprecated 2012, banned by Wi-Fi Alliance 2020.
		// Vulnerable to TKIP MIC attacks (Beck-Tews 2008), RC4 keystream
		// reuse, and PMKID extraction. Firmware rarely supports upgrade
		// without full replacement — flag as critical.
		score -= 40
		findings = append(findings, Finding{
			Severity:    "critical",
			Title:       "WPA (TKIP) — deprecated and vulnerable",
			Description: "WPA1/TKIP was deprecated in 2012 and banned from Wi-Fi Alliance certification in 2020. Vulnerable to TKIP MIC attacks (Beck-Tews), RC4 keystream reuse, and PMKID capture. Treat as nearly equivalent to WEP.",
			Remediation: "Upgrade firmware to WPA2-AES/CCMP or WPA3. Disable TKIP mode. Replace hardware if firmware upgrade is unavailable.",
		})

	case strings.Contains(net.Security, "WPA2") && !strings.Contains(net.Security, "Enterprise"):
		// WPA2-Personal is standard, minor deduction
		score -= 5
		findings = append(findings, Finding{
			Severity:    "info",
			Title:       "WPA2-Personal (adequate)",
			Description: "Standard encryption. Vulnerable to offline dictionary attacks on weak passwords.",
			Remediation: "Consider upgrading to WPA3. Use a strong passphrase (12+ random characters).",
		})

	case strings.Contains(net.Security, "WPA3"):
		// WPA3 is best — no deduction
		findings = append(findings, Finding{
			Severity:    "info",
			Title:       "WPA3 encryption (strong)",
			Description: "Current best standard. Resistant to offline dictionary attacks.",
			Remediation: "None needed. Ensure SAE transition mode is disabled if not needed.",
		})

	case strings.Contains(net.Security, "Enterprise"):
		// Enterprise is best for organizations
		findings = append(findings, Finding{
			Severity:    "info",
			Title:       "WPA2/3-Enterprise (strong)",
			Description: "Per-user authentication via RADIUS. Strong when properly configured.",
			Remediation: "Ensure RADIUS certificate validation is enforced on all clients.",
		})
	}

	// --- WPS assessment ---
	if net.WPS {
		score -= 25
		findings = append(findings, Finding{
			Severity:    "high",
			Title:       "WPS enabled",
			Description: "WiFi Protected Setup is vulnerable to Pixie-Dust attack (~30% of APs) and PIN brute force. Attacker can recover WPA password without knowing it.",
			Remediation: "Disable WPS in router settings. It provides minimal convenience for significant risk.",
		})
	}

	// --- Portal / open network assessment ---
	if net.Security == "Open" || net.Security == "" {
		if net.PortalLikely {
			score -= 10
			findings = append(findings, Finding{
				Severity:    "high",
				Title:       "Captive portal on open network",
				Description: "Captive portal provides access control but NOT encryption. All post-auth traffic is unencrypted. Vulnerable to: MAC spoofing, session hijacking, traffic sniffing.",
				Remediation: "Implement WPA2/3 with portal (Passpoint/Hotspot 2.0). At minimum, force HTTPS on the portal itself.",
			})
		}
	}

	// --- Client isolation heuristic ---
	// Can't test without connecting, but note the risk
	if net.Security == "Open" || net.PortalLikely {
		findings = append(findings, Finding{
			Severity:    "medium",
			Title:       "Client isolation unknown",
			Description: "Cannot verify client isolation without connecting. If disabled, devices on this network can attack each other (ARP spoofing, MITM).",
			Remediation: "Enable AP isolation / Private VLAN on all guest networks.",
		})
	}

	// --- Signal strength (opportunity assessment) ---
	if net.Signal > -50 {
		findings = append(findings, Finding{
			Severity:    "info",
			Title:       "Strong signal (close proximity)",
			Description: fmt.Sprintf("Signal: %d dBm. Attacker within ~10m range.", net.Signal),
			Remediation: "Reduce transmit power if network doesn't need wide coverage.",
		})
	}

	// --- Hidden SSID ---
	if net.SSID == "" || net.SSID == "<hidden>" {
		findings = append(findings, Finding{
			Severity:    "low",
			Title:       "Hidden SSID",
			Description: "SSID is hidden but easily discovered via probe requests. Provides zero security benefit and can cause client privacy issues.",
			Remediation: "Unhide the SSID. Hidden SSIDs are a false sense of security.",
		})
	}

	// --- Calculate grade ---
	if score < 0 {
		score = 0
	}
	ns.Score = score
	ns.Grade = scoreToGrade(score)
	ns.Findings = findings

	return ns
}

// ScoreAll scans nearby networks and scores each one.
func ScoreAll(iface string) (*ScanReport, error) {
	networks, err := discover.ScanNetworks(iface)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	report := &ScanReport{
		Timestamp: time.Now(),
		Interface: iface,
		Networks:  make([]NetworkScore, 0, len(networks)),
	}

	for _, net := range networks {
		ns := ScoreNetwork(net)
		report.Networks = append(report.Networks, ns)
	}

	// Sort by score (worst first — most interesting for security assessment)
	sort.Slice(report.Networks, func(i, j int) bool {
		return report.Networks[i].Score < report.Networks[j].Score
	})

	// Build summary
	report.Summary = buildSummary(report.Networks)

	return report, nil
}

// ScoreConnected scores the currently connected network with deep analysis.
func ScoreConnected(iface string) (*NetworkScore, error) {
	// Get current network info
	portal := detect.DetectPortal(iface)
	probes := probe.ProbeAll(iface, true, "")

	// Start with basic scan score
	ns := NetworkScore{
		SSID:      portal.SSID,
		Timestamp: time.Now(),
	}

	score := 100
	findings := []Finding{}

	// Portal-specific findings
	if portal.IsCaptive {
		ns.PortalType = string(portal.Type)
		score -= 15
		findings = append(findings, Finding{
			Severity:    "high",
			Title:       fmt.Sprintf("Captive portal detected (%s)", portal.Type),
			Description: fmt.Sprintf("Portal vendor: %s. Auth methods: %s", portal.Vendor, strings.Join(portal.AuthMethods, ", ")),
			Remediation: "Ensure portal uses HTTPS, enforces client isolation, and binds sessions to MAC+IP+cookie.",
		})
	}

	// Probe-based findings
	if probes.DNS.IsOpen {
		findings = append(findings, Finding{
			Severity:    "medium",
			Title:       "External DNS reachable pre-auth",
			Description: "DNS queries to external resolvers (1.1.1.1, 8.8.8.8) succeed before authentication. Enables DNS tunneling bypass.",
			Remediation: "Restrict DNS to portal-operated resolvers only. Block UDP/53 to external IPs for unauthenticated clients.",
		})
		score -= 10
	}

	if probes.ICMP.IsOpen {
		findings = append(findings, Finding{
			Severity:    "medium",
			Title:       "ICMP (ping) reachable pre-auth",
			Description: "Ping to external hosts succeeds. Enables ICMP tunneling bypass.",
			Remediation: "Block or rate-limit ICMP for unauthenticated clients.",
		})
		score -= 10
	}

	if probes.IPv6.IsOpen {
		findings = append(findings, Finding{
			Severity:    "critical",
			Title:       "IPv6 bypasses portal",
			Description: "IPv6 traffic flows freely without portal authentication. Complete portal bypass.",
			Remediation: "Apply captive portal ACLs to IPv6 traffic. Filter RA/DHCPv6 or mirror IPv4 rules.",
		})
		score -= 30
	}

	if probes.QUIC.IsOpen {
		findings = append(findings, Finding{
			Severity:    "medium",
			Title:       "UDP/443 (QUIC) open pre-auth",
			Description: "QUIC traffic is not filtered. Enables Hysteria2 tunnel bypass disguised as HTTP/3.",
			Remediation: "Inspect or block UDP/443 for unauthenticated clients.",
		})
		score -= 10
	}

	if probes.NTP.IsOpen {
		findings = append(findings, Finding{
			Severity:    "low",
			Title:       "NTP (UDP/123) reachable",
			Description: "NTP traffic passes through. Low-bandwidth tunnel possible via NTP extension fields.",
			Remediation: "Restrict NTP to known time servers only.",
		})
		score -= 5
	}

	if probes.DoH.IsOpen {
		findings = append(findings, Finding{
			Severity:    "medium",
			Title:       "DNS-over-HTTPS reachable",
			Description: "DoH endpoints (Cloudflare, Google) are accessible. Enables encrypted DNS tunnel bypass.",
			Remediation: "Block DoH endpoints for unauthenticated clients.",
		})
		score -= 10
	}

	// Open port findings
	openPorts := 0
	for _, p := range probes.OpenPorts {
		if p.IsOpen {
			openPorts++
		}
	}
	if openPorts > 5 {
		findings = append(findings, Finding{
			Severity:    "high",
			Title:       fmt.Sprintf("%d open outbound ports pre-auth", openPorts),
			Description: "Multiple TCP ports are accessible without authentication. Each is a potential tunnel endpoint.",
			Remediation: "Block all outbound traffic for unauthenticated clients except portal-required ports.",
		})
		score -= 15
	}

	if score < 0 {
		score = 0
	}
	ns.Score = score
	ns.Grade = scoreToGrade(score)
	ns.Findings = findings

	return &ns, nil
}

func scoreToGrade(score int) Grade {
	switch {
	case score >= 90:
		return GradeA
	case score >= 75:
		return GradeB
	case score >= 60:
		return GradeC
	case score >= 40:
		return GradeD
	default:
		return GradeF
	}
}

func buildSummary(networks []NetworkScore) ReportSummary {
	s := ReportSummary{TotalNetworks: len(networks)}

	worst := 100
	best := 0

	for _, n := range networks {
		switch n.Grade {
		case GradeA:
			s.GradeA++
		case GradeB:
			s.GradeB++
		case GradeC:
			s.GradeC++
		case GradeD:
			s.GradeD++
		case GradeF:
			s.GradeF++
		}

		for _, f := range n.Findings {
			switch f.Severity {
			case "critical":
				s.CriticalFindings++
			case "high":
				s.HighFindings++
			case "medium":
				s.MediumFindings++
			}
		}

		if n.Score < worst {
			worst = n.Score
			s.WorstNetwork = n.SSID
		}
		if n.Score > best {
			best = n.Score
			s.BestNetwork = n.SSID
		}
	}

	return s
}
