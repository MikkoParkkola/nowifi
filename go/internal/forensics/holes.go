// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package forensics

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// MapHoles is the heart of the port: it translates raw probe results into the
// ranked holes taxonomy used by the shell script and the reference JSON. Each
// open channel that survives enforcement maps to a nowifi bypass technique.
//
// Pure function — no I/O, no network — so it is directly table-testable by
// injecting a RawSections fixture.
func MapHoles(raw *RawSections) []Hole {
	var holes []Hole
	if raw == nil {
		return holes
	}

	// Section 2: authenticated-device enumeration. >1 neighbor MAC (excluding
	// self) is a MAC-clone candidate pool.
	others := 0
	self := strings.ToLower(raw.SelfMAC)
	for _, e := range raw.ARP {
		if strings.ToLower(e.MAC) != self {
			others++
		}
	}
	if others >= 1 {
		holes = append(holes, Hole{
			Technique: "mac_clone_idle",
			Severity:  SeverityHigh,
			Detail: fmt.Sprintf("%d neighbor MAC(s) visible on subnet; clone an idle paid device to inherit its session",
				others),
		})
	}

	// Section 3: TCP/UDP egress sweep. Open = exploitable hole.
	for _, p := range raw.OpenPorts {
		if !p.IsOpen {
			continue
		}
		switch p.Port {
		case 53:
			if strings.EqualFold(p.Protocol, "udp") {
				holes = append(holes, Hole{"dns_tunnel", SeverityHigh,
					"UDP/53 egress open — iodine/dnscat2 DNS tunnel viable"})
			} else {
				holes = append(holes, Hole{"tcp53_tunnel", SeverityHigh,
					"TCP/53 egress open — chisel/ssh over :53"})
			}
		case 443:
			if strings.EqualFold(p.Protocol, "udp") {
				holes = append(holes, Hole{"quic_tunnel", SeverityMed,
					"UDP/443 (QUIC) egress open — masque/quic tunnel"})
			} else {
				holes = append(holes, Hole{"tcp443_tunnel", SeverityMed,
					"TCP/443 egress open to non-allowlisted IP — wstunnel/chisel/openvpn over :443"})
			}
		case 22:
			holes = append(holes, Hole{"ssh_egress", SeverityHigh,
				"TCP/22 open — direct SSH SOCKS proxy"})
		case 123:
			holes = append(holes, Hole{"ntp_tunnel", SeverityMed,
				"UDP/123 (NTP) egress open — covert channel"})
		}
	}

	// Section 3 (dedicated probes): QUIC, NTP.
	if raw.QUIC.IsOpen {
		holes = append(holes, Hole{"quic_tunnel", SeverityMed,
			"UDP/443 (QUIC) reaches the internet — masque/quic tunnel"})
	}
	if raw.NTP.IsOpen {
		holes = append(holes, Hole{"ntp_tunnel", SeverityMed,
			"UDP/123 (NTP) reaches the internet — covert channel"})
	}

	// Section 4: DNS external recursion (the classic survivor).
	if raw.DNS.IsOpen {
		for _, r := range raw.DNS.Resolvers {
			holes = append(holes, Hole{"dns_tunnel", SeverityHigh,
				fmt.Sprintf("resolver %s returns external A records — full recursion = DNS tunnel works", r.IP)})
		}
		if len(raw.DNS.Resolvers) == 0 {
			holes = append(holes, Hole{"dns_tunnel", SeverityHigh,
				"external DNS recursion reachable — DNS tunnel viable"})
		}
	}

	// Section 5: DoH endpoints.
	if raw.DoH.IsOpen {
		holes = append(holes, Hole{"doh_tunnel", SeverityHigh,
			"DoH endpoint reachable + answers — DoH tunnel / cloudflared works"})
	}

	// Section 6: ICMP echo to the internet.
	if raw.ICMP.IsOpen {
		holes = append(holes, Hole{"icmp_tunnel", SeverityHigh,
			"ICMP echo reaches the internet — ptunnel-ng covert channel"})
	}

	// Section 7: allowlist + SNI/domain-fronting.
	for _, w := range raw.Whitelists {
		if w.IsOpen {
			holes = append(holes, Hole{"domain_front", SeverityMed,
				fmt.Sprintf("allowlisted host %s returns %d — SNI/domain-fronting hop candidate", w.Domain, w.StatusCode)})
		}
	}

	// Section 8c: a live enforcement endpoint is a PoC surface.
	for _, ep := range raw.PaxAPI {
		if ep.StatusCode >= 200 && ep.StatusCode < 500 && ep.StatusCode != 404 {
			holes = append(holes, Hole{"portal_api_session", SeverityMed,
				fmt.Sprintf("enforcement endpoint %s is live (HTTP %d, %s) — inspect/replay for session/quota state",
					ep.Path, ep.StatusCode, ep.ContentType)})
		}
	}

	// Section 9: enforcement model — per-MAC quota reset vector.
	if raw.SelfMAC != "" {
		holes = append(holes, Hole{"mac_rotate", SeverityMed,
			"if quota is per-MAC, a fresh random MAC resets it"})
	}

	return rankHoles(holes)
}

// rankHoles orders holes HIGH, then MED, then LOW, preserving discovery order
// within each tier. Deterministic for stable test assertions and reports.
func rankHoles(holes []Hole) []Hole {
	order := map[string]int{SeverityHigh: 0, SeverityMed: 1, SeverityLow: 2}
	sort.SliceStable(holes, func(i, j int) bool {
		return order[holes[i].Severity] < order[holes[j].Severity]
	})
	return holes
}

// holeKey identifies a hole channel for diffing (technique + severity-agnostic
// channel). We key on technique alone: the same technique open in two runs is
// the reliable channel regardless of how the detail string was phrased.
func holeKey(h Hole) string { return h.Technique }

// DiffBaseline returns the holes that are open in BOTH the current capture and
// the baseline (set intersection by technique). Channels open in both runs
// survive enforcement and are the reliable holes (section 10).
//
// Pure function — table-testable without any network.
func DiffBaseline(current, baseline []Hole) []Hole {
	base := make(map[string]bool, len(baseline))
	for _, h := range baseline {
		base[holeKey(h)] = true
	}
	seen := make(map[string]bool)
	var out []Hole
	for _, h := range current {
		k := holeKey(h)
		if base[k] && !seen[k] {
			seen[k] = true
			out = append(out, h)
		}
	}
	return rankHoles(out)
}

// JSON serializes the package to indented JSON mirroring forensics/holes-*.json
// ({ts, provider, iface, gw, holes[]} plus raw sections).
func (p *Package) JSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// Text renders the human-readable .txt report (the HOLES section plus a
// captured-state summary), matching the shell script's report shape.
func (p *Package) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# nowifi captive forensics — %s\n", p.TS)
	fmt.Fprintf(&b, "# iface=%s gw=%s provider=%s self_mac=%s\n", p.Iface, p.GW, p.Provider, p.Raw.SelfMAC)
	b.WriteString("# read-only capture: no MAC change, no tunnel, no proxy, no upload\n\n")

	b.WriteString("===== 1. NETWORK STATE =====\n")
	fmt.Fprintf(&b, "  DNS open: %t — %s\n", p.Raw.DNS.IsOpen, p.Raw.DNS.Details)
	fmt.Fprintf(&b, "  IPv6 open: %t — %s\n", p.Raw.IPv6.IsOpen, p.Raw.IPv6.Details)
	if p.Raw.Topology.Details != "" {
		fmt.Fprintf(&b, "  topology: %s\n", p.Raw.Topology.Details)
	}

	b.WriteString("\n===== 2. MAC-CLONE CANDIDATES =====\n")
	if len(p.Raw.ARP) == 0 {
		b.WriteString("  (no neighbor MACs in ARP cache)\n")
	}
	for _, e := range p.Raw.ARP {
		fmt.Fprintf(&b, "  %-15s  %s  (%s)\n", e.IP, e.MAC, e.Interface)
	}

	b.WriteString("\n===== 3-7. EGRESS / RECURSION / DoH / ICMP / ALLOWLIST =====\n")
	for _, prt := range p.Raw.OpenPorts {
		if prt.IsOpen {
			fmt.Fprintf(&b, "  %s/%d OPEN (%s)\n", prt.Protocol, prt.Port, prt.Service)
		}
	}
	fmt.Fprintf(&b, "  QUIC open: %t | NTP open: %t | DoH open: %t | ICMP open: %t\n",
		p.Raw.QUIC.IsOpen, p.Raw.NTP.IsOpen, p.Raw.DoH.IsOpen, p.Raw.ICMP.IsOpen)
	for _, w := range p.Raw.Whitelists {
		fmt.Fprintf(&b, "  allow? %s -> open=%t (%d)\n", w.Domain, w.IsOpen, w.StatusCode)
	}

	b.WriteString("\n===== 8c. PORTAL API (pax-api enforcement control plane) =====\n")
	for _, ep := range p.Raw.PaxAPI {
		if ep.Error != "" {
			fmt.Fprintf(&b, "  %-40s ERR %s\n", ep.Path, ep.Error)
			continue
		}
		fmt.Fprintf(&b, "  %-40s %d %s%s\n", ep.Path, ep.StatusCode, ep.ContentType,
			truncMark(ep.Truncated))
	}
	if pa := p.Raw.PaxAPIAnalysis; pa != nil {
		fmt.Fprintf(&b, "  -> real-API=%v swagger-openapi=%v\n", pa.IsRealAPI, pa.SwaggerIsOpenAPI)
		for _, rv := range pa.CandidateResetVectors {
			fmt.Fprintf(&b, "     candidate reset vector: %s\n", rv)
		}
		for _, note := range pa.Notes {
			fmt.Fprintf(&b, "     %s\n", note)
		}
	}

	b.WriteString("\n===== HOLES FOUND (ranked; each maps to a nowifi technique) =====\n")
	if len(p.Holes) == 0 {
		b.WriteString("  none detected — portal enforcement is tight on every probed vector\n")
	}
	for _, h := range p.Holes {
		fmt.Fprintf(&b, "\n  [%s] %s\n       what : %s\n", h.Severity, h.Technique, h.Detail)
	}

	if len(p.Raw.Limitations) > 0 {
		b.WriteString("\n===== LIMITATIONS (degraded / privilege-gated / timed-out) =====\n")
		for _, l := range p.Raw.Limitations {
			fmt.Fprintf(&b, "  - %s\n", l)
		}
	}
	return b.String()
}

func truncMark(t bool) string {
	if t {
		return " [body truncated]"
	}
	return ""
}

// Baseline renders the capture-at-full-access baseline file. It records every
// channel that is open right now, so a later under-enforcement run can diff
// against it (channels open in both = reliable holes).
func (p *Package) Baseline() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# nowifi forensic baseline (full-access capture) — %s\n", p.TS)
	fmt.Fprintf(&b, "# iface=%s gw=%s provider=%s\n", p.Iface, p.GW, p.Provider)
	b.WriteString("# open channels at baseline (diff a later capture against these)\n\n")
	for _, h := range p.Holes {
		fmt.Fprintf(&b, "%s|%s|%s\n", h.Technique, h.Severity, h.Detail)
	}
	return b.String()
}

// ParseBaseline reads a baseline file produced by Baseline() back into holes,
// for diffing. Lines are "technique|severity|detail"; comments and blanks are
// skipped. Tolerant of the shell script's baseline files too (best-effort).
func ParseBaseline(content string) []Hole {
	var holes []Hole
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			continue
		}
		h := Hole{Technique: strings.TrimSpace(parts[0]), Severity: strings.TrimSpace(parts[1])}
		if len(parts) == 3 {
			h.Detail = strings.TrimSpace(parts[2])
		}
		if h.Technique == "" {
			continue
		}
		holes = append(holes, h)
	}
	return holes
}
