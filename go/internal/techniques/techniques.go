// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package techniques centralizes user-facing nowifi technique metadata.
package techniques

// ID identifies a portal-bypass technique.
type ID string

const (
	IPv6Bypass      ID = "ipv6_bypass"
	ChiselTunnel    ID = "chisel_tunnel"
	CNASpoof        ID = "cna_useragent_spoof"
	JSOnlyPortal    ID = "js_only_bypass"
	HTTPConnect     ID = "http_connect_abuse"
	MACCloneIdle    ID = "mac_clone_idle"
	MACClone        ID = "mac_clone"
	DNSTunnel       ID = "dns_tunnel"
	ICMPTunnel      ID = "icmp_tunnel"
	VPNPort53       ID = "vpn_port_53"
	WhitelistDomain ID = "whitelist_domain"
	SessionReplay   ID = "session_cookie_replay"
	PortalCreds     ID = "portal_default_creds"
	MACRotate       ID = "mac_rotate"
	DHCPRotate      ID = "dhcp_rotate"
	QUICTunnel      ID = "quic_tunnel"
	CFWorkers       ID = "cf_workers_proxy"
	NTPTunnel       ID = "ntp_tunnel"
	DoHTunnel       ID = "doh_tunnel"
)

// BypassTechniqueSignals captures the probe facts needed for feasibility
// assessment without coupling callers to any specific probe package.
type BypassTechniqueSignals struct {
	PortalDetected     bool
	IPv6Open           bool
	DNSOpen            bool
	ICMPOpen           bool
	CloudflareOpen     bool
	QUICOpen           bool
	NTPOpen            bool
	DoHOpen            bool
	WhitelistReachable bool
	HTTP443Open        bool
	HTTP8080Open       bool
}

// BypassTechniqueInfo is the canonical user-facing metadata for a bypass
// technique.
type BypassTechniqueInfo struct {
	Number         int
	ID             ID
	Name           string
	HelpName       string
	RequiresServer bool
	Confidence     string
	Reason         string
	Risk           string
}

// BypassTechniqueAssessment combines the canonical metadata with a
// feasibility decision for a specific probe snapshot.
type BypassTechniqueAssessment struct {
	BypassTechniqueInfo
	Feasible bool
}

type bypassTechniqueSpec struct {
	info     BypassTechniqueInfo
	feasible func(BypassTechniqueSignals) bool
}

var bypassTechniqueSpecs = []bypassTechniqueSpec{
	{
		info: BypassTechniqueInfo{
			Number: 1, ID: IPv6Bypass, Name: "IPv6 bypass", HelpName: "IPv6 bypass",
			Confidence: "HIGH", Reason: "IPv6 unfiltered by portal", Risk: "None (read-only)",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.IPv6Open },
	},
	{
		info: BypassTechniqueInfo{
			Number: 2, ID: ChiselTunnel, Name: "HTTPS/WS tunnel", HelpName: "HTTPS tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "TCP/443 open", Risk: "Needs tunnel server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.HTTP443Open },
	},
	{
		info: BypassTechniqueInfo{
			Number: 3, ID: CNASpoof, Name: "CNA User-Agent spoof", HelpName: "CNA UA spoof",
			Confidence: "MEDIUM", Reason: "Always possible to attempt", Risk: "Detected by portal logs",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.PortalDetected },
	},
	{
		info: BypassTechniqueInfo{
			Number: 4, ID: JSOnlyPortal, Name: "JS-only bypass", HelpName: "JS-only bypass",
			Confidence: "LOW", Reason: "Requires portal analysis", Risk: "Portal-dependent",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.PortalDetected },
	},
	{
		info: BypassTechniqueInfo{
			Number: 5, ID: HTTPConnect, Name: "HTTP CONNECT abuse", HelpName: "HTTP CONNECT",
			Confidence: "MEDIUM", Reason: "TCP/443 or TCP/8080 open", Risk: "Transparent proxy needed",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.HTTP443Open || signals.HTTP8080Open
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 6, ID: MACCloneIdle, Name: "MAC clone (idle)", HelpName: "MAC clone idle",
			Confidence: "HIGH", Reason: "Always possible", Risk: "MAC change visible",
		},
		feasible: func(BypassTechniqueSignals) bool { return true },
	},
	{
		info: BypassTechniqueInfo{
			Number: 7, ID: MACClone, Name: "MAC clone (any)", HelpName: "MAC clone any",
			Confidence: "HIGH", Reason: "Always possible", Risk: "Disconnects victim",
		},
		feasible: func(BypassTechniqueSignals) bool { return true },
	},
	{
		info: BypassTechniqueInfo{
			Number: 8, ID: DNSTunnel, Name: "DNS tunnel", HelpName: "DNS tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "DNS UDP/53 open", Risk: "Needs DNS tunnel server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.DNSOpen },
	},
	{
		info: BypassTechniqueInfo{
			Number: 9, ID: ICMPTunnel, Name: "ICMP tunnel", HelpName: "ICMP tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "ICMP open to external", Risk: "Needs ICMP tunnel server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.ICMPOpen },
	},
	{
		info: BypassTechniqueInfo{
			Number: 10, ID: VPNPort53, Name: "VPN on port 53", HelpName: "VPN port 53",
			RequiresServer: true, Confidence: "MEDIUM", Reason: "UDP/53 open", Risk: "Needs VPN server on 53",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.DNSOpen },
	},
	{
		info: BypassTechniqueInfo{
			Number: 11, ID: WhitelistDomain, Name: "Whitelist domain abuse", HelpName: "Whitelist",
			RequiresServer: true, Confidence: "LOW", Reason: "Whitelisted domains found", Risk: "Needs endpoint on whitelisted domain",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.WhitelistReachable },
	},
	{
		info: BypassTechniqueInfo{
			Number: 12, ID: SessionReplay, Name: "Session cookie replay", HelpName: "Session cookie",
			Confidence: "LOW", Reason: "Requires traffic capture", Risk: "Needs monitor mode",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.PortalDetected },
	},
	{
		info: BypassTechniqueInfo{
			Number: 13, ID: PortalCreds, Name: "Portal default credentials", HelpName: "Portal creds",
			Confidence: "LOW", Reason: "Try common passwords", Risk: "Rate-limited by portal",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.PortalDetected },
	},
	{
		info: BypassTechniqueInfo{
			Number: 14, ID: MACRotate, Name: "MAC rotate", HelpName: "MAC rotate",
			Confidence: "MEDIUM", Reason: "Always possible", Risk: "MAC change visible",
		},
		feasible: func(BypassTechniqueSignals) bool { return true },
	},
	{
		info: BypassTechniqueInfo{
			Number: 15, ID: DHCPRotate, Name: "DHCP rotate", HelpName: "DHCP rotate",
			Confidence: "MEDIUM", Reason: "Always possible", Risk: "New IP lease",
		},
		feasible: func(BypassTechniqueSignals) bool { return true },
	},
	{
		info: BypassTechniqueInfo{
			Number: 16, ID: QUICTunnel, Name: "QUIC tunnel", HelpName: "QUIC tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "UDP/443 open", Risk: "Needs Hysteria2 server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.QUICOpen },
	},
	{
		info: BypassTechniqueInfo{
			Number: 17, ID: CFWorkers, Name: "Cloudflare Workers proxy", HelpName: "CF Workers",
			RequiresServer: true, Confidence: "MEDIUM", Reason: "HTTPS open to Cloudflare", Risk: "Free CF account required",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.CloudflareOpen },
	},
	{
		info: BypassTechniqueInfo{
			Number: 18, ID: NTPTunnel, Name: "NTP tunnel", HelpName: "NTP tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "NTP open", Risk: "Needs NTP tunnel server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.NTPOpen },
	},
	{
		info: BypassTechniqueInfo{
			Number: 19, ID: DoHTunnel, Name: "DoH tunnel", HelpName: "DoH tunnel",
			RequiresServer: true, Confidence: "MEDIUM", Reason: "DoH reachable", Risk: "DNS-over-HTTPS channel",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.DoHOpen },
	},
}

// BypassTechniqueCount returns the number of portal-bypass techniques.
func BypassTechniqueCount() int {
	return len(bypassTechniqueSpecs)
}

// BypassTechniqueInfos returns the canonical ordered portal-bypass metadata.
func BypassTechniqueInfos() []BypassTechniqueInfo {
	infos := make([]BypassTechniqueInfo, len(bypassTechniqueSpecs))
	for i, spec := range bypassTechniqueSpecs {
		infos[i] = spec.info
	}
	return infos
}

// BypassTechniqueInfoByID returns the canonical metadata for one technique.
func BypassTechniqueInfoByID(id ID) (BypassTechniqueInfo, bool) {
	for _, spec := range bypassTechniqueSpecs {
		if spec.info.ID == id {
			return spec.info, true
		}
	}
	return BypassTechniqueInfo{}, false
}

// ServerlessBypassTechniqueInfos returns the portal-bypass techniques that do
// not depend on user-managed external infrastructure.
func ServerlessBypassTechniqueInfos() []BypassTechniqueInfo {
	return filteredBypassTechniqueInfos(false)
}

// ServerRequiredBypassTechniqueInfos returns the portal-bypass techniques that
// depend on user-managed external infrastructure.
func ServerRequiredBypassTechniqueInfos() []BypassTechniqueInfo {
	return filteredBypassTechniqueInfos(true)
}

func filteredBypassTechniqueInfos(requiresServer bool) []BypassTechniqueInfo {
	var infos []BypassTechniqueInfo
	for _, spec := range bypassTechniqueSpecs {
		if spec.info.RequiresServer == requiresServer {
			infos = append(infos, spec.info)
		}
	}
	return infos
}

// AssessBypassTechniques evaluates the canonical portal-bypass feasibility
// rules against a specific probe snapshot.
func AssessBypassTechniques(signals BypassTechniqueSignals) []BypassTechniqueAssessment {
	assessments := make([]BypassTechniqueAssessment, len(bypassTechniqueSpecs))
	for i, spec := range bypassTechniqueSpecs {
		assessments[i] = BypassTechniqueAssessment{
			BypassTechniqueInfo: spec.info,
			Feasible:            spec.feasible(signals),
		}
	}
	return assessments
}

// CountFeasibleBypassTechniques counts how many portal-bypass techniques are
// currently feasible for the supplied probe snapshot.
func CountFeasibleBypassTechniques(signals BypassTechniqueSignals) int {
	feasible := 0
	for _, spec := range bypassTechniqueSpecs {
		if spec.feasible(signals) {
			feasible++
		}
	}
	return feasible
}
