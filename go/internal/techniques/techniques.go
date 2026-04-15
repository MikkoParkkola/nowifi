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
	// Wave 20: Modern portal/transport techniques (2026-04).
	CAPPORTExtend ID = "capport_session_extend" // RFC 8908 session extension
	DoQTunnel     ID = "doq_tunnel"             // DNS-over-QUIC tunnel
	HTTP3Tunnel   ID = "http3_tunnel"           // HTTP/3-specific tunnel (QUIC Alt-Svc)
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
	// Wave 20: Modern portal/transport signals.
	// CAPPORTAvailable is true when RFC 8908 captive-portal API is advertised
	// via DHCP option 114 and the API endpoint responds.
	CAPPORTAvailable bool
	// CAPPORTExtendable is true when the CAPPORT API exposes
	// "can-extend-session": true (RFC 8908 §5).
	CAPPORTExtendable bool
	// DoQOpen is true when DNS-over-QUIC endpoints (UDP/853 or UDP/443
	// to known DoQ providers) are reachable.
	DoQOpen bool
	// HTTP3Open is true when a test UDP/443 QUIC handshake succeeds
	// (distinct from QUICOpen which may only check protocol presence).
	HTTP3Open bool
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

// BypassTechniqueResultMetadata is the canonical severity/impact/remediation
// contract for a technique result.
type BypassTechniqueResultMetadata struct {
	Severity    string
	Impact      string
	Remediation string
}

func (m BypassTechniqueResultMetadata) isZero() bool {
	return m.Severity == "" && m.Impact == "" && m.Remediation == ""
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
	success  BypassTechniqueResultMetadata
	finding  BypassTechniqueResultMetadata
}

var bypassTechniqueSpecs = []bypassTechniqueSpec{
	{
		info: BypassTechniqueInfo{
			Number: 1, ID: IPv6Bypass, Name: "IPv6 bypass", HelpName: "IPv6 bypass",
			Confidence: "HIGH", Reason: "IPv6 unfiltered by portal", Risk: "None (read-only)",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.IPv6Open },
		success: BypassTechniqueResultMetadata{
			Severity:    "critical",
			Impact:      "Full unrestricted IPv6 internet -- bypasses all portal controls",
			Remediation: "Apply captive portal ACLs to IPv6. Filter RA/DHCPv6 or mirror IPv4 rules.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 2, ID: ChiselTunnel, Name: "HTTPS/WS tunnel", HelpName: "HTTPS tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "TCP/443 open", Risk: "Needs tunnel server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.HTTP443Open },
		success: BypassTechniqueResultMetadata{
			Severity:    "critical",
			Impact:      "Full internet via system SOCKS proxy (auto-configured)",
			Remediation: "Block WebSocket upgrades pre-auth. Inspect TLS SNI. Whitelist only portal domains.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 3, ID: CNASpoof, Name: "CNA User-Agent spoof", HelpName: "CNA UA spoof",
			Confidence: "MEDIUM", Reason: "Always possible to attempt", Risk: "Detected by portal logs",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.PortalDetected },
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "Internet access via captive-network User-Agent spoofing",
			Remediation: "Do not auto-approve CNA/Wispr User-Agents. Require explicit authentication for all clients.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 4, ID: JSOnlyPortal, Name: "JS-only bypass", HelpName: "JS-only bypass",
			Confidence: "LOW", Reason: "Requires portal analysis", Risk: "Portal-dependent",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.PortalDetected },
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "Internet access -- portal only enforces auth in JavaScript",
			Remediation: "Enforce captive portal at the firewall/gateway level, not in client-side JavaScript.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 5, ID: HTTPConnect, Name: "HTTP CONNECT abuse", HelpName: "HTTP CONNECT",
			Confidence: "MEDIUM", Reason: "TCP/443 or TCP/8080 open", Risk: "Transparent proxy needed",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.HTTP443Open || signals.HTTP8080Open
		},
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "HTTP CONNECT tunnel via gateway proxy",
			Remediation: "Block HTTP CONNECT method for unauthenticated clients. Restrict proxy to whitelisted destinations only.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 6, ID: MACCloneIdle, Name: "MAC clone (idle)", HelpName: "MAC clone idle",
			Confidence: "HIGH", Reason: "Always possible", Risk: "MAC change visible",
		},
		feasible: func(BypassTechniqueSignals) bool { return true },
		success: BypassTechniqueResultMetadata{
			Severity:    "critical",
			Impact:      "Full internet by cloning an authenticated device MAC",
			Remediation: "Use 802.1X. Enable client isolation. Bind sessions to MAC+IP+DHCP lease. Detect duplicate MACs.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 7, ID: MACClone, Name: "MAC clone (any)", HelpName: "MAC clone any",
			Confidence: "HIGH", Reason: "Always possible", Risk: "Disconnects victim",
		},
		feasible: func(BypassTechniqueSignals) bool { return true },
		success: BypassTechniqueResultMetadata{
			Severity:    "critical",
			Impact:      "Full internet by cloning an authenticated device MAC",
			Remediation: "Use 802.1X. Enable client isolation. Bind sessions to MAC+IP+DHCP lease. Detect duplicate MACs.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 8, ID: DNSTunnel, Name: "DNS tunnel", HelpName: "DNS tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "DNS UDP/53 open", Risk: "Needs DNS tunnel server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.DNSOpen },
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "Internet via DNS tunnel (50-500 Kbps)",
			Remediation: "Restrict DNS to portal resolvers. Block UDP/53 to external IPs. Inspect DNS for tunnel signatures.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 9, ID: ICMPTunnel, Name: "ICMP tunnel", HelpName: "ICMP tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "ICMP open to external", Risk: "Needs ICMP tunnel server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.ICMPOpen },
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "Internet via ICMP tunnel (100-300 Kbps)",
			Remediation: "Block/rate-limit ICMP to external hosts. Allow only to gateway.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 10, ID: VPNPort53, Name: "VPN on port 53", HelpName: "VPN port 53",
			RequiresServer: true, Confidence: "MEDIUM", Reason: "UDP/53 open", Risk: "Needs VPN server on 53",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.DNSOpen },
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "Full internet via WireGuard VPN on port 53",
			Remediation: "Inspect UDP/53 traffic. Block non-DNS payloads on port 53. Use DNS response validation.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 11, ID: WhitelistDomain, Name: "Whitelist domain abuse", HelpName: "Whitelist",
			RequiresServer: true, Confidence: "LOW", Reason: "Whitelisted domains found", Risk: "Needs endpoint on whitelisted domain",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.WhitelistReachable },
		finding: BypassTechniqueResultMetadata{
			Severity:    "medium",
			Remediation: "Minimize whitelisted domains. Block WebSocket/tunneling on whitelisted destinations.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 12, ID: SessionReplay, Name: "Session cookie replay", HelpName: "Session cookie",
			Confidence: "LOW", Reason: "Requires traffic capture", Risk: "Needs monitor mode",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.PortalDetected },
		finding: BypassTechniqueResultMetadata{
			Severity:    "high",
			Remediation: "Serve captive portal exclusively over HTTPS. Set Secure flag on all cookies.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 13, ID: PortalCreds, Name: "Portal default credentials", HelpName: "Portal creds",
			Confidence: "LOW", Reason: "Try common passwords", Risk: "Rate-limited by portal",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.PortalDetected },
		success: BypassTechniqueResultMetadata{
			Severity:    "critical",
			Impact:      "Portal admin access with default credentials",
			Remediation: "Change default admin credentials. Restrict management interface to wired/VLAN access. Require MFA for admin.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 14, ID: MACRotate, Name: "MAC rotate", HelpName: "MAC rotate",
			Confidence: "MEDIUM", Reason: "Always possible", Risk: "MAC change visible",
		},
		feasible: func(BypassTechniqueSignals) bool { return true },
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "Internet with fresh MAC -- portal auto-approves new devices",
			Remediation: "Require explicit authentication for all new devices. Don't auto-approve.",
		},
		finding: BypassTechniqueResultMetadata{
			Severity:    "medium",
			Remediation: "Portal correctly requires auth for new devices. Time/quota bypass still possible by re-authenticating with new MAC.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 15, ID: DHCPRotate, Name: "DHCP rotate", HelpName: "DHCP rotate",
			Confidence: "MEDIUM", Reason: "Always possible", Risk: "New IP lease",
		},
		feasible: func(BypassTechniqueSignals) bool { return true },
		success: BypassTechniqueResultMetadata{
			Severity:    "medium",
			Impact:      "Internet after DHCP renewal -- portal tracked by IP, not MAC",
			Remediation: "Track sessions by MAC+IP. Don't rely on IP alone for portal state.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 16, ID: QUICTunnel, Name: "QUIC tunnel", HelpName: "QUIC tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "UDP/443 open", Risk: "Needs Hysteria2 server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.QUICOpen },
		success: BypassTechniqueResultMetadata{
			Severity:    "critical",
			Impact:      "Full internet via QUIC tunnel (UDP/443 -- looks like HTTP/3)",
			Remediation: "Inspect UDP/443 traffic. Block non-HTTP/3 QUIC connections for unauthenticated clients. Deploy QUIC-aware DPI.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 17, ID: CFWorkers, Name: "Cloudflare Workers proxy", HelpName: "CF Workers",
			RequiresServer: true, Confidence: "MEDIUM", Reason: "HTTPS open to Cloudflare", Risk: "Free CF account required",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.CloudflareOpen },
		success: BypassTechniqueResultMetadata{
			Severity:    "critical",
			Impact:      "Full internet via Cloudflare Workers proxy (serverless, free, no server needed)",
			Remediation: "Block access to *.workers.dev domains. Inspect HTTPS traffic to Cloudflare for proxy patterns. Consider blocking unknown Cloudflare subdomains.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 18, ID: NTPTunnel, Name: "NTP tunnel", HelpName: "NTP tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "NTP open", Risk: "Needs NTP tunnel server",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.NTPOpen },
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "Internet via NTP tunnel (UDP/123, ~1-10 Kbps -- slow but stealthy)",
			Remediation: "Restrict NTP to known time servers only. Inspect NTP packets for abnormal extension fields or payload sizes. Rate-limit NTP traffic per client.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 19, ID: DoHTunnel, Name: "DoH tunnel", HelpName: "DoH tunnel",
			RequiresServer: true, Confidence: "MEDIUM", Reason: "DoH reachable", Risk: "DNS-over-HTTPS channel",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.DoHOpen },
		success: BypassTechniqueResultMetadata{
			Severity:    "high",
			Impact:      "DNS resolution via encrypted DoH (enables further tunneling)",
			Remediation: "Block DoH endpoints (cloudflare-dns.com, dns.google) for unauthenticated clients. Deploy DoH-aware filtering.",
		},
	},
	// Wave 20: Modern portal/transport techniques discovered 2026-04 on KLM Thales portal.
	{
		info: BypassTechniqueInfo{
			Number: 20, ID: CAPPORTExtend, Name: "CAPPORT session extend", HelpName: "CAPPORT extend",
			Confidence: "HIGH", Reason: "RFC 8908 API advertises can-extend-session", Risk: "None -- uses legitimate API",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.CAPPORTAvailable && signals.CAPPORTExtendable
		},
		success: BypassTechniqueResultMetadata{
			Severity: "low",
			// Not a bypass -- it's the LEGITIMATE API contract. Prevents re-auth loops
			// and lost connectivity on providers like KLM/Thales with 54-minute leases.
			Impact:      "Extend paid session without re-login. Legitimate use of RFC 8908 API.",
			Remediation: "Not a vulnerability -- RFC 8908 intended behavior. Ensure session limits enforced server-side.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 21, ID: DoQTunnel, Name: "DoQ tunnel", HelpName: "DoQ tunnel",
			RequiresServer: true, Confidence: "MEDIUM", Reason: "DNS-over-QUIC reachable", Risk: "Needs DoQ endpoint",
		},
		feasible: func(signals BypassTechniqueSignals) bool { return signals.DoQOpen },
		success: BypassTechniqueResultMetadata{
			Severity: "high",
			Impact:   "DNS tunneling via DoQ (UDP/853 or UDP/443). Less commonly filtered than DoH.",
			Remediation: "Block DoQ endpoints (dns.adguard.com:853, dns.google QUIC). Deploy QUIC-aware DPI. " +
				"Note: DoQ traffic is indistinguishable from HTTP/3 without deep inspection.",
		},
	},
	{
		info: BypassTechniqueInfo{
			Number: 22, ID: HTTP3Tunnel, Name: "HTTP/3 tunnel (QUIC Alt-Svc)", HelpName: "HTTP/3 tunnel",
			RequiresServer: true, Confidence: "HIGH", Reason: "HTTP/3 UDP/443 reachable", Risk: "Needs HTTP/3-capable endpoint",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.HTTP3Open && signals.QUICOpen
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full internet via HTTP/3 to Alt-Svc-advertised endpoints. " +
				"Bypasses TCP-only middleboxes and portal filters focused on TCP/443.",
			Remediation: "Deploy QUIC-aware inspection. Block UDP/443 to untrusted destinations for " +
				"unauthenticated clients. Inspect Alt-Svc headers for rogue endpoints.",
		},
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

// SuccessResultMetadataByID returns the canonical success metadata for one
// technique when that technique has a user-facing success contract.
func SuccessResultMetadataByID(id ID) (BypassTechniqueResultMetadata, bool) {
	for _, spec := range bypassTechniqueSpecs {
		if spec.info.ID == id {
			return spec.success, !spec.success.isZero()
		}
	}
	return BypassTechniqueResultMetadata{}, false
}

// FindingResultMetadataByID returns the canonical severity metadata for
// techniques that still surface a meaningful non-success finding.
func FindingResultMetadataByID(id ID) (BypassTechniqueResultMetadata, bool) {
	for _, spec := range bypassTechniqueSpecs {
		if spec.info.ID == id {
			return spec.finding, !spec.finding.isZero()
		}
	}
	return BypassTechniqueResultMetadata{}, false
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
