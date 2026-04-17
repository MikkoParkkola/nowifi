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
	// Wave 21: Serverless, infrastructure-native techniques (2026-04).
	DHCPRouteBypass ID = "dhcp_route_bypass" //nolint:gosec // G101 false positive on "bypass"; not a credential. CVE-2024-3661 TunnelVision.
	ECHFronting          ID = "ech_fronting"           // TLS 1.3 Encrypted Client Hello SNI concealment
	SecondaryIfaceBypass ID = "secondary_iface_bypass" //nolint:gosec // G101 false positive; not a credential.
	WGOverWebSocket      ID = "wg_over_websocket"
	MASQUETunnel         ID = "masque_tunnel"         // RFC 9298 CONNECT via HTTP/3 Extended CONNECT
	WebTransportTunnel   ID = "webtransport_tunnel"   // RFC 9220 WebTransport over HTTP/3
	// Wave 22: Application-layer smuggling techniques (2026-04).
	H2ConnectTunnel ID = "h2_connect_tunnel" // HTTP/2 CONNECT via gRPC-style framing
	SSETunnel       ID = "sse_tunnel"        // Server-Sent Events streaming channel
	GRPCTunnel      ID = "grpc_tunnel"       // gRPC bidi streaming via HTTP/2
	ConnectIPTunnel ID = "connect_ip_tunnel" // RFC 9484 IP-layer MASQUE proxy
	WARPTunnel      ID = "warp_tunnel"       // Cloudflare WARP bootstrap (zero-config)
	// Wave 23: Zero-config relay techniques (2026-04).
	PortalRelay ID = "portal_relay" // Tunnel through portal-whitelisted domains
	TURNRelay   ID = "turn_relay"   // Relay through public TURN/STUN servers
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
	// DHCPClasslessRoutesAvailable is true when the DHCP server advertises
	// RFC 3442 option 121 routes AND at least one is non-default. Powers
	// Wave 21 technique #23 (CVE-2024-3661 TunnelVision).
	DHCPClasslessRoutesAvailable bool
	// ECHServerConfigured is true when the user has provided both an ECH
	// server URL and an ECHConfigList (raw or base64). Powers Wave 21 #24.
	ECHServerConfigured bool
	// SecondaryIfaceDetected is true when the device has a non-WiFi network
	// interface (cellular, USB ethernet, Bluetooth tethering) that is up
	// and has an IPv4 address. Powers Wave 21 #25.
	SecondaryIfaceDetected bool
	// WSServerConfigured is true when a WebSocket tunnel server URL is set.
	WSServerConfigured bool
	// MASQUEServerConfigured is true when a MASQUE proxy URL is set.
	MASQUEServerConfigured bool
	// WTServerConfigured is true when a WebTransport tunnel server URL is set.
	WTServerConfigured bool
	// H2ProxyConfigured is true when an HTTP/2 CONNECT proxy URL is set.
	H2ProxyConfigured bool
	// SSEServerConfigured is true when an SSE tunnel relay URL is set.
	SSEServerConfigured bool
	// GRPCServerConfigured is true when a gRPC tunnel server URL is set.
	GRPCServerConfigured bool
	// ConnectIPServerConfigured is true when a CONNECT-IP proxy URL is set.
	ConnectIPServerConfigured bool
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
	// Wave 21 (2026-04): serverless DHCP option 121 route injection.
	// Based on CVE-2024-3661 ("TunnelVision", Leviathan Security 2024-05).
	{
		info: BypassTechniqueInfo{
			Number: 23, ID: DHCPRouteBypass, Name: "DHCP Option 121 route bypass", HelpName: "DHCP route",
			Confidence: "MEDIUM", Reason: "DHCP advertises non-default classless static routes",
			Risk: "Adds kernel routes -- rolls back on failure",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.DHCPClasslessRoutesAvailable
		},
		success: BypassTechniqueResultMetadata{
			Severity: "high",
			Impact: "Full internet via DHCP-advertised routes that bypass portal filtering chains. " +
				"Same primitive as CVE-2024-3661 applied to captive portals.",
			Remediation: "Strip DHCP option 121 on untrusted networks. Enforce captive policy in the " +
				"forwarding plane (netfilter/PF FORWARD chain) rather than only in the default-route " +
				"chain. Alert on DHCP leases advertising non-default static routes.",
		},
	},
	// Wave 21 #24: TLS 1.3 ECH (RFC 9147) Encrypted Client Hello domain fronting.
	{
		info: BypassTechniqueInfo{
			Number: 24, ID: ECHFronting, Name: "ECH domain fronting", HelpName: "ECH fronting",
			RequiresServer: true, Confidence: "HIGH",
			Reason: "ECH config + bypass server URL configured",
			Risk:   "Requires an ECH-capable HTTPS proxy",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.ECHServerConfigured && signals.HTTP443Open
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full internet via TLS 1.3 ECH-cloaked HTTPS tunnel. Outer SNI is " +
				"the CDN cover name; the real target is encrypted and invisible to SNI-based DPI.",
			Remediation: "Deploy ECH-aware TLS inspection or terminate TLS at the network edge. " +
				"Block HTTPS RR DNS queries for known ECH CDNs on untrusted clients. ECH is an IETF " +
				"standard since 2024 and production Cloudflare deployments mean DPI signatures lag.",
		},
	},
	// Wave 21 #25: WireGuard-over-WebSocket.
	{
		info: BypassTechniqueInfo{
			Number: 25, ID: WGOverWebSocket, Name: "WireGuard-over-WebSocket", HelpName: "WG/WS tunnel",
			RequiresServer: true, Confidence: "HIGH",
			Reason: "TCP/443 open + WebSocket upgrade allowed",
			Risk:   "Requires a wstunnel-compatible endpoint",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.WSServerConfigured && signals.HTTP443Open
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full internet via WebSocket tunnel on TCP/443. WS upgrade is " +
				"indistinguishable from Teams/Zoom/Discord — portals that allow WS pass this.",
			Remediation: "Inspect WebSocket frame payloads for non-standard content. Block WS " +
				"upgrades to unknown destinations for unauthenticated clients. Deploy WS-aware DPI.",
		},
	},
	// Wave 21 #26: Secondary interface bypass (cellular/ethernet/tethered).
	{
		info: BypassTechniqueInfo{
			Number: 26, ID: SecondaryIfaceBypass, Name: "Secondary interface bypass", HelpName: "Alt iface",
			Confidence: "HIGH",
			Reason:     "Device has a non-WiFi interface (cellular, USB Ethernet, Bluetooth PAN)",
			Risk:       "None — uses an existing interface that already has internet",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.SecondaryIfaceDetected
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full internet via secondary interface — traffic exits the carrier/ISP network, " +
				"completely bypassing the captive portal gateway. No tunnel, no server, no protocol tricks.",
			Remediation: "Deploy portal enforcement at the device level (MDM), not only at the WiFi gateway. " +
				"Secondary-interface bypass is unfilterable by the captive portal infrastructure.",
		},
	},
	// Wave 21 #27: MASQUE CONNECT via HTTP/3 Extended CONNECT (RFC 9298).
	{
		info: BypassTechniqueInfo{
			Number: 27, ID: MASQUETunnel, Name: "MASQUE tunnel (HTTP/3 Extended CONNECT)", HelpName: "MASQUE tunnel",
			RequiresServer: true, Confidence: "HIGH",
			Reason: "UDP/443 open + MASQUE proxy configured",
			Risk:   "Requires a MASQUE-capable proxy endpoint",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.MASQUEServerConfigured && signals.QUICOpen
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full internet via HTTP/3 Extended CONNECT (RFC 9220/9298). Traffic fingerprint " +
				"matches Apple Private Relay, Cloudflare WARP, and browser WebTransport — no " +
				"commercial captive portal DPI inspects HTTP/3 frame types at this depth.",
			Remediation: "Deploy QUIC-aware DPI that validates HTTP/3 Extended CONNECT targets. " +
				"Block UDP/443 to untrusted destinations for unauthenticated clients. " +
				"Rate-limit QUIC sessions per MAC.",
		},
	},
	// Wave 21 #28: WebTransport tunnel (RFC 9220) over HTTP/3.
	{
		info: BypassTechniqueInfo{
			Number: 28, ID: WebTransportTunnel, Name: "WebTransport tunnel", HelpName: "WebTransport",
			RequiresServer: true, Confidence: "HIGH",
			Reason: "UDP/443 open + WebTransport server configured",
			Risk:   "Requires a WebTransport-capable tunnel endpoint",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.WTServerConfigured && signals.QUICOpen
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full internet via RFC 9220 WebTransport over HTTP/3. Session establishment " +
				"uses CONNECT with :protocol webtransport — identical to Google Meet, Zoom, and " +
				"browser-initiated WebTransport. No commercial DPI distinguishes this from video calls.",
			Remediation: "Inspect WebTransport session targets. Block CONNECT :protocol webtransport " +
				"to untrusted destinations for unauthenticated clients. Deploy HTTP/3-aware DPI.",
		},
	},
	// Wave 22 #29: HTTP/2 CONNECT tunnel (gRPC-style binary framing).
	{
		info: BypassTechniqueInfo{
			Number: 29, ID: H2ConnectTunnel, Name: "HTTP/2 CONNECT tunnel", HelpName: "H2 CONNECT",
			RequiresServer: true, Confidence: "HIGH",
			Reason: "TCP/443 open + HTTP/2 proxy configured",
			Risk:   "Requires an HTTP/2 CONNECT-capable proxy",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.H2ProxyConfigured && signals.HTTP443Open
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full internet via HTTP/2 CONNECT (RFC 9113). Binary framing is opaque to " +
				"HTTP/1.1-only DPI. Traffic is indistinguishable from gRPC health checks or " +
				"Google Cloud API calls. Multiplexed streams share one TLS connection.",
			Remediation: "Deploy HTTP/2-aware DPI that inspects CONNECT method across multiplexed " +
				"streams. Block CONNECT to non-whitelisted targets. Most portals only inspect " +
				"HTTP/1.1 — upgrading to HTTP/2-aware filtering is the primary mitigation.",
		},
	},
	// Wave 22 #30: SSE (Server-Sent Events) streaming covert channel.
	{
		info: BypassTechniqueInfo{
			Number: 30, ID: SSETunnel, Name: "SSE streaming tunnel", HelpName: "SSE tunnel",
			RequiresServer: true, Confidence: "MEDIUM",
			Reason: "HTTPS open + SSE relay configured",
			Risk:   "Asymmetric bandwidth (uplink limited by POST rate)",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.SSEServerConfigured && signals.HTTP443Open
		},
		success: BypassTechniqueResultMetadata{
			Severity: "high",
			Impact: "Internet via SSE downlink + HTTP POST uplink. Downlink is a chunked " +
				"text/event-stream response indistinguishable from a news feed or chat stream. " +
				"Uplink uses standard HTTP POST. Serverless CF Workers variant available.",
			Remediation: "Inspect SSE event payloads for non-text content (base64 data patterns). " +
				"Rate-limit chunked transfer encoding sessions. Enforce response size limits " +
				"for unauthenticated clients — note this may break legitimate streaming apps.",
		},
	},
	// Wave 22 #31: gRPC bidirectional streaming tunnel.
	{
		info: BypassTechniqueInfo{
			Number: 31, ID: GRPCTunnel, Name: "gRPC bidi streaming tunnel", HelpName: "gRPC tunnel",
			RequiresServer: true, Confidence: "MEDIUM",
			Reason: "HTTPS open + gRPC server configured",
			Risk:   "Requires operator-controlled gRPC server",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.GRPCServerConfigured && signals.HTTP443Open
		},
		success: BypassTechniqueResultMetadata{
			Severity: "high",
			Impact: "Internet via gRPC bidi streaming over HTTP/2. Traffic uses " +
				"content-type: application/grpc — indistinguishable from Kubernetes API calls, " +
				"microservice communication, or any cloud gRPC application. " +
				"Proto-less framing: zero dependency weight, identical wire format.",
			Remediation: "Deep-inspect gRPC streams for non-protobuf payloads (raw binary data " +
				"without protobuf wire format). Rate-limit long-lived gRPC streams from " +
				"unauthenticated clients. Note: blocking gRPC breaks legitimate cloud apps.",
		},
	},
	// Wave 22 #32: CONNECT-IP tunnel (RFC 9484).
	{
		info: BypassTechniqueInfo{
			Number: 32, ID: ConnectIPTunnel, Name: "CONNECT-IP tunnel (RFC 9484)", HelpName: "CONNECT-IP",
			RequiresServer: true, Confidence: "HIGH",
			Reason: "QUIC open + CONNECT-IP server configured",
			Risk:   "Requires root for TUN device creation",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.ConnectIPServerConfigured && signals.QUICOpen
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full IP tunnel via TUN device — ALL traffic (TCP, UDP, ICMP, DNS) " +
				"routed through QUIC datagrams. Indistinguishable from Apple Private Relay " +
				"and iCloud+. Most powerful tunnel: not limited to TCP like SOCKS-based techniques.",
			Remediation: "Block QUIC datagrams (UDP/443 with DATAGRAM frames). Inspect HTTP/3 " +
				"Extended CONNECT for :protocol=connect-ip. Note: blocking this also blocks " +
				"Apple Private Relay, iCloud+, and Cloudflare WARP — high collateral damage.",
		},
	},
	// Wave 22 #33: Cloudflare WARP bootstrap — zero-config tunnel.
	{
		info: BypassTechniqueInfo{
			Number: 33, ID: WARPTunnel, Name: "Cloudflare WARP tunnel (zero-config)", HelpName: "WARP tunnel",
			RequiresServer: false, Confidence: "HIGH",
			Reason: "HTTPS open (WARP uses engage.cloudflareclient.com:443)",
			Risk:   "Depends on Cloudflare WARP API availability",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.HTTP443Open
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Zero-config internet via Cloudflare WARP free tier. Auto-registers device, " +
				"connects via HTTP/2 CONNECT to engage.cloudflareclient.com:443. Traffic is " +
				"genuine Cloudflare WARP — identical to 10M+ WARP users. No server to deploy, " +
				"no account needed, no URL to remember.",
			Remediation: "Block engage.cloudflareclient.com — but this also blocks Cloudflare WARP " +
				"for all legitimate users (10M+ devices). Deep-inspect HTTP/2 CONNECT to WARP " +
				"endpoints for unauthenticated portal sessions.",
		},
	},
	// Wave 23 #34: Portal self-relay — tunnel through whitelisted domains.
	{
		info: BypassTechniqueInfo{
			Number: 34, ID: PortalRelay, Name: "Portal self-relay (whitelisted domain)", HelpName: "Portal relay",
			RequiresServer: false, Confidence: "MEDIUM",
			Reason: "Portal whitelists payment/CDN/connectivity-check domains",
			Risk:   "Depends on portal allowing HTTP/2 CONNECT to whitelisted hosts",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.PortalDetected && signals.HTTP443Open
		},
		success: BypassTechniqueResultMetadata{
			Severity: "critical",
			Impact: "Full internet via HTTP/2 CONNECT through portal-whitelisted domain. " +
				"Portal trusts the SNI/DNS (stripe.com, googleapis.com, apple.com) and " +
				"does not inspect the HTTP/2 session. Zero-config — no server deployment needed.",
			Remediation: "Inspect HTTP/2 CONNECT method within TLS sessions to whitelisted domains. " +
				"Use application-layer filtering, not just SNI-based whitelisting. " +
				"Deploy HTTP/2-aware DPI that validates CONNECT targets against whitelist policy.",
		},
	},
	// Wave 23 #35: TURN relay — tunnel through public WebRTC TURN servers.
	{
		info: BypassTechniqueInfo{
			Number: 35, ID: TURNRelay, Name: "TURN relay (public WebRTC servers)", HelpName: "TURN relay",
			RequiresServer: false, Confidence: "MEDIUM",
			Reason: "TURN servers use TCP/443 (indistinguishable from HTTPS)",
			Risk:   "Depends on public TURN server availability and portal not blocking them",
		},
		feasible: func(signals BypassTechniqueSignals) bool {
			return signals.HTTP443Open
		},
		success: BypassTechniqueResultMetadata{
			Severity: "high",
			Impact: "Internet via public TURN server relay (RFC 5766). TURN-over-TLS on TCP/443 " +
				"is indistinguishable from HTTPS to portal DPI. Uses public servers " +
				"(openrelay.metered.ca, relay.metered.ca) — no account needed. " +
				"Bandwidth limited by TURN relay capacity (~1-5 Mbps).",
			Remediation: "Block known TURN server domains/IPs for unauthenticated clients. " +
				"Inspect TLS sessions for STUN/TURN protocol signatures. " +
				"Note: blocking TURN also breaks WebRTC video calls (Zoom, Teams, Meet).",
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
