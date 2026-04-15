// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package inflight provides airline WiFi portal intelligence profiles.
//
// It contains a curated database of inflight connectivity providers and
// their known portal characteristics, enabling nowifi to auto-detect the
// airline/provider and optimize bypass technique ordering.
//
// Major inflight connectivity providers (2026):
//   - Panasonic Avionics (eXConnect): Finnair, Emirates, Singapore Airlines, Cathay Pacific, Qatar
//   - Gogo: American Airlines, Delta (domestic), Alaska Airlines, Air Canada
//   - Viasat: Delta (international), JetBlue, United (some fleet)
//   - Inmarsat GX Aviation: Lufthansa, British Airways, Norwegian
//   - Thales InFlyt (FlytLIVE): Air France, KLM, SAS, Turkish Airlines
//   - SITA OnAir: Older European carriers
//   - Anuvu (Global Eagle): Budget carriers
//
// Note: Boingo is omitted as it primarily operates ground hotspots, not inflight.
package inflight

import "strings"

// Provider identifies an inflight connectivity provider.
type Provider string

const (
	Panasonic Provider = "panasonic_avionics"
	Gogo      Provider = "gogo_inflight"
	Viasat    Provider = "viasat_inflight"
	Inmarsat  Provider = "inmarsat_gx"
	Thales    Provider = "thales_inflyt"
	SITA      Provider = "sita_onair"
	Anuvu     Provider = "anuvu_inflight"
	Unknown   Provider = "unknown"
)

// LinkType describes the satellite/radio link technology.
type LinkType string

const (
	KuBand      LinkType = "ku_band"      // Satellite Ku-band, RTT 500-700ms
	KaBand      LinkType = "ka_band"      // Satellite Ka-band, RTT 500-700ms
	GX          LinkType = "gx"           // Inmarsat Global Xpress, RTT 600-800ms
	AirToGround LinkType = "air_to_ground" // Gogo ATG, RTT 100-200ms
	LEO         LinkType = "leo"          // Starlink/OneWeb, RTT 25-60ms
)

// PortalProfile describes a known inflight WiFi portal configuration.
type PortalProfile struct {
	Provider    Provider `json:"provider"`
	Name        string   `json:"name"`
	Description string   `json:"description"`

	// Detection fingerprints.
	GatewayOUI    []string `json:"gateway_oui"`    // MAC OUI prefixes for gateway
	DNSPatterns   []string `json:"dns_patterns"`    // Patterns in DNS search domain
	PortalDomains []string `json:"portal_domains"`  // Known portal hostnames
	HTMLMarkers   []string `json:"html_markers"`    // Strings in portal HTML
	HeaderMarkers []string `json:"header_markers"`  // Strings in HTTP headers

	// Network characteristics.
	LinkTypes    []LinkType `json:"link_types"`
	TypicalRTTMs int        `json:"typical_rtt_ms"` // Expected RTT in milliseconds

	// Portal characteristics.
	PortalType   string `json:"portal_type"`   // "spa", "redirect", "walled_garden"
	GatewayStack string `json:"gateway_stack"` // "kong", "nginx", "apache", "custom"

	// Known whitelist domains (accessible without paying).
	WhitelistDomains []string `json:"whitelist_domains"`

	// Free tier available? Some airlines offer free messaging.
	HasFreeTier     bool     `json:"has_free_tier"`
	FreeTierDomains []string `json:"free_tier_domains,omitempty"`

	// Technique effectiveness (ordered best-first for this provider).
	// These are the bypass.Method string values.
	RecommendedOrder []string `json:"recommended_order"`

	// Techniques known NOT to work on this provider.
	IneffectiveTechniques []string `json:"ineffective_techniques"`

	// Airlines known to use this provider.
	Airlines []string `json:"airlines"`
}

// Profiles is the curated database of inflight WiFi portal profiles.
var Profiles = map[Provider]PortalProfile{
	Panasonic: {
		Provider:    Panasonic,
		Name:        "Panasonic Avionics eXConnect",
		Description: "Most widely deployed IFE+connectivity system. Kong API gateway, SPA portal, satellite Ku/Ka-band.",
		GatewayOUI:  []string{"00:A0:BC"},
		DNSPatterns: []string{"nordic-sky", "panasonic.aero"},
		PortalDomains: []string{
			"www.nordic-sky.finnair.com",
			"portal.panasonic.aero",
		},
		HTMLMarkers:   []string{"portal-loader.js", "portal-versions.json", "pax-api-service", "fwp"},
		HeaderMarkers: []string{"kong/", "x-kong-upstream-latency", "x-kong-proxy-latency"},
		LinkTypes:     []LinkType{KuBand, KaBand},
		TypicalRTTMs:  700,
		PortalType:    "spa",
		GatewayStack:  "kong",
		WhitelistDomains: []string{
			"finnair.com", "*.finnair.com",
			"panasonic.aero", "*.panasonic.aero",
			"stripe.com", "js.stripe.com",
		},
		HasFreeTier: false,
		RecommendedOrder: []string{
			"mac_clone_idle",      // 17 paid devices visible, high success
			"mac_clone",           // Fallback: any device
			"dns_tunnel",          // DNS always passes for portal redirect
			"doh_tunnel",          // Cloudflare-dns.com likely whitelisted
			"ntp_tunnel",          // UDP/123 almost never filtered
			"quic_tunnel",         // UDP/443 often passes
			"cf_workers_proxy",    // Cloudflare domains may be whitelisted
			"cna_useragent_spoof", // Worth trying, zero cost
			"mac_rotate",          // Fresh session
		},
		IneffectiveTechniques: []string{
			"ipv6_bypass",          // No global IPv6 on inflight networks
			"portal_default_creds", // Kong is not a consumer router
			"http_connect_abuse",   // Kong doesn't expose transparent proxy
		},
		Airlines: []string{
			"Finnair", "Emirates", "Singapore Airlines", "Cathay Pacific",
			"Qatar Airways", "Etihad", "ANA", "JAL", "Virgin Atlantic",
			"Iberia", "LATAM", "Air China", "Garuda Indonesia",
		},
	},
	Gogo: {
		Provider:    Gogo,
		Name:        "Gogo Inflight Internet",
		Description: "Dominant US domestic provider. Air-to-ground (ATG) + satellite. Lower latency than pure satellite.",
		GatewayOUI:  []string{"00:25:2F", "00:26:44"},
		DNSPatterns: []string{"gogoinflight", "gogo.aero"},
		PortalDomains: []string{
			"airborne.gogoinflight.com",
			"buy.gogoinflight.com",
			"www.gogoinflight.com",
		},
		HTMLMarkers:   []string{"gogo", "gogoinflight", "gogo-portal", "Gogo LLC"},
		HeaderMarkers: []string{"Gogo"},
		LinkTypes:     []LinkType{AirToGround, KuBand},
		TypicalRTTMs:  150, // ATG is much faster than satellite
		PortalType:    "redirect",
		GatewayStack:  "custom",
		WhitelistDomains: []string{
			"gogoinflight.com",
			"aa.com", "delta.com", "united.com",
			"imessage.apple.com", "push.apple.com",
			"t-mobile.com",
		},
		HasFreeTier:     true,
		FreeTierDomains: []string{"imessage.apple.com", "push.apple.com", "t-mobile.com"},
		RecommendedOrder: []string{
			"mac_clone_idle",
			"mac_clone",
			"cna_useragent_spoof",
			"js_only_bypass",
			"dns_tunnel",
			"chisel_tunnel",
			"vpn_port_53",
			"mac_rotate",
		},
		IneffectiveTechniques: []string{
			"ipv6_bypass",
		},
		Airlines: []string{
			"American Airlines", "Delta Air Lines (domestic)", "Alaska Airlines",
			"Air Canada", "Japan Airlines (domestic)",
		},
	},
	Viasat: {
		Provider:    Viasat,
		Name:        "Viasat Inflight WiFi",
		Description: "High-throughput Ka-band satellite. Known for offering free WiFi on JetBlue and some Delta international.",
		GatewayOUI:  []string{},
		DNSPatterns: []string{"viasat", "row44", "exede"},
		PortalDomains: []string{
			"wifi.viasat.com",
			"portal.viasat.com",
		},
		HTMLMarkers:   []string{"viasat", "row44"},
		HeaderMarkers: []string{"Viasat"},
		LinkTypes:     []LinkType{KaBand},
		TypicalRTTMs:  600,
		PortalType:    "redirect",
		GatewayStack:  "nginx",
		WhitelistDomains: []string{
			"viasat.com", "*.viasat.com",
			"delta.com", "jetblue.com", "united.com",
		},
		HasFreeTier:     true, // JetBlue offers free WiFi via Viasat
		FreeTierDomains: []string{"jetblue.com"},
		RecommendedOrder: []string{
			"mac_clone_idle",
			"mac_clone",
			"dns_tunnel",
			"doh_tunnel",
			"cna_useragent_spoof",
			"quic_tunnel",
			"ntp_tunnel",
		},
		IneffectiveTechniques: []string{"ipv6_bypass"},
		Airlines: []string{
			"JetBlue", "Delta Air Lines (international)", "United Airlines (some fleet)",
			"EasyJet", "Icelandair", "El Al",
		},
	},
	Inmarsat: {
		Provider:    Inmarsat,
		Name:        "Inmarsat GX Aviation (European Aviation Network)",
		Description: "GX Ka-band satellite + EAN hybrid. Used by major European carriers.",
		GatewayOUI:  []string{},
		DNSPatterns: []string{"inmarsat", "gx-aviation"},
		PortalDomains: []string{
			"portal.inmarsat.com",
			"wifi.lufthansa.com",
		},
		HTMLMarkers:   []string{"inmarsat", "gx-aviation", "FlyNet"},
		HeaderMarkers: []string{"Inmarsat"},
		LinkTypes:     []LinkType{GX, KaBand},
		TypicalRTTMs:  700,
		PortalType:    "redirect",
		GatewayStack:  "nginx",
		WhitelistDomains: []string{
			"lufthansa.com", "*.lufthansa.com",
			"britishairways.com",
		},
		HasFreeTier:     true, // Lufthansa offers free messaging
		FreeTierDomains: []string{"whatsapp.com", "imessage.apple.com"},
		RecommendedOrder: []string{
			"mac_clone_idle",
			"mac_clone",
			"dns_tunnel",
			"ntp_tunnel",
			"chisel_tunnel",
			"cna_useragent_spoof",
		},
		IneffectiveTechniques: []string{"ipv6_bypass"},
		Airlines: []string{
			"Lufthansa", "British Airways", "Norwegian Air Shuttle",
			"Cathay Pacific (some routes)", "Aer Lingus",
		},
	},
	Thales: {
		Provider:    Thales,
		Name:        "Thales InFlyt Experience (FlytLIVE / TopConnect)",
		Description: "Major European IFE provider. Used by Air France-KLM group and SAS.",
		GatewayOUI:  []string{},
		DNSPatterns: []string{"inflyt", "flytlive", "topconnect", "thales", "aircon", "afklm"},
		PortalDomains: []string{
			"wifi.airfrance.com",
			"wifi.klm.com",
			"connect.klm.com", // KLM onboard portal (observed in-flight 2026-04, KLM)
			"portal.inflyt.com",
		},
		// Search domain often exposed via DHCP: "connect.klm.com" seen on KLM 172.19.0.0/23
		HTMLMarkers:   []string{"inflyt", "thales", "flytlive", "topconnect", "onboard portal", "afklm"},
		// AFKLM AIRCON HUB: unique KLM onboard portal Server header (observed 2026-04).
		// Note: Kong gateway is NOT used as a marker here — it overlaps with Panasonic.
		HeaderMarkers: []string{"Thales", "AFKLM AIRCON HUB"},
		LinkTypes:     []LinkType{KaBand, KuBand},
		// Measured RTT on KLM flight 2026-04: min 604ms, avg 842ms, max 1283ms.
		// Upstream 650ms was low — true average is ~850ms with satellite jitter.
		TypicalRTTMs: 850,
		PortalType:   "spa",
		// Observed on KLM: Kong 3.3.1 fronting nginx backend. Panasonic also uses Kong,
		// so detection relies on AFKLM AIRCON HUB marker, not gateway stack alone.
		GatewayStack: "kong+nginx",
		WhitelistDomains: []string{
			"airfrance.com", "klm.com",
			"flysas.com",
		},
		HasFreeTier:     true,
		FreeTierDomains: []string{"whatsapp.com"},
		RecommendedOrder: []string{
			"mac_clone_idle",
			"mac_clone",
			"dns_tunnel",
			"doh_tunnel",
			"ntp_tunnel",
			"js_only_bypass",
			"cna_useragent_spoof",
		},
		IneffectiveTechniques: []string{"ipv6_bypass", "portal_default_creds"},
		Airlines: []string{
			"Air France", "KLM", "SAS", "Turkish Airlines",
			"Korean Air", "Vietnam Airlines", "Saudia",
		},
	},
	SITA: {
		Provider:    SITA,
		Name:        "SITA OnAir",
		Description: "Legacy European provider, being replaced by newer systems.",
		GatewayOUI:  []string{},
		DNSPatterns: []string{"sita.aero", "onair.aero"},
		PortalDomains: []string{
			"portal.onair.aero",
		},
		HTMLMarkers:   []string{"sita", "onair"},
		HeaderMarkers: []string{"SITA"},
		LinkTypes:     []LinkType{KuBand},
		TypicalRTTMs:  800,
		PortalType:    "redirect",
		GatewayStack:  "custom",
		WhitelistDomains: []string{},
		HasFreeTier:     false,
		RecommendedOrder: []string{
			"mac_clone_idle",
			"mac_clone",
			"dns_tunnel",
			"cna_useragent_spoof",
			"ntp_tunnel",
		},
		IneffectiveTechniques: []string{"ipv6_bypass"},
		Airlines: []string{
			"Various legacy carriers",
		},
	},
	Anuvu: {
		Provider:    Anuvu,
		Name:        "Anuvu (formerly Global Eagle)",
		Description: "Budget carrier provider. Simpler portals, potentially more bypasses.",
		GatewayOUI:  []string{},
		DNSPatterns: []string{"anuvu", "global-eagle"},
		PortalDomains: []string{
			"portal.anuvu.com",
		},
		HTMLMarkers:   []string{"anuvu", "global-eagle"},
		HeaderMarkers: nil,
		LinkTypes:     []LinkType{KuBand},
		TypicalRTTMs:  750,
		PortalType:    "redirect",
		GatewayStack:  "nginx",
		WhitelistDomains: []string{},
		HasFreeTier:     false,
		RecommendedOrder: []string{
			"mac_clone_idle",
			"mac_clone",
			"dns_tunnel",
			"portal_default_creds", // Budget portals more likely to have defaults
			"cna_useragent_spoof",
			"js_only_bypass",
		},
		IneffectiveTechniques: []string{"ipv6_bypass"},
		Airlines: []string{
			"Southwest Airlines", "Ryanair (some fleet)", "WOW air",
		},
	},
}

// DetectProvider identifies the inflight connectivity provider from
// available network signals.
func DetectProvider(gatewayMAC, dnsSearchDomain, portalHTML string, httpHeaders map[string]string) Provider {
	gatewayMAC = strings.ToUpper(gatewayMAC)
	dnsLower := strings.ToLower(dnsSearchDomain)
	htmlLower := strings.ToLower(portalHTML)

	for provider, profile := range Profiles {
		// Check gateway OUI.
		for _, oui := range profile.GatewayOUI {
			if strings.HasPrefix(gatewayMAC, strings.ToUpper(strings.ReplaceAll(oui, ":", ""))) ||
				strings.HasPrefix(gatewayMAC, oui) {
				return provider
			}
		}

		// Check DNS patterns.
		for _, pattern := range profile.DNSPatterns {
			if strings.Contains(dnsLower, pattern) {
				return provider
			}
		}

		// Check portal HTML markers.
		for _, marker := range profile.HTMLMarkers {
			if strings.Contains(htmlLower, strings.ToLower(marker)) {
				return provider
			}
		}

		// Check HTTP headers.
		for headerKey, headerVal := range httpHeaders {
			combined := strings.ToLower(headerKey + ": " + headerVal)
			for _, marker := range profile.HeaderMarkers {
				if strings.Contains(combined, strings.ToLower(marker)) {
					return provider
				}
			}
		}
	}

	return Unknown
}

// GetProfile returns the profile for a given provider, or nil if unknown.
func GetProfile(provider Provider) *PortalProfile {
	if p, ok := Profiles[provider]; ok {
		return &p
	}
	return nil
}

// AllAirlines returns a flat list of all known airlines and their providers.
func AllAirlines() map[string]Provider {
	result := make(map[string]Provider)
	for provider, profile := range Profiles {
		for _, airline := range profile.Airlines {
			result[airline] = provider
		}
	}
	return result
}
