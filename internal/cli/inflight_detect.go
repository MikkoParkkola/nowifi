// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"net/http"
	"strings"

	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/inflight"
	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// detectInflightProvider returns the inflight WiFi provider ID string (or empty
// if unknown) based on portal detection output. The returned string is the
// stringified Provider value suitable for bypass.Config.InflightProvider.
//
// When we can't identify an inflight provider, returns empty string — bypass
// engine falls back to canonical technique ordering.
func detectInflightProvider(portalInfo *detect.PortalInfo) string {
	if portalInfo == nil || !portalInfo.IsCaptive {
		return ""
	}

	// Gather signals for DetectProvider.
	var gatewayMAC string
	if portalInfo.Gateway != "" {
		// Look up the gateway's MAC from the ARP table.
		arpEntries, _ := platform.GetARPTable()
		for _, e := range arpEntries {
			if e.IP == portalInfo.Gateway {
				gatewayMAC = e.MAC
				break
			}
		}
	}

	// DNS search domain isn't easily available without parsing resolv.conf;
	// we rely on portal URL + vendor hint instead.
	dnsDomain := ""

	// Portal HTML: we don't re-fetch here (already fetched by detect). Use
	// the vendor name as a proxy fingerprint.
	portalHTML := portalInfo.Vendor

	// HTTP headers: captured vendor/type as pseudo-header map.
	headers := map[string]string{}
	if portalInfo.Vendor != "" {
		headers["Server"] = portalInfo.Vendor
	}

	// Also try matching portal URL against known inflight portal domains.
	if portalInfo.PortalURL != "" {
		for providerID, profile := range inflight.Profiles {
			for _, domain := range profile.PortalDomains {
				if strings.Contains(strings.ToLower(portalInfo.PortalURL), strings.ToLower(domain)) {
					return string(providerID)
				}
			}
		}
	}

	provider := inflight.DetectProvider(gatewayMAC, dnsDomain, portalHTML, headers)
	if provider == inflight.Unknown {
		return ""
	}
	return string(provider)
}

// Ensure http import isn't dead even if refactors remove headers usage.
var _ = http.Header{}
