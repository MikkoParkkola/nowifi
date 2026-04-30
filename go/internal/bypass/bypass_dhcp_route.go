// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// ---------------------------------------------------------------------------
// Wave 21 #23 — DHCP Option 121 static-route bypass (CVE-2024-3661 primitive).
//
// Some captive-portal gateways enforce policy only in the default-route chain
// (iptables PREROUTING / pf rdr rules tied to the default gateway's interface
// and subnet). An RFC 3442 option-121 classless static route advertised via
// DHCP can install a *second* path to the outside world, one that the portal
// filter chain doesn't cover.
//
// We don't spoof DHCP here — we just honor what the network itself advertised.
// When the DHCP lease already includes a non-default option-121 route, we:
//
//  1. Pick the narrowest non-default route (least likely to disrupt the user).
//  2. Install it via platform.AddRoute.
//  3. Probe internet access (HTTP 204 to gstatic) through the new path.
//  4. Leave the route in place on success; guard package cleanup removes it
//     on exit. Roll back on failure so we never leave the user worse off.
//
// The technique only triggers when Config.DHCPClasslessRoutes contains at
// least one non-default entry, populated by the audit pipeline via
// platform.GetDHCPClasslessRoutes(iface). There is no active DHCP spoofing.
// ---------------------------------------------------------------------------

// dhcpRouteVerifyURL is the connectivity-check URL. Overridable by tests.
var dhcpRouteVerifyURL = "http://connectivitycheck.gstatic.com/generate_204"

// platformAddRoute / platformDeleteRoute are package-level indirections so
// tests can inject stubs without mocking the whole platform package.
var (
	platformAddRoute    = platform.AddRoute
	platformDeleteRoute = platform.DeleteRoute
)

// tryDHCPRouteBypass attempts the Wave 21 #23 technique. Returns a Result
// with Success=true iff a non-default route was added and gstatic/generate_204
// returns 204 afterwards.
func tryDHCPRouteBypass(config *Config, _ *ProbeResults) Result {
	if config == nil || len(config.DHCPClasslessRoutes) == 0 {
		return Result{
			Method:  DHCPRouteBypass,
			Success: false,
			Details: "DHCP option 121 not advertised on this network.",
		}
	}

	candidates := filterNonDefaultRoutes(config.DHCPClasslessRoutes)
	if len(candidates) == 0 {
		return Result{
			Method:  DHCPRouteBypass,
			Success: false,
			Details: "DHCP option 121 present but only default route advertised (no bypass primitive).",
		}
	}

	// Try candidates narrowest-first (highest prefix length). Narrower routes
	// are safer: they affect less of the user's traffic if the gateway
	// doesn't actually provide internet.
	candidates = sortByPrefixDesc(candidates)

	var attempts []string
	for _, route := range candidates {
		attempts = append(attempts, fmt.Sprintf("%s via %s", route.CIDR, route.Gateway))
		if err := platformAddRoute(route.CIDR, route.Gateway); err != nil {
			continue
		}

		if dhcpRouteInternetReachable() {
			return successResult(
				DHCPRouteBypass,
				fmt.Sprintf("DHCP-advertised route %s via %s bypasses portal filter. "+
					"Internet reachable via this path without authentication.",
					route.CIDR, route.Gateway),
			)
		}

		// No internet via this route -- roll back before trying next.
		_ = platformDeleteRoute(route.CIDR)
	}

	return Result{
		Method:  DHCPRouteBypass,
		Success: false,
		Details: "Tried " + strings.Join(attempts, ", ") + " — none provided external connectivity.",
	}
}

// filterNonDefaultRoutes drops the default route (0.0.0.0/0) which the system
// already uses; only narrower routes can give a bypass primitive.
func filterNonDefaultRoutes(in []platform.DHCPRoute) []platform.DHCPRoute {
	out := make([]platform.DHCPRoute, 0, len(in))
	for _, r := range in {
		if r.IsDefault() || r.Gateway == "" || r.CIDR == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(r.CIDR); err != nil {
			continue
		}
		if net.ParseIP(r.Gateway) == nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

// sortByPrefixDesc returns routes ordered by prefix length descending
// (most-specific first).
func sortByPrefixDesc(in []platform.DHCPRoute) []platform.DHCPRoute {
	out := make([]platform.DHCPRoute, len(in))
	copy(out, in)
	// Simple insertion sort; expected len <= ~8.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && prefixLen(out[j]) > prefixLen(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func prefixLen(r platform.DHCPRoute) int {
	_, n, err := net.ParseCIDR(r.CIDR)
	if err != nil {
		return 0
	}
	ones, _ := n.Mask.Size()
	return ones
}

// dhcpRouteInternetReachable hits the Google captive-portal check URL and
// reports whether it returns HTTP 204 within a short deadline. After a 204
// hit it confirms via the captive-resistant quorum verifier (issue #31),
// rejecting whitelist false positives where the gateway answers 204
// without actually opening the firewall to the rest of the public
// internet.
func dhcpRouteInternetReachable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dhcpRouteVerifyURL, nil)
	if err != nil {
		return false
	}
	resp, err := internetCheckClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 204 {
		return false
	}
	if internetCheckURL != "" || !internetVerifyEnabled {
		// Legacy test mode — see confirmInternetAfterTechnique.
		return true
	}
	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), internetVerifyTimeout)
	defer verifyCancel()
	return verifyInternetReachable(verifyCtx, nil)
}
