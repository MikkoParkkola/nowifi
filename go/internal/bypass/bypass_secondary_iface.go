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
)

// ---------------------------------------------------------------------------
// Wave 21 #25 — Secondary interface bypass (cellular/ethernet/tethered).
//
// When the device has a non-WiFi interface (e.g., a cellular modem, a USB
// ethernet adapter, or Bluetooth PAN tethering) with active internet
// connectivity, the captive portal is irrelevant — traffic routed through the
// secondary interface exits the carrier's network, not the portal gateway.
//
// This is the simplest possible bypass: no tunnel, no server, no protocol
// tricks. We just detect and use the interface that already works.
//
// Implementation:
//  1. Enumerate all network interfaces with non-loopback, non-portal IPv4
//     addresses. Exclude the primary WiFi interface (Config.Interface).
//  2. For each candidate: HTTP GET to gstatic/generate_204 through a
//     transport bound to that interface (SO_BINDTODEVICE on Linux,
//     -ifscope routing on macOS). Accept any 204 as "this interface has
//     internet".
//  3. On success, report the working interface and optionally configure a
//     system default route through it.
//
// This technique is always feasible (just depends on hardware) and requires
// zero external infrastructure. It fails if the device has only one NIC
// or if the secondary NIC also lacks internet.
// ---------------------------------------------------------------------------

// secondaryIfaceCheckURL is the connectivity-check URL. Overridable by tests.
var secondaryIfaceCheckURL = "http://connectivitycheck.gstatic.com/generate_204"

func trySecondaryIfaceBypass(config *Config, _ *ProbeResults) Result {
	if config == nil {
		return Result{
			Method:  SecondaryIfaceBypass,
			Success: false,
			Details: "No configuration provided.",
		}
	}

	primaryIface := config.Interface
	if primaryIface == "" {
		primaryIface = "en0"
	}

	candidates := findSecondaryInterfaces(primaryIface)
	if len(candidates) == 0 {
		return Result{
			Method:  SecondaryIfaceBypass,
			Success: false,
			Details: "No secondary network interface detected (only WiFi available).",
		}
	}

	var attempts []string
	for _, iface := range candidates {
		attempts = append(attempts, fmt.Sprintf("%s (%s)", iface.Name, iface.IP))
		if probeInterfaceInternet(iface.Name) {
			return successResult(
				SecondaryIfaceBypass,
				fmt.Sprintf("Internet available via %s (%s). This interface bypasses the "+
					"captive portal entirely — traffic exits via %s, not the WiFi gateway. "+
					"Configure as default route or bind applications to this interface.",
					iface.Name, iface.IP, classifyInterface(iface.Name)),
			)
		}
	}

	return Result{
		Method:  SecondaryIfaceBypass,
		Success: false,
		Details: fmt.Sprintf("Checked %s — none have internet.", strings.Join(attempts, ", ")),
	}
}

type ifaceCandidate struct {
	Name string
	IP   string
}

// findSecondaryInterfaces returns non-loopback, non-primary interfaces that
// have a usable IPv4 address.
func findSecondaryInterfaces(primaryIface string) []ifaceCandidate {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var candidates []ifaceCandidate
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Name == primaryIface {
			continue
		}
		// Skip common virtual/bridge interfaces that are unlikely to be useful.
		if isVirtualInterface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			candidates = append(candidates, ifaceCandidate{
				Name: iface.Name,
				IP:   ip.String(),
			})
			break // one IPv4 per interface is enough
		}
	}
	return candidates
}

// probeInterfaceInternet checks if the named interface has internet by doing
// an HTTP GET to the connectivity-check URL. On supported platforms the
// request is bound to the specific interface; on others it falls back to
// system routing (which may still be useful if the secondary interface is
// the default route).
func probeInterfaceInternet(ifaceName string) bool {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	// Bind to interface where supported. On macOS, Go's net package doesn't
	// support SO_BINDTODEVICE, but we can set the local address from the
	// interface's IP to encourage routing through it.
	if iface, err := net.InterfaceByName(ifaceName); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					if ip := ipNet.IP.To4(); ip != nil && !ip.IsLoopback() {
						dialer.LocalAddr = &net.TCPAddr{IP: ip}
						break
					}
				}
			}
		}
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, secondaryIfaceCheckURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 204 {
		return false
	}
	// Per issue #31: a 204 from gstatic alone is whitelisted on every
	// major captive network. Confirm via the quorum verifier, binding the
	// probes to this interface's local IP so we test THIS NIC's path to
	// the public internet, not the system default route.
	if internetCheckURL != "" || !internetVerifyEnabled {
		// Legacy test mode — see confirmInternetAfterTechnique.
		return true
	}
	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), internetVerifyTimeout)
	defer verifyCancel()
	return verifyInternetReachable(verifyCtx, dialer)
}

// isVirtualInterface returns true for names that indicate a virtual adapter
// (bridges, VPNs, Docker, VMs) rather than a physical secondary NIC.
func isVirtualInterface(name string) bool {
	prefixes := []string{
		"lo",     // loopback
		"br",     // bridge
		"docker", // Docker
		"veth",   // Docker/container veth
		"virbr",  // libvirt bridge
		"vbox",   // VirtualBox
		"vmnet",  // VMware
		"utun",   // macOS userspace tunnels (VPN)
		"ipsec",  // IPsec tunnel
		"gif",    // generic tunnel interface
		"stf",    // 6to4 interface
		"llw",    // low-latency WLAN (macOS — not a separate NIC)
		"awdl",   // Apple Wireless Direct Link (AirDrop)
		"ap",     // access point virtual interface
		"anpi",   // Apple neural processing
	}
	lower := strings.ToLower(name)
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// classifyInterface returns a human-readable description of an interface
// by its name convention (e.g. "cellular modem", "USB Ethernet").
func classifyInterface(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "pdp_ip") || strings.HasPrefix(lower, "rmnet") ||
		strings.HasPrefix(lower, "wwan") || strings.HasPrefix(lower, "ccmni"):
		return "cellular modem"
	case strings.HasPrefix(lower, "en") && !strings.HasPrefix(lower, "en0"):
		return "secondary Ethernet/WiFi adapter"
	case strings.HasPrefix(lower, "eth"):
		return "Ethernet"
	case strings.HasPrefix(lower, "usb"):
		return "USB network adapter"
	case strings.HasPrefix(lower, "bnep") || strings.HasPrefix(lower, "pan"):
		return "Bluetooth PAN tethering"
	default:
		return "secondary interface"
	}
}
