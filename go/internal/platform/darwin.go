//go:build darwin

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	networkServiceRE = regexp.MustCompile(`Hardware Port:\s*(.+)`)
	serviceNameRE    = regexp.MustCompile(`^[a-zA-Z0-9 ./_-]+$`)
)

// GetWifiInfo returns the current WiFi connection info on macOS.
//
// Tries, in order: system_profiler (JSON), the legacy airport command,
// networksetup, and finally ifconfig as a last resort.
func GetWifiInfo(iface string) (*WifiInfo, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return nil, fmt.Errorf("wifi info: %w", err)
	}
	// Strategy 1: system_profiler SPAirPortDataType -json
	if info := getWifiInfoSystemProfiler(); info != nil {
		return info, nil
	}

	// Strategy 2: legacy airport -I command
	if info := getWifiInfoAirport(); info != nil {
		return info, nil
	}

	// Strategy 3: networksetup -getairportnetwork
	if info := getWifiInfoNetworksetup(iface); info != nil {
		return info, nil
	}

	// Strategy 3.5: wdutil (requires root, but nowifi often runs as root)
	if info := getWifiInfoWdutil(); info != nil {
		return info, nil
	}

	// Strategy 4: ifconfig (just check if interface is active with an IP)
	if info := getWifiInfoIfconfig(iface); info != nil {
		return info, nil
	}

	return nil, fmt.Errorf("unable to determine WiFi info for %s", iface)
}

// systemProfilerAirPort is the top-level structure returned by system_profiler.
type systemProfilerAirPort struct {
	SPAirPortDataType []spAirPortItem `json:"SPAirPortDataType"`
}

type spAirPortItem struct {
	Interfaces []spAirPortInterface `json:"spairport_airport_interfaces"`
}

type spAirPortInterface struct {
	CurrentNetwork *spCurrentNetwork `json:"spairport_current_network_information"`
}

type spCurrentNetwork struct {
	Name        string      `json:"_name"`
	BSSID       string      `json:"spairport_network_bssid"`
	Channel     interface{} `json:"spairport_network_channel"`
	Security    string      `json:"spairport_security_mode"`
	SignalNoise interface{} `json:"spairport_signal_noise"`
}

func getWifiInfoSystemProfiler() *WifiInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "system_profiler", "SPAirPortDataType", "-json").Output()
	if err != nil {
		return nil
	}

	var data systemProfilerAirPort
	if err := json.Unmarshal(out, &data); err != nil {
		return nil
	}

	for _, item := range data.SPAirPortDataType {
		for _, iface := range item.Interfaces {
			cn := iface.CurrentNetwork
			if cn == nil {
				continue
			}
			ssid := cn.Name
			if ssid == "" || ssid == "<redacted>" {
				// macOS Sequoia+ redacts SSID without Location Services.
				// Try DNS search domain as a hint.
				if hint := ssidFromDNSSearchDomain(); hint != "" {
					ssid = hint + " (from DNS)"
				} else {
					ssid = "<redacted by macOS — enable Location Services in System Settings → Privacy & Security → Location Services for Terminal/iTerm>"
				}
			}
			return &WifiInfo{
				SSID:     ssid,
				BSSID:    cn.BSSID,
				Channel:  fmt.Sprint(cn.Channel),
				Security: cn.Security,
				RSSI:     parseRSSI(cn.SignalNoise),
			}
		}
	}
	return nil
}

// parseRSSI extracts RSSI from system_profiler format like "-64 dBm / -96 dBm".
func parseRSSI(val interface{}) int {
	switch v := val.(type) {
	case float64:
		return int(v)
	case string:
		parts := strings.Fields(v)
		if len(parts) > 0 {
			n, err := strconv.Atoi(parts[0])
			if err == nil {
				return n
			}
		}
	}
	return -99
}

func getWifiInfoAirport() *WifiInfo {
	const airportPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, airportPath, "-I").Output()
	if err != nil {
		return nil
	}

	info := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		info[key] = val
	}

	ssid, ok := info["SSID"]
	if !ok || ssid == "" {
		return nil
	}

	rssi := -99
	if s, ok := info["agrCtlRSSI"]; ok {
		if n, err := strconv.Atoi(s); err == nil {
			rssi = n
		}
	}

	return &WifiInfo{
		SSID:     ssid,
		BSSID:    info["BSSID"],
		Channel:  info["channel"],
		Security: info["link auth"],
		RSSI:     rssi,
	}
}

var networksetupSSIDRE = regexp.MustCompile(`Current Wi-Fi Network:\s*(.+)`)

func getWifiInfoNetworksetup(iface string) *WifiInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "networksetup", "-getairportnetwork", iface).Output()
	if err != nil {
		return nil
	}

	m := networksetupSSIDRE.FindSubmatch(out)
	if m == nil {
		return nil
	}

	return &WifiInfo{
		SSID:     strings.TrimSpace(string(m[1])),
		Security: "unknown",
		RSSI:     -99,
	}
}

var ifconfigInetRE = regexp.MustCompile(`inet\s+(\d+\.\d+\.\d+\.\d+)`)

func getWifiInfoIfconfig(iface string) *WifiInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ifconfig", iface).Output()
	if err != nil {
		return nil
	}

	s := string(out)
	hasIP := ifconfigInetRE.MatchString(s)
	isActive := strings.Contains(s, "status: active")
	if hasIP && isActive {
		return &WifiInfo{
			SSID:     "<redacted>",
			Security: "unknown",
			RSSI:     -99,
		}
	}
	return nil
}

// ssidFromDNSSearchDomain attempts to infer the network name from the DNS
// search domain. On inflight WiFi, this often reveals the airline/portal
// (e.g., "www.nordic-sky.finnair.com" → "Nordic Sky (Finnair)").
//
// This is a best-effort fallback when macOS Sequoia redacts the real SSID.
func ssidFromDNSSearchDomain() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		return ""
	}

	// Extract search domain from scutil output.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "search domain") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		domain := strings.TrimSpace(parts[1])
		if domain == "" || domain == "local" {
			continue
		}

		// Known inflight WiFi domain patterns → friendly names.
		knownPatterns := []struct {
			contains string
			name     string
		}{
			{"nordic-sky.finnair", "Nordic Sky (Finnair)"},
			{"finnair.com", "Finnair WiFi"},
			{"gogoinflight.com", "Gogo Inflight"},
			{"gogo.aero", "Gogo Inflight"},
			{"panasonic.aero", "Panasonic Avionics"},
			{"viasat", "Viasat Inflight"},
			{"inflyt", "Thales InFlyt"},
			{"flytlive", "Thales FlytLIVE"},
			{"inmarsat", "Inmarsat GX"},
			{"sita.aero", "SITA OnAir"},
			{"onair.aero", "SITA OnAir"},
			{"boingo", "Boingo"},
		}

		domainLower := strings.ToLower(domain)
		for _, kp := range knownPatterns {
			if strings.Contains(domainLower, kp.contains) {
				return kp.name
			}
		}

		// Generic: use the domain itself as hint.
		// Strip "www." prefix and trailing dots.
		hint := strings.TrimPrefix(domain, "www.")
		hint = strings.TrimSuffix(hint, ".")
		if hint != "" {
			return hint
		}
	}
	return ""
}

func getWifiInfoWdutil() *WifiInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "wdutil", "info").Output()
	if err != nil {
		return nil
	}

	info := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		info[key] = val
	}

	ssid := info["SSID"]
	if ssid == "" {
		return nil
	}

	rssi := -99
	if s, ok := info["RSSI"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(strings.Split(s, " ")[0])); err == nil {
			rssi = n
		}
	}

	return &WifiInfo{
		SSID:     ssid,
		BSSID:    info["BSSID"],
		Channel:  info["Channel"],
		Security: info["Security"],
		RSSI:     rssi,
	}
}

// GetCurrentMAC returns the current MAC address of the given interface.
func GetCurrentMAC(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get MAC: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ifconfig", iface).Output()
	if err != nil {
		return "", fmt.Errorf("ifconfig %s: %w", iface, err)
	}

	re := regexp.MustCompile(`ether\s+(\S+)`)
	m := re.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("no MAC address found for %s", iface)
	}
	mac, err := normalizeMAC(string(m[1]))
	if err != nil {
		return "", fmt.Errorf("invalid MAC address found for %s: %w", iface, err)
	}
	return mac, nil
}

// SetMAC sets the MAC address on the given interface (requires sudo).
func SetMAC(iface, mac string) error {
	mac, err := ValidateMAC(mac)
	if err != nil {
		return err
	}
	iface, err = ValidateInterface(iface)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "ifconfig", iface, "ether", mac)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set MAC on %s: %w: %s", iface, err, string(out))
	}
	return nil
}

// GetGateway returns the default gateway IP address.
func GetGateway(iface string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("route get default: %w", err)
	}

	re := regexp.MustCompile(`gateway:\s+(\S+)`)
	m := re.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("no gateway found")
	}
	return string(m[1]), nil
}

// GetLocalIP returns the local IPv4 address of the given interface.
func GetLocalIP(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get local IP: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ifconfig", iface).Output()
	if err != nil {
		return "", fmt.Errorf("ifconfig %s: %w", iface, err)
	}

	m := ifconfigInetRE.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("no IPv4 address found for %s", iface)
	}
	return string(m[1]), nil
}

// GetIPv6Address returns the global IPv6 address of the given interface, if any.
func GetIPv6Address(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get IPv6: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ifconfig", iface).Output()
	if err != nil {
		return "", fmt.Errorf("ifconfig %s: %w", iface, err)
	}

	re := regexp.MustCompile(`inet6\s+([0-9a-f:]+)`)
	for _, m := range re.FindAllSubmatch(out, -1) {
		addr := string(m[1])
		if !strings.HasPrefix(addr, "fe80") {
			return addr, nil
		}
	}
	return "", nil
}

// GetARPTable returns all ARP table entries.
func GetARPTable() ([]ArpEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "arp", "-a").Output()
	if err != nil {
		return nil, fmt.Errorf("arp -a: %w", err)
	}

	re := regexp.MustCompile(`\S+\s+\((\S+)\)\s+at\s+(\S+)\s+on\s+(\S+)`)
	return parseArpEntries(string(out), re, 1, 2, 3), nil
}

// RenewDHCP renews the DHCP lease on the given interface (requires sudo).
func RenewDHCP(iface string) error {
	if _, err := ValidateInterface(iface); err != nil {
		return fmt.Errorf("DHCP renew: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "ipconfig", "set", iface, "DHCP")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("DHCP renew on %s: %w: %s", iface, err, string(out))
	}
	return nil
}

// FlushDNS flushes the macOS DNS cache.
func FlushDNS() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Flush the directory service cache.
	_ = exec.CommandContext(ctx, "sudo", "dscacheutil", "-flushcache").Run()

	// Restart mDNSResponder to clear its cache.
	_ = exec.CommandContext(ctx, "sudo", "killall", "-HUP", "mDNSResponder").Run()

	return nil
}

// SetSystemProxy configures a system-wide SOCKS proxy on the given interface.
func SetSystemProxy(iface string, port int) error {
	service, err := resolveNetworkService(iface)
	if err != nil {
		return fmt.Errorf("set proxy: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxy",
		service, "127.0.0.1", strconv.Itoa(port))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set SOCKS proxy on %s: %w: %s", service, err, string(out))
	}

	cmd = exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxystate", service, "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable SOCKS proxy on %s: %w: %s", service, err, string(out))
	}
	return nil
}

// ClearSystemProxy removes the system-wide SOCKS proxy on the given interface.
func ClearSystemProxy(iface string) error {
	service, err := resolveNetworkService(iface)
	if err != nil {
		return fmt.Errorf("clear proxy: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxystate", service, "off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("clear SOCKS proxy on %s: %w: %s", service, err, string(out))
	}
	return nil
}

func resolveNetworkService(iface string) (string, error) {
	iface, err := ValidateInterface(iface)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "networksetup", "-listallhardwareports").Output()
	if err != nil {
		return iface, nil
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "Device: "+iface) || i == 0 {
			continue
		}

		match := networkServiceRE.FindStringSubmatch(lines[i-1])
		if len(match) < 2 {
			continue
		}

		service := strings.TrimSpace(match[1])
		if serviceNameRE.MatchString(service) {
			return service, nil
		}
	}

	return iface, nil
}

// DisconnectWifi turns off WiFi on the given interface.
func DisconnectWifi(iface string) error {
	if _, err := ValidateInterface(iface); err != nil {
		return fmt.Errorf("disconnect wifi: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "networksetup", "-setairportpower", iface, "off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("disconnect WiFi %s: %w: %s", iface, err, string(out))
	}
	return nil
}

// ConnectWifi turns on WiFi on the given interface.
func ConnectWifi(iface string) error {
	if _, err := ValidateInterface(iface); err != nil {
		return fmt.Errorf("connect wifi: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "networksetup", "-setairportpower", iface, "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("connect WiFi %s: %w: %s", iface, err, string(out))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Post-bypass traffic stealth — anti-tethering detection
// ---------------------------------------------------------------------------

// EnableStealth applies traffic normalization to avoid portal detection.
// It adjusts TTL and enables PF rules that normalize outbound traffic.
// Returns a StealthState for later restoration via DisableStealth.
func EnableStealth(iface string) (*StealthState, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return nil, fmt.Errorf("stealth: %w", err)
	}

	state := &StealthState{}

	// 1. Save and set TTL.
	// Default macOS TTL is 64. Set to 65 so after one hop it appears as 64
	// (indistinguishable from a directly-connected device).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "sysctl", "-n", "net.inet.ip.ttl").Output()
	if err == nil {
		if ttl, parseErr := strconv.Atoi(strings.TrimSpace(string(out))); parseErr == nil {
			state.OriginalTTL = ttl
		} else {
			state.OriginalTTL = 64
		}
	} else {
		state.OriginalTTL = 64
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if err := exec.CommandContext(ctx2, "sysctl", "-w", "net.inet.ip.ttl=65").Run(); err != nil {
		return state, fmt.Errorf("failed to set TTL: %w", err)
	}

	// 2. Enable PF rules for traffic normalization.
	// Scrub normalizes fragmented packets and randomizes IP ID,
	// preventing OS fingerprinting via IP ID sequencing.
	pfRules := fmt.Sprintf("scrub out on %s all random-id min-ttl 64 max-mss 1460\n", iface)

	// Write to a temporary anchor file.
	pfFile := "/tmp/nowifi-stealth.conf"
	if err := os.WriteFile(pfFile, []byte(pfRules), 0600); err != nil {
		return state, fmt.Errorf("failed to write PF rules: %w", err)
	}

	// Check if PF is currently enabled.
	ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel3()
	pfStatus, _ := exec.CommandContext(ctx3, "pfctl", "-s", "info").Output()
	state.PFWasEnabled = strings.Contains(string(pfStatus), "Status: Enabled")

	// Load the anchor.
	ctx4, cancel4 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel4()
	if err := exec.CommandContext(ctx4, "pfctl", "-a", "nowifi-stealth", "-f", pfFile).Run(); err != nil {
		return state, fmt.Errorf("failed to load PF rules: %w", err)
	}
	state.PFRulesAdded = true

	// Enable PF if it wasn't already.
	if !state.PFWasEnabled {
		ctx5, cancel5 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel5()
		_ = exec.CommandContext(ctx5, "pfctl", "-e").Run()
	}

	// 3. Set IPv6 hop limit to match (prevents IPv6 TTL leak).
	ctx6, cancel6 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel6()
	_ = exec.CommandContext(ctx6, "sysctl", "-w", "net.inet6.ip6.hlim=65").Run()

	// Cleanup temp file.
	os.Remove(pfFile)

	return state, nil
}

// DisableStealth restores original TTL and removes PF stealth rules.
func DisableStealth(state *StealthState) {
	if state == nil {
		return
	}

	// Restore original TTL.
	if state.OriginalTTL > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "sysctl", "-w",
			fmt.Sprintf("net.inet.ip.ttl=%d", state.OriginalTTL)).Run()
	}

	// Restore IPv6 hop limit.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	_ = exec.CommandContext(ctx2, "sysctl", "-w", "net.inet6.ip6.hlim=64").Run()

	// Remove PF anchor.
	if state.PFRulesAdded {
		ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel3()
		_ = exec.CommandContext(ctx3, "pfctl", "-a", "nowifi-stealth", "-F", "all").Run()

		// Disable PF if we enabled it.
		if !state.PFWasEnabled {
			ctx4, cancel4 := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel4()
			_ = exec.CommandContext(ctx4, "pfctl", "-d").Run()
		}
	}
}

// GetCAPPORTURL returns the RFC 8908 captive-portal API URL advertised
// by DHCP option 114 (RFC 7710). Empty string if the network does not
// advertise CAPPORT.
//
// On macOS, we parse `ipconfig getpacket <iface>` output which exposes
// DHCP option fields including captive_portal_url.
func GetCAPPORTURL(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get capport url: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ipconfig", "getpacket", iface).Output()
	if err != nil {
		return "", fmt.Errorf("ipconfig getpacket: %w", err)
	}

	// Format in DHCP packet output:
	//   captive_portal_url (string): https://connect.klm.com/ach/api/captive-portal
	re := regexp.MustCompile(`captive_portal_url\s*\(string\):\s*(\S+)`)
	m := re.FindSubmatch(out)
	if m == nil {
		return "", nil // Not advertised -- not an error
	}
	return string(m[1]), nil
}

// GetDNSResolvers returns the system's configured DNS resolver IPs for the
// given interface. Uses `scutil --dns` which exposes per-resolver nameserver
// lists on macOS. Returns unique resolvers in their discovered order.
func GetDNSResolvers(iface string) ([]string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return nil, fmt.Errorf("get dns resolvers: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		return nil, fmt.Errorf("scutil --dns: %w", err)
	}

	// Match any `nameserver[N] : IPv4-or-IPv6`.
	re := regexp.MustCompile(`nameserver\[\d+\]\s*:\s*([0-9a-fA-F:.]+)`)
	matches := re.FindAllSubmatch(out, -1)
	seen := make(map[string]struct{}, len(matches))
	resolvers := make([]string, 0, len(matches))
	for _, m := range matches {
		ip := string(m[1])
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		resolvers = append(resolvers, ip)
	}
	return resolvers, nil
}

// GetDNSSearchDomain returns the first non-trivial DNS search domain
// advertised on the network (via DHCP option 15 or IPv6 RA RDNSS).
// Empty string means no search domain (or only "local").
func GetDNSSearchDomain(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get dns search domain: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		return "", fmt.Errorf("scutil --dns: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "search domain") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		domain := strings.TrimSpace(parts[1])
		if domain == "" || domain == "local" {
			continue
		}
		return domain, nil
	}
	return "", nil
}
