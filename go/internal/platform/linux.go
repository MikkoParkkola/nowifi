//go:build linux

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// hasCmd reports whether a command is available on PATH.
func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// run executes a command with a timeout and returns its combined output.
func run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.Output()
	return string(out), err
}

// GetWifiInfo returns the current WiFi connection info on Linux.
//
// Tries, in order: nmcli, iw dev link, iwgetid+iwconfig, and ip addr (last resort).
func GetWifiInfo(iface string) (*WifiInfo, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return nil, fmt.Errorf("wifi info: %w", err)
	}

	// Strategy 1: nmcli (NetworkManager, most common on desktop Linux)
	if info := getWifiInfoNmcli(iface); info != nil {
		return info, nil
	}

	// Strategy 2: iw dev <iface> link
	if info := getWifiInfoIw(iface); info != nil {
		return info, nil
	}

	// Strategy 3: iwgetid + iwconfig
	if info := getWifiInfoIwgetid(iface); info != nil {
		return info, nil
	}

	// Strategy 4: ip addr show (just check if interface is up with an IP)
	if info := getWifiInfoIPAddr(iface); info != nil {
		return info, nil
	}

	return nil, fmt.Errorf("unable to determine WiFi info for %s", iface)
}

// nmcliFieldRE splits on unescaped colons (nmcli -t escapes colons in BSSID as \:).
var nmcliFieldRE = regexp.MustCompile(`(?:\\:|[^:])+`)

func getWifiInfoNmcli(iface string) *WifiInfo {
	if !hasCmd("nmcli") {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := run(ctx, "nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SECURITY,SIGNAL",
		"dev", "wifi", "list", "ifname", iface)
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(out, "\n") {
		// Split on unescaped colons.
		fields := nmcliFieldRE.FindAllString(line, -1)
		if len(fields) < 6 || fields[0] != "yes" {
			continue
		}

		bssid := strings.ReplaceAll(fields[2], `\:`, ":")
		rssiPct, _ := strconv.Atoi(fields[5])
		rssiDbm := -99
		if rssiPct > 0 {
			rssiDbm = -100 + int(float64(rssiPct)*0.6)
		}

		return &WifiInfo{
			SSID:     fields[1],
			BSSID:    bssid,
			Channel:  fields[3],
			Security: fields[4],
			RSSI:     rssiDbm,
		}
	}
	return nil
}

func getWifiInfoIw(iface string) *WifiInfo {
	if !hasCmd("iw") {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := run(ctx, "iw", "dev", iface, "link")
	if err != nil || strings.Contains(out, "Not connected") {
		return nil
	}

	var ssid, bssid, channel string
	rssi := -99

	if m := regexp.MustCompile(`SSID:\s*(.+)`).FindStringSubmatch(out); m != nil {
		ssid = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`Connected to\s+([0-9a-f:]{17})`).FindStringSubmatch(out); m != nil {
		bssid = m[1]
	}
	if m := regexp.MustCompile(`freq:\s*(\d+)`).FindStringSubmatch(out); m != nil {
		channel = m[1]
	}
	if m := regexp.MustCompile(`signal:\s*(-?\d+)`).FindStringSubmatch(out); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			rssi = n
		}
	}

	if ssid == "" {
		return nil
	}

	return &WifiInfo{
		SSID:     ssid,
		BSSID:    bssid,
		Channel:  channel,
		Security: "unknown",
		RSSI:     rssi,
	}
}

func getWifiInfoIwgetid(iface string) *WifiInfo {
	if !hasCmd("iwgetid") {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := run(ctx, "iwgetid", "-r", iface)
	if err != nil {
		return nil
	}
	ssid := strings.TrimSpace(out)
	if ssid == "" {
		return nil
	}

	rssi := -99
	bssid := ""

	if hasCmd("iwconfig") {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()

		iwOut, err := run(ctx2, "iwconfig", iface)
		if err == nil {
			if m := regexp.MustCompile(`Signal level[=:](-?\d+)`).FindStringSubmatch(iwOut); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil {
					rssi = n
				}
			}
			if m := regexp.MustCompile(`Access Point:\s*([0-9A-Fa-f:]{17})`).FindStringSubmatch(iwOut); m != nil {
				bssid = strings.ToLower(m[1])
			}
		}
	}

	return &WifiInfo{
		SSID:     ssid,
		BSSID:    bssid,
		Security: "unknown",
		RSSI:     rssi,
	}
}

var ipAddrInetRE = regexp.MustCompile(`inet\s+(\d+\.\d+\.\d+\.\d+)`)

func getWifiInfoIPAddr(iface string) *WifiInfo {
	if !hasCmd("ip") {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := run(ctx, "ip", "addr", "show", iface)
	if err != nil {
		return nil
	}

	hasIP := ipAddrInetRE.MatchString(out)
	isUp := strings.Contains(out, "state UP")
	if hasIP && isUp {
		return &WifiInfo{
			SSID:     "<unknown>",
			Security: "unknown",
			RSSI:     -99,
		}
	}
	return nil
}

// GetCurrentMAC returns the current MAC address of the given interface.
func GetCurrentMAC(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get MAC: %w", err)
	}

	if hasCmd("ip") {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		out, err := run(ctx, "ip", "link", "show", iface)
		if err == nil {
			re := regexp.MustCompile(`link/ether\s+(\S+)`)
			if m := re.FindStringSubmatch(out); m != nil {
				mac, err := normalizeMAC(m[1])
				if err != nil {
					return "", fmt.Errorf("invalid MAC address found for %s: %w", iface, err)
				}
				return mac, nil
			}
		}
	}

	// Fallback: read from sysfs.
	sysfsPath := fmt.Sprintf("/sys/class/net/%s/address", iface)
	data, err := os.ReadFile(sysfsPath)
	if err != nil {
		return "", fmt.Errorf("read MAC for %s: %w", iface, err)
	}
	mac, err := normalizeMAC(string(data))
	if err != nil {
		return "", fmt.Errorf("invalid MAC in sysfs for %s: %w", iface, err)
	}
	return mac, nil
}

// SetMAC sets the MAC address on the given interface (requires sudo).
// Brings the interface down, sets the MAC, and brings it back up.
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

	// Must bring interface down before changing MAC on Linux.
	if out, err := exec.CommandContext(ctx, "sudo", "ip", "link", "set", iface, "down").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set %s down: %w: %s", iface, err, string(out))
	}
	if out, err := exec.CommandContext(ctx, "sudo", "ip", "link", "set", iface, "address", mac).CombinedOutput(); err != nil {
		// Try to bring interface back up even on failure.
		_ = exec.CommandContext(ctx, "sudo", "ip", "link", "set", iface, "up").Run()
		return fmt.Errorf("ip link set %s address: %w: %s", iface, err, string(out))
	}
	if out, err := exec.CommandContext(ctx, "sudo", "ip", "link", "set", iface, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set %s up: %w: %s", iface, err, string(out))
	}
	return nil
}

// GetGateway returns the default gateway IP address.
func GetGateway(iface string) (string, error) {
	if hasCmd("ip") {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		out, err := run(ctx, "ip", "route", "show", "default")
		if err == nil {
			re := regexp.MustCompile(`default via\s+(\S+)`)
			if m := re.FindStringSubmatch(out); m != nil {
				return m[1], nil
			}
		}
	}

	// Fallback: read /proc/net/route.
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("no gateway found: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			gwHex := fields[2]
			if len(gwHex) == 8 {
				// Gateway is in hex, little-endian.
				gw, err := parseHexGateway(gwHex)
				if err == nil {
					return gw, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no gateway found")
}

// parseHexGateway converts a little-endian hex gateway from /proc/net/route.
func parseHexGateway(hex string) (string, error) {
	if len(hex) != 8 {
		return "", fmt.Errorf("invalid gateway hex: %s", hex)
	}
	var octets [4]uint64
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return "", err
		}
		octets[i] = v
	}
	// Little-endian: reverse the byte order.
	return fmt.Sprintf("%d.%d.%d.%d", octets[3], octets[2], octets[1], octets[0]), nil
}

// GetLocalIP returns the local IPv4 address of the given interface.
func GetLocalIP(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get local IP: %w", err)
	}

	if !hasCmd("ip") {
		return "", fmt.Errorf("ip command not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := run(ctx, "ip", "addr", "show", iface)
	if err != nil {
		return "", fmt.Errorf("ip addr show %s: %w", iface, err)
	}

	if m := ipAddrInetRE.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("no IPv4 address found for %s", iface)
}

// GetIPv6Address returns the global IPv6 address of the given interface, if any.
func GetIPv6Address(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get IPv6: %w", err)
	}

	if !hasCmd("ip") {
		return "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := run(ctx, "ip", "-6", "addr", "show", iface, "scope", "global")
	if err != nil {
		return "", nil
	}

	re := regexp.MustCompile(`inet6\s+([0-9a-f:]+)`)
	if m := re.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", nil
}

// GetARPTable returns all ARP table entries.
func GetARPTable() ([]ArpEntry, error) {
	// Prefer ip neigh show.
	if hasCmd("ip") {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		out, err := run(ctx, "ip", "neigh", "show")
		if err == nil {
			re := regexp.MustCompile(`(\S+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)`)
			return parseArpEntries(out, re, 1, 3, 2), nil
		}
	}

	// Fallback: arp -a.
	if hasCmd("arp") {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		out, err := run(ctx, "arp", "-a")
		if err != nil {
			return nil, fmt.Errorf("arp -a: %w", err)
		}

		re := regexp.MustCompile(`\S+\s+\((\S+)\)\s+at\s+(\S+)\s+.*on\s+(\S+)`)
		return parseArpEntries(out, re, 1, 2, 3), nil
	}

	return nil, fmt.Errorf("no arp command available")
}

// RenewDHCP renews the DHCP lease on the given interface.
func RenewDHCP(iface string) error {
	if _, err := ValidateInterface(iface); err != nil {
		return fmt.Errorf("DHCP renew: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Try dhclient first (most common).
	if hasCmd("dhclient") {
		_ = exec.CommandContext(ctx, "sudo", "dhclient", "-r", iface).Run()
		if err := exec.CommandContext(ctx, "sudo", "dhclient", iface).Run(); err == nil {
			return nil
		}
	}

	// Try dhcpcd.
	if hasCmd("dhcpcd") {
		if err := exec.CommandContext(ctx, "sudo", "dhcpcd", "-n", iface).Run(); err == nil {
			return nil
		}
	}

	// Try nmcli: deactivate and reactivate the active connection.
	if hasCmd("nmcli") {
		out, err := run(ctx, "nmcli", "-t", "-f", "NAME", "con", "show", "--active")
		if err == nil {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) > 0 && lines[0] != "" {
				connName := lines[0]
				_ = exec.CommandContext(ctx, "nmcli", "con", "down", connName).Run()
				if err := exec.CommandContext(ctx, "nmcli", "con", "up", connName).Run(); err == nil {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("DHCP renewal failed on %s: no suitable DHCP client found", iface)
}

// FlushDNS flushes the Linux DNS cache using available tools.
func FlushDNS() error {
	flushed := false

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// systemd-resolved / resolvectl.
	if hasCmd("resolvectl") {
		if err := exec.CommandContext(ctx, "sudo", "resolvectl", "flush-caches").Run(); err == nil {
			flushed = true
		}
	} else if hasCmd("systemd-resolve") {
		if err := exec.CommandContext(ctx, "sudo", "systemd-resolve", "--flush-caches").Run(); err == nil {
			flushed = true
		}
	}

	// nscd (Name Service Cache Daemon).
	if hasCmd("nscd") {
		if err := exec.CommandContext(ctx, "sudo", "nscd", "--invalidate=hosts").Run(); err == nil {
			flushed = true
		}
	}

	// dnsmasq (if running as local cache).
	if hasCmd("killall") {
		_ = exec.CommandContext(ctx, "sudo", "killall", "-HUP", "dnsmasq").Run()
	}

	if !flushed {
		return fmt.Errorf("no DNS cache flush tool found")
	}
	return nil
}

// SetSystemProxy configures a system-wide SOCKS proxy via environment variables.
//
// On Linux there is no universal system proxy command like macOS networksetup.
// We set ALL_PROXY for the current process tree and also try GNOME gsettings.
func SetSystemProxy(iface string, port int) error {
	proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", port)
	os.Setenv("ALL_PROXY", proxyURL)
	os.Setenv("all_proxy", proxyURL)
	os.Setenv("SOCKS_PROXY", proxyURL)

	// Try GNOME gsettings if available.
	if hasCmd("gsettings") {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy.socks", "host", "127.0.0.1").Run()
		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy.socks", "port", strconv.Itoa(port)).Run()
	}
	return nil
}

// ClearSystemProxy removes the system-wide SOCKS proxy.
func ClearSystemProxy(iface string) error {
	os.Unsetenv("ALL_PROXY")
	os.Unsetenv("all_proxy")
	os.Unsetenv("SOCKS_PROXY")

	if hasCmd("gsettings") {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
	}
	return nil
}

// DisconnectWifi disconnects from WiFi or brings the interface down.
func DisconnectWifi(iface string) error {
	if _, err := ValidateInterface(iface); err != nil {
		return fmt.Errorf("disconnect wifi: %w", err)
	}

	if hasCmd("nmcli") {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := exec.CommandContext(ctx, "nmcli", "dev", "disconnect", iface).Run(); err == nil {
			return nil
		}
	}

	if hasCmd("ip") {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if out, err := exec.CommandContext(ctx, "sudo", "ip", "link", "set", iface, "down").CombinedOutput(); err != nil {
			return fmt.Errorf("disconnect %s: %w: %s", iface, err, string(out))
		}
		return nil
	}

	return fmt.Errorf("no tool available to disconnect %s", iface)
}

// ConnectWifi reconnects WiFi or brings the interface up.
func ConnectWifi(iface string) error {
	if _, err := ValidateInterface(iface); err != nil {
		return fmt.Errorf("connect wifi: %w", err)
	}

	if hasCmd("nmcli") {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := exec.CommandContext(ctx, "nmcli", "dev", "connect", iface).Run(); err == nil {
			return nil
		}
	}

	if hasCmd("ip") {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if out, err := exec.CommandContext(ctx, "sudo", "ip", "link", "set", iface, "up").CombinedOutput(); err != nil {
			return fmt.Errorf("connect %s: %w: %s", iface, err, string(out))
		}
		return nil
	}

	return fmt.Errorf("no tool available to connect %s", iface)
}

// ---------------------------------------------------------------------------
// Post-bypass traffic stealth — anti-tethering detection
// ---------------------------------------------------------------------------

// EnableStealth applies traffic normalization to avoid portal detection on Linux.
func EnableStealth(iface string) (*StealthState, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return nil, fmt.Errorf("stealth: %w", err)
	}

	state := &StealthState{}

	// 1. Save and set TTL.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sysctl", "-n", "net.ipv4.ip_default_ttl").Output()
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
	if err := exec.CommandContext(ctx2, "sysctl", "-w", "net.ipv4.ip_default_ttl=65").Run(); err != nil {
		return state, fmt.Errorf("failed to set TTL: %w", err)
	}

	// 2. Add iptables rules for traffic normalization.
	// Mangle table: set TTL to 64 on all outbound packets (normalizes tethered traffic).
	rules := [][]string{
		{"iptables", "-t", "mangle", "-A", "POSTROUTING", "-o", iface, "-j", "TTL", "--ttl-set", "64"},
		{"ip6tables", "-t", "mangle", "-A", "POSTROUTING", "-o", iface, "-j", "HL", "--hl-set", "64"},
	}
	for _, rule := range rules {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = exec.CommandContext(ctx, rule[0], rule[1:]...).Run()
		cancel()
	}
	state.PFRulesAdded = true // Reuse field name for iptables rules.

	// 3. Set IPv6 hop limit.
	ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel3()
	_ = exec.CommandContext(ctx3, "sysctl", "-w", "net.ipv6.conf.all.hop_limit=65").Run()

	return state, nil
}

// DisableStealth restores original TTL and removes iptables stealth rules on Linux.
func DisableStealth(state *StealthState) {
	if state == nil {
		return
	}

	// Restore original TTL.
	if state.OriginalTTL > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "sysctl", "-w",
			fmt.Sprintf("net.ipv4.ip_default_ttl=%d", state.OriginalTTL)).Run()
	}

	// Restore IPv6 hop limit.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	_ = exec.CommandContext(ctx2, "sysctl", "-w", "net.ipv6.conf.all.hop_limit=64").Run()

	// Remove iptables rules.
	if state.PFRulesAdded {
		rules := [][]string{
			{"iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "TTL", "--ttl-set", "64"},
			{"ip6tables", "-t", "mangle", "-D", "POSTROUTING", "-j", "HL", "--hl-set", "64"},
		}
		for _, rule := range rules {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = exec.CommandContext(ctx, rule[0], rule[1:]...).Run()
			cancel()
		}
	}
}

// GetCAPPORTURL returns the RFC 8908 captive-portal API URL advertised
// by DHCP option 114 (RFC 7710). Empty string if the network does not
// advertise CAPPORT.
//
// On Linux, we parse the active DHCP lease file. Different DHCP clients
// write to different paths; we check the common ones.
func GetCAPPORTURL(iface string) (string, error) {
	if _, err := ValidateInterface(iface); err != nil {
		return "", fmt.Errorf("get capport url: %w", err)
	}

	// Common lease file paths across dhclient, dhcpcd, systemd-networkd.
	candidates := []string{
		fmt.Sprintf("/var/lib/dhcp/dhclient.%s.leases", iface),
		fmt.Sprintf("/var/lib/dhcpcd/%s.lease", iface),
		fmt.Sprintf("/run/systemd/netif/leases/%s", iface),
		"/var/lib/dhcp/dhclient.leases",
	}

	// Pattern matches DHCP option 114 in various client formats.
	// dhclient: option captive-portal "https://...";
	// systemd-networkd: CAPTIVE_PORTAL=https://...
	// dhcpcd: captive_portal=https://...
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)captive[-_]portal\s*=?\s*"?([^"\s;]+)"?`),
		regexp.MustCompile(`(?i)option\s+captive-portal\s+"([^"]+)"`),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path) //nolint:gosec // known lease paths
		if err != nil {
			continue
		}
		for _, re := range patterns {
			if m := re.FindSubmatch(data); m != nil {
				return string(m[1]), nil
			}
		}
	}
	return "", nil // Not advertised or no readable lease file
}
