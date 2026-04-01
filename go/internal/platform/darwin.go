//go:build darwin

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// GetWifiInfo returns the current WiFi connection info on macOS.
//
// Tries, in order: system_profiler (JSON), the legacy airport command,
// networksetup, and finally ifconfig as a last resort.
func GetWifiInfo(iface string) (*WifiInfo, error) {
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
			if ssid == "" {
				ssid = "<redacted>"
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

// GetCurrentMAC returns the current MAC address of the given interface.
func GetCurrentMAC(iface string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ifconfig", iface).Output()
	if err != nil {
		return "", fmt.Errorf("ifconfig %s: %w", iface, err)
	}

	re := regexp.MustCompile(`ether\s+([0-9a-f:]{17})`)
	m := re.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("no MAC address found for %s", iface)
	}
	return string(m[1]), nil
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

	re := regexp.MustCompile(`\S+\s+\((\S+)\)\s+at\s+([0-9a-f:]+)\s+on\s+(\S+)`)
	var entries []ArpEntry
	for _, line := range strings.Split(string(out), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		mac := m[2]
		if mac == "(incomplete)" {
			continue
		}
		entries = append(entries, ArpEntry{
			IP:        m[1],
			MAC:       mac,
			Interface: m[3],
		})
	}
	return entries, nil
}

// RenewDHCP renews the DHCP lease on the given interface (requires sudo).
func RenewDHCP(iface string) error {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxy",
		iface, "127.0.0.1", strconv.Itoa(port))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set SOCKS proxy on %s: %w: %s", iface, err, string(out))
	}

	cmd = exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxystate", iface, "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("enable SOCKS proxy on %s: %w: %s", iface, err, string(out))
	}
	return nil
}

// ClearSystemProxy removes the system-wide SOCKS proxy on the given interface.
func ClearSystemProxy(iface string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "networksetup", "-setsocksfirewallproxystate", iface, "off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("clear SOCKS proxy on %s: %w: %s", iface, err, string(out))
	}
	return nil
}

// DisconnectWifi turns off WiFi on the given interface.
func DisconnectWifi(iface string) error {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "networksetup", "-setairportpower", iface, "on")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("connect WiFi %s: %w: %s", iface, err, string(out))
	}
	return nil
}
