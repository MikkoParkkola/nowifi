// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package clone implements Full Device Clone — spoofing MAC + IP + DHCP fingerprint
// to become indistinguishable from the target device at every inspection layer.
package clone

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// DeviceProfile captures identifiable attributes for DHCP fingerprint spoofing.
type DeviceProfile struct {
	OS            string
	Hostname      string
	DHCPOptions55 string // Comma-separated option codes for dhclient request list
	DHCPOption60  string // Vendor Class Identifier
	TTL           int
}

// Pre-built profiles for common device types.
var (
	ProfileMacOS = DeviceProfile{
		OS: "macos", Hostname: "MacBook-Pro",
		DHCPOptions55: "subnet-mask,routers,domain-name-servers,domain-name,domain-search,classless-static-routes",
		TTL: 64,
	}
	ProfileiOS = DeviceProfile{
		OS: "ios", Hostname: "iPhone",
		DHCPOptions55: "subnet-mask,routers,domain-name-servers,domain-name,domain-search",
		TTL: 64,
	}
	ProfileWindows = DeviceProfile{
		OS: "windows", Hostname: "DESKTOP-NOWIFI",
		DHCPOptions55: "subnet-mask,routers,domain-name-servers,domain-name,ntp-servers,vendor-encapsulated-options",
		DHCPOption60:  "MSFT 5.0",
		TTL: 128,
	}
	ProfileAndroid = DeviceProfile{
		OS: "android", Hostname: "android-nowifi",
		DHCPOptions55: "subnet-mask,routers,domain-name-servers,domain-name,broadcast-address",
		DHCPOption60:  "android-dhcp-14",
		TTL: 64,
	}
	ProfileLinux = DeviceProfile{
		OS: "linux", Hostname: "localhost",
		DHCPOptions55: "subnet-mask,routers,domain-name-servers,domain-name,host-name",
		TTL: 64,
	}
)

// DetectTargetOS guesses a device's OS from its MAC OUI prefix.
func DetectTargetOS(mac string) string {
	upper := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(upper) < 6 {
		return "linux"
	}
	oui := upper[:6]

	// Apple OUIs (simplified — Apple has hundreds)
	appleOUIs := []string{"A4B197", "F0D1A9", "3C06A7", "28CF51", "8866A5", "DC56E7"}
	for _, a := range appleOUIs {
		if oui == a {
			return "ios" // Could be macOS too, but iOS is more common
		}
	}

	// Samsung / Android
	androidOUIs := []string{"B47C9C", "CC07AB", "843835", "F8D0BD", "9463D1"}
	for _, a := range androidOUIs {
		if oui == a {
			return "android"
		}
	}

	// Windows / Dell / HP / Lenovo
	windowsOUIs := []string{"F48E38", "3C2EFF", "B499BA", "1C697A", "509A4C"}
	for _, w := range windowsOUIs {
		if oui == w {
			return "windows"
		}
	}

	return "linux" // Safe default
}

// ProfileForOS returns the matching device profile.
func ProfileForOS(os string) DeviceProfile {
	switch os {
	case "macos":
		return ProfileMacOS
	case "ios":
		return ProfileiOS
	case "windows":
		return ProfileWindows
	case "android":
		return ProfileAndroid
	default:
		return ProfileLinux
	}
}

// FullClone performs MAC clone + DHCP fingerprint spoofing.
// It sets the MAC, then does a DHCP request with options matching the target's OS.
func FullClone(iface, targetMAC, targetIP string) error {
	// Validate all inputs before any exec.Command calls.
	if _, err := platform.ValidateInterface(iface); err != nil {
		return fmt.Errorf("clone: %w", err)
	}
	if _, err := platform.ValidateMAC(targetMAC); err != nil {
		return fmt.Errorf("clone: %w", err)
	}
	if targetIP != "" {
		if ip := net.ParseIP(targetIP); ip == nil {
			return fmt.Errorf("clone: invalid target IP: %q", targetIP)
		}
	}

	// 1. Detect target OS
	targetOS := DetectTargetOS(targetMAC)
	profile := ProfileForOS(targetOS)

	// 2. Set MAC (SetMAC also validates internally)
	if err := platform.SetMAC(iface, targetMAC); err != nil {
		return fmt.Errorf("MAC clone failed: %w", err)
	}

	// 3. DHCP with spoofed fingerprint
	if runtime.GOOS == "linux" {
		return dhcpWithProfileLinux(iface, targetIP, profile)
	}
	// macOS: limited DHCP control, just do standard DHCP renew
	return platform.RenewDHCP(iface)
}

// dhcpWithProfileLinux writes a temporary dhclient.conf and runs dhclient.
func dhcpWithProfileLinux(iface, requestIP string, profile DeviceProfile) error {
	// Validate interface (already validated by caller, but defense in depth).
	if _, err := platform.ValidateInterface(iface); err != nil {
		return fmt.Errorf("dhcp profile: %w", err)
	}
	// Validate IP if provided (already validated by caller, but defense in depth).
	if requestIP != "" {
		if ip := net.ParseIP(requestIP); ip == nil {
			return fmt.Errorf("dhcp profile: invalid request IP: %q", requestIP)
		}
	}

	// Sanitize profile fields to prevent injection into dhclient config.
	// Hostname: alphanumeric + hyphens only (RFC 952/1123).
	hostname := sanitizeHostname(profile.Hostname)
	// DHCP options: comma-separated alphanumeric option names with hyphens.
	dhcpOpts := sanitizeDHCPOptions(profile.DHCPOptions55)

	// Build dhclient config
	conf := fmt.Sprintf(`# nowifi Full Device Clone — DHCP fingerprint spoofing
interface "%s" {
  send host-name "%s";
  request %s;
`, iface, hostname, dhcpOpts)

	if profile.DHCPOption60 != "" {
		vendorClass := sanitizeVendorClass(profile.DHCPOption60)
		conf += fmt.Sprintf("  send vendor-class-identifier \"%s\";\n", vendorClass)
	}
	if requestIP != "" {
		conf += fmt.Sprintf("  request-ip %s;\n", requestIP)
	}
	conf += "}\n"

	// Write temp config using os.WriteFile (no shell needed).
	confPath := "/tmp/nowifi-dhclient.conf"
	if err := writeFile(confPath, conf); err != nil {
		return fmt.Errorf("failed to write dhclient config: %w", err)
	}

	// Release existing lease
	_ = exec.Command("sudo", "dhclient", "-r", iface).Run()
	time.Sleep(500 * time.Millisecond)

	// Request with spoofed fingerprint
	cmd := exec.Command("sudo", "dhclient", "-cf", confPath, "-1", iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("dhclient failed: %s: %w", string(out), err)
	}

	return nil
}

// sanitizeHostname ensures the hostname only contains safe characters (RFC 952/1123).
func sanitizeHostname(h string) string {
	var b strings.Builder
	for _, c := range h {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "localhost"
	}
	return b.String()
}

// sanitizeDHCPOptions ensures only valid DHCP option names (alphanumeric + hyphens + commas).
func sanitizeDHCPOptions(opts string) string {
	var b strings.Builder
	for _, c := range opts {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == ',' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// sanitizeVendorClass ensures vendor class identifier only contains printable ASCII without quotes.
func sanitizeVendorClass(vc string) string {
	var b strings.Builder
	for _, c := range vc {
		if c >= ' ' && c <= '~' && c != '"' && c != '\\' && c != ';' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}
