// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package monitor manages WiFi monitor mode on macOS and Linux.
//
// Handles enabling/disabling monitor mode and reverts to managed mode
// on exit via the Guard type.
//
// macOS: Built-in card does not support monitor mode. Requires an external
// USB WiFi adapter (e.g., Alfa AWUS036ACH with RTL8812AU driver).
//
// Linux: airmon-ng (preferred) or iw dev set type monitor.
package monitor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// Interface represents a WiFi interface that has been put into monitor mode.
type Interface struct {
	Name         string // Monitor mode interface name (e.g., wlan0mon)
	OriginalName string // Original managed mode name (e.g., wlan0)
	WasManaged   bool   // True if we switched from managed mode
}

// ---------------------------------------------------------------------------
// Check support
// ---------------------------------------------------------------------------

// CheckSupport checks if an interface supports monitor mode without enabling it.
func CheckSupport(iface string) bool {
	if runtime.GOOS == "darwin" {
		return checkSupportDarwin(iface)
	}
	if runtime.GOOS == "linux" {
		return checkSupportLinux(iface)
	}
	return false
}

// checkSupportDarwin checks monitor mode support on macOS.
// The built-in WiFi (en0) never supports monitor mode; external USB adapters might.
func checkSupportDarwin(iface string) bool {
	if iface == "en0" {
		return false
	}
	// Check if interface exists.
	cmd := exec.Command("ifconfig", iface)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// checkSupportLinux checks monitor mode support on Linux via iw phy.
func checkSupportLinux(iface string) bool {
	// Get the phy for this interface.
	phy := getPhyForInterface(iface)
	if phy == "" {
		goto fallback
	}

	{
		out, err := exec.Command("iw", "phy").Output()
		if err == nil {
			inPhy := false
			inModes := false
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, phy) {
					inPhy = true
				}
				if inPhy && strings.Contains(line, "Supported interface modes:") {
					inModes = true
					continue
				}
				if inModes {
					trimmed := strings.TrimSpace(line)
					if strings.Contains(trimmed, "* monitor") {
						return true
					}
					// End of modes section: non-empty line that doesn't start with *.
					if trimmed != "" && !strings.HasPrefix(trimmed, "*") {
						inModes = false
					}
				}
			}
		}
	}

fallback:
	// Fallback: check if airmon-ng exists.
	if _, err := exec.LookPath("airmon-ng"); err == nil {
		return true // airmon-ng exists, assume it can handle the interface.
	}

	return false
}

// ---------------------------------------------------------------------------
// Find interfaces
// ---------------------------------------------------------------------------

// FindInterfaces finds WiFi interfaces that may support monitor mode.
func FindInterfaces() []string {
	if runtime.GOOS == "darwin" {
		return findInterfacesDarwin()
	}
	if runtime.GOOS == "linux" {
		return findInterfacesLinux()
	}
	return nil
}

// findInterfacesDarwin finds monitor-capable interfaces on macOS.
// Only external USB WiFi adapters support monitor mode.
func findInterfacesDarwin() []string {
	var interfaces []string

	out, err := exec.Command("ifconfig", "-l").Output()
	if err != nil {
		return nil
	}

	skipPrefixes := []string{"lo", "gif", "stf", "bridge", "utun", "awdl", "llw", "ap"}

	for _, iface := range strings.Fields(string(out)) {
		if iface == "en0" {
			continue // Built-in, no monitor mode.
		}

		skip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(iface, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		if CheckSupport(iface) {
			interfaces = append(interfaces, iface)
		}
	}

	return interfaces
}

// findInterfacesLinux finds monitor-capable wireless interfaces on Linux.
func findInterfacesLinux() []string {
	var interfaces []string

	ifaceRE := regexp.MustCompile(`Interface\s+(\S+)`)

	out, err := exec.Command("iw", "dev").Output()
	if err == nil {
		for _, m := range ifaceRE.FindAllStringSubmatch(string(out), -1) {
			iface := m[1]
			if CheckSupport(iface) {
				interfaces = append(interfaces, iface)
			}
		}
		if len(interfaces) > 0 {
			return interfaces
		}
	}

	// Fallback: check /proc/net/wireless.
	f, err := os.Open("/proc/net/wireless")
	if err != nil {
		return nil
	}
	defer f.Close()

	lineRE := regexp.MustCompile(`^\s*(\S+):`)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if m := lineRE.FindStringSubmatch(scanner.Text()); len(m) > 1 {
			interfaces = append(interfaces, m[1])
		}
	}

	return interfaces
}

// ---------------------------------------------------------------------------
// Enable / Disable
// ---------------------------------------------------------------------------

// Enable puts a WiFi interface into monitor mode.
//
// Linux: Uses airmon-ng (preferred) or iw.
// macOS: Limited support -- only external USB adapters.
//
// Returns the Interface with the monitor-mode interface name.
func Enable(iface string) (*Interface, error) {
	switch runtime.GOOS {
	case "linux":
		return enableLinux(iface)
	case "darwin":
		return enableDarwin(iface)
	default:
		return nil, fmt.Errorf("monitor mode not supported on %s", runtime.GOOS)
	}
}

// Disable reverts an interface from monitor mode to managed mode.
func Disable(mon *Interface) error {
	if mon == nil || !mon.WasManaged {
		return nil // Nothing to revert.
	}

	switch runtime.GOOS {
	case "linux":
		if disableLinux(mon) {
			return nil
		}
		return fmt.Errorf("failed to disable monitor mode on %s", mon.Name)
	case "darwin":
		if disableDarwin(mon) {
			return nil
		}
		return fmt.Errorf("failed to disable monitor mode on %s", mon.Name)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

// enableLinux enables monitor mode on Linux.
func enableLinux(iface string) (*Interface, error) {
	// Try airmon-ng first (handles driver quirks, kills interfering processes).
	if airmon, err := exec.LookPath("airmon-ng"); err == nil {
		// Kill interfering processes.
		_ = exec.Command("sudo", airmon, "check", "kill").Run()

		// Start monitor mode.
		out, _ := exec.Command("sudo", airmon, "start", iface).CombinedOutput()
		output := string(out)

		// Parse output for new interface name (e.g., wlan0mon).
		re := regexp.MustCompile(`\(monitor mode.*enabled on (\S+)\)`)
		if m := re.FindStringSubmatch(output); len(m) > 1 {
			return &Interface{Name: m[1], OriginalName: iface, WasManaged: true}, nil
		}

		// Some versions just append "mon".
		monName := iface + "mon"
		if err := exec.Command("ifconfig", monName).Run(); err == nil {
			return &Interface{Name: monName, OriginalName: iface, WasManaged: true}, nil
		}
	}

	// Fallback: iw.
	if err := exec.Command("sudo", "ip", "link", "set", iface, "down").Run(); err != nil {
		return nil, fmt.Errorf("failed to bring %s down: %w", iface, err)
	}

	if err := exec.Command("sudo", "iw", "dev", iface, "set", "type", "monitor").Run(); err != nil {
		// Try to bring the interface back up before returning error.
		_ = exec.Command("sudo", "ip", "link", "set", iface, "up").Run()
		return nil, fmt.Errorf("failed to enable monitor mode on %s: %w", iface, err)
	}

	if err := exec.Command("sudo", "ip", "link", "set", iface, "up").Run(); err != nil {
		return nil, fmt.Errorf("failed to bring %s up: %w", iface, err)
	}

	return &Interface{Name: iface, OriginalName: iface, WasManaged: true}, nil
}

// enableDarwin enables monitor mode on macOS (limited -- external adapters only).
func enableDarwin(iface string) (*Interface, error) {
	if iface == "en0" {
		return nil, fmt.Errorf(
			"built-in macOS Wi-Fi (en0) does not support monitor mode; " +
				"use an external USB Wi-Fi adapter (recommended: Alfa AWUS036ACH with RTL8812AU)")
	}

	if err := exec.Command("sudo", "ifconfig", iface, "monitor").Run(); err != nil {
		return nil, fmt.Errorf("failed to enable monitor mode on %s: %w", iface, err)
	}

	return &Interface{Name: iface, OriginalName: iface, WasManaged: true}, nil
}

// disableLinux disables monitor mode on Linux.
func disableLinux(mon *Interface) bool {
	// Try airmon-ng first.
	if airmon, err := exec.LookPath("airmon-ng"); err == nil {
		if err := exec.Command("sudo", airmon, "stop", mon.Name).Run(); err == nil {
			// Restart NetworkManager if it was killed.
			if systemctl, err := exec.LookPath("systemctl"); err == nil {
				_ = exec.Command("sudo", systemctl, "restart", "NetworkManager").Run()
			}
			return true
		}
	}

	// Fallback: iw.
	_ = exec.Command("sudo", "ip", "link", "set", mon.Name, "down").Run()
	_ = exec.Command("sudo", "iw", "dev", mon.Name, "set", "type", "managed").Run()
	_ = exec.Command("sudo", "ip", "link", "set", mon.OriginalName, "up").Run()

	return true
}

// disableDarwin disables monitor mode on macOS.
func disableDarwin(mon *Interface) bool {
	err := exec.Command("sudo", "ifconfig", mon.Name, "-monitor").Run()
	return err == nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// getPhyForInterface gets the phy name for a wireless interface on Linux.
func getPhyForInterface(iface string) string {
	out, err := exec.Command("iw", "dev", iface, "info").Output()
	if err != nil {
		return ""
	}

	re := regexp.MustCompile(`wiphy\s+(\d+)`)
	m := re.FindStringSubmatch(string(out))
	if len(m) > 1 {
		return "phy#" + m[1]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Guard -- context manager pattern
// ---------------------------------------------------------------------------

// Guard enables monitor mode on creation and reverts on Close.
//
// Usage:
//
//	g := monitor.NewGuard("wlan0")
//	mon, err := g.Enable()
//	if err != nil { ... }
//	defer g.Close()
//	// use mon.Name for capture
type Guard struct {
	iface   string
	monitor *Interface
	enable  func(string) (*Interface, error)
	disable func(*Interface) error
}

// NewGuard creates a new Guard for the given interface.
func NewGuard(iface string) *Guard {
	return &Guard{iface: iface, enable: Enable, disable: Disable}
}

// Enable puts the interface into monitor mode and returns the Interface.
func (g *Guard) Enable() (*Interface, error) {
	enable := g.enable
	if enable == nil {
		enable = Enable
	}
	mon, err := enable(g.iface)
	if err != nil {
		return nil, err
	}
	g.monitor = mon
	return mon, nil
}

// Close reverts the interface from monitor mode. Safe to call multiple times.
func (g *Guard) Close() error {
	if g.monitor != nil && g.monitor.WasManaged {
		disable := g.disable
		if disable == nil {
			disable = Disable
		}
		err := disable(g.monitor)
		g.monitor = nil
		return err
	}
	return nil
}
