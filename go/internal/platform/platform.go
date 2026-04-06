// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package platform provides cross-platform network operations.
//
// Platform-specific implementations live in darwin.go and linux.go,
// selected at compile time via build tags. This file defines the
// shared types used by both platforms.
package platform

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// WifiInfo holds current WiFi connection details.
type WifiInfo struct {
	SSID     string
	BSSID    string
	Channel  string
	Security string
	RSSI     int // signal strength in dBm
}

// ArpEntry represents a single ARP table row.
type ArpEntry struct {
	IP        string
	MAC       string
	Interface string
}

// StealthState holds the original system settings for stealth restoration.
type StealthState struct {
	OriginalTTL  int
	PFRulesAdded bool // On Linux, reused for iptables rules.
	PFWasEnabled bool
}

var (
	macRE = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
	// Linux interface names: up to 31 chars (IFNAMSIZ-1), letters/digits/dot/hyphen/underscore.
	// Covers en0, wlan0, enp3s0, wlx001122334455, wlan0.1 (VLAN), bond0.100, p2p-dev-wlan0.
	ifaceRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{0,30}$`)
)

// ValidateMAC validates a MAC address format and returns it lower-cased.
// Returns an error if the format is invalid (prevents command injection).
func ValidateMAC(mac string) (string, error) {
	if !macRE.MatchString(mac) {
		return "", fmt.Errorf("invalid MAC address format: %q, expected xx:xx:xx:xx:xx:xx", mac)
	}
	// Lower-case the MAC for consistency.
	result := make([]byte, len(mac))
	for i, c := range mac {
		if c >= 'A' && c <= 'F' {
			result[i] = byte(c + 32) // to lowercase
		} else {
			result[i] = byte(c)
		}
	}
	return string(result), nil
}

func normalizeMAC(mac string) (string, error) {
	return ValidateMAC(strings.TrimSpace(mac))
}

func parseArpEntries(output string, re *regexp.Regexp, ipIndex, macIndex, ifaceIndex int) []ArpEntry {
	var entries []ArpEntry
	for _, line := range strings.Split(output, "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		mac, err := normalizeMAC(m[macIndex])
		if err != nil {
			continue
		}
		entries = append(entries, ArpEntry{
			IP:        m[ipIndex],
			MAC:       mac,
			Interface: m[ifaceIndex],
		})
	}
	return entries
}

// ValidateInterface validates an interface name to prevent command injection.
func ValidateInterface(iface string) (string, error) {
	if !ifaceRE.MatchString(iface) {
		return "", fmt.Errorf("invalid interface name: %q", iface)
	}
	return iface, nil
}

// ValidateIP validates an IPv4 or IPv6 address string.
// Prevents command injection through parameters expected to be IP addresses.
func ValidateIP(ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", fmt.Errorf("empty IP address")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP address: %q", ip)
	}
	// Return the canonical string form (prevents any embedded shell metacharacters).
	return parsed.String(), nil
}

// ValidateURL validates a URL string and ensures it has an http or https scheme.
// Prevents command injection through parameters expected to be URLs.
func ValidateURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid URL scheme %q: must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid URL %q: missing host", rawURL)
	}
	// Rebuild the URL from parsed components to eliminate any embedded shell metacharacters.
	return u.String(), nil
}

// ValidateServerAddr validates a server address (IP, host:port, or hostname).
// Ensures the address does not contain shell metacharacters.
var serverAddrRE = regexp.MustCompile(`^[a-zA-Z0-9._:\[\]-]+$`)

func ValidateServerAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("empty server address")
	}
	if !serverAddrRE.MatchString(addr) {
		return "", fmt.Errorf("invalid server address: %q (contains disallowed characters)", addr)
	}
	return addr, nil
}

// ValidateDomain validates a DNS domain name.
// Prevents command injection through parameters expected to be domain names.
var domainRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

func ValidateDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", fmt.Errorf("empty domain")
	}
	if len(domain) > 253 {
		return "", fmt.Errorf("domain too long: %q", domain)
	}
	if !domainRE.MatchString(domain) {
		return "", fmt.Errorf("invalid domain: %q", domain)
	}
	return domain, nil
}

// GenerateRandomMAC generates a random locally-administered unicast MAC address.
//
// Locally administered: bit 1 of first octet = 1 (second hex char is 2,6,a,e).
// Unicast: bit 0 of first octet = 0.
func GenerateRandomMAC() string {
	// Possible first bytes: 0x02, 0x06, 0x0A, 0x0E
	firstChoices := []byte{0x02, 0x06, 0x0A, 0x0E}

	var buf [6]byte
	// Use crypto/rand for the random bytes.
	_, _ = rand.Read(buf[:])

	// Pick a first byte from the valid set using a random index.
	buf[0] = firstChoices[buf[0]%4]

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}
