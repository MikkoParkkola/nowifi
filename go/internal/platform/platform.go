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
	"regexp"
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

var (
	macRE   = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
	ifaceRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,15}$`)
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

// ValidateInterface validates an interface name to prevent command injection.
func ValidateInterface(iface string) (string, error) {
	if !ifaceRE.MatchString(iface) {
		return "", fmt.Errorf("invalid interface name: %q", iface)
	}
	return iface, nil
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
