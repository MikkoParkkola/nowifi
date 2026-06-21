//go:build darwin

// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package platform

import (
	"strings"
	"testing"
)

func TestNetworkServiceRE(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Hardware Port: Wi-Fi", "Wi-Fi"},
		{"Hardware Port: Ethernet", "Ethernet"},
		{"Hardware Port: USB 10/100/1000 LAN", "USB 10/100/1000 LAN"},
		{"Hardware Port:  Thunderbolt Bridge", "Thunderbolt Bridge"},
		{"Not a port line", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			match := networkServiceRE.FindStringSubmatch(tc.input)
			got := ""
			if len(match) > 1 {
				got = strings.TrimSpace(match[1])
			}
			if got != tc.want {
				t.Errorf("networkServiceRE(%q) captured %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestServiceNameRE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"Wi-Fi", "Wi-Fi", true},
		{"Ethernet", "Ethernet", true},
		{"USB 10/100/1000 LAN", "USB 10/100/1000 LAN", true},
		{"injection attempt", "Wi-Fi; rm -rf /", false},
		{"backtick injection", "Wi-Fi`id`", false},
		{"pipe injection", "Wi-Fi|cat /etc/passwd", false},
		{"empty", "", false},
		{"normal with dots", "VPN.Connection.1", true},
		{"underscores", "eth_0", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := serviceNameRE.MatchString(tc.input)
			if got != tc.valid {
				t.Errorf("serviceNameRE(%q) = %v, want %v", tc.input, got, tc.valid)
			}
		})
	}
}
