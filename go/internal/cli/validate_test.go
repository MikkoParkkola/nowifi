// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// validateFlags — unit tests via direct calls (no cobra execution)
// ---------------------------------------------------------------------------

func TestValidateFlags_ValidInterface(t *testing.T) {
	// Save and restore flags.
	orig := flagInterface
	defer func() { flagInterface = orig }()

	flagInterface = "en0"
	err := validateFlags(rootCmd, nil)
	if err != nil {
		t.Errorf("validateFlags with en0: %v", err)
	}
}

func TestValidateFlags_ValidInterfaces(t *testing.T) {
	orig := flagInterface
	defer func() { flagInterface = orig }()

	valid := []string{"en0", "en1", "wlan0", "wlan1", "eth0", "br0"}
	for _, iface := range valid {
		t.Run(iface, func(t *testing.T) {
			flagInterface = iface
			// Reset optional flags.
			flagTunnelServer = ""
			flagDNSDomain = ""
			flagICMPServer = ""
			flagCFWorkers = ""
			flagQUICServer = ""
			flagNTPServer = ""
			if err := validateFlags(rootCmd, nil); err != nil {
				t.Errorf("validateFlags with %q: %v", iface, err)
			}
		})
	}
}

func TestValidateFlags_InvalidInterface(t *testing.T) {
	orig := flagInterface
	defer func() { flagInterface = orig }()

	invalid := []string{"../../etc", "en0;rm -rf /", "en0 && evil", ""}
	for _, iface := range invalid {
		t.Run(iface, func(t *testing.T) {
			flagInterface = iface
			err := validateFlags(rootCmd, nil)
			if err == nil {
				t.Errorf("validateFlags should reject interface %q", iface)
			}
			if !strings.Contains(err.Error(), "--interface") {
				t.Errorf("error should mention --interface: %v", err)
			}
		})
	}
}

func TestValidateFlags_ValidTunnelServer(t *testing.T) {
	orig := flagInterface
	origTS := flagTunnelServer
	defer func() { flagInterface = orig; flagTunnelServer = origTS }()

	flagInterface = "en0"
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagTunnelServer = "https://tunnel.example.com:8443"
	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with valid tunnel: %v", err)
	}
}

func TestValidateFlags_InvalidTunnelServer(t *testing.T) {
	orig := flagInterface
	origTS := flagTunnelServer
	defer func() { flagInterface = orig; flagTunnelServer = origTS }()

	flagInterface = "en0"
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagTunnelServer = "not a url %%"
	err := validateFlags(rootCmd, nil)
	if err == nil {
		t.Error("validateFlags should reject invalid tunnel server URL")
	}
}

func TestValidateFlags_ValidICMPServer(t *testing.T) {
	orig := flagInterface
	origICMP := flagICMPServer
	defer func() { flagInterface = orig; flagICMPServer = origICMP }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagICMPServer = "192.168.1.1"
	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with valid ICMP server: %v", err)
	}
}

func TestValidateFlags_InvalidICMPServer(t *testing.T) {
	orig := flagInterface
	origICMP := flagICMPServer
	defer func() { flagInterface = orig; flagICMPServer = origICMP }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagICMPServer = "not-an-ip"
	err := validateFlags(rootCmd, nil)
	if err == nil {
		t.Error("validateFlags should reject invalid ICMP server IP")
	}
	if !strings.Contains(err.Error(), "--icmp-server") {
		t.Errorf("error should mention --icmp-server: %v", err)
	}
}

func TestValidateFlags_ValidNTPServer(t *testing.T) {
	orig := flagInterface
	origNTP := flagNTPServer
	defer func() { flagInterface = orig; flagNTPServer = origNTP }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""

	flagNTPServer = "10.0.0.1"
	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with valid NTP server: %v", err)
	}
}

func TestValidateFlags_InvalidNTPServer(t *testing.T) {
	orig := flagInterface
	origNTP := flagNTPServer
	defer func() { flagInterface = orig; flagNTPServer = origNTP }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""

	flagNTPServer = "abc.def.ghi"
	err := validateFlags(rootCmd, nil)
	if err == nil {
		t.Error("validateFlags should reject invalid NTP server IP")
	}
	if !strings.Contains(err.Error(), "--ntp-server") {
		t.Errorf("error should mention --ntp-server: %v", err)
	}
}

func TestValidateFlags_ValidCFWorkers(t *testing.T) {
	orig := flagInterface
	origCF := flagCFWorkers
	defer func() { flagInterface = orig; flagCFWorkers = origCF }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagCFWorkers = "https://my-worker.example.workers.dev"
	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with valid CF workers: %v", err)
	}
}

func TestValidateFlags_EmptyOptionals(t *testing.T) {
	orig := flagInterface
	defer func() { flagInterface = orig }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""
	flagVPNServer = ""

	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with all empty optionals: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateFlags — DNS domain validation
// ---------------------------------------------------------------------------

func TestValidateFlags_ValidDNSDomain(t *testing.T) {
	orig := flagInterface
	origDNS := flagDNSDomain
	defer func() { flagInterface = orig; flagDNSDomain = origDNS }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagDNSDomain = "tunnel.example.com"
	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with valid DNS domain: %v", err)
	}
}

func TestValidateFlags_InvalidDNSDomain(t *testing.T) {
	orig := flagInterface
	origDNS := flagDNSDomain
	defer func() { flagInterface = orig; flagDNSDomain = origDNS }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagDNSDomain = "not a valid domain!@#$"
	err := validateFlags(rootCmd, nil)
	if err == nil {
		t.Error("validateFlags should reject invalid DNS domain")
	}
	if !strings.Contains(err.Error(), "--dns-domain") {
		t.Errorf("error should mention --dns-domain: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateFlags — QUIC server validation
// ---------------------------------------------------------------------------

func TestValidateFlags_ValidQUICServer(t *testing.T) {
	orig := flagInterface
	origQUIC := flagQUICServer
	defer func() { flagInterface = orig; flagQUICServer = origQUIC }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagNTPServer = ""

	flagQUICServer = "quic.example.com:443"
	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with valid QUIC server: %v", err)
	}
}

func TestValidateFlags_InvalidQUICServer(t *testing.T) {
	orig := flagInterface
	origQUIC := flagQUICServer
	defer func() { flagInterface = orig; flagQUICServer = origQUIC }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagNTPServer = ""

	flagQUICServer = "not valid server!!"
	err := validateFlags(rootCmd, nil)
	if err == nil {
		t.Error("validateFlags should reject invalid QUIC server")
	}
	if !strings.Contains(err.Error(), "--quic-server") {
		t.Errorf("error should mention --quic-server: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateFlags — VPN server validation
// ---------------------------------------------------------------------------

func TestValidateFlags_ValidVPNServer(t *testing.T) {
	orig := flagInterface
	origVPN := flagVPNServer
	defer func() { flagInterface = orig; flagVPNServer = origVPN }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagVPNServer = "vpn.example.com:51820"
	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with valid VPN server: %v", err)
	}
}

func TestValidateFlags_InvalidVPNServer(t *testing.T) {
	orig := flagInterface
	origVPN := flagVPNServer
	defer func() { flagInterface = orig; flagVPNServer = origVPN }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagCFWorkers = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagVPNServer = "vpn server!"
	err := validateFlags(rootCmd, nil)
	if err == nil {
		t.Fatal("validateFlags should reject invalid VPN server")
	}
	if !strings.Contains(err.Error(), "--vpn-server") {
		t.Errorf("error should mention --vpn-server: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateFlags — CF Workers invalid
// ---------------------------------------------------------------------------

func TestValidateFlags_InvalidCFWorkers(t *testing.T) {
	orig := flagInterface
	origCF := flagCFWorkers
	defer func() { flagInterface = orig; flagCFWorkers = origCF }()

	flagInterface = "en0"
	flagTunnelServer = ""
	flagDNSDomain = ""
	flagICMPServer = ""
	flagQUICServer = ""
	flagNTPServer = ""

	flagCFWorkers = "not a url %%"
	err := validateFlags(rootCmd, nil)
	if err == nil {
		t.Error("validateFlags should reject invalid CF workers URL")
	}
	if !strings.Contains(err.Error(), "--cf-workers") {
		t.Errorf("error should mention --cf-workers: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateFlags — all flags set with valid values
// ---------------------------------------------------------------------------

func TestValidateFlags_AllFlagsValid(t *testing.T) {
	orig := flagInterface
	origTS := flagTunnelServer
	origDNS := flagDNSDomain
	origICMP := flagICMPServer
	origCF := flagCFWorkers
	origQUIC := flagQUICServer
	origNTP := flagNTPServer
	origVPN := flagVPNServer
	defer func() {
		flagInterface = orig
		flagTunnelServer = origTS
		flagDNSDomain = origDNS
		flagICMPServer = origICMP
		flagCFWorkers = origCF
		flagQUICServer = origQUIC
		flagNTPServer = origNTP
		flagVPNServer = origVPN
	}()

	flagInterface = "en0"
	flagTunnelServer = "https://tunnel.example.com:8443"
	flagDNSDomain = "tunnel.example.com"
	flagICMPServer = "10.0.0.1"
	flagCFWorkers = "https://worker.example.workers.dev"
	flagQUICServer = "quic.example.com:443"
	flagNTPServer = "192.168.1.100"
	flagVPNServer = "vpn.example.com:51820"

	if err := validateFlags(rootCmd, nil); err != nil {
		t.Errorf("validateFlags with all valid flags: %v", err)
	}
}
