// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// scan.go implements WiFi network scanning with security assessment.
//
// On macOS it uses system_profiler SPAirPortDataType to enumerate nearby
// networks. On Linux it uses iw dev scan. Both paths parse signal strength,
// security type, WPS status, and estimate portal likelihood.
package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// ScannedNetwork represents a nearby WiFi network with security metadata.
type ScannedNetwork struct {
	SSID         string `json:"ssid"`
	BSSID        string `json:"bssid"`
	Channel      int    `json:"channel"`
	Signal       int    `json:"signal_dbm"` // dBm
	Security     string `json:"security"`   // Open, WPA2, WPA3, WPA2-Enterprise, etc.
	WPS          bool   `json:"wps"`
	Clients      int    `json:"clients"`       // approximate from probe responses
	PortalLikely bool   `json:"portal_likely"` // heuristic: Open/WPA2 + many clients
}

// ScanNetworks enumerates nearby WiFi networks on the given interface.
// Results are sorted by signal strength (strongest first).
func ScanNetworks(iface string) ([]ScannedNetwork, error) {
	// Validate interface name before passing to exec.Command.
	if _, err := platform.ValidateInterface(iface); err != nil {
		return nil, fmt.Errorf("scan networks: %w", err)
	}

	var networks []ScannedNetwork
	var err error

	switch runtime.GOOS {
	case "darwin":
		networks, err = scanDarwin()
	case "linux":
		networks, err = scanLinux(iface)
	default:
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	// Sort by signal strength descending (strongest first, least negative dBm).
	sort.Slice(networks, func(i, j int) bool {
		return networks[i].Signal > networks[j].Signal
	})

	// Apply portal heuristic.
	for i := range networks {
		n := &networks[i]
		isOpenish := strings.Contains(strings.ToLower(n.Security), "open") ||
			strings.Contains(strings.ToLower(n.Security), "none")
		if isOpenish || (n.Clients > 5 && !strings.Contains(n.Security, "Enterprise")) {
			n.PortalLikely = true
		}
	}

	return networks, nil
}

// SignalBars converts dBm to a 1-4 bar visual indicator.
func SignalBars(dBm int) string {
	switch {
	case dBm >= -50:
		return "||||"
	case dBm >= -60:
		return "|||."
	case dBm >= -70:
		return "||.."
	case dBm >= -80:
		return "|..."
	default:
		return "...."
	}
}

// --- macOS scanner via system_profiler ---

type spScanResult struct {
	SPAirPortDataType []spScanItem `json:"SPAirPortDataType"`
}

type spScanItem struct {
	Interfaces []spScanInterface `json:"spairport_airport_interfaces"`
}

type spScanInterface struct {
	OtherNetworks []spScanNetwork `json:"spairport_airport_other_local_wireless_networks"`
	CurrentNet    *spScanCurrent  `json:"spairport_current_network_information"`
}

type spScanNetwork struct {
	Name     string      `json:"_name"`
	BSSID    string      `json:"spairport_network_bssid"`
	Channel  interface{} `json:"spairport_network_channel"`
	Security string      `json:"spairport_security_mode"`
	Signal   interface{} `json:"spairport_signal_noise"`
}

type spScanCurrent struct {
	Name     string      `json:"_name"`
	BSSID    string      `json:"spairport_network_bssid"`
	Channel  interface{} `json:"spairport_network_channel"`
	Security string      `json:"spairport_security_mode"`
	Signal   interface{} `json:"spairport_signal_noise"`
}

func scanDarwin() ([]ScannedNetwork, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "system_profiler", "SPAirPortDataType", "-json").Output()
	if err != nil {
		return nil, err
	}

	var data spScanResult
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool) // BSSID dedup
	var networks []ScannedNetwork

	for _, item := range data.SPAirPortDataType {
		for _, iface := range item.Interfaces {
			// Add current network.
			if cn := iface.CurrentNet; cn != nil && cn.Name != "" {
				net := parseSPNetwork(cn.Name, cn.BSSID, cn.Channel, cn.Security, cn.Signal)
				if !seen[net.BSSID] {
					seen[net.BSSID] = true
					networks = append(networks, net)
				}
			}

			// Add other visible networks.
			for _, n := range iface.OtherNetworks {
				net := parseSPNetwork(n.Name, n.BSSID, n.Channel, n.Security, n.Signal)
				if net.SSID == "" {
					continue
				}
				if !seen[net.BSSID] {
					seen[net.BSSID] = true
					networks = append(networks, net)
				}
			}
		}
	}

	return networks, nil
}

func parseSPNetwork(name, bssid string, ch interface{}, security string, signal interface{}) ScannedNetwork {
	n := ScannedNetwork{
		SSID:     name,
		BSSID:    bssid,
		Security: normalizeSecurity(security),
		Signal:   -99,
	}

	// Parse channel.
	switch v := ch.(type) {
	case float64:
		n.Channel = int(v)
	case string:
		// Channel may be like "6" or "36 (5GHz, 80MHz)"
		parts := strings.Fields(v)
		if len(parts) > 0 {
			if c, err := strconv.Atoi(parts[0]); err == nil {
				n.Channel = c
			}
		}
	}

	// Parse signal.
	switch v := signal.(type) {
	case float64:
		n.Signal = int(v)
	case string:
		// Format: "-64 dBm / -96 dBm"
		parts := strings.Fields(v)
		if len(parts) > 0 {
			if s, err := strconv.Atoi(parts[0]); err == nil {
				n.Signal = s
			}
		}
	}

	return n
}

// --- Linux scanner via iw ---

var (
	bssRE      = regexp.MustCompile(`BSS\s+([0-9a-f:]{17})`)
	ssidRE     = regexp.MustCompile(`SSID:\s*(.+)`)
	freqRE     = regexp.MustCompile(`freq:\s*(\d+)`)
	signalRE   = regexp.MustCompile(`signal:\s*(-?\d+\.?\d*)`)
	wpsRE      = regexp.MustCompile(`(?i)WPS`)
	wpaRE      = regexp.MustCompile(`(?i)(WPA2?|RSN)`)
	wpa3RE     = regexp.MustCompile(`(?i)(SAE|WPA3)`)
	entRE      = regexp.MustCompile(`(?i)(802\.1X|EAP|Enterprise)`)
)

func scanLinux(iface string) ([]ScannedNetwork, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "sudo", "iw", "dev", iface, "scan").Output()
	if err != nil {
		return nil, err
	}

	// Split output into per-BSS blocks.
	blocks := splitBSSBlocks(string(out))

	var networks []ScannedNetwork
	for _, block := range blocks {
		n := parseBSSBlock(block)
		if n.SSID != "" {
			networks = append(networks, n)
		}
	}

	return networks, nil
}

// splitBSSBlocks splits iw scan output into per-BSS text blocks.
func splitBSSBlocks(output string) []string {
	lines := strings.Split(output, "\n")
	var blocks []string
	current := strings.Builder{}

	for _, line := range lines {
		if bssRE.MatchString(line) {
			if current.Len() > 0 {
				blocks = append(blocks, current.String())
				current.Reset()
			}
		}
		current.WriteString(line + "\n")
	}
	if current.Len() > 0 {
		blocks = append(blocks, current.String())
	}

	return blocks
}

// parseBSSBlock parses a single BSS block from iw scan output.
func parseBSSBlock(block string) ScannedNetwork {
	n := ScannedNetwork{Signal: -99}

	if m := bssRE.FindStringSubmatch(block); m != nil {
		n.BSSID = m[1]
	}
	if m := ssidRE.FindStringSubmatch(block); m != nil {
		n.SSID = strings.TrimSpace(m[1])
	}
	if m := freqRE.FindStringSubmatch(block); m != nil {
		if freq, err := strconv.Atoi(m[1]); err == nil {
			n.Channel = freqToChannel(freq)
		}
	}
	if m := signalRE.FindStringSubmatch(block); m != nil {
		if s, err := strconv.ParseFloat(m[1], 64); err == nil {
			n.Signal = int(s)
		}
	}

	// Security detection.
	n.WPS = wpsRE.MatchString(block)
	switch {
	case wpa3RE.MatchString(block):
		n.Security = "WPA3"
	case entRE.MatchString(block):
		n.Security = "WPA2-Enterprise"
	case wpaRE.MatchString(block):
		n.Security = "WPA2"
	default:
		n.Security = "Open"
	}

	return n
}

// freqToChannel converts a frequency in MHz to a WiFi channel number.
func freqToChannel(freq int) int {
	switch {
	case freq >= 2412 && freq <= 2484:
		if freq == 2484 {
			return 14
		}
		return (freq - 2412) / 5 + 1
	case freq >= 5170 && freq <= 5825:
		return (freq - 5000) / 5
	case freq >= 5955 && freq <= 7115:
		return (freq - 5950) / 5
	default:
		return 0
	}
}

// normalizeSecurity simplifies macOS security strings to consistent labels.
func normalizeSecurity(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "wpa3") || strings.Contains(lower, "sae"):
		return "WPA3"
	case strings.Contains(lower, "enterprise") || strings.Contains(lower, "802.1x"):
		return "WPA2-Enterprise"
	case strings.Contains(lower, "wpa2") || strings.Contains(lower, "wpa_wpa2"):
		return "WPA2"
	case strings.Contains(lower, "wpa"):
		return "WPA"
	case strings.Contains(lower, "wep"):
		return "WEP"
	case strings.Contains(lower, "none") || strings.Contains(lower, "open") || raw == "":
		return "Open"
	default:
		return raw
	}
}
