// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package ui provides an embedded web dashboard and system tray for nowifi.
//
// The web dashboard uses Go's embed package to bundle a single-page HTML
// application that polls /api/state via htmx for real-time updates. It
// binds to 127.0.0.1 only for security.
//
// Background goroutines (audit, diagnose, probe, reset) update the shared
// State struct, which the dashboard renders via JSON polling.
package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/probe"
)

//go:embed static/*
var staticFiles embed.FS

// State holds the dashboard state, updated by background goroutines.
type State struct {
	mu sync.RWMutex

	Status  string `json:"status"` // idle, probing, bypassing, diagnosing, active, error
	Message string `json:"message"`

	// WiFi info.
	SSID        string `json:"ssid"`
	BSSID       string `json:"bssid"`
	Channel     string `json:"channel"`
	RSSI        int    `json:"rssi"`
	Gateway     string `json:"gateway"`
	CurrentMAC  string `json:"current_mac"`
	OriginalMAC string `json:"original_mac"`

	// Portal info.
	Portal *PortalState `json:"portal"`

	// Probe results: protocol key -> status string.
	Probes map[string]ProbeStatus `json:"probes"`

	// Bypass method feasibility (from diagnose).
	Methods []MethodState `json:"methods"`

	// Bypass attempt results (from audit).
	Bypasses []BypassState `json:"bypasses"`

	// Active tunnel info.
	ActiveTunnel *TunnelState `json:"active_tunnel"`

	// Log lines.
	Log []string `json:"log"`
}

// PortalState holds detected captive portal info.
type PortalState struct {
	IsCaptive   bool     `json:"is_captive"`
	Type        string   `json:"type"`
	Vendor      string   `json:"vendor"`
	AuthMethods []string `json:"auth_methods"`
	PortalURL   string   `json:"portal_url"`
}

// ProbeStatus holds the status and detail for a single protocol probe.
type ProbeStatus struct {
	Status  string `json:"status"` // pending, running, open, closed
	Details string `json:"details"`
}

// MethodState holds bypass method feasibility info.
type MethodState struct {
	Number     int    `json:"number"`
	Name       string `json:"name"`
	Feasible   bool   `json:"feasible"`
	Confidence string `json:"confidence"` // HIGH, MEDIUM, LOW
	Reason     string `json:"reason"`
	Risk       string `json:"risk"`
}

// BypassState holds the result of a bypass attempt.
type BypassState struct {
	Method   string `json:"method"`
	Success  bool   `json:"success"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}

// TunnelState holds info about the active tunnel.
type TunnelState struct {
	Method string `json:"method"`
	Port   int    `json:"port"`
}

// ProbeNames defines the display order and labels for probes.
var ProbeNames = []struct {
	Key  string
	Name string
}{
	{"dns", "DNS (UDP/53)"},
	{"icmp", "ICMP (ping)"},
	{"ipv6", "IPv6"},
	{"cloudflare", "HTTPS (Cloudflare)"},
	{"quic", "QUIC (UDP/443)"},
	{"ntp", "NTP (UDP/123)"},
	{"doh", "DoH (HTTPS)"},
	{"whitelists", "Whitelist domains"},
	{"ports", "Open ports"},
	{"tunnel_server", "Tunnel server"},
}

// Global shared state instance.
var state = &State{
	Status: "idle",
	Probes: make(map[string]ProbeStatus),
	RSSI:   -99,
}

// GetState returns a pointer to the global state for external updates.
func GetState() *State {
	return state
}

// AppendLog adds a timestamped message to the log.
func AppendLog(msg string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	ts := time.Now().Format("15:04:05")
	state.Log = append(state.Log, fmt.Sprintf("[%s] %s", ts, msg))
	if len(state.Log) > 300 {
		state.Log = state.Log[len(state.Log)-200:]
	}
}

// Serve starts the web dashboard on the given port, bound to 127.0.0.1.
func Serve(port int) error {
	mux := http.NewServeMux()

	// Serve embedded static files.
	mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Main page.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// JSON state endpoint for htmx polling.
	mux.HandleFunc("/api/state", handleState)

	// Action endpoints.
	mux.HandleFunc("/api/audit", handleAudit)
	mux.HandleFunc("/api/diagnose", handleDiagnose)
	mux.HandleFunc("/api/probe", handleProbe)
	mux.HandleFunc("/api/reset", handleReset)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("Dashboard: http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func handleState(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	state.mu.Lock()
	if state.Status != "idle" && state.Status != "error" {
		state.mu.Unlock()
		http.Error(w, "busy", http.StatusConflict)
		return
	}
	state.Status = "probing"
	state.mu.Unlock()

	go runAuditBackground()
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprint(w, `{"ok":true}`)
}

func handleDiagnose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	state.mu.Lock()
	if state.Status != "idle" && state.Status != "error" {
		state.mu.Unlock()
		http.Error(w, "busy", http.StatusConflict)
		return
	}
	state.Status = "diagnosing"
	state.mu.Unlock()

	go runDiagnoseBackground()
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprint(w, `{"ok":true}`)
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	state.mu.Lock()
	if state.Status != "idle" && state.Status != "error" {
		state.mu.Unlock()
		http.Error(w, "busy", http.StatusConflict)
		return
	}
	state.Status = "probing"
	state.mu.Unlock()

	go runProbeBackground()
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprint(w, `{"ok":true}`)
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	go runResetBackground()
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprint(w, `{"ok":true}`)
}

// Background tasks.

func gatherWifiInfo() {
	wifi, err := platform.GetWifiInfo("en0")
	if err == nil && wifi != nil {
		state.mu.Lock()
		state.SSID = wifi.SSID
		state.BSSID = wifi.BSSID
		state.Channel = wifi.Channel
		state.RSSI = wifi.RSSI
		state.mu.Unlock()
		AppendLog(fmt.Sprintf("WiFi: %s (RSSI: %d dBm)", wifi.SSID, wifi.RSSI))
	} else {
		AppendLog("WiFi: not connected")
	}

	gw, err := platform.GetGateway("en0")
	if err == nil {
		state.mu.Lock()
		state.Gateway = gw
		state.mu.Unlock()
	}
	AppendLog(fmt.Sprintf("Gateway: %s", gw))

	mac, err := platform.GetCurrentMAC("en0")
	if err == nil {
		state.mu.Lock()
		state.CurrentMAC = mac
		if state.OriginalMAC == "" {
			state.OriginalMAC = mac
		}
		state.mu.Unlock()
	}
}

func setProbeStatus(key, status, details string) {
	state.mu.Lock()
	state.Probes[key] = ProbeStatus{Status: status, Details: details}
	state.mu.Unlock()
}

func runProbeBackground() {
	defer func() {
		if r := recover(); r != nil {
			state.mu.Lock()
			state.Status = "error"
			state.mu.Unlock()
			AppendLog(fmt.Sprintf("Error: %v", r))
		}
	}()

	gatherWifiInfo()

	// Detect portal.
	AppendLog("Detecting portal...")
	portal := detect.DetectPortal("en0")
	if portal != nil {
		state.mu.Lock()
		state.Portal = &PortalState{
			IsCaptive:   portal.IsCaptive,
			Type:        string(portal.Type),
			Vendor:      portal.Vendor,
			AuthMethods: portal.AuthMethods,
			PortalURL:   portal.PortalURL,
		}
		state.mu.Unlock()
		if portal.IsCaptive {
			AppendLog(fmt.Sprintf("Portal: CAPTIVE (%s)", portal.Type))
		} else {
			AppendLog("Portal: No captive portal detected")
		}
	}

	// Initialize all probes as pending.
	for _, p := range ProbeNames {
		setProbeStatus(p.Key, "pending", "")
	}

	// Run probes one by one with status updates.
	runProbesIncremental()

	state.mu.Lock()
	state.Status = "idle"
	state.mu.Unlock()
	AppendLog("Probe complete.")
}

func runProbesIncremental() {
	// DNS
	setProbeStatus("dns", "running", "")
	AppendLog("Probing DNS...")
	dns := probe.ProbeDNS(false)
	s := "closed"
	if dns.IsOpen {
		s = "open"
	}
	setProbeStatus("dns", s, dns.Details)
	AppendLog(fmt.Sprintf("  DNS: %s -- %s", statusLabel(dns.IsOpen), dns.Details))

	// ICMP
	setProbeStatus("icmp", "running", "")
	AppendLog("Probing ICMP...")
	icmp := probe.ProbeICMP(false)
	s = "closed"
	if icmp.IsOpen {
		s = "open"
	}
	setProbeStatus("icmp", s, icmp.Details)
	AppendLog(fmt.Sprintf("  ICMP: %s -- %s", statusLabel(icmp.IsOpen), icmp.Details))

	// IPv6
	setProbeStatus("ipv6", "running", "")
	AppendLog("Probing IPv6...")
	ipv6 := probe.ProbeIPv6("en0")
	s = "closed"
	if ipv6.IsOpen {
		s = "open"
	}
	setProbeStatus("ipv6", s, ipv6.Details)
	AppendLog(fmt.Sprintf("  IPv6: %s -- %s", statusLabel(ipv6.IsOpen), ipv6.Details))

	// HTTPS (Cloudflare)
	setProbeStatus("cloudflare", "running", "")
	AppendLog("Probing HTTPS (Cloudflare)...")
	cf := probe.ProbeHTTPS("https://1.1.1.1", "Cloudflare")
	s = "closed"
	if cf.IsOpen {
		s = "open"
	}
	setProbeStatus("cloudflare", s, cf.Details)
	AppendLog(fmt.Sprintf("  HTTPS: %s -- %s", statusLabel(cf.IsOpen), cf.Details))

	// QUIC
	setProbeStatus("quic", "running", "")
	AppendLog("Probing QUIC...")
	quic := probe.ProbeQUIC("1.1.1.1", false)
	s = "closed"
	if quic.IsOpen {
		s = "open"
	}
	setProbeStatus("quic", s, quic.Details)
	AppendLog(fmt.Sprintf("  QUIC: %s -- %s", statusLabel(quic.IsOpen), quic.Details))

	// NTP
	setProbeStatus("ntp", "running", "")
	AppendLog("Probing NTP...")
	ntp := probe.ProbeNTP(false)
	s = "closed"
	if ntp.IsOpen {
		s = "open"
	}
	setProbeStatus("ntp", s, ntp.Details)
	AppendLog(fmt.Sprintf("  NTP: %s -- %s", statusLabel(ntp.IsOpen), ntp.Details))

	// DoH
	setProbeStatus("doh", "running", "")
	AppendLog("Probing DoH...")
	doh := probe.ProbeDoH(false)
	s = "closed"
	if doh.IsOpen {
		s = "open"
	}
	setProbeStatus("doh", s, doh.Details)
	AppendLog(fmt.Sprintf("  DoH: %s -- %s", statusLabel(doh.IsOpen), doh.Details))

	// Whitelists
	setProbeStatus("whitelists", "running", "")
	AppendLog("Probing whitelist domains...")
	wl := probe.ProbeWhitelists(false)
	openCount := 0
	for _, w := range wl {
		if w.IsOpen {
			openCount++
		}
	}
	s = "closed"
	if openCount > 0 {
		s = "open"
	}
	setProbeStatus("whitelists", s, fmt.Sprintf("%d/%d accessible", openCount, len(wl)))
	AppendLog(fmt.Sprintf("  Whitelists: %d/%d accessible", openCount, len(wl)))

	// Ports
	setProbeStatus("ports", "running", "")
	AppendLog("Probing outbound ports...")
	ports := probe.ProbePorts("1.1.1.1", false)
	openPorts := 0
	for _, p := range ports {
		if p.IsOpen {
			openPorts++
		}
	}
	s = "closed"
	if openPorts > 0 {
		s = "open"
	}
	setProbeStatus("ports", s, fmt.Sprintf("%d open", openPorts))
	AppendLog(fmt.Sprintf("  Ports: %d open", openPorts))

	// Tunnel server (not configured in dashboard mode).
	setProbeStatus("tunnel_server", "closed", "No tunnel server configured")

	AppendLog("All probes complete.")
}

func runDiagnoseBackground() {
	defer func() {
		if r := recover(); r != nil {
			state.mu.Lock()
			state.Status = "error"
			state.mu.Unlock()
			AppendLog(fmt.Sprintf("Error: %v", r))
		}
	}()

	gatherWifiInfo()

	// Detect portal.
	AppendLog("Detecting portal...")
	portal := detect.DetectPortal("en0")
	if portal != nil {
		state.mu.Lock()
		state.Portal = &PortalState{
			IsCaptive:   portal.IsCaptive,
			Type:        string(portal.Type),
			Vendor:      portal.Vendor,
			AuthMethods: portal.AuthMethods,
			PortalURL:   portal.PortalURL,
		}
		state.mu.Unlock()
		if portal.IsCaptive {
			AppendLog(fmt.Sprintf("Portal: CAPTIVE (%s)", portal.Type))
		} else {
			AppendLog("Portal: No captive portal detected")
		}
	}

	// Initialize and run probes.
	for _, p := range ProbeNames {
		setProbeStatus(p.Key, "pending", "")
	}
	runProbesIncremental()

	// Assess bypass methods (read-only).
	AppendLog("Assessing bypass methods (read-only)...")
	methods := assessMethods()
	state.mu.Lock()
	state.Methods = methods
	state.mu.Unlock()
	feasible := 0
	for _, m := range methods {
		if m.Feasible {
			feasible++
		}
	}
	AppendLog(fmt.Sprintf("Assessment: %d/%d methods feasible", feasible, len(methods)))

	state.mu.Lock()
	state.Status = "idle"
	state.mu.Unlock()
	AppendLog("Diagnosis complete.")
}

func runAuditBackground() {
	defer func() {
		if r := recover(); r != nil {
			state.mu.Lock()
			state.Status = "error"
			state.mu.Unlock()
			AppendLog(fmt.Sprintf("Error: %v", r))
		}
	}()

	gatherWifiInfo()

	// Detect portal.
	AppendLog("Detecting portal...")
	portal := detect.DetectPortal("en0")
	if portal != nil {
		state.mu.Lock()
		state.Portal = &PortalState{
			IsCaptive:   portal.IsCaptive,
			Type:        string(portal.Type),
			Vendor:      portal.Vendor,
			AuthMethods: portal.AuthMethods,
			PortalURL:   portal.PortalURL,
		}
		state.mu.Unlock()
		if portal.IsCaptive {
			AppendLog(fmt.Sprintf("Portal: CAPTIVE (%s)", portal.Type))
		} else {
			AppendLog("Portal: No captive portal detected")
		}
	}

	// Run probes.
	for _, p := range ProbeNames {
		setProbeStatus(p.Key, "pending", "")
	}
	runProbesIncremental()

	// Assess methods.
	methods := assessMethods()
	state.mu.Lock()
	state.Methods = methods
	state.mu.Unlock()

	// In a full audit, bypass attempts would run here.
	// For now, we report what would happen.
	if portal != nil && portal.IsCaptive {
		state.mu.Lock()
		state.Status = "bypassing"
		state.mu.Unlock()
		AppendLog("Portal is captive. Bypass execution not yet wired to dashboard.")
		AppendLog("Run `sudo nowifi` from the terminal for full bypass pipeline.")
	} else {
		AppendLog("No captive portal detected. Network appears open.")
	}

	state.mu.Lock()
	state.Status = "idle"
	state.mu.Unlock()
	AppendLog("Audit complete.")
}

func runResetBackground() {
	AppendLog("Resetting network...")
	state.mu.Lock()
	state.Status = "idle"
	state.Portal = nil
	state.Probes = make(map[string]ProbeStatus)
	state.Methods = nil
	state.Bypasses = nil
	state.ActiveTunnel = nil
	state.Message = ""
	state.mu.Unlock()
	AppendLog("State cleared. Run a new probe or audit.")
}

// assessMethods returns a static feasibility assessment based on probe results.
// This matches the 19 bypass techniques from the bypass package.
func assessMethods() []MethodState {
	state.mu.RLock()
	probes := state.Probes
	state.mu.RUnlock()

	isOpen := func(key string) bool {
		p, ok := probes[key]
		return ok && p.Status == "open"
	}

	return []MethodState{
		{1, "IPv6 bypass", isOpen("ipv6"), "HIGH", "IPv6 unfiltered by portal", "None (read-only)"},
		{2, "HTTPS/WS tunnel", isOpen("cloudflare"), "HIGH", "HTTPS outbound open", "Needs tunnel server"},
		{3, "CNA User-Agent spoof", true, "MEDIUM", "Always possible to attempt", "Detected by portal logs"},
		{4, "JS-only bypass", true, "LOW", "Requires portal analysis", "Portal-dependent"},
		{5, "HTTP CONNECT abuse", isOpen("cloudflare"), "MEDIUM", "HTTP outbound required", "Transparent proxy needed"},
		{6, "MAC clone (idle)", true, "HIGH", "ARP table has targets", "MAC change visible"},
		{7, "MAC clone (any)", true, "HIGH", "ARP table has targets", "Disconnects victim"},
		{8, "DNS tunnel", isOpen("dns"), "HIGH", "DNS UDP/53 open", "Needs DNS tunnel server"},
		{9, "ICMP tunnel", isOpen("icmp"), "HIGH", "ICMP open to external", "Needs ICMP tunnel server"},
		{10, "VPN on port 53", isOpen("dns"), "MEDIUM", "UDP/53 open", "Needs VPN server on 53"},
		{11, "Whitelist domain abuse", isOpen("whitelists"), "LOW", "Whitelisted domains found", "Domain fronting required"},
		{12, "Session cookie replay", true, "LOW", "Requires traffic capture", "Needs monitor mode"},
		{13, "Portal default creds", true, "LOW", "Try common passwords", "Rate-limited by portal"},
		{14, "MAC rotate", true, "MEDIUM", "Always possible", "MAC change visible"},
		{15, "DHCP rotate", true, "MEDIUM", "Always possible", "New IP lease"},
		{16, "QUIC tunnel", isOpen("quic"), "HIGH", "UDP/443 open", "Needs Hysteria2 server"},
		{17, "CF Workers proxy", isOpen("cloudflare"), "MEDIUM", "HTTPS open to Cloudflare", "Free CF account required"},
		{18, "NTP tunnel", isOpen("ntp"), "HIGH", "NTP open", "Needs NTP tunnel server"},
		{19, "DoH tunnel", isOpen("doh"), "MEDIUM", "DoH reachable", "DNS-over-HTTPS channel"},
	}
}

func statusLabel(isOpen bool) string {
	if isOpen {
		return "OPEN"
	}
	return "CLOSED"
}
