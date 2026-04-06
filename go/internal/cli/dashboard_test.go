// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NewDashboard (unit-safe: does not render to real terminal)
// ---------------------------------------------------------------------------

func newTestDashboard() *Dashboard {
	return &Dashboard{
		width:  80,
		height: 25,
		probes: make(map[string]probeState),
	}
}

// ---------------------------------------------------------------------------
// State setters
// ---------------------------------------------------------------------------

func TestDashboard_SetWifi(t *testing.T) {
	d := newTestDashboard()
	d.SetWifi("CoffeeShop", "36", -45)

	if d.ssid != "CoffeeShop" {
		t.Errorf("ssid = %q, want CoffeeShop", d.ssid)
	}
	if d.channel != "36" {
		t.Errorf("channel = %q, want 36", d.channel)
	}
	if d.rssi != -45 {
		t.Errorf("rssi = %d, want -45", d.rssi)
	}
	if d.wifiErr != "" {
		t.Errorf("wifiErr should be empty, got %q", d.wifiErr)
	}
}

func TestDashboard_SetWifiError(t *testing.T) {
	d := newTestDashboard()
	d.SetWifiError("en0 -- not found")

	if d.wifiErr != "en0 -- not found" {
		t.Errorf("wifiErr = %q", d.wifiErr)
	}
}

func TestDashboard_SetPortal(t *testing.T) {
	d := newTestDashboard()
	d.SetPortal("http_redirect", "Aruba", true)

	if d.portalType != "http_redirect" {
		t.Errorf("portalType = %q", d.portalType)
	}
	if d.vendor != "Aruba" {
		t.Errorf("vendor = %q", d.vendor)
	}
	if !d.isCaptive {
		t.Error("expected isCaptive=true")
	}
}

func TestDashboard_SetPortal_NoCaptive(t *testing.T) {
	d := newTestDashboard()
	d.SetPortal("none", "", false)

	if d.isCaptive {
		t.Error("expected isCaptive=false")
	}
}

func TestDashboard_SetNetwork(t *testing.T) {
	d := newTestDashboard()
	d.SetNetwork("192.168.1.1", 12, 8)

	if d.gateway != "192.168.1.1" {
		t.Errorf("gateway = %q", d.gateway)
	}
	if d.clientCount != 12 {
		t.Errorf("clientCount = %d", d.clientCount)
	}
	if d.rttMs != 8 {
		t.Errorf("rttMs = %d", d.rttMs)
	}
}

func TestDashboard_SetProbe_Open(t *testing.T) {
	d := newTestDashboard()
	d.SetProbe("DNS", true)

	if d.probes["DNS"] != probeOpen {
		t.Errorf("probes[DNS] = %d, want probeOpen", d.probes["DNS"])
	}
}

func TestDashboard_SetProbe_Closed(t *testing.T) {
	d := newTestDashboard()
	d.SetProbe("ICMP", false)

	if d.probes["ICMP"] != probeClosed {
		t.Errorf("probes[ICMP] = %d, want probeClosed", d.probes["ICMP"])
	}
}

func TestDashboard_SetProbeRunning(t *testing.T) {
	d := newTestDashboard()
	d.SetProbeRunning("QUIC")

	if d.probes["QUIC"] != probeRunning {
		t.Errorf("probes[QUIC] = %d, want probeRunning", d.probes["QUIC"])
	}
}

func TestDashboard_SetBypassing(t *testing.T) {
	d := newTestDashboard()
	d.SetBypassing("DNS tunnel")

	if d.activeBypass != "DNS tunnel" {
		t.Errorf("activeBypass = %q", d.activeBypass)
	}
	if d.spinnerTick == 0 {
		t.Error("spinnerTick should be > 0")
	}
}

func TestDashboard_AddBypass(t *testing.T) {
	d := newTestDashboard()
	d.activeBypass = "DNS tunnel" // Simulate active.
	d.AddBypass("DNS tunnel", true, "connected via dns")

	if d.activeBypass != "" {
		t.Errorf("activeBypass should be cleared, got %q", d.activeBypass)
	}
	if len(d.bypassLog) != 1 {
		t.Fatalf("bypassLog len = %d, want 1", len(d.bypassLog))
	}
	if !d.bypassLog[0].Success {
		t.Error("expected Success=true")
	}
	if d.bypassLog[0].Name != "DNS tunnel" {
		t.Errorf("Name = %q", d.bypassLog[0].Name)
	}
}

func TestDashboard_AddBypass_Multiple(t *testing.T) {
	d := newTestDashboard()
	for i := 0; i < 8; i++ {
		d.AddBypass("technique", i%2 == 0, "detail")
	}

	if len(d.bypassLog) != 8 {
		t.Errorf("bypassLog len = %d, want 8", len(d.bypassLog))
	}
}

func TestDashboard_SetConnected(t *testing.T) {
	d := newTestDashboard()
	d.SetConnected(5*time.Minute, 3)

	if !d.connected {
		t.Error("expected connected=true")
	}
	if d.uptime != 5*time.Minute {
		t.Errorf("uptime = %v", d.uptime)
	}
	if d.renewals != 3 {
		t.Errorf("renewals = %d", d.renewals)
	}
}

func TestDashboard_SetDisconnected(t *testing.T) {
	d := newTestDashboard()
	d.connected = true
	d.SetDisconnected()

	if d.connected {
		t.Error("expected connected=false")
	}
}

func TestDashboard_SetStealth(t *testing.T) {
	d := newTestDashboard()
	d.SetStealth(true, true)

	if !d.stealthTTL {
		t.Error("expected stealthTTL=true")
	}
	if !d.stealthPF {
		t.Error("expected stealthPF=true")
	}
}

func TestDashboard_SetStatus(t *testing.T) {
	d := newTestDashboard()
	d.SetStatus("testing status message")

	if d.statusMsg != "testing status message" {
		t.Errorf("statusMsg = %q", d.statusMsg)
	}
}

func TestDashboard_TickSpinner(t *testing.T) {
	d := newTestDashboard()
	initial := d.spinnerTick
	d.TickSpinner()
	if d.spinnerTick != initial+1 {
		t.Errorf("spinnerTick = %d, want %d", d.spinnerTick, initial+1)
	}
}

func TestDashboard_CloseIdempotent(t *testing.T) {
	d := newTestDashboard()
	d.Close()
	d.Close() // Should not panic.

	if !d.closed {
		t.Error("expected closed=true")
	}
}

// ---------------------------------------------------------------------------
// Display formatters
// ---------------------------------------------------------------------------

func TestDashboard_WifiDisplay_NoData(t *testing.T) {
	d := newTestDashboard()
	got := d.wifiDisplay()
	if !strings.Contains(got, "scanning") {
		t.Errorf("empty wifi should show scanning, got %q", got)
	}
}

func TestDashboard_WifiDisplay_WithData(t *testing.T) {
	d := newTestDashboard()
	d.ssid = "TestNet"
	d.channel = "6"
	d.rssi = -45
	got := d.wifiDisplay()
	if !strings.Contains(got, "TestNet") {
		t.Errorf("wifi display should contain SSID, got %q", got)
	}
}

func TestDashboard_WifiDisplay_Error(t *testing.T) {
	d := newTestDashboard()
	d.wifiErr = "interface not found"
	got := d.wifiDisplay()
	if !strings.Contains(got, "interface not found") {
		t.Errorf("wifi display should show error, got %q", got)
	}
}

func TestDashboard_WifiDisplay_WeakSignal(t *testing.T) {
	d := newTestDashboard()
	d.ssid = "Weak"
	d.channel = "1"
	d.rssi = -80
	got := d.wifiDisplay()
	// Should contain red color for weak signal.
	if !strings.Contains(got, "\033[31m") {
		t.Errorf("weak signal should use red color, got %q", got)
	}
}

func TestDashboard_WifiDisplay_MediumSignal(t *testing.T) {
	d := newTestDashboard()
	d.ssid = "Medium"
	d.channel = "11"
	d.rssi = -60
	got := d.wifiDisplay()
	// Should contain yellow color for medium signal.
	if !strings.Contains(got, "\033[33m") {
		t.Errorf("medium signal should use yellow color, got %q", got)
	}
}

func TestDashboard_PortalDisplay_Detecting(t *testing.T) {
	d := newTestDashboard()
	got := d.portalDisplay()
	if !strings.Contains(got, "detecting") {
		t.Errorf("empty portal should show detecting, got %q", got)
	}
}

func TestDashboard_PortalDisplay_Open(t *testing.T) {
	d := newTestDashboard()
	d.portalType = "none"
	d.isCaptive = false
	got := d.portalDisplay()
	if !strings.Contains(got, "open") {
		t.Errorf("no captive should show open, got %q", got)
	}
}

func TestDashboard_PortalDisplay_Captive(t *testing.T) {
	d := newTestDashboard()
	d.portalType = "http_redirect"
	d.isCaptive = true
	got := d.portalDisplay()
	if !strings.Contains(got, "http_redirect") {
		t.Errorf("captive should show type, got %q", got)
	}
}

func TestDashboard_GatewayDisplay_Empty(t *testing.T) {
	d := newTestDashboard()
	got := d.gatewayDisplay()
	if !strings.Contains(got, "---") {
		t.Errorf("empty gateway should show ---, got %q", got)
	}
}

func TestDashboard_GatewayDisplay_Set(t *testing.T) {
	d := newTestDashboard()
	d.gateway = "10.0.0.1"
	got := d.gatewayDisplay()
	if !strings.Contains(got, "10.0.0.1") {
		t.Errorf("gateway should show IP, got %q", got)
	}
}

func TestDashboard_RttDisplay_Values(t *testing.T) {
	tests := []struct {
		rtt       int
		wantColor string
	}{
		{5, "\033[32m"},   // Green.
		{50, "\033[33m"},  // Yellow.
		{200, "\033[31m"}, // Red.
	}
	for _, tt := range tests {
		d := newTestDashboard()
		d.rttMs = tt.rtt
		got := d.rttDisplay()
		if !strings.Contains(got, tt.wantColor) {
			t.Errorf("rtt %d: expected color %q in %q", tt.rtt, tt.wantColor, got)
		}
	}
}

func TestDashboard_VendorDisplay_NoCaptive(t *testing.T) {
	d := newTestDashboard()
	d.portalType = "none"
	d.isCaptive = false
	got := d.vendorDisplay()
	if !strings.Contains(got, "n/a") {
		t.Errorf("vendor with no captive should show n/a, got %q", got)
	}
}

func TestDashboard_ClientDisplay_Zero(t *testing.T) {
	d := newTestDashboard()
	got := d.clientDisplay()
	if !strings.Contains(got, "---") {
		t.Errorf("zero clients should show ---, got %q", got)
	}
}

func TestDashboard_ClientDisplay_Set(t *testing.T) {
	d := newTestDashboard()
	d.clientCount = 7
	got := d.clientDisplay()
	if !strings.Contains(got, "7") {
		t.Errorf("client display should show count, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Indicator
// ---------------------------------------------------------------------------

func TestDashboard_Indicator_Active(t *testing.T) {
	d := newTestDashboard()
	got := d.indicator(true)
	if !strings.Contains(got, "\u25C9") {
		t.Errorf("active indicator should be filled circle, got %q", got)
	}
}

func TestDashboard_Indicator_Inactive(t *testing.T) {
	d := newTestDashboard()
	got := d.indicator(false)
	if !strings.Contains(got, "\u25CB") {
		t.Errorf("inactive indicator should be empty circle, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// visLen (ANSI stripping)
// ---------------------------------------------------------------------------

func TestDashboard_VisLen_Plain(t *testing.T) {
	d := newTestDashboard()
	if got := d.visLen("hello"); got != 5 {
		t.Errorf("visLen(hello) = %d, want 5", got)
	}
}

func TestDashboard_VisLen_WithANSI(t *testing.T) {
	d := newTestDashboard()
	s := "\033[1;32mOK\033[0m"
	if got := d.visLen(s); got != 2 {
		t.Errorf("visLen(colored OK) = %d, want 2", got)
	}
}

func TestDashboard_VisLen_Empty(t *testing.T) {
	d := newTestDashboard()
	if got := d.visLen(""); got != 0 {
		t.Errorf("visLen(empty) = %d, want 0", got)
	}
}

func TestDashboard_VisLen_OnlyANSI(t *testing.T) {
	d := newTestDashboard()
	s := "\033[0m\033[1m\033[0m"
	if got := d.visLen(s); got != 0 {
		t.Errorf("visLen(only escape) = %d, want 0", got)
	}
}

func TestDashboard_VisLen_Nested(t *testing.T) {
	d := newTestDashboard()
	s := "\033[1m\033[32mAB\033[0mCD"
	if got := d.visLen(s); got != 4 {
		t.Errorf("visLen(nested) = %d, want 4", got)
	}
}

// ---------------------------------------------------------------------------
// formatUptime
// ---------------------------------------------------------------------------

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		dur  time.Duration
		want string
	}{
		{0, "00:00:00"},
		{30 * time.Second, "00:00:30"},
		{5*time.Minute + 30*time.Second, "00:05:30"},
		{2*time.Hour + 15*time.Minute + 45*time.Second, "02:15:45"},
		{100 * time.Hour, "100:00:00"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatUptime(tt.dur)
			if got != tt.want {
				t.Errorf("formatUptime(%v) = %q, want %q", tt.dur, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Box drawing primitives
// ---------------------------------------------------------------------------

func TestDashboard_BorderTop(t *testing.T) {
	d := newTestDashboard()
	got := d.borderTop(20)
	if !strings.Contains(got, "\u2554") || !strings.Contains(got, "\u2557") {
		t.Errorf("borderTop should contain corner chars, got %q", got)
	}
}

func TestDashboard_BorderBottom(t *testing.T) {
	d := newTestDashboard()
	got := d.borderBottom(20)
	if !strings.Contains(got, "\u255A") || !strings.Contains(got, "\u255D") {
		t.Errorf("borderBottom should contain corner chars, got %q", got)
	}
}

func TestDashboard_FullSep(t *testing.T) {
	d := newTestDashboard()
	got := d.fullSep(20, '\u2560', '\u2563')
	if !strings.Contains(got, "\u2560") || !strings.Contains(got, "\u2563") {
		t.Errorf("fullSep should contain junction chars, got %q", got)
	}
}

func TestDashboard_HeaderSep(t *testing.T) {
	d := newTestDashboard()
	got := d.headerSep(80, 35)
	if !strings.Contains(got, "\u2560") || !strings.Contains(got, "\u2566") {
		t.Errorf("headerSep should contain T-junction, got %q", got)
	}
}

func TestDashboard_MidColumn(t *testing.T) {
	d := newTestDashboard()
	// Width 80 -> inner 78 -> 45% = 35.
	mid := d.midColumn(78)
	if mid < 26 {
		t.Errorf("midColumn too small: %d", mid)
	}
	if mid > 78 {
		t.Errorf("midColumn too large: %d", mid)
	}
}

func TestDashboard_MidColumn_Narrow(t *testing.T) {
	d := newTestDashboard()
	// Very narrow: should clamp to minimum 26.
	mid := d.midColumn(40)
	if mid < 26 {
		t.Errorf("midColumn narrow = %d, want >= 26", mid)
	}
}

// ---------------------------------------------------------------------------
// Bypass lines builder
// ---------------------------------------------------------------------------

func TestDashboard_BypassLines_Empty(t *testing.T) {
	d := newTestDashboard()
	lines := d.bypassLines()
	if len(lines) == 0 {
		t.Fatal("bypassLines should return at least one line when empty")
	}
	if !strings.Contains(lines[0].text, "waiting") {
		t.Errorf("empty bypass lines should show waiting, got %q", lines[0].text)
	}
}

func TestDashboard_BypassLines_WithActive(t *testing.T) {
	d := newTestDashboard()
	d.activeBypass = "DNS tunnel"
	d.spinnerTick = 3

	lines := d.bypassLines()
	found := false
	for _, l := range lines {
		if strings.Contains(l.text, "DNS tunnel") {
			found = true
			break
		}
	}
	if !found {
		t.Error("bypass lines should include active technique")
	}
}

func TestDashboard_BypassLines_Scrolling(t *testing.T) {
	d := newTestDashboard()
	for i := 0; i < 10; i++ {
		d.bypassLog = append(d.bypassLog, BypassEntry{
			Name:    strings.Repeat("x", 5),
			Success: i%2 == 0,
			Detail:  "detail",
		})
	}

	lines := d.bypassLines()
	// Should show at most 4 completed + potentially 1 active = 5 max.
	if len(lines) > 5 {
		t.Errorf("bypass lines should cap at 5, got %d", len(lines))
	}
}

func TestDashboard_BypassLines_WithResults(t *testing.T) {
	d := newTestDashboard()
	d.AddBypass("IPv6 bypass", false, "not available")
	d.AddBypass("DNS tunnel", true, "connected")

	lines := d.bypassLines()
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d", len(lines))
	}

	// First should have cross mark.
	if !strings.Contains(lines[0].text, "\u2717") {
		t.Errorf("failed bypass should have cross mark: %q", lines[0].text)
	}
	// Second should have check mark.
	if !strings.Contains(lines[1].text, "\u2713") {
		t.Errorf("successful bypass should have check mark: %q", lines[1].text)
	}
}

// ---------------------------------------------------------------------------
// Session row
// ---------------------------------------------------------------------------

func TestDashboard_SessionRow_NotConnected(t *testing.T) {
	d := newTestDashboard()
	got := d.sessionRow(78)
	if !strings.Contains(got, "waiting") {
		t.Errorf("session row should show waiting when not connected: %q", got)
	}
}

func TestDashboard_SessionRow_Connected(t *testing.T) {
	d := newTestDashboard()
	d.connected = true
	d.uptime = 5 * time.Minute
	d.renewals = 2

	got := d.sessionRow(78)
	if !strings.Contains(got, "CONNECTED") {
		t.Errorf("session row should show CONNECTED: %q", got)
	}
	if !strings.Contains(got, "00:05:00") {
		t.Errorf("session row should show uptime: %q", got)
	}
	if !strings.Contains(got, "2 renewals") {
		t.Errorf("session row should show renewals: %q", got)
	}
}

func TestDashboard_SessionRow_Reconnecting(t *testing.T) {
	d := newTestDashboard()
	d.connected = false
	d.uptime = 1 * time.Minute // Was connected, now reconnecting.

	got := d.sessionRow(78)
	if !strings.Contains(got, "RECONNECTING") {
		t.Errorf("session row should show RECONNECTING: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Stealth row
// ---------------------------------------------------------------------------

func TestDashboard_StealthRow_BothEnabled(t *testing.T) {
	d := newTestDashboard()
	d.stealthTTL = true
	d.stealthPF = true
	d.connected = true

	got := d.stealthRow(78)
	if !strings.Contains(got, "TTL") || !strings.Contains(got, "PF") {
		t.Errorf("stealth row should show TTL and PF: %q", got)
	}
}

func TestDashboard_StealthRow_Disconnected(t *testing.T) {
	d := newTestDashboard()
	got := d.stealthRow(78)
	// Should show empty/dim bar.
	if !strings.Contains(got, "\u2591") {
		t.Errorf("disconnected stealth row should show dim blocks: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Status display
// ---------------------------------------------------------------------------

func TestDashboard_StatusDisplay_Default(t *testing.T) {
	d := newTestDashboard()
	got := d.statusDisplay()
	if !strings.Contains(got.text, "Ctrl+C") {
		t.Errorf("default status should mention Ctrl+C: %q", got.text)
	}
}

func TestDashboard_StatusDisplay_Custom(t *testing.T) {
	d := newTestDashboard()
	d.statusMsg = "Custom message"
	got := d.statusDisplay()
	if !strings.Contains(got.text, "Custom message") {
		t.Errorf("custom status should show message: %q", got.text)
	}
}

// ---------------------------------------------------------------------------
// Probe state constants
// ---------------------------------------------------------------------------

func TestProbeStateConstants(t *testing.T) {
	if probeUnknown != 0 {
		t.Errorf("probeUnknown = %d, want 0", probeUnknown)
	}
	if probeRunning != 1 {
		t.Errorf("probeRunning = %d, want 1", probeRunning)
	}
	if probeOpen != 2 {
		t.Errorf("probeOpen = %d, want 2", probeOpen)
	}
	if probeClosed != 3 {
		t.Errorf("probeClosed = %d, want 3", probeClosed)
	}
}

// ---------------------------------------------------------------------------
// Spinner frames
// ---------------------------------------------------------------------------

func TestSpinnerFrames(t *testing.T) {
	if len(spinnerFrames) != 10 {
		t.Errorf("spinnerFrames len = %d, want 10", len(spinnerFrames))
	}
}

// ---------------------------------------------------------------------------
// Probe names
// ---------------------------------------------------------------------------

func TestProbeNames(t *testing.T) {
	expected := []string{"DNS", "ICMP", "IPv6", "HTTPS", "QUIC", "NTP", "DoH"}
	if len(probeNames) != len(expected) {
		t.Fatalf("probeNames len = %d, want %d", len(probeNames), len(expected))
	}
	for i, name := range expected {
		if probeNames[i] != name {
			t.Errorf("probeNames[%d] = %q, want %q", i, probeNames[i], name)
		}
	}
}

// ---------------------------------------------------------------------------
// BypassEntry
// ---------------------------------------------------------------------------

func TestBypassEntry_Fields(t *testing.T) {
	e := BypassEntry{Name: "dns_tunnel", Success: true, Detail: "connected"}
	if e.Name != "dns_tunnel" {
		t.Errorf("Name = %q", e.Name)
	}
	if !e.Success {
		t.Error("expected Success=true")
	}
	if e.Detail != "connected" {
		t.Errorf("Detail = %q", e.Detail)
	}
}

// ---------------------------------------------------------------------------
// Content row padding
// ---------------------------------------------------------------------------

func TestDashboard_ContentRow_Padding(t *testing.T) {
	d := newTestDashboard()
	got := d.contentRow(40, "test", 4)

	// Should have left and right border chars.
	if !strings.Contains(got, "\u2551") {
		t.Errorf("contentRow should have border chars: %q", got)
	}
}

func TestDashboard_ContentRow_Empty(t *testing.T) {
	d := newTestDashboard()
	got := d.contentRow(40, "", 0)

	// Should be all padding between borders.
	if !strings.Contains(got, "\u2551") {
		t.Errorf("empty contentRow should have borders: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Dual pane row
// ---------------------------------------------------------------------------

func TestDashboard_DualPaneRow(t *testing.T) {
	d := newTestDashboard()
	got := d.dualPaneRow(30, 30, "left", "right", 4, 5)

	if !strings.Contains(got, "left") || !strings.Contains(got, "right") {
		t.Errorf("dual pane should contain both sides: %q", got)
	}

	// Should have 3 vertical bars (left border, middle divider, right border).
	count := strings.Count(got, "\u2551")
	if count < 3 {
		t.Errorf("dual pane should have 3 vertical bars, got %d", count)
	}
}
