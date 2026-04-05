// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package monitor

import (
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// CheckSupport
// ---------------------------------------------------------------------------

func TestCheckSupport_DarwinEn0(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only test")
	}
	// macOS built-in WiFi (en0) never supports monitor mode.
	if CheckSupport("en0") {
		t.Error("CheckSupport(en0) = true on macOS, want false (built-in card)")
	}
}

func TestCheckSupport_NonexistentInterface(t *testing.T) {
	// A fake interface name should return false on any OS.
	if CheckSupport("zzz_nonexistent_99") {
		t.Error("CheckSupport on nonexistent interface = true, want false")
	}
}

func TestCheckSupport_TableDriven(t *testing.T) {
	tests := []struct {
		name  string
		iface string
		want  bool
		skip  string // skip reason if not applicable
	}{
		{
			name:  "darwin en0 returns false",
			iface: "en0",
			want:  false,
			skip:  "linux", // only run on darwin
		},
		{
			name:  "nonexistent interface",
			iface: "fake_iface_xyz",
			want:  false,
		},
		{
			name:  "empty string",
			iface: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip != "" && runtime.GOOS == tt.skip {
				t.Skipf("skipping on %s", runtime.GOOS)
			}
			got := CheckSupport(tt.iface)
			if got != tt.want {
				t.Errorf("CheckSupport(%q) = %v, want %v", tt.iface, got, tt.want)
			}
		})
	}
}

func TestCheckSupport_UnsupportedOS(t *testing.T) {
	// On non-Linux, non-Darwin, CheckSupport always returns false.
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		if CheckSupport("wlan0") {
			t.Error("CheckSupport should return false on unsupported OS")
		}
	}
}

// ---------------------------------------------------------------------------
// checkSupportDarwin — specific darwin tests
// ---------------------------------------------------------------------------

func TestCheckSupportDarwin_En0AlwaysFalse(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	if checkSupportDarwin("en0") {
		t.Error("checkSupportDarwin(en0) should always be false")
	}
}

func TestCheckSupportDarwin_NonexistentFalse(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	if checkSupportDarwin("zzzfake99") {
		t.Error("checkSupportDarwin(nonexistent) should be false")
	}
}

// ---------------------------------------------------------------------------
// Interface type
// ---------------------------------------------------------------------------

func TestInterfaceStruct(t *testing.T) {
	iface := Interface{
		Name:         "wlan0mon",
		OriginalName: "wlan0",
		WasManaged:   true,
	}

	if iface.Name != "wlan0mon" {
		t.Errorf("Name = %q, want wlan0mon", iface.Name)
	}
	if iface.OriginalName != "wlan0" {
		t.Errorf("OriginalName = %q, want wlan0", iface.OriginalName)
	}
	if !iface.WasManaged {
		t.Error("WasManaged = false, want true")
	}
}

func TestInterfaceStruct_ZeroValue(t *testing.T) {
	var iface Interface
	if iface.Name != "" || iface.OriginalName != "" || iface.WasManaged {
		t.Error("zero-value Interface should have empty fields and false WasManaged")
	}
}

func TestInterfaceStruct_MonitorSuffix(t *testing.T) {
	// Common pattern: monitor mode adds "mon" suffix.
	iface := Interface{Name: "wlan0mon", OriginalName: "wlan0", WasManaged: true}
	if !strings.HasSuffix(iface.Name, "mon") {
		t.Errorf("monitor interface %q doesn't end in 'mon'", iface.Name)
	}
	if !strings.HasPrefix(iface.Name, iface.OriginalName) {
		t.Errorf("monitor name %q should start with original %q", iface.Name, iface.OriginalName)
	}
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

func TestNewGuard(t *testing.T) {
	g := NewGuard("wlan0")
	if g == nil {
		t.Fatal("NewGuard returned nil")
	}
	if g.iface != "wlan0" {
		t.Errorf("Guard.iface = %q, want wlan0", g.iface)
	}
	if g.monitor != nil {
		t.Error("Guard.monitor should be nil before Enable")
	}
}

func TestNewGuard_DifferentInterfaces(t *testing.T) {
	ifaces := []string{"wlan0", "wlan1", "ath0", "en1"}
	for _, name := range ifaces {
		g := NewGuard(name)
		if g.iface != name {
			t.Errorf("NewGuard(%q).iface = %q", name, g.iface)
		}
	}
}

func TestGuardClose_Idempotent(t *testing.T) {
	g := NewGuard("wlan0")
	// Close without Enable should be safe and return nil.
	if err := g.Close(); err != nil {
		t.Errorf("first Close() error = %v, want nil", err)
	}
	if err := g.Close(); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
	if err := g.Close(); err != nil {
		t.Errorf("third Close() error = %v, want nil", err)
	}
}

func TestGuardClose_NilMonitor(t *testing.T) {
	g := &Guard{iface: "test0", monitor: nil}
	if err := g.Close(); err != nil {
		t.Errorf("Close with nil monitor: %v", err)
	}
}

func TestGuardClose_NotManaged(t *testing.T) {
	// If WasManaged is false, Close should not attempt to disable.
	g := &Guard{
		iface:   "test0",
		monitor: &Interface{Name: "test0", OriginalName: "test0", WasManaged: false},
	}
	if err := g.Close(); err != nil {
		t.Errorf("Close with WasManaged=false: %v", err)
	}
}

func TestGuardClose_ClearsMonitor(t *testing.T) {
	// After Close with WasManaged=true, g.monitor should be nil.
	g := &Guard{
		iface:   "test0",
		monitor: &Interface{Name: "test0", OriginalName: "test0", WasManaged: true},
	}
	// Close will try to call Disable which calls platform-specific code.
	// On darwin with a fake interface it will fail, but monitor should still
	// be set to nil (that's the contract). The error itself is acceptable.
	_ = g.Close()
	if g.monitor != nil {
		t.Error("Guard.monitor should be nil after Close")
	}
}

// ---------------------------------------------------------------------------
// Enable — platform gate tests
// ---------------------------------------------------------------------------

func TestEnable_DarwinEn0Fails(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	_, err := Enable("en0")
	if err == nil {
		t.Error("Enable(en0) on darwin should return error")
	}
	if !strings.Contains(err.Error(), "built-in WiFi") {
		t.Errorf("error = %q, want to mention built-in WiFi", err.Error())
	}
}

func TestEnable_UnsupportedOS(t *testing.T) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		t.Skip("only for unsupported OS")
	}
	_, err := Enable("wlan0")
	if err == nil {
		t.Error("Enable should fail on unsupported OS")
	}
}

// ---------------------------------------------------------------------------
// enableDarwin — en0 rejection
// ---------------------------------------------------------------------------

func TestEnableDarwin_En0Error(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	_, err := enableDarwin("en0")
	if err == nil {
		t.Error("enableDarwin(en0) should return error")
	}
}

// ---------------------------------------------------------------------------
// Disable nil safety
// ---------------------------------------------------------------------------

func TestDisable_NilInterface(t *testing.T) {
	if err := Disable(nil); err != nil {
		t.Errorf("Disable(nil) = %v, want nil", err)
	}
}

func TestDisable_NotManaged(t *testing.T) {
	mon := &Interface{Name: "wlan0", OriginalName: "wlan0", WasManaged: false}
	if err := Disable(mon); err != nil {
		t.Errorf("Disable(WasManaged=false) = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// FindInterfaces
// ---------------------------------------------------------------------------

func TestFindInterfaces_DoesNotPanic(t *testing.T) {
	// Should not panic on any platform, even if no wireless interfaces exist.
	ifaces := FindInterfaces()
	// Result may be nil or empty on CI -- that's fine.
	_ = ifaces
}

func TestFindInterfaces_ResultTypeSlice(t *testing.T) {
	ifaces := FindInterfaces()
	// Even if nil, it should be a valid []string.
	for _, name := range ifaces {
		if name == "" {
			t.Error("FindInterfaces returned empty string in results")
		}
	}
}

// ---------------------------------------------------------------------------
// Regex patterns used internally — test as pure functions
// ---------------------------------------------------------------------------

func TestAirmonOutputRegex(t *testing.T) {
	// enableLinux uses this regex to parse airmon-ng output.
	re := regexp.MustCompile(`\(monitor mode.*enabled on (\S+)\)`)

	tests := []struct {
		input string
		want  string
	}{
		{"(monitor mode enabled on wlan0mon)", "wlan0mon"},
		{"(monitor mode vif enabled on wlan1mon)", "wlan1mon"},
		{"no match here", ""},
	}
	for _, tt := range tests {
		m := re.FindStringSubmatch(tt.input)
		got := ""
		if len(m) > 1 {
			got = m[1]
		}
		if got != tt.want {
			t.Errorf("airmon regex on %q: got %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIwDevInterfaceRegex(t *testing.T) {
	// findInterfacesLinux uses this regex to parse "iw dev" output.
	re := regexp.MustCompile(`Interface\s+(\S+)`)

	tests := []struct {
		input string
		want  []string
	}{
		{"Interface wlan0\n\ttype managed", []string{"wlan0"}},
		{"Interface wlan0\nInterface wlan1", []string{"wlan0", "wlan1"}},
		{"no interfaces here", nil},
		{"", nil},
	}
	for _, tt := range tests {
		matches := re.FindAllStringSubmatch(tt.input, -1)
		var got []string
		for _, m := range matches {
			got = append(got, m[1])
		}
		if len(got) != len(tt.want) {
			t.Errorf("iw dev regex on %q: got %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("iw dev regex[%d]: got %q, want %q", i, got[i], tt.want[i])
			}
		}
	}
}

func TestWiphyRegex(t *testing.T) {
	// getPhyForInterface uses this regex to parse "iw dev <iface> info".
	re := regexp.MustCompile(`wiphy\s+(\d+)`)

	tests := []struct {
		input string
		want  string
	}{
		{"wiphy 0", "0"},
		{"wiphy 3", "3"},
		{"wiphy 42", "42"},
		{"no phy", ""},
	}
	for _, tt := range tests {
		m := re.FindStringSubmatch(tt.input)
		got := ""
		if len(m) > 1 {
			got = m[1]
		}
		if got != tt.want {
			t.Errorf("wiphy regex on %q: got %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestProcWirelessRegex(t *testing.T) {
	// findInterfacesLinux fallback parses /proc/net/wireless.
	re := regexp.MustCompile(`^\s*(\S+):`)

	tests := []struct {
		input string
		want  string
	}{
		{"  wlan0: 0000  ...", "wlan0"},
		{"wlan1: 0000  ...", "wlan1"},
		{"Inter-| sta-|   Quality", ""},
		{" face | tus", ""},
	}
	for _, tt := range tests {
		m := re.FindStringSubmatch(tt.input)
		got := ""
		if len(m) > 1 {
			got = m[1]
		}
		if got != tt.want {
			t.Errorf("proc wireless regex on %q: got %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Mode detection logic (iw phy output parsing)
// ---------------------------------------------------------------------------

func TestMonitorModeInIwPhyOutput(t *testing.T) {
	// Simulate the iw phy parsing logic from checkSupportLinux.
	output := `Wiphy phy0
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * monitor
		 * P2P-client`

	inModes := false
	foundMonitor := false
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Supported interface modes:") {
			inModes = true
			continue
		}
		if inModes {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "* monitor") {
				foundMonitor = true
				break
			}
			if trimmed != "" && !strings.HasPrefix(trimmed, "*") {
				inModes = false
			}
		}
	}
	if !foundMonitor {
		t.Error("should detect monitor mode in iw phy output")
	}
}

func TestMonitorModeNotInIwPhyOutput(t *testing.T) {
	output := `Wiphy phy0
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
	Band 1:`

	inModes := false
	foundMonitor := false
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Supported interface modes:") {
			inModes = true
			continue
		}
		if inModes {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "* monitor") {
				foundMonitor = true
				break
			}
			if trimmed != "" && !strings.HasPrefix(trimmed, "*") {
				inModes = false
			}
		}
	}
	if foundMonitor {
		t.Error("should NOT detect monitor mode when absent")
	}
}

// ---------------------------------------------------------------------------
// Interface filtering logic (findInterfacesDarwin skip prefixes)
// ---------------------------------------------------------------------------

func TestDarwinSkipPrefixes(t *testing.T) {
	skipPrefixes := []string{"lo", "gif", "stf", "bridge", "utun", "awdl", "llw", "ap"}

	tests := []struct {
		iface string
		skip  bool
	}{
		{"lo0", true},
		{"gif0", true},
		{"stf0", true},
		{"bridge0", true},
		{"utun0", true},
		{"awdl0", true},
		{"llw0", true},
		{"ap1", true},
		{"en0", false}, // en0 is special-cased separately
		{"en1", false},
		{"wlan0", false},
	}

	for _, tt := range tests {
		shouldSkip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(tt.iface, prefix) {
				shouldSkip = true
				break
			}
		}
		if shouldSkip != tt.skip {
			t.Errorf("interface %q: skip=%v, want %v", tt.iface, shouldSkip, tt.skip)
		}
	}
}

// ---------------------------------------------------------------------------
// getPhyForInterface — non-existent interface
// ---------------------------------------------------------------------------

func TestGetPhyForInterface_NonExistent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	phy := getPhyForInterface("zzz_nonexistent_99")
	if phy != "" {
		t.Errorf("getPhyForInterface(nonexistent) = %q, want empty", phy)
	}
}
