package monitor

import (
	"runtime"
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
