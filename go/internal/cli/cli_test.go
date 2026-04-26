// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/probe"
)

// ---------------------------------------------------------------------------
// rootCmd properties
// ---------------------------------------------------------------------------

func TestRootCmd_Use(t *testing.T) {
	if rootCmd.Use != "nowifi" {
		t.Errorf("rootCmd.Use = %q, want %q", rootCmd.Use, "nowifi")
	}
}

func TestRootCmd_Short(t *testing.T) {
	if rootCmd.Short != "No WiFi? Now WiFi." {
		t.Errorf("rootCmd.Short = %q, want %q", rootCmd.Short, "No WiFi? Now WiFi.")
	}
}

// ---------------------------------------------------------------------------
// Subcommands registered
// ---------------------------------------------------------------------------

func TestSubcommandsRegistered(t *testing.T) {
	expected := []string{
		"crack",
		"diagnose",
		"tools",
		"reset",
		"server",
		"ecosystem",
		"doctor",
		"config",
		"setup",
		"ui",
		"menubar",
		"scan",
		"history",
		"watch",
	}

	commands := rootCmd.Commands()
	registered := make(map[string]bool, len(commands))
	for _, cmd := range commands {
		registered[cmd.Name()] = true
	}

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			if !registered[name] {
				t.Errorf("subcommand %q not registered on rootCmd", name)
			}
		})
	}
}

func TestSubcommandCount(t *testing.T) {
	// At minimum, the expected subcommands should be present.
	count := len(rootCmd.Commands())
	if count < 14 {
		t.Errorf("rootCmd has %d subcommands, want >= 14", count)
	}
}

// ---------------------------------------------------------------------------
// --version flag
// ---------------------------------------------------------------------------

func TestVersionFlag(t *testing.T) {
	// Save and restore version.
	origVersion := version
	defer func() { version = origVersion }()

	version = "1.2.3"
	rootCmd.SetVersionTemplate(strings.Replace("nowifi v%s\n", "%s", version, 1))

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute --version: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1.2.3") {
		t.Errorf("--version output = %q, want to contain 1.2.3", output)
	}
}

// ---------------------------------------------------------------------------
// --help contains "<N> portal bypass techniques" where N is kept in sync with
// techniques.BypassTechniqueCount(). The current assertion below is the source
// of truth; update both together whenever the technique count changes.
// ---------------------------------------------------------------------------

func TestHelpContainsBypassTechniqueCount(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute --help: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "35 portal bypass techniques") {
		t.Errorf("--help output should contain '35 portal bypass techniques', got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// Individual subcommand properties
// ---------------------------------------------------------------------------

func TestCrackCmd(t *testing.T) {
	if crackCmd.Use != "crack" {
		t.Errorf("crackCmd.Use = %q, want crack", crackCmd.Use)
	}
	if crackCmd.Short == "" {
		t.Error("crackCmd.Short is empty")
	}
}

func TestDiagnoseCmd(t *testing.T) {
	if diagnoseCmd.Use != "diagnose" {
		t.Errorf("diagnoseCmd.Use = %q, want diagnose", diagnoseCmd.Use)
	}
}

func TestToolsCmd(t *testing.T) {
	if toolsCmd.Use != "tools" {
		t.Errorf("toolsCmd.Use = %q, want tools", toolsCmd.Use)
	}
}

func TestResetCmd(t *testing.T) {
	if resetCmd.Use != "reset" {
		t.Errorf("resetCmd.Use = %q, want reset", resetCmd.Use)
	}
}

func TestServerCmd(t *testing.T) {
	if serverCmd.Use != "server" {
		t.Errorf("serverCmd.Use = %q, want server", serverCmd.Use)
	}
	// Server should have subcommands.
	subs := serverCmd.Commands()
	if len(subs) < 3 {
		t.Errorf("serverCmd has %d subcommands, want >= 3 (create, list, destroy)", len(subs))
	}
}

func TestEcosystemCmd(t *testing.T) {
	if ecosystemCmd.Use != "ecosystem" {
		t.Errorf("ecosystemCmd.Use = %q, want ecosystem", ecosystemCmd.Use)
	}
}

func TestDoctorCmd(t *testing.T) {
	if doctorCmd.Use != "doctor" {
		t.Errorf("doctorCmd.Use = %q, want doctor", doctorCmd.Use)
	}
}

func TestSetupCmd(t *testing.T) {
	if setupCmd.Use != "setup" {
		t.Errorf("setupCmd.Use = %q, want setup", setupCmd.Use)
	}
}

func TestUICmd(t *testing.T) {
	if uiCmd.Use != "ui" {
		t.Errorf("uiCmd.Use = %q, want ui", uiCmd.Use)
	}
	if uiCmd.Short == "" {
		t.Error("uiCmd.Short is empty")
	}
	f := uiCmd.Flags().Lookup("port")
	if f == nil {
		t.Fatal("--port flag not registered on uiCmd")
	}
	if f.DefValue != "8321" {
		t.Errorf("--port default = %q, want 8321", f.DefValue)
	}
}

func TestMenubarCmd(t *testing.T) {
	if menubarCmd.Use != "menubar" {
		t.Errorf("menubarCmd.Use = %q, want menubar", menubarCmd.Use)
	}
	if menubarCmd.Short == "" {
		t.Error("menubarCmd.Short is empty")
	}
}

// ---------------------------------------------------------------------------
// SetVersion
// ---------------------------------------------------------------------------

func TestSetVersion(t *testing.T) {
	origVersion := version
	defer func() { version = origVersion }()

	SetVersion("99.88.77")
	if version != "99.88.77" {
		t.Errorf("SetVersion did not update version: %q", version)
	}
}

// ---------------------------------------------------------------------------
// Persistent flags
// ---------------------------------------------------------------------------

func TestPersistentFlags_Interface(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("interface")
	if f == nil {
		t.Fatal("--interface persistent flag not registered")
	}
	if f.Shorthand != "i" {
		t.Errorf("--interface shorthand = %q, want i", f.Shorthand)
	}
	if f.DefValue != "en0" {
		t.Errorf("--interface default = %q, want en0", f.DefValue)
	}
}

func TestRootFlags(t *testing.T) {
	flags := []struct {
		name     string
		defValue string
	}{
		{"tunnel-server", ""},
		{"dns-domain", ""},
		{"icmp-server", ""},
		{"cf-workers", ""},
		{"quic-server", ""},
		{"ntp-server", ""},
		{"stealth", "true"},
		{"fast", "false"},
		{"probe-only", "false"},
		{"auto", "false"},
	}

	for _, tt := range flags {
		t.Run(tt.name, func(t *testing.T) {
			f := rootCmd.Flags().Lookup(tt.name)
			if f == nil {
				t.Errorf("flag --%s not registered on rootCmd", tt.name)
				return
			}
			if f.DefValue != tt.defValue {
				t.Errorf("flag --%s default = %q, want %q", tt.name, f.DefValue, tt.defValue)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Server subcommand flags
// ---------------------------------------------------------------------------

func TestServerCreateFlags(t *testing.T) {
	f := serverCreateCmd.Flags().Lookup("provider")
	if f == nil {
		t.Fatal("--provider flag not registered on serverCreateCmd")
	}
	if f.DefValue != "cloudflare" {
		t.Errorf("--provider default = %q, want cloudflare", f.DefValue)
	}
}

func TestServerDestroyFlags(t *testing.T) {
	f := serverDestroyCmd.Flags().Lookup("all")
	if f == nil {
		t.Fatal("--all flag not registered on serverDestroyCmd")
	}
}

// ---------------------------------------------------------------------------
// Long description content
// ---------------------------------------------------------------------------

func TestScanCmd(t *testing.T) {
	if scanCmd.Use != "scan" {
		t.Errorf("scanCmd.Use = %q, want scan", scanCmd.Use)
	}
	if scanCmd.Short == "" {
		t.Error("scanCmd.Short is empty")
	}
}

func TestHistoryCmd(t *testing.T) {
	if historyCmd.Use != "history" {
		t.Errorf("historyCmd.Use = %q, want history", historyCmd.Use)
	}
	if historyCmd.Short == "" {
		t.Error("historyCmd.Short is empty")
	}
}

func TestWatchCmd(t *testing.T) {
	if watchCmd.Use != "watch" {
		t.Errorf("watchCmd.Use = %q, want watch", watchCmd.Use)
	}
	if watchCmd.Short == "" {
		t.Error("watchCmd.Short is empty")
	}
	f := watchCmd.Flags().Lookup("interval")
	if f == nil {
		t.Fatal("--interval flag not registered on watchCmd")
	}
	if f.DefValue != "60" {
		t.Errorf("--interval default = %q, want 60", f.DefValue)
	}
}

func TestAutoFlag(t *testing.T) {
	f := rootCmd.Flags().Lookup("auto")
	if f == nil {
		t.Fatal("--auto flag not registered on rootCmd")
	}
	if f.Shorthand != "y" {
		t.Errorf("--auto shorthand = %q, want y", f.Shorthand)
	}
	if f.DefValue != "false" {
		t.Errorf("--auto default = %q, want false", f.DefValue)
	}
}

func TestRootLongDescription(t *testing.T) {
	tests := []struct {
		name   string
		substr string
	}{
		{"mentions sudo", "sudo nowifi"},
		{"mentions overall technique count", "43 techniques overall"},
		{"mentions IPv6", "IPv6"},
		{"mentions DNS tunnel", "DNS tunnel"},
		{"mentions portal bypass split", "Portal bypass (35): nowifi"},
		{"mentions crack split", "WPA cracking (4):   nowifi crack"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(rootCmd.Long, tt.substr) {
				t.Errorf("rootCmd.Long should contain %q", tt.substr)
			}
		})
	}
}

func TestCrackLongDescription(t *testing.T) {
	tests := []struct {
		name   string
		substr string
	}{
		{"mentions 8-technique pipeline", "8-technique pipeline"},
		{"mentions WPS Pixie-Dust", "WPS Pixie-Dust"},
		{"mentions WPS PIN brute force", "WPS PIN brute force"},
		{"mentions smart common passwords", "Smart common passwords"},
		{"mentions online brute force", "Online brute force"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(crackCmd.Long, tt.substr) {
				t.Errorf("crackCmd.Long should contain %q", tt.substr)
			}
		})
	}
}

func TestReadmeRootCommandTableMatchesSessionMaintenance(t *testing.T) {
	readmePath := filepath.Join("..", "..", "..", "README.md")
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}

	readme := string(data)
	want := "| `sudo nowifi` | Full audit: detect, probe, bypass, maintain access, restore on exit |"
	if !strings.Contains(readme, want) {
		t.Errorf("README.md should contain %q", want)
	}

	stale := "| `sudo nowifi` | Full audit: detect, probe, bypass, report |"
	if strings.Contains(readme, stale) {
		t.Errorf("README.md still contains stale command table row %q", stale)
	}
}

// ---------------------------------------------------------------------------
// extractHost (audit.go helper) — including error path
// ---------------------------------------------------------------------------

func TestExtractHost_URLParseError(t *testing.T) {
	// url.Parse is very permissive, so exercise the empty return path.
	got := extractHost("")
	if got != "" {
		t.Errorf("extractHost empty = %q, want empty", got)
	}
}

func TestExtractHost_NoScheme(t *testing.T) {
	// Without a scheme, url.Parse puts the value in Path, not Host.
	got := extractHost("bare-hostname")
	if got != "" {
		t.Errorf("extractHost(bare-hostname) = %q, want empty (no scheme)", got)
	}
}

func TestExtractHost_SchemeWithPort(t *testing.T) {
	// url.Parse treats "host:port" as scheme:opaque, returning empty Hostname.
	got := extractHost("myserver:8080")
	if got != "" {
		t.Errorf("extractHost(myserver:8080) = %q, want empty", got)
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"bare hostname no scheme", "example.com", ""}, // url.Parse puts this in Path, not Host
		{"https URL", "https://tunnel.example.com:8443/path", "tunnel.example.com"},
		{"http URL", "http://192.168.1.1:8080", "192.168.1.1"},
		{"URL with path", "https://host.com/some/path?q=1", "host.com"},
		{"scheme only host", "https://myserver", "myserver"},
		{"IP address URL", "https://10.0.0.1:443", "10.0.0.1"},
		{"no scheme with port", "myserver:8080", ""}, // parsed as scheme:opaque by url.Parse
		{"IPv6 URL", "https://[::1]:443/path", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHost(tt.input)
			if got != tt.want {
				t.Errorf("extractHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// countOpenPorts (audit.go helper)
// ---------------------------------------------------------------------------

func TestCountOpenPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports []probe.PortProbeResult
		want  int
	}{
		{"nil ports", nil, 0},
		{"empty ports", []probe.PortProbeResult{}, 0},
		{"all closed", []probe.PortProbeResult{
			{Port: 80, IsOpen: false},
			{Port: 443, IsOpen: false},
		}, 0},
		{"all open", []probe.PortProbeResult{
			{Port: 80, IsOpen: true},
			{Port: 443, IsOpen: true},
			{Port: 53, IsOpen: true},
		}, 3},
		{"mixed", []probe.PortProbeResult{
			{Port: 80, IsOpen: true},
			{Port: 443, IsOpen: false},
			{Port: 53, IsOpen: true},
			{Port: 22, IsOpen: false},
			{Port: 8080, IsOpen: true},
		}, 3},
		{"single open", []probe.PortProbeResult{
			{Port: 443, IsOpen: true},
		}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probes := &probe.ProbeResults{OpenPorts: tt.ports}
			got := countOpenPorts(probes)
			if got != tt.want {
				t.Errorf("countOpenPorts() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// mapProbeResults (audit.go helper)
// ---------------------------------------------------------------------------

func TestMapProbeResults_Basic(t *testing.T) {
	p := &probe.ProbeResults{
		DNS:        probe.DnsProbeResult{IsOpen: true, Details: "dns-details"},
		ICMP:       probe.IcmpProbeResult{IsOpen: false, Details: "icmp-details"},
		IPv6:       probe.Ipv6ProbeResult{IsOpen: true, Details: "ipv6-details"},
		Cloudflare: probe.HttpsProbeResult{IsOpen: true, Details: "cf-details"},
		QUIC:       probe.PortProbeResult{IsOpen: false, Details: "quic-details"},
		NTP:        probe.PortProbeResult{IsOpen: true, Details: "ntp-details"},
		DoH:        probe.PortProbeResult{IsOpen: false, Details: "doh-details"},
	}

	bp := mapProbeResults(p)

	if bp.DNS.IsOpen != true || bp.DNS.Details != "dns-details" {
		t.Errorf("DNS mapping: got IsOpen=%v Details=%q", bp.DNS.IsOpen, bp.DNS.Details)
	}
	if bp.ICMP.IsOpen != false || bp.ICMP.Details != "icmp-details" {
		t.Errorf("ICMP mapping: got IsOpen=%v Details=%q", bp.ICMP.IsOpen, bp.ICMP.Details)
	}
	if bp.IPv6.IsOpen != true {
		t.Error("IPv6 mapping: expected IsOpen=true")
	}
	if bp.Cloudflare.IsOpen != true {
		t.Error("Cloudflare mapping: expected IsOpen=true")
	}
	if bp.QUIC.IsOpen != false {
		t.Error("QUIC mapping: expected IsOpen=false")
	}
	if bp.NTP.IsOpen != true {
		t.Error("NTP mapping: expected IsOpen=true")
	}
	if bp.DoH.IsOpen != false {
		t.Error("DoH mapping: expected IsOpen=false")
	}
}

func TestMapProbeResults_Whitelists(t *testing.T) {
	p := &probe.ProbeResults{
		Whitelists: []probe.WhitelistResult{
			{Domain: "apple.com", IsOpen: true, Details: "200 OK"},
			{Domain: "google.com", IsOpen: false, Details: "timeout"},
		},
	}

	bp := mapProbeResults(p)

	if len(bp.Whitelists) != 2 {
		t.Fatalf("Whitelists len = %d, want 2", len(bp.Whitelists))
	}
	if bp.Whitelists[0].Domain != "apple.com" || !bp.Whitelists[0].IsOpen {
		t.Errorf("Whitelist[0] = %+v, want apple.com/open", bp.Whitelists[0])
	}
	if bp.Whitelists[1].Domain != "google.com" || bp.Whitelists[1].IsOpen {
		t.Errorf("Whitelist[1] = %+v, want google.com/closed", bp.Whitelists[1])
	}
}

func TestMapProbeResults_OpenPorts(t *testing.T) {
	p := &probe.ProbeResults{
		OpenPorts: []probe.PortProbeResult{
			{Port: 80, Service: "HTTP", IsOpen: true},
			{Port: 443, Service: "HTTPS", IsOpen: false},
		},
	}

	bp := mapProbeResults(p)

	if len(bp.OpenPorts) != 2 {
		t.Fatalf("OpenPorts len = %d, want 2", len(bp.OpenPorts))
	}
	if bp.OpenPorts[0].Port != 80 || bp.OpenPorts[0].Service != "HTTP" || !bp.OpenPorts[0].IsOpen {
		t.Errorf("OpenPorts[0] = %+v", bp.OpenPorts[0])
	}
}

func TestMapProbeResults_TunnelServerPorts(t *testing.T) {
	p := &probe.ProbeResults{
		TunnelServerPorts: []probe.PortProbeResult{
			{Port: 51820, Service: "WireGuard", IsOpen: true},
		},
	}

	bp := mapProbeResults(p)

	if len(bp.TunnelServerPorts) != 1 {
		t.Fatalf("TunnelServerPorts len = %d, want 1", len(bp.TunnelServerPorts))
	}
	if bp.TunnelServerPorts[0].Port != 51820 {
		t.Errorf("TunnelServerPorts[0].Port = %d, want 51820", bp.TunnelServerPorts[0].Port)
	}
}

func TestMapProbeResults_Empty(t *testing.T) {
	p := &probe.ProbeResults{}
	bp := mapProbeResults(p)

	if bp.DNS.IsOpen || bp.ICMP.IsOpen || bp.IPv6.IsOpen {
		t.Error("empty probes should map to all closed")
	}
	if len(bp.Whitelists) != 0 || len(bp.OpenPorts) != 0 || len(bp.TunnelServerPorts) != 0 {
		t.Error("empty probes should have no whitelists/ports")
	}
}
