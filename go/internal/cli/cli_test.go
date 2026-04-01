// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"bytes"
	"strings"
	"testing"
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
	// At minimum, the 13 expected subcommands should be present.
	count := len(rootCmd.Commands())
	if count < 13 {
		t.Errorf("rootCmd has %d subcommands, want >= 13", count)
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
// --help contains "23 techniques"
// ---------------------------------------------------------------------------

func TestHelpContains23Techniques(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute --help: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "23 techniques") {
		t.Errorf("--help output should contain '23 techniques', got:\n%s", output)
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
		name    string
		substr  string
	}{
		{"mentions sudo", "sudo nowifi"},
		{"mentions 23", "23 techniques"},
		{"mentions IPv6", "IPv6"},
		{"mentions DNS tunnel", "DNS tunnel"},
		{"mentions PMKID", "PMKID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(rootCmd.Long, tt.substr) {
				t.Errorf("rootCmd.Long should contain %q", tt.substr)
			}
		})
	}
}
