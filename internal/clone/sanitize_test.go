// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package clone

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// sanitizeHostname
// ---------------------------------------------------------------------------

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal", "MacBook-Pro", "MacBook-Pro"},
		{"lowercase", "iphone", "iphone"},
		{"alphanumeric", "DESKTOP123", "DESKTOP123"},
		{"hyphen", "my-host-name", "my-host-name"},
		{"with spaces", "My Host Name", "MyHostName"},
		{"with special chars", "host$(evil)", "hostevil"},
		{"injection attempt", "host\";rm -rf /;\"", "hostrm-rf"},
		{"quotes", "host\"name\"", "hostname"},
		{"semicolons", "host;name;evil", "hostnameevil"},
		{"backticks", "host`id`name", "hostidname"},
		{"unicode", "hst\u00e9", "hst"},
		{"empty string", "", "localhost"},
		{"only special chars", "!@#$%^&*()", "localhost"},
		{"only spaces", "   ", "localhost"},
		{"tabs and newlines", "\t\n\r", "localhost"},
		{"single valid char", "a", "a"},
		{"numbers only", "12345", "12345"},
		{"hyphens only", "---", "---"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeHostname(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeHostname(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sanitizeDHCPOptions
// ---------------------------------------------------------------------------

func TestSanitizeDHCPOptions(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"valid options",
			"subnet-mask,routers,domain-name-servers,domain-name",
			"subnet-mask,routers,domain-name-servers,domain-name",
		},
		{
			"windows options",
			"subnet-mask,routers,domain-name-servers,domain-name,ntp-servers,vendor-encapsulated-options",
			"subnet-mask,routers,domain-name-servers,domain-name,ntp-servers,vendor-encapsulated-options",
		},
		{
			"injection attempt",
			"subnet-mask\"; evil-command;\"routers",
			"subnet-maskevil-commandrouters",
		},
		{
			"with semicolons",
			"subnet-mask;routers",
			"subnet-maskrouters",
		},
		{
			"with spaces",
			"subnet-mask, routers, domain-name",
			"subnet-mask,routers,domain-name",
		},
		{
			"empty",
			"",
			"",
		},
		{
			"special chars",
			"opt$(cmd)!@#",
			"optcmd",
		},
		{
			"numeric option codes",
			"1,3,6,15,44,46",
			"1,3,6,15,44,46",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeDHCPOptions(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeDHCPOptions(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sanitizeVendorClass
// ---------------------------------------------------------------------------

func TestSanitizeVendorClass(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"windows", "MSFT 5.0", "MSFT 5.0"},
		{"android", "android-dhcp-14", "android-dhcp-14"},
		{"with quotes", "vendor\"class", "vendorclass"},
		{"with backslash", "vendor\\class", "vendorclass"},
		{"with semicolons", "vendor;class", "vendorclass"},
		{"printable ascii", "Hello World 123!", "Hello World 123!"},
		{"control chars", "hello\x00world", "helloworld"},
		{"tabs", "hello\tworld", "helloworld"},
		{"newlines", "hello\nworld", "helloworld"},
		{"empty", "", ""},
		{"all special", "\"\\\";", ""},
		{"tilde", "vendor~class", "vendor~class"},
		{"at sign", "vendor@class", "vendor@class"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeVendorClass(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeVendorClass(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DHCP config generation (via profile fields)
// ---------------------------------------------------------------------------

func TestDHCPConfigGeneration_ProfileFields(t *testing.T) {
	// Verify that profile fields survive sanitization correctly.
	profiles := []DeviceProfile{
		ProfileMacOS, ProfileiOS, ProfileWindows, ProfileAndroid, ProfileLinux,
	}

	for _, p := range profiles {
		t.Run(p.OS, func(t *testing.T) {
			hostname := sanitizeHostname(p.Hostname)
			if hostname == "" || hostname == "localhost" && p.OS != "linux" {
				t.Errorf("sanitizeHostname(%q) = %q — unexpected for %s", p.Hostname, hostname, p.OS)
			}

			opts := sanitizeDHCPOptions(p.DHCPOptions55)
			if opts == "" {
				t.Errorf("sanitizeDHCPOptions(%q) returned empty for %s", p.DHCPOptions55, p.OS)
			}
			// Options should contain commas (multiple options).
			if !strings.Contains(opts, ",") {
				t.Errorf("sanitized options for %s have no commas: %q", p.OS, opts)
			}

			if p.DHCPOption60 != "" {
				vc := sanitizeVendorClass(p.DHCPOption60)
				if vc == "" {
					t.Errorf("sanitizeVendorClass(%q) returned empty for %s", p.DHCPOption60, p.OS)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge cases: DeviceProfile handling
// ---------------------------------------------------------------------------

func TestDeviceProfile_ZeroValue(t *testing.T) {
	var p DeviceProfile

	hostname := sanitizeHostname(p.Hostname)
	if hostname != "localhost" {
		t.Errorf("zero-value hostname should sanitize to localhost, got %q", hostname)
	}

	opts := sanitizeDHCPOptions(p.DHCPOptions55)
	if opts != "" {
		t.Errorf("zero-value options should sanitize to empty, got %q", opts)
	}

	vc := sanitizeVendorClass(p.DHCPOption60)
	if vc != "" {
		t.Errorf("zero-value vendor class should sanitize to empty, got %q", vc)
	}
}

func TestDeviceProfile_LongHostname(t *testing.T) {
	// RFC 952 limits hostnames to 63 characters per label.
	// sanitizeHostname should at least not crash on long input.
	long := strings.Repeat("a", 1000)
	result := sanitizeHostname(long)
	if len(result) != 1000 {
		t.Errorf("sanitizeHostname preserved %d chars, want 1000", len(result))
	}
}

func TestDeviceProfile_LongDHCPOptions(t *testing.T) {
	long := strings.Repeat("opt-name,", 200)
	result := sanitizeDHCPOptions(long)
	if result == "" {
		t.Error("sanitizeDHCPOptions should handle long input")
	}
}
