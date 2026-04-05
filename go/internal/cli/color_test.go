// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Color helpers — return non-empty strings containing the input
// ---------------------------------------------------------------------------

func TestGreen(t *testing.T) {
	result := green("OK")
	if result == "" {
		t.Error("green() returned empty string")
	}
	if !strings.Contains(result, "OK") {
		t.Errorf("green(%q) = %q, should contain input", "OK", result)
	}
}

func TestRed(t *testing.T) {
	result := red("FAIL")
	if result == "" {
		t.Error("red() returned empty string")
	}
	if !strings.Contains(result, "FAIL") {
		t.Errorf("red(%q) = %q, should contain input", "FAIL", result)
	}
}

func TestYellow(t *testing.T) {
	result := yellow("WARN")
	if result == "" {
		t.Error("yellow() returned empty string")
	}
	if !strings.Contains(result, "WARN") {
		t.Errorf("yellow(%q) = %q, should contain input", "WARN", result)
	}
}

func TestBold(t *testing.T) {
	result := bold("text")
	if result == "" {
		t.Error("bold() returned empty string")
	}
	if !strings.Contains(result, "text") {
		t.Errorf("bold(%q) = %q, should contain input", "text", result)
	}
}

func TestDim(t *testing.T) {
	result := dim("timestamp")
	if result == "" {
		t.Error("dim() returned empty string")
	}
	if !strings.Contains(result, "timestamp") {
		t.Errorf("dim(%q) = %q, should contain input", "timestamp", result)
	}
}

func TestColorEmpty(t *testing.T) {
	// Color helpers with empty input should still return something
	// (either empty or ANSI codes around empty).
	_ = green("")
	_ = red("")
	_ = yellow("")
	_ = bold("")
	_ = dim("")
}

// ---------------------------------------------------------------------------
// status helper
// ---------------------------------------------------------------------------

func TestStatus_Open(t *testing.T) {
	result := status(true)
	if !strings.Contains(result, "OPEN") {
		t.Errorf("status(true) = %q, should contain OPEN", result)
	}
}

func TestStatus_Closed(t *testing.T) {
	result := status(false)
	if !strings.Contains(result, "CLOSED") {
		t.Errorf("status(false) = %q, should contain CLOSED", result)
	}
}

// ---------------------------------------------------------------------------
// hint helper — just verify no panic
// ---------------------------------------------------------------------------

func TestHint(t *testing.T) {
	// hint() prints to stdout. Just verify it doesn't panic.
	hint("Run sudo nowifi", "Check WiFi is enabled")
}

func TestHint_Empty(t *testing.T) {
	hint()
}

func TestHint_SingleLine(t *testing.T) {
	hint("single instruction")
}

// ---------------------------------------------------------------------------
// Color identity in non-terminal mode (test context)
// ---------------------------------------------------------------------------

func TestColorPreservesInput(t *testing.T) {
	// In test context, useColor is typically false (stdout is not a terminal),
	// so color functions should return the input unchanged.
	inputs := []string{"hello", "test123", "!@#$%"}
	fns := []struct {
		name string
		fn   func(string) string
	}{
		{"green", green},
		{"red", red},
		{"yellow", yellow},
		{"bold", bold},
		{"dim", dim},
	}

	for _, input := range inputs {
		for _, fn := range fns {
			t.Run(fn.name+"_"+input, func(t *testing.T) {
				result := fn.fn(input)
				if !strings.Contains(result, input) {
					t.Errorf("%s(%q) = %q, does not contain input", fn.name, input, result)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Color functions — forced color ON: ANSI codes must be present
// ---------------------------------------------------------------------------

func TestColorFunctions_ColorEnabled(t *testing.T) {
	// Save and restore.
	orig := useColor
	t.Cleanup(func() { useColor = orig })
	useColor = true

	tests := []struct {
		name   string
		fn     func(string) string
		ansi   string // expected ANSI prefix
		input  string
	}{
		{"green", green, "\033[32m", "OK"},
		{"red", red, "\033[31m", "FAIL"},
		{"yellow", yellow, "\033[33m", "WARN"},
		{"bold", bold, "\033[1m", "text"},
		{"dim", dim, "\033[2m", "stamp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn(tt.input)
			if !strings.HasPrefix(result, tt.ansi) {
				t.Errorf("%s(%q) = %q, want prefix %q", tt.name, tt.input, result, tt.ansi)
			}
			if !strings.HasSuffix(result, "\033[0m") {
				t.Errorf("%s(%q) = %q, want suffix \\033[0m", tt.name, tt.input, result)
			}
			if !strings.Contains(result, tt.input) {
				t.Errorf("%s(%q) = %q, does not contain input", tt.name, tt.input, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Color functions — forced color OFF: plain text, no ANSI codes
// ---------------------------------------------------------------------------

func TestColorFunctions_ColorDisabled(t *testing.T) {
	orig := useColor
	t.Cleanup(func() { useColor = orig })
	useColor = false

	fns := []struct {
		name string
		fn   func(string) string
	}{
		{"green", green},
		{"red", red},
		{"yellow", yellow},
		{"bold", bold},
		{"dim", dim},
	}

	for _, fn := range fns {
		t.Run(fn.name, func(t *testing.T) {
			result := fn.fn("test")
			if result != "test" {
				t.Errorf("%s(%q) with color off = %q, want plain %q", fn.name, "test", result, "test")
			}
			if strings.Contains(result, "\033[") {
				t.Errorf("%s(%q) with color off contains ANSI escape", fn.name, "test")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// status — with color on and off
// ---------------------------------------------------------------------------

func TestStatus_ColorEnabled(t *testing.T) {
	orig := useColor
	t.Cleanup(func() { useColor = orig })
	useColor = true

	open := status(true)
	if !strings.Contains(open, "\033[32m") {
		t.Errorf("status(true) with color = %q, want green ANSI", open)
	}
	if !strings.Contains(open, "OPEN") {
		t.Errorf("status(true) = %q, missing OPEN", open)
	}

	closed := status(false)
	if !strings.Contains(closed, "\033[31m") {
		t.Errorf("status(false) with color = %q, want red ANSI", closed)
	}
	if !strings.Contains(closed, "CLOSED") {
		t.Errorf("status(false) = %q, missing CLOSED", closed)
	}
}

func TestStatus_ColorDisabled(t *testing.T) {
	orig := useColor
	t.Cleanup(func() { useColor = orig })
	useColor = false

	open := status(true)
	if open != "OPEN" {
		t.Errorf("status(true) with color off = %q, want %q", open, "OPEN")
	}

	closed := status(false)
	if closed != "CLOSED" {
		t.Errorf("status(false) with color off = %q, want %q", closed, "CLOSED")
	}
}
