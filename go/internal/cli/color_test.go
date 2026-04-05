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
