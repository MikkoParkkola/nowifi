// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package portal

import (
	"strings"
	"testing"
)

func TestDisposableEmail(t *testing.T) {
	email := DisposableEmail()

	if !strings.HasPrefix(email, "guest.") {
		t.Errorf("email should start with 'guest.', got %q", email)
	}
	if !strings.HasSuffix(email, "@protonmail.com") {
		t.Errorf("email should end with '@protonmail.com', got %q", email)
	}
	if len(email) != len("guest.") + 8 + len("@protonmail.com") {
		t.Errorf("email length unexpected: %q (len=%d)", email, len(email))
	}

	// Two calls should produce different emails.
	email2 := DisposableEmail()
	if email == email2 {
		t.Error("two calls to DisposableEmail() produced the same result")
	}
}

func TestClassifyForm_ClickThrough(t *testing.T) {
	html := `<form><input type="checkbox" name="accept">I agree to <b>terms</b></input><input type="submit" value="Connect"></form>`
	fields := []formField{
		{Name: "accept", Type: "checkbox"},
	}
	result := classifyForm(html, fields)
	if result != "click_through" {
		t.Errorf("classifyForm = %q, want click_through", result)
	}
}

func TestClassifyForm_Email(t *testing.T) {
	html := `<form><input type="email" name="email" placeholder="your@email.com"><input type="submit"></form>`
	fields := []formField{
		{Name: "email", Type: "email"},
	}
	result := classifyForm(html, fields)
	if result != "email" {
		t.Errorf("classifyForm = %q, want email", result)
	}
}

func TestClassifyForm_RoomNumber(t *testing.T) {
	html := `<form><label>Room Number</label><input type="text" name="room_no"><input type="submit"></form>`
	fields := []formField{
		{Name: "room_no", Type: "text"},
	}
	result := classifyForm(html, fields)
	if result != "room_number" {
		t.Errorf("classifyForm = %q, want room_number", result)
	}
}

func TestClassifyForm_Social(t *testing.T) {
	html := `<a href="https://accounts.google.com/oauth">Sign in with Google</a>`
	result := classifyForm(html, nil)
	if result != "social" {
		t.Errorf("classifyForm = %q, want social", result)
	}
}

func TestParseForm(t *testing.T) {
	html := `<form action="/login" method="post">
		<input type="hidden" name="token" value="abc123">
		<input type="email" name="email">
		<input type="submit" value="Go">
	</form>`

	action, fields := parseForm(html, "http://portal.example.com/page")
	if action != "http://portal.example.com/login" {
		t.Errorf("action = %q, want http://portal.example.com/login", action)
	}
	// The submit input has no name attribute, so only token and email are captured.
	if len(fields) != 2 {
		t.Fatalf("got %d fields, want 2", len(fields))
	}

	// Check hidden field.
	found := false
	for _, f := range fields {
		if f.Name == "token" && f.Value == "abc123" && f.Type == "hidden" {
			found = true
		}
	}
	if !found {
		t.Error("hidden field 'token' not found")
	}
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		base, ref, want string
	}{
		{"http://portal.example.com/page", "/login", "http://portal.example.com/login"},
		{"http://portal.example.com/page", "https://other.com/auth", "https://other.com/auth"},
		{"http://portal.example.com/dir/page", "submit.php", "http://portal.example.com/dir/submit.php"},
	}

	for _, tt := range tests {
		got := resolveURL(tt.base, tt.ref)
		if got != tt.want {
			t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.base, tt.ref, got, tt.want)
		}
	}
}

func TestAutoLogin_EmptyURL(t *testing.T) {
	result, err := AutoLogin("")
	if err != nil {
		t.Fatalf("AutoLogin('') error = %v", err)
	}
	if result.Method != "manual" {
		t.Errorf("method = %q, want manual", result.Method)
	}
}
