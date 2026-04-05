// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package portal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
	if len(email) != len("guest.")+8+len("@protonmail.com") {
		t.Errorf("email length unexpected: %q (len=%d)", email, len(email))
	}

	// Two calls should produce different emails.
	email2 := DisposableEmail()
	if email == email2 {
		t.Error("two calls to DisposableEmail() produced the same result")
	}
}

func TestDisposableEmail_ValidCharset(t *testing.T) {
	for i := 0; i < 20; i++ {
		email := DisposableEmail()
		local := strings.TrimPrefix(email, "guest.")
		local = strings.TrimSuffix(local, "@protonmail.com")
		for _, c := range local {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				t.Errorf("unexpected character %q in local part %q", string(c), local)
			}
		}
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

func TestClassifyForm_EmailByName(t *testing.T) {
	html := `<form><input name="email" type="text"><input type="submit"></form>`
	fields := []formField{
		{Name: "email", Type: "text"},
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

func TestClassifyForm_AccessCode(t *testing.T) {
	html := `<form><label>Access Code</label><input type="text" name="code"></form>`
	result := classifyForm(html, []formField{{Name: "code", Type: "text"}})
	if result != "room_number" {
		t.Errorf("classifyForm = %q, want room_number", result)
	}
}

func TestClassifyForm_Voucher(t *testing.T) {
	html := `<form><label>Enter your voucher</label><input type="text" name="v"></form>`
	result := classifyForm(html, []formField{{Name: "v", Type: "text"}})
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

func TestClassifyForm_FacebookLogin(t *testing.T) {
	html := `<a href="https://facebook.com/dialog/oauth">Login with Facebook</a>`
	result := classifyForm(html, nil)
	if result != "social" {
		t.Errorf("classifyForm = %q, want social", result)
	}
}

func TestClassifyForm_Unknown(t *testing.T) {
	html := `<div>Welcome to the network</div>`
	result := classifyForm(html, nil)
	if result != "unknown" {
		t.Errorf("classifyForm = %q, want unknown", result)
	}
}

func TestClassifyForm_FieldsOnlyClickThrough(t *testing.T) {
	// Has fields but no terms/email/room/social patterns => click_through
	html := `<form><input type="hidden" name="token" value="x"></form>`
	fields := []formField{{Name: "token", Type: "hidden", Value: "x"}}
	result := classifyForm(html, fields)
	if result != "click_through" {
		t.Errorf("classifyForm = %q, want click_through", result)
	}
}

func TestClassifyForm_Priority(t *testing.T) {
	// Social takes priority over email.
	html := `<form><input type="email" name="email"><a href="https://accounts.google.com/o">Google</a></form>`
	fields := []formField{{Name: "email", Type: "email"}}
	result := classifyForm(html, fields)
	if result != "social" {
		t.Errorf("classifyForm = %q, want social (social > email priority)", result)
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

func TestParseForm_NoAction(t *testing.T) {
	html := `<form method="post"><input type="text" name="user"></form>`
	action, fields := parseForm(html, "http://example.com/captive")
	if action != "http://example.com/captive" {
		t.Errorf("action = %q, want base URL when no action attr", action)
	}
	if len(fields) != 1 || fields[0].Name != "user" {
		t.Errorf("fields = %v, want [{user text }]", fields)
	}
}

func TestParseForm_AbsoluteAction(t *testing.T) {
	html := `<form action="https://auth.example.com/submit"><input type="hidden" name="k" value="v"></form>`
	action, _ := parseForm(html, "http://portal.example.com/page")
	if action != "https://auth.example.com/submit" {
		t.Errorf("action = %q, want https://auth.example.com/submit", action)
	}
}

func TestParseForm_MultipleInputs(t *testing.T) {
	html := `<form action="/go">
		<input type="hidden" name="csrf" value="tok1">
		<input type="email" name="email">
		<input type="checkbox" name="terms">
		<input type="text" name="name" value="Guest">
	</form>`
	_, fields := parseForm(html, "http://example.com")
	if len(fields) != 4 {
		t.Fatalf("got %d fields, want 4", len(fields))
	}
	names := make(map[string]bool)
	for _, f := range fields {
		names[f.Name] = true
	}
	for _, want := range []string{"csrf", "email", "terms", "name"} {
		if !names[want] {
			t.Errorf("missing field %q", want)
		}
	}
}

func TestParseForm_NoInputs(t *testing.T) {
	html := `<div>No form here</div>`
	action, fields := parseForm(html, "http://example.com")
	if action != "http://example.com" {
		t.Errorf("action = %q, want base URL", action)
	}
	if len(fields) != 0 {
		t.Errorf("got %d fields, want 0", len(fields))
	}
}

func TestParseForm_InputWithoutName(t *testing.T) {
	html := `<form action="/go"><input type="submit" value="Go"><input type="hidden" name="tok" value="x"></form>`
	_, fields := parseForm(html, "http://example.com")
	// submit has no name, only tok should appear
	if len(fields) != 1 {
		t.Fatalf("got %d fields, want 1 (submit without name skipped)", len(fields))
	}
	if fields[0].Name != "tok" {
		t.Errorf("field name = %q, want tok", fields[0].Name)
	}
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		base, ref, want string
	}{
		{"http://portal.example.com/page", "/login", "http://portal.example.com/login"},
		{"http://portal.example.com/page", "https://other.com/auth", "https://other.com/auth"},
		{"http://portal.example.com/dir/page", "submit.php", "http://portal.example.com/dir/submit.php"},
		{"http://portal.example.com", "http://portal.example.com", "http://portal.example.com"},
		{"http://portal.example.com/a/b/c", "../d", "http://portal.example.com/a/d"},
	}

	for _, tt := range tests {
		got := resolveURL(tt.base, tt.ref)
		if got != tt.want {
			t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.base, tt.ref, got, tt.want)
		}
	}
}

func TestResolveURL_InvalidBase(t *testing.T) {
	// With an unparseable base, ref is returned as-is.
	got := resolveURL("://bad", "/path")
	if got != "/path" {
		t.Errorf("resolveURL with bad base = %q, want /path", got)
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
	if result.Details != "no portal URL" {
		t.Errorf("details = %q, want 'no portal URL'", result.Details)
	}
}

func TestAutoLogin_RoomNumberPortal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>
			<form action="/auth" method="post">
				<label>Room Number</label>
				<input type="text" name="room_no">
				<input type="submit" value="Login">
			</form>
		</body></html>`)
	}))
	defer ts.Close()

	result, err := AutoLogin(ts.URL)
	if err != nil {
		t.Fatalf("AutoLogin error = %v", err)
	}
	if result.Method != "room_number" {
		t.Errorf("method = %q, want room_number", result.Method)
	}
	if !strings.Contains(result.Details, "room number") {
		t.Errorf("details = %q, should mention room number", result.Details)
	}
}

func TestAutoLogin_SocialPortal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>
			<a href="https://accounts.google.com/oauth">Sign in with Google</a>
		</body></html>`)
	}))
	defer ts.Close()

	result, err := AutoLogin(ts.URL)
	if err != nil {
		t.Fatalf("AutoLogin error = %v", err)
	}
	if result.Method != "social" {
		t.Errorf("method = %q, want social", result.Method)
	}
	if !strings.Contains(result.Details, "social login") {
		t.Errorf("details = %q, should mention social login", result.Details)
	}
}

func TestAutoLogin_UnknownPortal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><p>Welcome</p></body></html>`)
	}))
	defer ts.Close()

	result, err := AutoLogin(ts.URL)
	if err != nil {
		t.Fatalf("AutoLogin error = %v", err)
	}
	if result.Method != "manual" {
		t.Errorf("method = %q, want manual", result.Method)
	}
}

func TestAutoLogin_ClickThroughPortal(t *testing.T) {
	submitted := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			submitted = true
			w.WriteHeader(http.StatusOK)
			return
		}
		fmt.Fprint(w, `<html><body>
			<form action="/accept" method="post">
				<input type="hidden" name="token" value="abc">
				<p>I accept the terms and conditions</p>
				<input type="submit" name="accept" value="Connect">
			</form>
		</body></html>`)
	}))
	defer ts.Close()

	result, err := AutoLogin(ts.URL)
	if err != nil {
		t.Fatalf("AutoLogin error = %v", err)
	}
	if result.Method != "click_through" {
		t.Errorf("method = %q, want click_through", result.Method)
	}
	if !submitted {
		t.Error("form was not submitted")
	}
}

func TestAutoLogin_EmailPortal(t *testing.T) {
	var postedEmail string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			r.ParseForm()
			postedEmail = r.FormValue("email")
			w.WriteHeader(http.StatusOK)
			return
		}
		fmt.Fprint(w, `<html><body>
			<form action="/register" method="post">
				<input type="email" name="email" placeholder="your@email.com">
				<input type="checkbox" name="terms">
				<input type="submit" value="Register">
			</form>
		</body></html>`)
	}))
	defer ts.Close()

	result, err := AutoLogin(ts.URL)
	if err != nil {
		t.Fatalf("AutoLogin error = %v", err)
	}
	if result.Method != "email" {
		t.Errorf("method = %q, want email", result.Method)
	}
	if !strings.HasSuffix(postedEmail, "@protonmail.com") {
		t.Errorf("posted email = %q, want *@protonmail.com", postedEmail)
	}
}

func TestAutoLogin_InvalidURL(t *testing.T) {
	// Use a server that immediately closes connections.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	// Close it so connections fail fast.
	ts.Close()

	_, err := AutoLogin(ts.URL)
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

func TestAutoLogin_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	// Server returns 500 with empty body => unknown portal => manual
	result, err := AutoLogin(ts.URL)
	if err != nil {
		t.Fatalf("AutoLogin error = %v", err)
	}
	if result.Method != "manual" {
		t.Errorf("method = %q, want manual for empty body", result.Method)
	}
}

func TestAutoLogin_RedirectChain(t *testing.T) {
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/portal", http.StatusFound)
	})
	mux.HandleFunc("/portal", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><form action="/auth"><label>Room Number</label><input name="room"></form></html>`)
	})

	result, err := AutoLogin(ts.URL)
	if err != nil {
		t.Fatalf("AutoLogin error = %v", err)
	}
	if result.Method != "room_number" {
		t.Errorf("method = %q, want room_number after redirect", result.Method)
	}
}

func TestVerify_Success(t *testing.T) {
	// Mock the connectivity check endpoint returning 204.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	// We cannot easily inject the URL into Verify() since it's hardcoded,
	// but we can at least verify the function does not panic.
	// The real connectivity check will fail in test env, returning false.
	result := Verify()
	// In a test environment without actual internet, this should return false.
	_ = result // just verify no panic
}

func TestLoginResult_Fields(t *testing.T) {
	r := &LoginResult{
		Success: true,
		Method:  "click_through",
		Details: "accepted terms",
	}
	if !r.Success {
		t.Error("Success should be true")
	}
	if r.Method != "click_through" {
		t.Errorf("Method = %q", r.Method)
	}
	if r.Details != "accepted terms" {
		t.Errorf("Details = %q", r.Details)
	}
}
