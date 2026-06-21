// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package portal implements automatic captive portal login.
//
// It fetches the portal page, detects the form type (click-through, email
// registration, room number, social login), and submits the appropriate
// response. For email-required portals, it generates a disposable address
// that looks real but does not need to receive mail.
package portal

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// LoginResult describes the outcome of an auto-login attempt.
type LoginResult struct {
	Success bool   `json:"success"`
	Method  string `json:"method"` // "click_through", "email", "room_number", "social", "manual"
	Details string `json:"details"`
}

// formField represents an HTML form input.
type formField struct {
	Name  string
	Type  string
	Value string
}

// AutoLogin attempts to automatically submit the captive portal login form.
//
// It handles four portal types:
//   - Click-through (terms acceptance): finds the submit button and clicks it.
//   - Email registration: fills the email field with a disposable address.
//   - Room/code: returns a result indicating manual input is required.
//   - Social login: returns a result with the OAuth URL for the user.
func AutoLogin(portalURL string) (*LoginResult, error) {
	if portalURL == "" {
		return &LoginResult{Method: "manual", Details: "no portal URL"}, nil
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Fetch the portal page.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, portalURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch portal: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch portal: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, fmt.Errorf("read portal body: %w", err)
	}
	body := string(bodyBytes)

	// Detect form type and extract action URL.
	formAction, fields := parseForm(body, portalURL)
	portalType := classifyForm(body, fields)

	switch portalType {
	case "click_through":
		return submitClickThrough(client, formAction, fields)
	case "email":
		return submitEmail(client, formAction, fields)
	case "room_number":
		return &LoginResult{
			Method:  "room_number",
			Details: "portal requires room number or access code -- enter manually",
		}, nil
	case "social":
		return &LoginResult{
			Method:  "social",
			Details: fmt.Sprintf("portal requires social login -- open %s in a browser", portalURL),
		}, nil
	default:
		return &LoginResult{
			Method:  "manual",
			Details: "unrecognized portal type -- open in browser to authenticate",
		}, nil
	}
}

// DisposableEmail generates a temporary email for portal registration.
// The address does not need to work -- most portals never verify delivery.
func DisposableEmail() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[0]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return fmt.Sprintf("guest.%s@protonmail.com", string(b))
}

// Verify checks internet connectivity by testing the canary URL.
// Returns true if the portal has been bypassed.
func Verify() bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://connectivitycheck.gstatic.com/generate_204", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 204
}

// --- Internal helpers ---

var (
	formActionRE = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']+)["']`)
	inputRE      = regexp.MustCompile(`(?i)<input[^>]*>`)
	inputNameRE  = regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
	inputTypeRE  = regexp.MustCompile(`(?i)type=["']([^"']+)["']`)
	inputValueRE = regexp.MustCompile(`(?i)value=["']([^"']*?)["']`)
	socialRE     = regexp.MustCompile(`(?i)(google.*sign.?in|facebook.*login|accounts\.google\.com|facebook\.com/dialog)`)
	roomCodeRE   = regexp.MustCompile(`(?i)(room.?number|room.?no|access.?code|voucher)`)
	emailFieldRE = regexp.MustCompile(`(?i)(type=["']email["']|name=["']email["'])`)
	termsRE      = regexp.MustCompile(`(?i)(accept.*terms|agree.*terms|terms.*conditions|type=["']submit["'])`)
)

// parseForm extracts the form action URL and input fields from HTML.
func parseForm(html, baseURL string) (string, []formField) {
	action := baseURL
	if m := formActionRE.FindStringSubmatch(html); m != nil {
		action = resolveURL(baseURL, m[1])
	}

	var fields []formField
	for _, inputTag := range inputRE.FindAllString(html, -1) {
		var f formField
		if m := inputNameRE.FindStringSubmatch(inputTag); m != nil {
			f.Name = m[1]
		}
		if m := inputTypeRE.FindStringSubmatch(inputTag); m != nil {
			f.Type = strings.ToLower(m[1])
		}
		if m := inputValueRE.FindStringSubmatch(inputTag); m != nil {
			f.Value = m[1]
		}
		if f.Name != "" {
			fields = append(fields, f)
		}
	}

	return action, fields
}

// classifyForm determines the portal type from its HTML and fields.
func classifyForm(html string, fields []formField) string {
	if socialRE.MatchString(html) {
		return "social"
	}
	if roomCodeRE.MatchString(html) {
		return "room_number"
	}
	if emailFieldRE.MatchString(html) {
		return "email"
	}
	// If there is a form with just a submit button or terms checkbox, it is click-through.
	if termsRE.MatchString(html) {
		return "click_through"
	}
	if len(fields) > 0 {
		return "click_through"
	}
	return "unknown"
}

// submitClickThrough submits a form with its existing values (terms acceptance).
func submitClickThrough(client *http.Client, actionURL string, fields []formField) (*LoginResult, error) {
	data := url.Values{}
	for _, f := range fields {
		if f.Type == "checkbox" {
			data.Set(f.Name, "on")
		} else if f.Value != "" {
			data.Set(f.Name, f.Value)
		}
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, actionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("submit click-through: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submit click-through: %w", err)
	}
	resp.Body.Close()

	if Verify() {
		return &LoginResult{
			Success: true,
			Method:  "click_through",
			Details: "accepted terms and gained access",
		}, nil
	}

	return &LoginResult{
		Method:  "click_through",
		Details: fmt.Sprintf("submitted form (HTTP %d) but connectivity check failed", resp.StatusCode),
	}, nil
}

// submitEmail fills the email field with a disposable address and submits.
func submitEmail(client *http.Client, actionURL string, fields []formField) (*LoginResult, error) {
	email := DisposableEmail()
	data := url.Values{}

	for _, f := range fields {
		switch {
		case f.Type == "email" || strings.Contains(strings.ToLower(f.Name), "email"):
			data.Set(f.Name, email)
		case f.Type == "checkbox":
			data.Set(f.Name, "on")
		case f.Value != "":
			data.Set(f.Name, f.Value)
		}
	}

	// If no email field was found by name/type, try adding one.
	if data.Get("email") == "" {
		data.Set("email", email)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, actionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("submit email: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submit email: %w", err)
	}
	resp.Body.Close()

	if Verify() {
		return &LoginResult{
			Success: true,
			Method:  "email",
			Details: fmt.Sprintf("registered with %s and gained access", email),
		}, nil
	}

	return &LoginResult{
		Method:  "email",
		Details: fmt.Sprintf("submitted email %s (HTTP %d) but connectivity check failed", email, resp.StatusCode),
	}, nil
}

// resolveURL resolves a potentially relative URL against a base.
func resolveURL(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}
