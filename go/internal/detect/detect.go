// Package detect implements captive portal detection and vendor fingerprinting.
//
// It uses multiple canary URLs (Apple CNA, Google 204, Firefox, Microsoft NCSI)
// with a consensus algorithm: a redirect to a different domain is an instant
// captive portal verdict, while majority canary failure indicates a transparent
// or firewall-style portal. DNS hijack detection is used as a fallback.
package detect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// PortalType describes the type of captive portal detected.
type PortalType string

const (
	PortalHTTPRedirect PortalType = "http_redirect"
	PortalDNSHijack    PortalType = "dns_hijack"
	PortalTransparent  PortalType = "transparent"
	PortalFirewall     PortalType = "firewall_block"
	PortalWalledGarden PortalType = "walled_garden"
	PortalNone         PortalType = "none"
)

// PortalInfo holds the results of captive portal detection.
type PortalInfo struct {
	IsCaptive    bool       `json:"is_captive"`
	Type         PortalType `json:"portal_type"`
	PortalURL    string     `json:"portal_url,omitempty"`
	RedirectURL  string     `json:"redirect_url,omitempty"`
	Vendor       string     `json:"vendor,omitempty"`
	VendorScore  int        `json:"vendor_score,omitempty"`
	AuthMethods  []string   `json:"auth_methods,omitempty"`
	PortalIP     string     `json:"portal_ip,omitempty"`
	SSID         string     `json:"ssid,omitempty"`
	Gateway      string     `json:"gateway,omitempty"`
}

// canary is an OS-level connectivity-check URL and its expected response.
type canary struct {
	URL            string
	ExpectedBody   string // empty means no body check
	ExpectedStatus int
	Name           string
}

var canaryURLs = []canary{
	{
		URL:            "http://captive.apple.com/hotspot-detect.html",
		ExpectedBody:   "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
		ExpectedStatus: 200,
		Name:           "Apple CNA",
	},
	{
		URL:            "http://connectivitycheck.gstatic.com/generate_204",
		ExpectedBody:   "",
		ExpectedStatus: 204,
		Name:           "Google 204",
	},
	{
		URL:            "http://detectportal.firefox.com/canonical.html",
		ExpectedBody:   "success",
		ExpectedStatus: 200,
		Name:           "Firefox",
	},
	{
		URL:            "http://www.msftconnecttest.com/connecttest.txt",
		ExpectedBody:   "Microsoft Connect Test",
		ExpectedStatus: 200,
		Name:           "Microsoft NCSI",
	},
}

// vendorSignature holds the patterns used to fingerprint a captive portal vendor.
type vendorSignature struct {
	URLPatterns    []string
	HTMLMarkers    []string
	HeaderPatterns []string
}

var vendorSignatures = map[string]vendorSignature{
	"cisco_meraki": {
		URLPatterns:    []string{"/splash/", "meraki"},
		HTMLMarkers:    []string{"meraki-splash", "meraki", "cisco-meraki"},
		HeaderPatterns: []string{"meraki"},
	},
	"aruba": {
		URLPatterns:    []string{"/cgi-bin/login", "setafi.com"},
		HTMLMarkers:    []string{"aruba_", "aruba", "clearpass", "hpe"},
		HeaderPatterns: []string{"Aruba"},
	},
	"ruckus": {
		URLPatterns:    []string{"/login.html", "ruckus"},
		HTMLMarkers:    []string{"ruckus-", "ruckus", "smartzone"},
		HeaderPatterns: []string{"Ruckus"},
	},
	"unifi": {
		URLPatterns:    []string{"/guest/s/", "unifi"},
		HTMLMarkers:    []string{"unifi-portal", "unifi", "ubnt"},
		HeaderPatterns: []string{"X-UniFi", "ubnt"},
	},
	"mikrotik": {
		URLPatterns:    []string{"/login", "mikrotik"},
		HTMLMarkers:    []string{"mikrotik", "routeros"},
		HeaderPatterns: []string{"Mikrotik"},
	},
	"fortinet": {
		URLPatterns:    []string{"/fgtauth", "fortinet"},
		HTMLMarkers:    []string{"ftnt_", "fortinet", "fortigate"},
		HeaderPatterns: []string{"FortiGate", "Fortinet"},
	},
	"pfsense": {
		URLPatterns:    []string{"/index.php?zone=", "pfsense"},
		HTMLMarkers:    []string{"captiveportal", "pfsense"},
		HeaderPatterns: []string{"pfSense"},
	},
	"opennds": {
		URLPatterns:    []string{"/opennds_preauth/"},
		HTMLMarkers:    []string{"opennds", "openNDS"},
		HeaderPatterns: nil,
	},
	"coovachilli": {
		URLPatterns:    []string{"/json/status"},
		HTMLMarkers:    []string{"coova", "chilli"},
		HeaderPatterns: nil,
	},
	"nomadix": {
		URLPatterns:    []string{"/nomadix/"},
		HTMLMarkers:    []string{"nomadix", "usg"},
		HeaderPatterns: []string{"Nomadix"},
	},
}

// canaryResult holds the parsed response from a single canary check.
type canaryResult struct {
	StatusCode int
	Body       string
	FinalURL   string
	Headers    http.Header
}

// DetectPortal checks whether the current network has a captive portal.
//
// It uses multiple canary URLs for consensus. A single canary failure could be
// a transparent proxy or network quirk -- require EITHER a redirect to a
// different domain (definitive) OR majority of canaries failing (consensus).
func DetectPortal(iface string) *PortalInfo {
	info := &PortalInfo{
		Type: PortalNone,
	}

	type redirect struct {
		url     string
		body    string
		headers http.Header
	}
	var redirects []redirect
	failures := 0
	successes := 0

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Do NOT follow redirects automatically -- we need to inspect the chain.
		// Actually, allow redirects but capture the final URL.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	for _, c := range canaryURLs {
		result := checkCanary(client, c)
		if result == nil {
			failures++
			continue
		}

		// Definitive redirect to a DIFFERENT domain = captive portal (instant verdict).
		canaryHost := hostFromURL(c.URL)
		finalHost := hostFromURL(result.FinalURL)
		if finalHost != "" && canaryHost != "" && finalHost != canaryHost {
			info.IsCaptive = true
			info.Type = PortalHTTPRedirect
			info.RedirectURL = result.FinalURL
			info.PortalURL = result.FinalURL
			info.PortalIP = resolvePortalIP(result.FinalURL)
			fingerprintPortal(info, result.Body, result.FinalURL, result.Headers)
			return info
		}

		// Check expected content.
		if result.StatusCode == c.ExpectedStatus &&
			(c.ExpectedBody == "" || strings.Contains(result.Body, c.ExpectedBody)) {
			successes++
		} else {
			failures++
			redirects = append(redirects, redirect{
				url:     result.FinalURL,
				body:    result.Body,
				headers: result.Headers,
			})
		}
	}

	// Consensus: majority of canaries fail = likely captive portal.
	if failures > successes && failures >= 2 {
		info.IsCaptive = true
		if len(redirects) > 0 {
			info.Type = PortalTransparent
			info.PortalURL = redirects[0].url
			fingerprintPortal(info, redirects[0].body, redirects[0].url, redirects[0].headers)
		} else {
			info.Type = PortalFirewall
		}
	}

	// Also check DNS hijacking as fallback.
	if !info.IsCaptive {
		if hijackIP := checkDNSHijack(); hijackIP != "" {
			info.IsCaptive = true
			info.Type = PortalDNSHijack
			info.PortalIP = hijackIP
		}
	}

	return info
}

// checkCanary probes a single canary URL and returns the response details,
// or nil if the request failed entirely.
func checkCanary(client *http.Client, c canary) *canaryResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "CaptiveNetworkSupport/1.0 wispr")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read up to 256KB of the body (portal pages are typically small).
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}

	return &canaryResult{
		StatusCode: resp.StatusCode,
		Body:       string(bodyBytes),
		FinalURL:   resp.Request.URL.String(),
		Headers:    resp.Header,
	}
}

// hostFromURL extracts the hostname from a URL string.
func hostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// resolvePortalIP resolves the portal URL hostname to an IP address.
func resolvePortalIP(rawURL string) string {
	hostname := hostFromURL(rawURL)
	if hostname == "" {
		return ""
	}
	ips, err := net.LookupHost(hostname)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

// checkDNSHijack checks if DNS is being hijacked by resolving multiple known
// domains. If they all resolve to the same single IP, DNS is being hijacked.
func checkDNSHijack() string {
	testDomains := []string{"google.com", "cloudflare.com", "microsoft.com", "amazon.com"}
	seen := make(map[string]struct{})

	for _, domain := range testDomains {
		ips, err := net.LookupHost(domain)
		if err != nil || len(ips) == 0 {
			continue
		}
		seen[ips[0]] = struct{}{}
	}

	// If all domains resolve to the same single IP, it is likely DNS hijacking.
	if len(seen) == 1 {
		for ip := range seen {
			return ip
		}
	}
	return ""
}

// fingerprintPortal identifies the portal vendor from page content, URL, and headers.
func fingerprintPortal(info *PortalInfo, body, rawURL string, headers http.Header) {
	bodyLower := strings.ToLower(body)
	urlLower := strings.ToLower(rawURL)

	// Build a single header string for matching.
	var headerParts []string
	for k, vals := range headers {
		for _, v := range vals {
			headerParts = append(headerParts, strings.ToLower(k+": "+v))
		}
	}
	headerStr := strings.Join(headerParts, " ")

	for vendor, sig := range vendorSignatures {
		score := 0

		for _, pattern := range sig.URLPatterns {
			if strings.Contains(urlLower, strings.ToLower(pattern)) {
				score += 2
			}
		}
		for _, marker := range sig.HTMLMarkers {
			if strings.Contains(bodyLower, strings.ToLower(marker)) {
				score++
			}
		}
		for _, pattern := range sig.HeaderPatterns {
			if strings.Contains(headerStr, strings.ToLower(pattern)) {
				score += 2
			}
		}

		if score >= 2 {
			info.Vendor = vendor
			info.VendorScore = score
			break
		}
	}

	// Detect auth methods from form fields.
	info.AuthMethods = detectAuthMethods(body)
}

// authPattern maps an authentication method name to a list of regexes
// that indicate its presence in portal HTML.
type authPattern struct {
	Method  string
	Regexes []*regexp.Regexp
}

var authPatterns = []authPattern{
	{"email", compilePatterns(`type=["']email["']`, `name=["']email["']`, `email`)},
	{"password", compilePatterns(`type=["']password["']`, `password`)},
	{"phone", compilePatterns(`type=["']tel["']`, `phone`, `mobile`)},
	{"social_google", compilePatterns(`google.*sign.?in`, `sign.?in.*google`, `accounts\.google\.com`, `oauth.*google`)},
	{"social_facebook", compilePatterns(`facebook.*login`, `facebook\.com/dialog`, `fb-login`)},
	{"room_number", compilePatterns(`room.?number`, `room.?no`)},
	{"voucher", compilePatterns(`voucher`, `access.?code`, `token`)},
	{"terms_only", compilePatterns(`accept.*terms`, `agree.*terms`, `terms.*conditions`)},
}

func compilePatterns(patterns ...string) []*regexp.Regexp {
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		// All patterns are matched case-insensitively.
		res = append(res, regexp.MustCompile("(?i)"+p))
	}
	return res
}

// detectAuthMethods parses portal HTML to detect available authentication methods.
func detectAuthMethods(html string) []string {
	var methods []string
	for _, ap := range authPatterns {
		for _, re := range ap.Regexes {
			if re.MatchString(html) {
				methods = append(methods, ap.Method)
				break
			}
		}
	}
	return methods
}
