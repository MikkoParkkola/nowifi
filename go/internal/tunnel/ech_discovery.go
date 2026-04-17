// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DiscoverECHConfigList fetches the ECHConfigList for a hostname by querying
// its HTTPS DNS RR (type 65) via DNS-over-HTTPS. Returns the raw bytes
// (ready for tls.Config.EncryptedClientHelloConfigList) or an error.
//
// Tries Cloudflare (1.1.1.1) first, then Google (8.8.8.8). These DoH
// endpoints are commonly whitelisted by captive portals since they're needed
// for legitimate HTTPS browsing.
func DiscoverECHConfigList(hostname string) ([]byte, error) {
	if hostname == "" {
		return nil, errors.New("ech discovery: empty hostname")
	}

	providers := []struct {
		name string
		url  string
	}{
		{"Cloudflare", "https://cloudflare-dns.com/dns-query"},
		{"Google", "https://dns.google/resolve"},
	}

	var lastErr error
	for _, p := range providers {
		raw, err := queryHTTPSRR(p.url, hostname)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", p.name, err)
			continue
		}
		return raw, nil
	}
	return nil, fmt.Errorf("ech discovery: all providers failed: %w", lastErr)
}

// dohResponse is the minimal JSON wire format for DoH application/dns-json.
type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

func queryHTTPSRR(endpoint, hostname string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s?name=%s&type=HTTPS", endpoint, hostname)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var doh dohResponse
	if err := json.Unmarshal(body, &doh); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	if doh.Status != 0 {
		return nil, fmt.Errorf("DNS error status %d", doh.Status)
	}

	// Find HTTPS RR (type 65) answers and extract the ech= SvcParam.
	for _, ans := range doh.Answer {
		if ans.Type != 65 {
			continue
		}
		echB64 := extractECHFromSvcParams(ans.Data)
		if echB64 == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(echB64)
		if err != nil {
			// Try URL-safe or raw variants.
			decoded, err = base64.RawStdEncoding.DecodeString(echB64)
			if err != nil {
				continue
			}
		}
		if len(decoded) > 0 {
			return decoded, nil
		}
	}

	return nil, errors.New("no ECH config in HTTPS RR")
}

// extractECHFromSvcParams parses the presentation-format HTTPS RR data
// and extracts the ech= SvcParam value. The data looks like:
//
//	1 . alpn="h2,h3" ech=AAAA... ipv4hint=1.2.3.4
//
// or with quoting:
//
//	1 . alpn=h2,h3 ech="AAAA..."
func extractECHFromSvcParams(data string) string {
	// Split on whitespace and look for ech= parameter.
	for _, field := range strings.Fields(data) {
		if strings.HasPrefix(field, "ech=") {
			val := strings.TrimPrefix(field, "ech=")
			// Strip surrounding quotes if present.
			val = strings.Trim(val, "\"")
			return val
		}
	}
	return ""
}
