// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

// ---------------------------------------------------------------------------
// Wave 21 #24 — Encrypted Client Hello (ECH) domain fronting.
//
// Starts a local SOCKS5-lite listener backed by a TLS 1.3+ECH connection to
// the user's bypass proxy. Outer SNI is the ECH cover name (CDN); inner SNI
// is the proxy's real hostname. Portal DPI sees only the cover.
//
// Success criterion: ECH actually negotiated (probe handshake reports
// tls.ConnectionState.ECHAccepted == true) AND the local SOCKS listener
// validates via tunnel.VerifySOCKS. We never fall back to non-ECH: the whole
// bypass value is SNI concealment.
// ---------------------------------------------------------------------------

func tryECHFronting(config *Config, _ *ProbeResults) Result {
	if config == nil {
		return Result{
			Method:  ECHFronting,
			Success: false,
			Details: "ECH technique requires --ech-server and --ech-config-list.",
		}
	}
	if config.ECHServerURL == "" {
		return Result{
			Method:  ECHFronting,
			Success: false,
			Details: "ECH not configured. Provide --ech-server <https-url>.",
		}
	}

	// Auto-discover ECHConfigList via DoH if not manually provided.
	echConfigB64 := config.ECHConfigListBase64
	if echConfigB64 == "" {
		if u, err := url.Parse(config.ECHServerURL); err == nil && u.Hostname() != "" {
			if discovered, err := tunnel.DiscoverECHConfigList(u.Hostname()); err == nil && len(discovered) > 0 {
				echConfigB64 = base64.StdEncoding.EncodeToString(discovered)
			}
		}
	}
	if echConfigB64 == "" {
		return Result{
			Method:  ECHFronting,
			Success: false,
			Details: "ECH config not found via DoH auto-discovery. Provide --ech-config-list <base64> manually.",
		}
	}

	handle, err := tunnel.StartECHProxy(tunnel.ECHServerConfig{
		ServerURL:           config.ECHServerURL,
		ECHConfigListBase64: echConfigB64,
		Timeout:             15 * time.Second,
	}, 0)
	if err != nil {
		return Result{
			Method:  ECHFronting,
			Success: false,
			Details: fmt.Sprintf("ECH handshake failed: %v", err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			ECHFronting,
			fmt.Sprintf("TLS 1.3 ECH tunnel to %s. Outer SNI is the CDN cover name; real destination "+
				"is encrypted in the inner ClientHello. SOCKS5 at 127.0.0.1:%d.",
				config.ECHServerURL, handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  ECHFronting,
		Success: false,
		Details: "ECH handshake succeeded but SOCKS verification failed (upstream proxy didn't forward CONNECT).",
	}
}
