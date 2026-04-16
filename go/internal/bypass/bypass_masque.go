// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

// ---------------------------------------------------------------------------
// Wave 21 #27 — MASQUE tunnel via HTTP/3 Extended CONNECT (RFC 9298).
//
// Opens an HTTP/3 connection with Extended CONNECT + Datagrams enabled to the
// user's MASQUE proxy. The traffic fingerprint (QUIC "h3" ALPN, SETTINGS with
// ENABLE_CONNECT_PROTOCOL, Capsule-Protocol header) matches Apple Private
// Relay, Cloudflare WARP, and browser WebTransport. No commercial captive
// portal DPI distinguishes this from legitimate HTTP/3 traffic.
//
// Success criterion: HTTP/3 handshake succeeds with Extended CONNECT
// negotiated AND local SOCKS5 proxy verifies end-to-end connectivity.
// ---------------------------------------------------------------------------

func tryMASQUETunnel(config *Config, _ *ProbeResults) Result {
	if config == nil || config.MASQUEServerURL == "" {
		return Result{
			Method:  MASQUETunnel,
			Success: false,
			Details: "No MASQUE proxy configured (use --masque-server https://...).",
		}
	}

	handle, err := tunnel.StartMASQUETunnel(config.MASQUEServerURL, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  MASQUETunnel,
			Success: false,
			Details: fmt.Sprintf("MASQUE tunnel failed (%s): %v", config.MASQUEServerURL, err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			MASQUETunnel,
			fmt.Sprintf("MASQUE tunnel to %s active. HTTP/3 Extended CONNECT (RFC 9220/9298) "+
				"— identical to Apple Private Relay/Cloudflare WARP. SOCKS5 at 127.0.0.1:%d.",
				config.MASQUEServerURL, handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  MASQUETunnel,
		Success: false,
		Details: "MASQUE Extended CONNECT negotiated but SOCKS verification failed (proxy didn't bridge).",
	}
}
