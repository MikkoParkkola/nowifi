// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

// ---------------------------------------------------------------------------
// Wave 21 #28 — WebTransport tunnel (RFC 9220).
//
// Opens a WebTransport session over HTTP/3 to the tunnel server. From DPI's
// perspective this is a Google Meet / Zoom video call — the CONNECT upgrade
// uses :protocol webtransport, and data flows over bidi QUIC streams within
// the HTTP/3 session. Captive portals that allow video calls pass this.
//
// Success: WebTransport session established AND SOCKS5 proxy verifies
// end-to-end connectivity.
// ---------------------------------------------------------------------------

func tryWebTransportTunnel(config *Config, _ *ProbeResults) Result {
	if config == nil || config.WTServerURL == "" {
		return Result{
			Method:  WebTransportTunnel,
			Success: false,
			Details: "No WebTransport server configured (use --wt-server https://...).",
		}
	}

	handle, err := tunnel.StartWebTransportTunnel(config.WTServerURL, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  WebTransportTunnel,
			Success: false,
			Details: fmt.Sprintf("WebTransport tunnel failed (%s): %v", config.WTServerURL, err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			WebTransportTunnel,
			fmt.Sprintf("WebTransport tunnel to %s active. RFC 9220 over HTTP/3 "+
				"— looks like Google Meet/Zoom to portal DPI. SOCKS5 at 127.0.0.1:%d.",
				config.WTServerURL, handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  WebTransportTunnel,
		Success: false,
		Details: "WebTransport session established but SOCKS verification failed (server didn't bridge).",
	}
}
