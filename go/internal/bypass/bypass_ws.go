// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

// tryWGOverWebSocket opens a WebSocket tunnel to the configured server and
// verifies SOCKS5 connectivity through it.
func tryWGOverWebSocket(config *Config, _ *ProbeResults) Result {
	if config == nil || config.WSServerURL == "" {
		return Result{
			Method:  WGOverWebSocket,
			Success: false,
			Details: "No WebSocket tunnel server configured (use --ws-server wss://...).",
		}
	}

	handle, err := tunnel.StartWebSocketTunnel(config.WSServerURL, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  WGOverWebSocket,
			Success: false,
			Details: fmt.Sprintf("WebSocket tunnel failed (%s): %v", config.WSServerURL, err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			WGOverWebSocket,
			fmt.Sprintf("WebSocket tunnel to %s active. SOCKS5 at 127.0.0.1:%d. "+
				"WS upgrade looks like Teams/Zoom/Discord to portal DPI.",
				config.WSServerURL, handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  WGOverWebSocket,
		Success: false,
		Details: "WebSocket upgrade succeeded but SOCKS verification failed (server didn't forward).",
	}
}
