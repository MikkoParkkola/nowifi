// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

func trySSETunnel(config *Config, _ *ProbeResults) Result {
	if config == nil || config.SSEServerURL == "" {
		return Result{
			Method:  SSETunnel,
			Success: false,
			Details: "No SSE relay configured (use --sse-server https://...).",
		}
	}

	handle, err := tunnel.StartSSETunnel(config.SSEServerURL, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  SSETunnel,
			Success: false,
			Details: fmt.Sprintf("SSE tunnel failed (%s): %v", config.SSEServerURL, err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			SSETunnel,
			fmt.Sprintf("SSE tunnel to %s active. Downlink is a text/event-stream "+
				"(looks like a news feed). SOCKS5 at 127.0.0.1:%d.",
				config.SSEServerURL, handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  SSETunnel,
		Success: false,
		Details: "SSE stream connected but SOCKS verification failed.",
	}
}
