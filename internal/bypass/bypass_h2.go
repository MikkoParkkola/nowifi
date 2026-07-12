// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

func tryH2ConnectTunnel(config *Config, _ *ProbeResults) Result {
	if config == nil || config.H2ProxyURL == "" {
		return Result{
			Method:  H2ConnectTunnel,
			Success: false,
			Details: "No HTTP/2 proxy configured (use --h2-proxy https://...).",
		}
	}

	handle, err := tunnel.StartH2ConnectTunnel(config.H2ProxyURL, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  H2ConnectTunnel,
			Success: false,
			Details: fmt.Sprintf("HTTP/2 CONNECT failed (%s): %v", config.H2ProxyURL, err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			H2ConnectTunnel,
			fmt.Sprintf("HTTP/2 CONNECT tunnel to %s active. Binary-framed multiplexed "+
				"streams — looks like gRPC/Cloud API to DPI. SOCKS5 at 127.0.0.1:%d.",
				config.H2ProxyURL, handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  H2ConnectTunnel,
		Success: false,
		Details: "HTTP/2 CONNECT negotiated but SOCKS verification failed.",
	}
}
