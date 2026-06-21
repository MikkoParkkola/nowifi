// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

func tryWARPTunnel(_ *Config, _ *ProbeResults) Result {
	handle, err := tunnel.StartWARPTunnel(0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  WARPTunnel,
			Success: false,
			Details: fmt.Sprintf("WARP tunnel failed: %v", err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			WARPTunnel,
			fmt.Sprintf("Cloudflare WARP tunnel active (zero-config). "+
				"Traffic is genuine WARP — identical to 10M+ WARP users. "+
				"SOCKS5 at 127.0.0.1:%d.", handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  WARPTunnel,
		Success: false,
		Details: "WARP connected but SOCKS verification failed.",
	}
}
