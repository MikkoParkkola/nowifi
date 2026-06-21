// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

func tryTURNRelay(_ *Config, _ *ProbeResults) Result {
	handle, err := tunnel.StartTURNRelayTunnel(0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  TURNRelay,
			Success: false,
			Details: fmt.Sprintf("TURN relay failed: %v", err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			TURNRelay,
			fmt.Sprintf("TURN relay active via public TURN server. "+
				"Traffic relayed through WebRTC infrastructure (TCP/443). "+
				"SOCKS5 at 127.0.0.1:%d.", handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  TURNRelay,
		Success: false,
		Details: "TURN relay connected but SOCKS verification failed.",
	}
}
