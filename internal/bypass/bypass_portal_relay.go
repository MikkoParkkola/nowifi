// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

func tryPortalRelay(_ *Config, probes *ProbeResults) Result {
	// Collect whitelisted domains from probes + common list.
	var extraDomains []string
	for _, w := range probes.Whitelists {
		if w.IsOpen {
			extraDomains = append(extraDomains, w.Domain)
		}
	}

	// Probe for reachable whitelisted domains.
	reachable := tunnel.FindWhitelistedDomains(extraDomains, 8*time.Second)
	if len(reachable) == 0 {
		return Result{
			Method:  PortalRelay,
			Success: false,
			Details: "No whitelisted domains reachable through portal",
		}
	}

	handle, err := tunnel.StartPortalRelayTunnel(reachable, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  PortalRelay,
			Success: false,
			Details: fmt.Sprintf("Portal relay failed: %v (probed %d whitelisted domains)", err, len(reachable)),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			PortalRelay,
			fmt.Sprintf("Portal relay active via whitelisted domain. "+
				"Tunneling through portal-trusted HTTPS endpoint. "+
				"SOCKS5 at 127.0.0.1:%d.", handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  PortalRelay,
		Success: false,
		Details: "Portal relay connected but SOCKS verification failed.",
	}
}
