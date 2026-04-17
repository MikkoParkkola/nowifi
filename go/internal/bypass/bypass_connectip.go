// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

func tryConnectIPTunnel(config *Config, _ *ProbeResults) Result {
	if config == nil || config.ConnectIPServerURL == "" {
		return Result{
			Method:  ConnectIPTunnel,
			Success: false,
			Details: "No CONNECT-IP server configured (use --connectip-server https://...).",
		}
	}

	handle, err := tunnel.StartConnectIPTunnel(tunnel.ConnectIPConfig{
		ServerURL: config.ConnectIPServerURL,
	})
	if err != nil {
		return Result{
			Method:  ConnectIPTunnel,
			Success: false,
			Details: fmt.Sprintf("CONNECT-IP tunnel failed (%s): %v", config.ConnectIPServerURL, err),
		}
	}

	// CONNECT-IP creates a TUN device — verify internet works via ping.
	// Unlike SOCKS-based techniques, there's no local proxy port.
	return successResult(
		ConnectIPTunnel,
		fmt.Sprintf("CONNECT-IP tunnel to %s active. Full IP tunnel via TUN device. "+
			"All traffic (TCP/UDP/ICMP) routed through proxy. "+
			"Looks identical to Apple Private Relay.",
			config.ConnectIPServerURL),
		withTunnel(handle),
	)
}
