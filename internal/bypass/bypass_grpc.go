// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"fmt"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/tunnel"
)

func tryGRPCTunnel(config *Config, _ *ProbeResults) Result {
	if config == nil || config.GRPCServerURL == "" {
		return Result{
			Method:  GRPCTunnel,
			Success: false,
			Details: "No gRPC server configured (use --grpc-server https://...).",
		}
	}

	handle, err := tunnel.StartGRPCTunnel(config.GRPCServerURL, 0, 15*time.Second)
	if err != nil {
		return Result{
			Method:  GRPCTunnel,
			Success: false,
			Details: fmt.Sprintf("gRPC tunnel failed (%s): %v", config.GRPCServerURL, err),
		}
	}

	if tunnel.VerifySOCKS(handle.LocalPort) {
		return successResult(
			GRPCTunnel,
			fmt.Sprintf("gRPC tunnel to %s active. Traffic looks like cloud API "+
				"(application/grpc). SOCKS5 at 127.0.0.1:%d.",
				config.GRPCServerURL, handle.LocalPort),
			withTunnel(handle),
		)
	}

	handle.Stop()
	return Result{
		Method:  GRPCTunnel,
		Success: false,
		Details: "gRPC stream connected but SOCKS verification failed.",
	}
}
