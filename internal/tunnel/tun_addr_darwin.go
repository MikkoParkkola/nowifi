// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

//go:build darwin

package tunnel

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"
)

// configureTUNAddressPlatform assigns an IP address and brings the
// interface up on macOS using ifconfig.
func configureTUNAddressPlatform(ifname string, ip net.IP) error {
	// Point-to-point: assign local IP with a dummy peer.
	peer := net.IP(make([]byte, 4))
	copy(peer, ip.To4())
	peer[3] = 1 // gateway is .1 in the /24

	// ifconfig utunN inet <local> <peer> up
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	out, err := exec.CommandContext(ctx, "ifconfig", ifname,
		"inet", ip.String(), peer.String(), "up").CombinedOutput()
	cancel()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %s: %w", ifname, string(out), err)
	}

	// Add default route through the tunnel.
	// Use a /1 split route to avoid replacing the default route entirely:
	// 0.0.0.0/1 via tunnel + 128.0.0.0/1 via tunnel covers all addresses
	// without touching the existing default route.
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		out, err = exec.CommandContext(ctx, "route", "add", "-net", cidr, "-interface", ifname).CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("route add %s: %s: %w", cidr, string(out), err)
		}
	}
	return nil
}
