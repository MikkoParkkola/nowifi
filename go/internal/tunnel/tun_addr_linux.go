// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

//go:build linux

package tunnel

import (
	"fmt"
	"net"
	"os/exec"
)

// configureTUNAddressPlatform assigns an IP address and brings the
// interface up on Linux using ip(8).
func configureTUNAddressPlatform(ifname string, ip net.IP) error {
	// ip addr add <ip>/24 dev <ifname>
	out, err := exec.Command("ip", "addr", "add",
		fmt.Sprintf("%s/24", ip.String()), "dev", ifname).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr add: %s: %w", string(out), err)
	}

	// ip link set <ifname> up
	out, err = exec.Command("ip", "link", "set", ifname, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set up: %s: %w", string(out), err)
	}

	// Split routes to avoid replacing the default route:
	// 0.0.0.0/1 via tunnel + 128.0.0.0/1 via tunnel
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		out, err = exec.Command("ip", "route", "add", cidr, "dev", ifname).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip route add %s: %s: %w", cidr, string(out), err)
		}
	}
	return nil
}
