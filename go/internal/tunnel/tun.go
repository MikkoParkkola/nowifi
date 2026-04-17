// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import "io"

// TUNDevice represents a virtual network interface (TUN device) that
// reads and writes raw IP packets. Platform-specific implementations
// are in tun_darwin.go and tun_linux.go.
type TUNDevice interface {
	io.ReadWriteCloser
	// Name returns the OS interface name (e.g. "utun3" or "tun0").
	Name() string
	// MTU returns the maximum transmission unit for the interface.
	MTU() int
}
