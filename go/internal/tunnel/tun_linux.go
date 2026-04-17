// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

//go:build linux

package tunnel

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// Linux TUN constants from <linux/if_tun.h>.
const (
	_IFF_TUN   = 0x0001
	_IFF_NO_PI = 0x1000 // no packet info header
	_TUNSETIFF = 0x400454ca
)

// ifreqFlags matches the relevant portion of struct ifreq for TUNSETIFF.
type ifreqFlags struct {
	name  [16]byte
	flags uint16
	_     [22]byte // padding
}

type linuxTUN struct {
	file *os.File
	name string
	mtu  int
}

// OpenTUN creates a new Linux TUN device. The name is auto-assigned if empty.
// Returns a TUNDevice that reads/writes raw IP packets (no packet info header).
func OpenTUN(mtu int) (TUNDevice, error) {
	if mtu == 0 {
		mtu = 1500
	}

	// Open the TUN clone device.
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}

	// Configure as TUN (not TAP), no packet info header.
	var req ifreqFlags
	// Leave name zeroed for auto-assignment (tun0, tun1, ...).
	req.flags = _IFF_TUN | _IFF_NO_PI

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(_TUNSETIFF),
		uintptr(unsafe.Pointer(&req))); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}

	// Extract assigned name.
	ifname := ""
	for i, b := range req.name {
		if b == 0 {
			ifname = string(req.name[:i])
			break
		}
	}
	if ifname == "" {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tun: empty interface name after TUNSETIFF")
	}

	// Set MTU.
	if err := setMTU(ifname, mtu); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "tun")
	return &linuxTUN{
		file: file,
		name: ifname,
		mtu:  mtu,
	}, nil
}

func (t *linuxTUN) Name() string { return t.name }
func (t *linuxTUN) MTU() int     { return t.mtu }

// Read reads a raw IP packet from the TUN device. On Linux with IFF_NO_PI,
// the kernel delivers raw IP packets without any header.
func (t *linuxTUN) Read(p []byte) (int, error) {
	return t.file.Read(p)
}

// Write writes a raw IP packet to the TUN device.
func (t *linuxTUN) Write(p []byte) (int, error) {
	return t.file.Write(p)
}

func (t *linuxTUN) Close() error {
	return t.file.Close()
}

// setMTU sets the interface MTU via SIOCSIFMTU ioctl.
func setMTU(ifname string, mtu int) error {
	if _, err := net.InterfaceByName(ifname); err != nil {
		return fmt.Errorf("tun: interface %s: %w", ifname, err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("tun: socket for mtu: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	type ifreqMTU struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}
	var req ifreqMTU
	copy(req.name[:], ifname)
	req.mtu = int32(mtu)

	const _SIOCSIFMTU = 0x8922
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(_SIOCSIFMTU),
		uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fmt.Errorf("tun: set mtu %d on %s: %w", mtu, ifname, errno)
	}
	return nil
}
