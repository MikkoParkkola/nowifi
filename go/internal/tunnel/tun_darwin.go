// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

//go:build darwin

package tunnel

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// macOS utun constants. These match <sys/kern_control.h> and <net/if_utun.h>.
const (
	_SYSPROTO_CONTROL = 2           // AF_SYSTEM, SYSPROTO_CONTROL
	_AF_SYSTEM        = 32          // AF_SYSTEM
	_PF_SYSTEM        = _AF_SYSTEM  // PF_SYSTEM
	_UTUN_CONTROL_NAME = "com.apple.net.utun_control"
	_CTLIOCGINFO      = 0xc0644e03 // _IOWR('N', 3, struct ctl_info)
	_UTUN_OPT_IFNAME  = 2
)

// ctlInfo matches struct ctl_info from <sys/kern_control.h>.
type ctlInfo struct {
	id   uint32
	name [96]byte
}

// sockaddrCtl matches struct sockaddr_ctl from <sys/kern_control.h>.
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

type darwinTUN struct {
	fd   int
	file *os.File
	name string
	mtu  int
}

// OpenTUN creates a new macOS utun device. The unit number is auto-assigned.
// Returns a TUNDevice that reads/writes raw IP packets (4-byte AF header
// prepended by the kernel on macOS).
func OpenTUN(mtu int) (TUNDevice, error) {
	if mtu == 0 {
		mtu = 1500
	}

	// Create a system socket for the utun kernel control.
	fd, err := syscall.Socket(_PF_SYSTEM, syscall.SOCK_DGRAM, _SYSPROTO_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("tun: socket: %w", err)
	}

	// Look up the control ID for com.apple.net.utun_control.
	var info ctlInfo
	copy(info.name[:], _UTUN_CONTROL_NAME)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(_CTLIOCGINFO),
		uintptr(unsafe.Pointer(&info))); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tun: CTLIOCGINFO: %w", errno)
	}

	// Connect with unit=0 for auto-assignment.
	addr := sockaddrCtl{
		scLen:    uint8(unsafe.Sizeof(sockaddrCtl{})),
		scFamily: _AF_SYSTEM,
		ssSysaddr: 2, // AF_SYS_CONTROL
		scID:     info.id,
		scUnit:   0, // 0 = auto-assign
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr)),
		unsafe.Sizeof(addr)); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tun: connect: %w", errno)
	}

	// Get the assigned interface name.
	ifnameBuf := make([]byte, 64)
	ifnameLen := uint32(len(ifnameBuf))
	if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(_SYSPROTO_CONTROL),
		uintptr(_UTUN_OPT_IFNAME),
		uintptr(unsafe.Pointer(&ifnameBuf[0])),
		uintptr(unsafe.Pointer(&ifnameLen)),
		0); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tun: get ifname: %w", errno)
	}
	ifname := string(ifnameBuf[:ifnameLen-1]) // trim null terminator

	// Set MTU via ifconfig (simplest cross-version approach).
	if err := setMTU(ifname, mtu); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "utun")
	return &darwinTUN{
		fd:   fd,
		file: file,
		name: ifname,
		mtu:  mtu,
	}, nil
}

func (t *darwinTUN) Name() string { return t.name }
func (t *darwinTUN) MTU() int     { return t.mtu }

// Read reads a raw IP packet from the TUN device. On macOS, the kernel
// prepends a 4-byte protocol header (AF_INET or AF_INET6); we strip it.
func (t *darwinTUN) Read(p []byte) (int, error) {
	buf := make([]byte, t.mtu+4)
	n, err := t.file.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, fmt.Errorf("tun: short read (%d bytes)", n)
	}
	// Strip the 4-byte AF header.
	copy(p, buf[4:n])
	return n - 4, nil
}

// Write writes a raw IP packet to the TUN device. On macOS, we must
// prepend a 4-byte protocol header.
func (t *darwinTUN) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Determine AF from IP version nibble.
	var af uint32
	switch p[0] >> 4 {
	case 4:
		af = syscall.AF_INET
	case 6:
		af = syscall.AF_INET6
	default:
		return 0, fmt.Errorf("tun: unknown IP version %d", p[0]>>4)
	}

	buf := make([]byte, 4+len(p))
	buf[0] = byte(af >> 24)
	buf[1] = byte(af >> 16)
	buf[2] = byte(af >> 8)
	buf[3] = byte(af)
	copy(buf[4:], p)

	n, err := t.file.Write(buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, nil
	}
	return n - 4, nil
}

func (t *darwinTUN) Close() error {
	return t.file.Close()
}

// setMTU sets the interface MTU using the net package's interface lookup
// and a sysctl/ioctl. Falls back to ifconfig if needed.
func setMTU(ifname string, mtu int) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("tun: interface %s: %w", ifname, err)
	}
	// The interface exists; MTU is set via SIOCSIFMTU ioctl.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("tun: socket for mtu: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	type ifreqMTU struct {
		name [16]byte
		mtu  int32
		_    [20]byte // padding to match struct ifreq size
	}
	var req ifreqMTU
	copy(req.name[:], ifname)
	req.mtu = int32(mtu)

	const _SIOCSIFMTU = 0x80206934
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(_SIOCSIFMTU),
		uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fmt.Errorf("tun: set mtu %d on %s: %w", mtu, ifname, errno)
	}
	_ = iface // used for validation above
	return nil
}
