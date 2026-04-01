// Package discover implements passive device observation on WiFi networks.
// Identifies authorized devices by monitoring ARP broadcast traffic (shared GTK on WPA2).
package discover

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// AuthorizedDevice represents a device observed on the network with authorization scoring.
type AuthorizedDevice struct {
	MAC       string
	IP        string
	Score     float64   // 0-1 authorization likelihood
	FirstSeen time.Time
	LastSeen  time.Time
	ARPCount  int
	IsIdle    bool // Not responding to ping
	IsGone    bool // Was seen before, now absent (for time-shifted clone)
}

// ObserveAuthorized passively watches ARP table to identify authorized devices.
// On WPA2-Personal, ARP broadcasts use the shared GTK and are visible to all clients.
// On Open WiFi, all traffic is visible.
func ObserveAuthorized(iface string, duration time.Duration) ([]AuthorizedDevice, error) {
	gateway, _ := platform.GetGateway(iface)
	ourMAC, _ := platform.GetCurrentMAC(iface)

	devices := make(map[string]*AuthorizedDevice)
	deadline := time.Now().Add(duration)

	// Sample ARP table periodically
	for time.Now().Before(deadline) {
		entries, err := platform.GetARPTable()
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		for _, e := range entries {
			if e.Interface != iface || e.IP == gateway || e.MAC == ourMAC {
				continue
			}
			if len(e.MAC) < 10 || strings.HasPrefix(e.MAC, "ff:ff") {
				continue
			}

			if d, ok := devices[e.MAC]; ok {
				d.LastSeen = time.Now()
				d.ARPCount++
			} else {
				devices[e.MAC] = &AuthorizedDevice{
					MAC:       e.MAC,
					IP:        e.IP,
					FirstSeen: time.Now(),
					LastSeen:  time.Now(),
					ARPCount:  1,
				}
			}
		}
		time.Sleep(5 * time.Second)
	}

	// Score devices
	result := make([]AuthorizedDevice, 0, len(devices))
	for _, d := range devices {
		// Higher ARP count = more active = more likely authorized
		d.Score = scoreDevice(d)
		// Check if idle (not responding to ping)
		d.IsIdle = !isReachable(d.IP)
		result = append(result, *d)
	}

	return result, nil
}

// WaitForDeparture monitors the network for devices that leave.
// Returns devices that were seen but are now gone — ideal for time-shifted clone.
func WaitForDeparture(iface string, timeout time.Duration) ([]AuthorizedDevice, error) {
	gateway, _ := platform.GetGateway(iface)
	ourMAC, _ := platform.GetCurrentMAC(iface)

	// Take initial snapshot
	initial := make(map[string]string) // MAC → IP
	entries, _ := platform.GetARPTable()
	for _, e := range entries {
		if e.Interface == iface && e.IP != gateway && e.MAC != ourMAC && len(e.MAC) >= 10 {
			initial[e.MAC] = e.IP
		}
	}

	if len(initial) == 0 {
		return nil, fmt.Errorf("no other devices found on network")
	}

	// Monitor for departures
	departed := make([]AuthorizedDevice, 0)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		time.Sleep(30 * time.Second)

		// Re-scan ARP table
		current := make(map[string]bool)
		entries, _ = platform.GetARPTable()
		for _, e := range entries {
			if e.Interface == iface {
				current[e.MAC] = true
			}
		}

		// Find devices that left
		for mac, ip := range initial {
			if !current[mac] {
				// Confirm with ping (ARP may just have expired)
				if !isReachable(ip) {
					departed = append(departed, AuthorizedDevice{
						MAC:    mac,
						IP:     ip,
						IsGone: true,
						Score:  0.9, // High confidence — was here, now gone
					})
					delete(initial, mac) // Don't report again
				}
			}
		}

		if len(departed) > 0 {
			return departed, nil
		}
	}

	return departed, nil
}

func scoreDevice(d *AuthorizedDevice) float64 {
	score := 0.0
	// More ARP activity = more likely authorized and active
	if d.ARPCount >= 10 {
		score += 0.4
	} else if d.ARPCount >= 5 {
		score += 0.3
	} else if d.ARPCount >= 2 {
		score += 0.2
	} else {
		score += 0.1
	}
	// Longer presence = more likely authorized
	duration := d.LastSeen.Sub(d.FirstSeen)
	if duration > 5*time.Minute {
		score += 0.3
	} else if duration > 1*time.Minute {
		score += 0.2
	} else {
		score += 0.1
	}
	// Recent activity = more likely still authorized
	if time.Since(d.LastSeen) < 30*time.Second {
		score += 0.3
	} else if time.Since(d.LastSeen) < 2*time.Minute {
		score += 0.2
	} else {
		score += 0.1
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func isReachable(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	return cmd.Run() == nil
}
