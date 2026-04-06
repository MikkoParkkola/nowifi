// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/toolchain"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system health and diagnose common issues",
	Long: `Check system health and diagnose common issues.

Quick non-interactive health check. Shows OK/FAIL for each item:
  - Go runtime and OS
  - WiFi connection
  - Sudo access
  - External tools
  - DNS resolution
  - Internet reachability`,
	Run: runDoctor,
}

func runDoctor(cmd *cobra.Command, args []string) {
	fmt.Println("\nnowifi — Doctor")
	fmt.Println()

	allOK := true

	check := func(label string, ok bool, detail string) {
		statusStr := green("OK")
		if !ok {
			statusStr = red("FAIL")
			allOK = false
		}
		msg := fmt.Sprintf("  %-6s %s", statusStr, label)
		if detail != "" {
			msg += "  " + detail
		}
		fmt.Println(msg)
	}

	// Go runtime.
	check("Go runtime", true, fmt.Sprintf("Go %s, %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH))

	// OS.
	osOK := runtime.GOOS == "darwin" || runtime.GOOS == "linux"
	check("Operating system", osOK, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))

	// WiFi connected.
	iface := flagInterface
	wifi, wifiErr := platform.GetWifiInfo(iface)
	wifiOK := wifiErr == nil && wifi != nil
	wifiDetail := fmt.Sprintf("interface %s", iface)
	if wifiOK {
		wifiDetail = fmt.Sprintf("%s on %s (%ddBm)", wifi.SSID, iface, wifi.RSSI)
	} else if wifiErr != nil {
		wifiDetail = fmt.Sprintf("%s: %v", iface, wifiErr)
	}
	check("WiFi interface", wifiOK, wifiDetail)

	// Sudo access.
	sudoOK := os.Geteuid() == 0
	sudoDetail := "running as root"
	if !sudoOK {
		sudoDetail = "run with sudo for full functionality"
	}
	check("Sudo access", sudoOK, sudoDetail)

	// Core tools (use toolchain.FindTool for comprehensive lookup).
	coreTools := []string{"chisel", "hysteria", "cloudflared"}
	for _, t := range coreTools {
		path := toolchain.FindTool(t)
		ok := path != ""
		detail := path
		if !ok {
			detail = "missing (nowifi tools -d)"
		}
		check(fmt.Sprintf("Tool: %s", t), ok, detail)
	}

	// Optional tools.
	optionalTools := []string{"iodine", "hans", "hashcat", "aircrack-ng"}
	for _, t := range optionalTools {
		path, lookErr := exec.LookPath(t)
		ok := lookErr == nil
		detail := path
		if !ok {
			detail = dim("optional, not installed")
		}
		check(fmt.Sprintf("Tool: %s", t), ok, detail)
	}

	// DNS resolution.
	dnsOK := false
	addrs, dnsErr := net.LookupHost("cloudflare.com")
	if dnsErr == nil && len(addrs) > 0 {
		dnsOK = true
	}
	dnsDetail := "cloudflare.com"
	if !dnsOK {
		dnsDetail = "cannot resolve cloudflare.com"
	}
	check("DNS resolution", dnsOK, dnsDetail)

	// Internet reachability.
	inetOK := false
	client := &http.Client{Timeout: 5 * time.Second}
	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://connectivitycheck.gstatic.com/generate_204", nil)
	inetErr := reqErr
	var resp *http.Response
	if reqErr == nil {
		resp, inetErr = client.Do(req)
	}
	if inetErr == nil {
		resp.Body.Close()
		inetOK = resp.StatusCode == 204
	}
	inetDetail := ""
	if !inetOK {
		inetDetail = "connectivity check failed (expected behind captive portal)"
	}
	check("Internet reachable", inetOK, inetDetail)

	// Summary.
	fmt.Println()
	if allOK {
		fmt.Println("  All checks passed.")
	} else {
		fmt.Println("  Some checks failed. See above for details.")
	}
	fmt.Println()
}
