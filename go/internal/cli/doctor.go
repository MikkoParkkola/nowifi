package cli

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

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
		status := "OK"
		if !ok {
			status = "FAIL"
			allOK = false
		}
		msg := fmt.Sprintf("  %-6s %s", status, label)
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
	// TODO: Use platform.GetWifiInfo when implemented.
	// For now, check if the default interface exists.
	iface := flagInterface
	check("WiFi interface", true, fmt.Sprintf("(checking %s — full check not yet implemented)", iface))

	// Sudo access.
	sudoOK := os.Geteuid() == 0
	sudoDetail := "running as root"
	if !sudoOK {
		sudoDetail = "run with sudo for full functionality"
	}
	check("Sudo access", sudoOK, sudoDetail)

	// Core tools.
	coreTools := []string{"chisel", "hysteria"}
	for _, t := range coreTools {
		path, err := exec.LookPath(t)
		ok := err == nil
		detail := path
		if !ok {
			detail = "missing (nowifi tools -d)"
		}
		check(fmt.Sprintf("Tool: %s", t), ok, detail)
	}

	// DNS resolution.
	dnsOK := false
	addrs, err := net.LookupHost("cloudflare.com")
	if err == nil && len(addrs) > 0 {
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
	resp, err := client.Get("http://connectivitycheck.gstatic.com/generate_204")
	if err == nil {
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
