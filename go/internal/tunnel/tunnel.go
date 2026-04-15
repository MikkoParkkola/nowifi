// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package tunnel manages external tunnel processes (chisel, iodine, hans,
// hysteria, ntpescape, cloudflared) and verifies connectivity through them.
//
// Each tunnel type starts a subprocess and waits for it to become ready
// (port listening or TUN interface appearing). The Handle struct tracks the
// running process so callers can stop it cleanly on exit.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/toolchain"
)

// Handle wraps a running tunnel. Two flavors are supported:
//  1. Subprocess-based (Process != nil) -- chisel, iodine, hans, hysteria,
//     ntpescape, cloudflared. Stop() terminates the child process.
//  2. Pure-Go in-process (extraStop != nil) -- HTTP/3 and DoQ tunnels that
//     run as goroutines inside nowifi. Stop() signals the stop channel and
//     invokes extraStop to close listeners/transports.
type Handle struct {
	Process   *exec.Cmd
	LocalPort int
	Method    string
	Active    bool

	// In-process tunnel bookkeeping (nil for subprocess tunnels).
	stop      chan struct{}
	wg        *sync.WaitGroup
	extraStop func()
}

// Stop terminates the tunnel gracefully, then forcefully if needed.
// Safe to call multiple times; subsequent calls are no-ops.
func (h *Handle) Stop() {
	// In-process tunnel: signal goroutines, close listeners/transports, wait.
	if h.extraStop != nil {
		// Signal stop exactly once; guard against double-close on repeat calls.
		if h.stop != nil {
			select {
			case <-h.stop:
				// Already closed.
			default:
				close(h.stop)
			}
		}
		h.extraStop()
		h.extraStop = nil
		if h.wg != nil {
			done := make(chan struct{})
			go func() {
				h.wg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				// Goroutines refused to exit; give up rather than block forever.
			}
		}
		h.Active = false
		return
	}

	// Subprocess tunnel.
	if h.Process == nil || h.Process.Process == nil {
		h.Active = false
		return
	}

	// Try graceful termination first.
	_ = h.Process.Process.Kill()

	// Wait up to 5 seconds for process to exit.
	done := make(chan error, 1)
	go func() {
		done <- h.Process.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Force kill if still running.
		_ = h.Process.Process.Kill()
	}

	h.Active = false
}

// StartChisel starts a chisel client connecting to a server URL, creating
// a local SOCKS5 proxy on the given port. Blocks until the proxy is ready
// or the timeout expires.
func StartChisel(serverURL string, localPort int, timeout time.Duration) (*Handle, error) {
	// Validate server URL before passing to exec.Command.
	serverURL, err := platform.ValidateURL(serverURL)
	if err != nil {
		return nil, fmt.Errorf("chisel server: %w", err)
	}

	chiselPath, err := toolchain.EnsureTool("chisel")
	if err != nil {
		return nil, err
	}

	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if localPort == 0 {
		localPort = 1080
	}

	cmd := exec.Command(chiselPath, "client", serverURL, fmt.Sprintf("%d:socks", localPort))
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Capture stderr for error reporting.
	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start chisel: %w", err)
	}

	handle := &Handle{
		Process:   cmd,
		LocalPort: localPort,
		Method:    "chisel",
	}

	if err := waitForPort(cmd, stderrPipe, localPort, timeout); err != nil {
		cmd.Process.Kill() //nolint:errcheck
		return nil, err
	}

	handle.Active = true
	return handle, nil
}

// StartDNSTunnel starts an iodine DNS tunnel. Requires sudo. Creates a TUN
// interface (dns0). Blocks until the interface has an IP address or timeout.
func StartDNSTunnel(domain string, serverIP string, timeout time.Duration) (*Handle, error) {
	// Validate domain before passing to exec.Command.
	domain, err := platform.ValidateDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("dns tunnel domain: %w", err)
	}
	// Validate server IP if provided.
	if serverIP != "" {
		serverIP, err = platform.ValidateIP(serverIP)
		if err != nil {
			return nil, fmt.Errorf("dns tunnel server: %w", err)
		}
	}

	iodinePath, err := toolchain.EnsureTool("iodine")
	if err != nil {
		return nil, err
	}

	if timeout == 0 {
		timeout = 30 * time.Second
	}

	args := []string{iodinePath, "-f"}
	if serverIP != "" {
		args = append(args, serverIP)
	}
	args = append(args, domain)

	cmd := exec.Command("sudo", args...)
	cmd.Stdout = nil

	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start iodine: %w", err)
	}

	handle := &Handle{
		Process:   cmd,
		LocalPort: 0,
		Method:    "dns_tunnel",
	}

	if err := waitForTunInterface(cmd, stderrPipe, "dns0", timeout); err != nil {
		cmd.Process.Kill() //nolint:errcheck
		return nil, err
	}

	handle.Active = true
	return handle, nil
}

// StartICMPTunnel starts a hans ICMP tunnel. Requires sudo. Creates a TUN
// interface (tun0). Blocks until the interface has an IP address or timeout.
func StartICMPTunnel(serverIP string, timeout time.Duration) (*Handle, error) {
	// Validate server IP before passing to exec.Command.
	serverIP, err := platform.ValidateIP(serverIP)
	if err != nil {
		return nil, fmt.Errorf("icmp tunnel server: %w", err)
	}

	hansPath, err := toolchain.EnsureTool("hans")
	if err != nil {
		return nil, err
	}

	if timeout == 0 {
		timeout = 15 * time.Second
	}

	cmd := exec.Command("sudo", hansPath, "-c", serverIP, "-f")
	cmd.Stdout = nil

	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start hans: %w", err)
	}

	handle := &Handle{
		Process:   cmd,
		LocalPort: 0,
		Method:    "icmp_tunnel",
	}

	if err := waitForTunInterface(cmd, stderrPipe, "tun0", timeout); err != nil {
		cmd.Process.Kill() //nolint:errcheck
		return nil, err
	}

	handle.Active = true
	return handle, nil
}

// StartQUICTunnel starts a Hysteria2 QUIC tunnel on UDP/443, creating a
// local SOCKS5 proxy. Most captive portals only inspect TCP, not UDP.
func StartQUICTunnel(server string, localPort int, timeout time.Duration) (*Handle, error) {
	// Validate server address before passing to exec.Command.
	server, err := platform.ValidateServerAddr(server)
	if err != nil {
		return nil, fmt.Errorf("quic tunnel server: %w", err)
	}

	hysteriaPath, err := toolchain.EnsureTool("hysteria")
	if err != nil {
		return nil, err
	}

	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if localPort == 0 {
		localPort = 1081
	}

	cmd := exec.Command(hysteriaPath, "client",
		"--server", server,
		"--socks5-listen", fmt.Sprintf("127.0.0.1:%d", localPort),
		"--insecure",
	)
	cmd.Stdout = nil

	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start hysteria: %w", err)
	}

	handle := &Handle{
		Process:   cmd,
		LocalPort: localPort,
		Method:    "quic_hysteria2",
	}

	if err := waitForPort(cmd, stderrPipe, localPort, timeout); err != nil {
		cmd.Process.Kill() //nolint:errcheck
		return nil, err
	}

	handle.Active = true
	return handle, nil
}

// StartNTPTunnel starts an NTP tunnel over UDP/123 using ntpescape.
// Very low bandwidth (~1-10 Kbps) but NTP is almost never blocked.
func StartNTPTunnel(serverIP string, localPort int, timeout time.Duration) (*Handle, error) {
	// Validate server IP before passing to exec.Command.
	serverIP, err := platform.ValidateIP(serverIP)
	if err != nil {
		return nil, fmt.Errorf("ntp tunnel server: %w", err)
	}

	ntpPath, err := toolchain.EnsureTool("ntpescape")
	if err != nil {
		return nil, err
	}

	if timeout == 0 {
		timeout = 20 * time.Second
	}
	if localPort == 0 {
		localPort = 1082
	}

	cmd := exec.Command(ntpPath, "client",
		"--server", serverIP,
		"--socks", fmt.Sprintf("127.0.0.1:%d", localPort),
	)
	cmd.Stdout = nil

	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ntpescape: %w", err)
	}

	handle := &Handle{
		Process:   cmd,
		LocalPort: localPort,
		Method:    "ntp_tunnel",
	}

	if err := waitForPort(cmd, stderrPipe, localPort, timeout); err != nil {
		cmd.Process.Kill() //nolint:errcheck
		return nil, err
	}

	handle.Active = true
	return handle, nil
}

// StartDoHTunnel starts a DNS-over-HTTPS tunnel using cloudflared or
// dnscrypt-proxy. Tries cloudflared first, then dnscrypt-proxy, then
// attempts to auto-download cloudflared.
func StartDoHTunnel(localPort int, dohServer string, timeout time.Duration) (*Handle, error) {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if localPort == 0 {
		localPort = 1083
	}
	if dohServer == "" {
		dohServer = "https://cloudflare-dns.com/dns-query"
	}
	// Validate DoH server URL before passing to exec.Command.
	dohServer, err := platform.ValidateURL(dohServer)
	if err != nil {
		return nil, fmt.Errorf("doh tunnel server: %w", err)
	}

	// Strategy 1: cloudflared (already installed)
	if cfPath := toolchain.FindTool("cloudflared"); cfPath != "" {
		h, err := tryCloudflaredDoH(cfPath, localPort, dohServer, timeout)
		if err == nil {
			return h, nil
		}
	}

	// Strategy 2: dnscrypt-proxy (already installed)
	if dnsPath := toolchain.FindTool("dnscrypt-proxy"); dnsPath != "" {
		h, err := tryDnscryptDoH(dnsPath, localPort, timeout)
		if err == nil {
			return h, nil
		}
	}

	// Strategy 3: auto-download cloudflared
	cfPath, err := toolchain.DownloadTool("cloudflared")
	if err == nil {
		h, err := tryCloudflaredDoH(cfPath, localPort, dohServer, timeout)
		if err == nil {
			return h, nil
		}
	}

	return nil, &toolchain.ToolNotFoundError{
		Tool:        "cloudflared or dnscrypt-proxy",
		InstallHint: "brew install cloudflared  OR  brew install dnscrypt-proxy",
	}
}

// VerifySOCKS verifies a SOCKS5 tunnel provides internet access by making
// an HTTP request through the proxy.
func VerifySOCKS(port int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Connect through SOCKS5 proxy.
			socksConn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return nil, err
			}
			// SOCKS5 handshake: no auth method.
			_, _ = socksConn.Write([]byte{0x05, 0x01, 0x00})
			buf := make([]byte, 2)
			if _, err := io.ReadFull(socksConn, buf); err != nil {
				socksConn.Close()
				return nil, err
			}
			if buf[0] != 0x05 || buf[1] != 0x00 {
				socksConn.Close()
				return nil, fmt.Errorf("socks5 auth rejected")
			}

			// SOCKS5 connect request.
			host, portStr, _ := net.SplitHostPort(addr)
			portNum := 80
			if portStr != "" {
				if parsedPort, err := strconv.Atoi(portStr); err == nil {
					portNum = parsedPort
				}
			}

			req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
			req = append(req, []byte(host)...)
			req = append(req, byte(portNum>>8), byte(portNum&0xff))
			_, _ = socksConn.Write(req)

			reply := make([]byte, 10)
			if _, err := io.ReadFull(socksConn, reply); err != nil {
				socksConn.Close()
				return nil, err
			}
			if reply[1] != 0x00 {
				socksConn.Close()
				return nil, fmt.Errorf("socks5 connect failed: %d", reply[1])
			}

			return socksConn, nil
		},
	}

	client := &http.Client{Transport: transport}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://detectportal.firefox.com/canonical.html", nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode == 200 && strings.Contains(string(body), "success")
}

// VerifyDirect verifies internet access works directly (for TUN-based tunnels
// like DNS/ICMP that route traffic at the network level).
func VerifyDirect() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://detectportal.firefox.com/canonical.html", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode == 200 && strings.Contains(string(body), "success")
}

// VerifyCFWorkersProxy checks that a Cloudflare Workers proxy URL provides
// internet access. The worker URL proxies requests: worker_url/https://target.
func VerifyCFWorkersProxy(workerURL string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	testURL := workerURL + "/https://connectivitycheck.gstatic.com/generate_204"
	req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 204
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// portListening checks if a local TCP port is accepting connections.
func portListening(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// waitForPort polls until a local port is listening, the process exits, or
// the timeout expires.
func waitForPort(cmd *exec.Cmd, stderrPipe io.Reader, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if time.Now().After(deadline) {
			stderr := readStderr(stderrPipe)
			return fmt.Errorf("tunnel did not start within %v: %s", timeout, truncate(stderr, 500))
		}

		// Check if process died.
		if cmd.ProcessState != nil {
			stderr := readStderr(stderrPipe)
			return fmt.Errorf("tunnel process exited early: %s", truncate(stderr, 500))
		}

		if portListening(port) {
			return nil
		}
	}

	return nil
}

// waitForTunInterface polls until a TUN interface has an IPv4 address,
// the process exits, or the timeout expires.
func waitForTunInterface(cmd *exec.Cmd, stderrPipe io.Reader, ifaceName string, timeout time.Duration) error {
	// Validate interface name before passing to exec.Command.
	if _, err := platform.ValidateInterface(ifaceName); err != nil {
		return fmt.Errorf("tunnel interface: %w", err)
	}

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if time.Now().After(deadline) {
			return fmt.Errorf("tunnel interface %s did not appear within %v", ifaceName, timeout)
		}

		// Check if process died.
		if cmd.ProcessState != nil {
			stderr := readStderr(stderrPipe)
			return fmt.Errorf("tunnel process exited early: %s", truncate(stderr, 500))
		}

		// Check if TUN interface has an IP.
		out, err := exec.Command("ifconfig", ifaceName).CombinedOutput()
		if err == nil && strings.Contains(string(out), "inet") {
			return nil
		}
	}

	return nil
}

// tryCloudflaredDoH attempts to start cloudflared in proxy-dns mode.
func tryCloudflaredDoH(cfPath string, port int, upstream string, timeout time.Duration) (*Handle, error) {
	cmd := exec.Command(cfPath, "proxy-dns",
		"--port", fmt.Sprintf("%d", port),
		"--upstream", upstream,
	)
	cmd.Stdout = nil

	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	handle := &Handle{
		Process:   cmd,
		LocalPort: port,
		Method:    "doh_tunnel",
	}

	if err := waitForPort(cmd, stderrPipe, port, timeout); err != nil {
		cmd.Process.Kill() //nolint:errcheck
		return nil, err
	}

	handle.Active = true
	return handle, nil
}

// tryDnscryptDoH attempts to start dnscrypt-proxy.
func tryDnscryptDoH(dnsPath string, port int, timeout time.Duration) (*Handle, error) {
	cmd := exec.Command(dnsPath, "--listen_addresses", fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = nil

	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	handle := &Handle{
		Process:   cmd,
		LocalPort: port,
		Method:    "doh_tunnel",
	}

	if err := waitForPort(cmd, stderrPipe, port, timeout); err != nil {
		cmd.Process.Kill() //nolint:errcheck
		return nil, err
	}

	handle.Active = true
	return handle, nil
}

// readStderr reads available bytes from a pipe without blocking indefinitely.
func readStderr(r io.Reader) string {
	if r == nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

// truncate returns at most maxLen bytes of s.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
