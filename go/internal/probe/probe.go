// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package probe implements pre-authentication leak enumeration.
//
// It tests which protocols and ports are open before authenticating to a
// captive portal, using stealth techniques: randomized port order, jitter
// between probes, parallel batches, short timeouts, and minimal packet
// footprints.
package probe

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// DnsProbeResult holds the result of external DNS resolver reachability tests.
type DnsProbeResult struct {
	IsOpen    bool             `json:"is_open"`
	Resolvers []ResolverResult `json:"resolvers,omitempty"`
	Details   string           `json:"details"`
}

// ResolverResult holds the result of a single DNS resolver test.
type ResolverResult struct {
	IP       string `json:"ip"`
	Name     string `json:"name"`
	Resolved string `json:"resolved"`
}

// IcmpProbeResult holds the result of ICMP ping tests.
type IcmpProbeResult struct {
	IsOpen         bool     `json:"is_open"`
	TargetsReached []string `json:"targets_reached,omitempty"`
	Details        string   `json:"details"`
}

// Ipv6ProbeResult holds the result of IPv6 connectivity tests.
type Ipv6ProbeResult struct {
	IsOpen  bool   `json:"is_open"`
	Address string `json:"address,omitempty"`
	Details string `json:"details"`
}

// HttpsProbeResult holds the result of an HTTPS reachability test.
type HttpsProbeResult struct {
	IsOpen  bool   `json:"is_open"`
	URL     string `json:"url"`
	Details string `json:"details"`
}

// WhitelistResult holds the result of a single whitelisted domain test.
type WhitelistResult struct {
	Domain     string `json:"domain"`
	IsOpen     bool   `json:"is_open"`
	StatusCode int    `json:"status_code,omitempty"`
	Redirected bool   `json:"redirected"`
	Details    string `json:"details"`
}

// PortProbeResult holds the result of a single port probe.
type PortProbeResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp", "udp", or "doh"
	IsOpen   bool   `json:"is_open"`
	Service  string `json:"service"`
	Details  string `json:"details"`
}

// ProbeResults aggregates all probe results.
type ProbeResults struct {
	DNS               DnsProbeResult    `json:"dns"`
	ICMP              IcmpProbeResult   `json:"icmp"`
	IPv6              Ipv6ProbeResult   `json:"ipv6"`
	Cloudflare        HttpsProbeResult  `json:"cloudflare"`
	Whitelists        []WhitelistResult `json:"whitelists,omitempty"`
	OpenPorts         []PortProbeResult `json:"open_ports,omitempty"`
	TunnelServerPorts []PortProbeResult `json:"tunnel_server_ports,omitempty"`
	QUIC              PortProbeResult   `json:"quic"`
	NTP               PortProbeResult   `json:"ntp"`
	DoH               PortProbeResult   `json:"doh"`
	Topology          SubnetTopology    `json:"topology"`
}

// PortServices maps well-known port numbers to human-readable service names.
var PortServices = map[int]string{
	22:    "SSH",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	123:   "NTP",
	143:   "IMAP",
	443:   "HTTPS",
	465:   "SMTPS",
	500:   "IKE/IPSec",
	587:   "Submission",
	853:   "DNS-over-TLS",
	993:   "IMAPS",
	995:   "POP3S",
	1194:  "OpenVPN",
	1723:  "PPTP",
	3478:  "STUN/TURN",
	3479:  "STUN/TURN",
	4500:  "IPSec NAT-T",
	5060:  "SIP",
	5061:  "SIPS",
	5223:  "Apple Push",
	8080:  "HTTP Alt",
	8443:  "HTTPS Alt",
	41641: "Tailscale",
	51820: "WireGuard",
}

// tunnelCandidatePorts are ports commonly allowed through firewalls/captive portals.
var tunnelCandidatePorts = []int{
	53, 80, 443,
	123, 853,
	8080, 8443,
	500, 4500,
	993, 995,
	1194, 1723,
	5223,
	51820, 41641,
	22, 25, 587, 465,
	143, 110,
	5060, 5061,
	3478, 3479,
}

// ProbeAll runs all probes to enumerate what is open pre-authentication.
//
// In stealth mode, probes are run sequentially with randomized jitter between them.
// In fast mode, probes run with minimal delay.
func ProbeAll(iface string, stealth bool, tunnelServerIP string) *ProbeResults {
	results := &ProbeResults{
		QUIC: PortProbeResult{Port: 443, Protocol: "udp", Service: "QUIC/HTTP3"},
		NTP:  PortProbeResult{Port: 123, Protocol: "udp", Service: "NTP"},
		DoH:  PortProbeResult{Port: 443, Protocol: "doh", Service: "DNS-over-HTTPS"},
	}

	results.DNS = ProbeDNS(stealth)
	stealthSleep(stealth, 300, 800)

	results.ICMP = ProbeICMP(stealth)
	stealthSleep(stealth, 300, 800)

	results.IPv6 = ProbeIPv6(iface)
	stealthSleep(stealth, 200, 500)

	results.Cloudflare = ProbeHTTPS("https://1.1.1.1", "Cloudflare")
	stealthSleep(stealth, 200, 500)

	results.Whitelists = ProbeWhitelists(stealth)
	stealthSleep(stealth, 300, 800)

	results.OpenPorts = ProbePorts("1.1.1.1", stealth)

	results.QUIC = ProbeQUIC("1.1.1.1", stealth)
	stealthSleep(stealth, 100, 300)

	results.NTP = ProbeNTP(stealth)
	stealthSleep(stealth, 100, 300)

	results.DoH = ProbeDoH(stealth)

	if tunnelServerIP != "" {
		stealthSleep(stealth, 300, 800)
		results.TunnelServerPorts = ProbeTunnelServer(tunnelServerIP, stealth)
	}

	return results
}

// ProbeDNS tests if external DNS resolvers are reachable by attempting
// a UDP connection to each resolver on port 53 and sending a minimal
// DNS query.
func ProbeDNS(stealth bool) DnsProbeResult {
	result := DnsProbeResult{}

	resolvers := []struct {
		IP   string
		Name string
	}{
		{"1.1.1.1", "Cloudflare"},
		{"8.8.8.8", "Google"},
		{"9.9.9.9", "Quad9"},
	}

	testDomain := "example.com"

	for _, r := range resolvers {
		stealthSleep(stealth, 200, 800)

		// Try a simple DNS lookup via this resolver by connecting to it.
		resolved := tryDNSResolve(r.IP, testDomain)
		if resolved != "" {
			result.Resolvers = append(result.Resolvers, ResolverResult{
				IP:       r.IP,
				Name:     r.Name,
				Resolved: resolved,
			})
		}
	}

	if len(result.Resolvers) > 0 {
		result.IsOpen = true
		var names []string
		for _, r := range result.Resolvers {
			names = append(names, r.Name)
		}
		result.Details = fmt.Sprintf("External DNS reachable: %s", strings.Join(names, ", "))
	} else {
		result.Details = "No external DNS resolvers reachable"
	}
	return result
}

// tryDNSResolve attempts to resolve a domain using a specific DNS resolver
// by sending a raw DNS query packet over UDP.
func tryDNSResolve(resolverIP, domain string) string {
	conn, err := net.DialTimeout("udp", resolverIP+":53", 5*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return ""
	}

	// Build a minimal DNS query for A record.
	query := buildDNSQuery(domain)
	if _, err := conn.Write(query); err != nil {
		return ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	return parseDNSResponse(buf[:n])
}

// buildDNSQuery constructs a minimal DNS A query packet.
func buildDNSQuery(domain string) []byte {
	// Transaction ID.
	var pkt []byte
	pkt = append(pkt, 0xAB, 0xCD) // ID
	pkt = append(pkt, 0x01, 0x00) // Flags: standard query, recursion desired
	pkt = append(pkt, 0x00, 0x01) // QDCOUNT: 1
	pkt = append(pkt, 0x00, 0x00) // ANCOUNT: 0
	pkt = append(pkt, 0x00, 0x00) // NSCOUNT: 0
	pkt = append(pkt, 0x00, 0x00) // ARCOUNT: 0

	// QNAME: encode domain labels.
	for _, label := range strings.Split(domain, ".") {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0x00) // Root label

	pkt = append(pkt, 0x00, 0x01) // QTYPE: A
	pkt = append(pkt, 0x00, 0x01) // QCLASS: IN

	return pkt
}

// parseDNSResponse extracts the first A record IP from a DNS response.
func parseDNSResponse(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	// Check ANCOUNT > 0.
	ancount := int(data[6])<<8 | int(data[7])
	if ancount == 0 {
		return ""
	}

	// Skip header (12 bytes) and question section.
	offset := 12
	// Skip QNAME.
	for offset < len(data) {
		labelLen := int(data[offset])
		if labelLen == 0 {
			offset++
			break
		}
		if labelLen >= 0xC0 {
			offset += 2
			break
		}
		offset += 1 + labelLen
	}
	offset += 4 // Skip QTYPE and QCLASS.

	// Parse first answer.
	for i := 0; i < ancount && offset < len(data); i++ {
		// Skip NAME (may be a pointer).
		if offset >= len(data) {
			break
		}
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(data) {
				labelLen := int(data[offset])
				if labelLen == 0 {
					offset++
					break
				}
				offset += 1 + labelLen
			}
		}

		if offset+10 > len(data) {
			break
		}

		rtype := int(data[offset])<<8 | int(data[offset+1])
		rdlength := int(data[offset+8])<<8 | int(data[offset+9])
		offset += 10

		if rtype == 1 && rdlength == 4 && offset+4 <= len(data) {
			return fmt.Sprintf("%d.%d.%d.%d",
				data[offset], data[offset+1], data[offset+2], data[offset+3])
		}
		offset += rdlength
	}
	return ""
}

// ProbeICMP tests if ICMP (ping) reaches external hosts.
func ProbeICMP(stealth bool) IcmpProbeResult {
	result := IcmpProbeResult{}

	targets := []struct {
		IP   string
		Name string
	}{
		{"1.1.1.1", "Cloudflare"},
		{"8.8.8.8", "Google DNS"},
	}

	for _, t := range targets {
		stealthSleep(stealth, 300, 800)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", t.IP)
		err := cmd.Run()
		cancel()

		if err == nil {
			label := fmt.Sprintf("%s (%s)", t.Name, t.IP)
			result.TargetsReached = append(result.TargetsReached, label)
		}
	}

	if len(result.TargetsReached) > 0 {
		result.IsOpen = true
		result.Details = fmt.Sprintf("ICMP open to: %s", strings.Join(result.TargetsReached, ", "))
	} else {
		result.Details = "ICMP blocked to external hosts"
	}
	return result
}

// ProbeIPv6 tests if IPv6 traffic bypasses the portal.
func ProbeIPv6(iface string) Ipv6ProbeResult {
	result := Ipv6ProbeResult{}

	// Check for a global IPv6 address via net.InterfaceByName.
	ipv6Addr := getGlobalIPv6(iface)
	if ipv6Addr == "" {
		result.Details = "No global IPv6 address on interface"
		return result
	}
	result.Address = ipv6Addr

	// Try to connect to well-known IPv6 addresses.
	ipv6Targets := []struct {
		Addr string
		Port int
		Name string
	}{
		{"2607:f8b0:4004:800::200e", 80, "google.com"},
		{"2606:4700::6810:85e5", 80, "cloudflare.com"},
	}

	for _, t := range ipv6Targets {
		conn, err := net.DialTimeout("tcp6",
			fmt.Sprintf("[%s]:%d", t.Addr, t.Port), 5*time.Second)
		if err == nil {
			conn.Close()
			result.IsOpen = true
			result.Details = fmt.Sprintf("IPv6 unfiltered! Connected to %s [%s]", t.Name, t.Addr)
			return result
		}
	}

	// Fallback: try HTTP over IPv6.
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://ipv6.google.com", nil)
	if err != nil {
		result.Details = fmt.Sprintf("IPv6 address %s present but no external connectivity", ipv6Addr)
		return result
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			result.IsOpen = true
			result.Details = "IPv6 HTTP connectivity confirmed via ipv6.google.com"
			return result
		}
	}

	result.Details = fmt.Sprintf("IPv6 address %s present but no external connectivity", ipv6Addr)
	return result
}

// getGlobalIPv6 returns the first global (non-link-local) IPv6 address
// on the given interface.
func getGlobalIPv6(iface string) string {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return ""
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.To4() != nil {
			continue // Skip IPv4.
		}
		if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
			continue
		}
		return ip.String()
	}
	return ""
}

// ProbeHTTPS tests if HTTPS to a specific URL works.
func ProbeHTTPS(targetURL, label string) HttpsProbeResult {
	result := HttpsProbeResult{URL: targetURL}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects.
		},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, targetURL, nil)
	if err != nil {
		result.Details = fmt.Sprintf("%s: connection failed (%s)", labelOrURL(label, targetURL), err)
		return result
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Details = fmt.Sprintf("%s: connection failed (%s)", labelOrURL(label, targetURL), err)
		return result
	}
	resp.Body.Close()

	if resp.StatusCode < 400 {
		result.IsOpen = true
		result.Details = fmt.Sprintf("%s: HTTP %d", labelOrURL(label, targetURL), resp.StatusCode)
	} else {
		result.Details = fmt.Sprintf("%s: HTTP %d (blocked)", labelOrURL(label, targetURL), resp.StatusCode)
	}
	return result
}

func labelOrURL(label, u string) string {
	if label != "" {
		return label
	}
	return u
}

// whitelistTargets are commonly whitelisted domains to check for pre-auth access.
var whitelistTargets = []struct {
	Domain string
	URL    string
}{
	{"captive.apple.com", "http://captive.apple.com/hotspot-detect.html"},
	{"connectivitycheck.gstatic.com", "http://connectivitycheck.gstatic.com/generate_204"},
	{"clients3.google.com", "http://clients3.google.com/generate_204"},
	{"www.msftconnecttest.com", "http://www.msftconnecttest.com/connecttest.txt"},
	{"cloudflare.com", "https://cloudflare.com"},
	{"1.1.1.1", "https://1.1.1.1"},
	{"www.apple.com", "https://www.apple.com"},
	{"www.google.com", "https://www.google.com"},
	{"login.microsoftonline.com", "https://login.microsoftonline.com"},
	{"facebook.com", "https://facebook.com"},

	// Inflight WiFi — payment processors (almost always whitelisted for WiFi purchase).
	{"stripe.com", "https://stripe.com"},
	{"js.stripe.com", "https://js.stripe.com"},
	{"checkout.stripe.com", "https://checkout.stripe.com"},
	{"*.adyen.com", "https://www.adyen.com"},

	// Inflight WiFi — CDN/infrastructure (whitelisted for portal assets).
	{"cdn.cloudflare.com", "https://cdn.cloudflare.com"},
	{"cdnjs.cloudflare.com", "https://cdnjs.cloudflare.com"},

	// Inflight WiFi — IFE portal infrastructure (whitelisted for portal operation).
	{"panasonic.aero", "https://www.panasonic.aero"},

	// Inflight WiFi — DNS providers (often whitelisted).
	{"dns.google", "https://dns.google"},
	{"cloudflare-dns.com", "https://cloudflare-dns.com/dns-query?name=example.com&type=A"},

	// Inflight WiFi — entertainment/messaging (sometimes whitelisted as free tier).
	{"icloud.com", "https://www.icloud.com"},
	{"imessage.apple.com", "https://init.push.apple.com"},
	{"whatsapp.com", "https://web.whatsapp.com"},
}

// ProbeWhitelists tests commonly whitelisted domains for pre-auth access.
func ProbeWhitelists(stealth bool) []WhitelistResult {
	client := &http.Client{Timeout: 8 * time.Second}

	var results []WhitelistResult
	for _, t := range whitelistTargets {
		stealthSleep(stealth, 200, 600)

		wr := WhitelistResult{Domain: t.Domain}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, t.URL, nil)
		if err != nil {
			wr.Details = "Invalid request URL"
			results = append(results, wr)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			if isTimeout(err) {
				wr.Details = "Timeout"
			} else {
				wr.Details = "Connection refused/failed"
			}
			results = append(results, wr)
			continue
		}
		resp.Body.Close()

		wr.StatusCode = resp.StatusCode
		finalURL := resp.Request.URL.String()

		if finalURL != t.URL && looksLikePortalRedirect(finalURL, t.URL) {
			wr.Redirected = true
			wr.Details = fmt.Sprintf("Redirected to portal: %s", finalURL)
		} else if resp.StatusCode < 400 {
			wr.IsOpen = true
			wr.Details = fmt.Sprintf("Accessible (HTTP %d)", resp.StatusCode)
		} else {
			wr.Details = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}

		results = append(results, wr)
	}
	return results
}

// portalPatterns are URL fragments that indicate a captive portal redirect.
var portalPatterns = []string{"login", "portal", "captive", "auth", "hotspot", "splash", "guest"}

// looksLikePortalRedirect uses heuristics to detect if a redirect is a
// captive portal intercept vs a normal redirect.
func looksLikePortalRedirect(finalURL, originalURL string) bool {
	origHost := hostFromURL(originalURL)
	finalHost := hostFromURL(finalURL)

	// If redirected to a completely different domain, likely a portal.
	if origHost != "" && finalHost != "" &&
		!strings.Contains(finalHost, origHost) &&
		!strings.Contains(origHost, finalHost) {
		return true
	}

	finalLower := strings.ToLower(finalURL)
	for _, pattern := range portalPatterns {
		if strings.Contains(finalLower, pattern) {
			return true
		}
	}
	return false
}

func hostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ProbePorts scans for open outbound TCP ports with stealth.
//
// Stealth mode uses randomized port order, parallel batches of 4 with jitter,
// and short timeouts. Fast mode uses batches of 8 with no jitter.
func ProbePorts(targetIP string, stealth bool) []PortProbeResult {
	ports := make([]int, len(tunnelCandidatePorts))
	copy(ports, tunnelCandidatePorts)
	shufflePorts(ports)

	batchSize := 4
	if !stealth {
		batchSize = 8
	}
	timeout := 1500 * time.Millisecond
	if !stealth {
		timeout = 1000 * time.Millisecond
	}

	var results []PortProbeResult
	for i := 0; i < len(ports); i += batchSize {
		end := i + batchSize
		if end > len(ports) {
			end = len(ports)
		}
		batch := ports[i:end]
		results = append(results, probeBatch(batch, targetIP, timeout)...)

		if stealth && end < len(ports) {
			stealthSleep(true, 100, 400)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}

// probeBatch probes a batch of TCP ports in parallel using goroutines.
func probeBatch(ports []int, targetIP string, timeout time.Duration) []PortProbeResult {
	results := make([]PortProbeResult, len(ports))
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			service := PortServices[p]
			if service == "" {
				service = "unknown"
			}
			pr := PortProbeResult{
				Port:     p,
				Protocol: "tcp",
				Service:  service,
			}

			addr := net.JoinHostPort(targetIP, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				pr.IsOpen = true
				pr.Details = fmt.Sprintf("TCP/%d (%s) open", p, service)
			} else {
				pr.Details = fmt.Sprintf("TCP/%d closed", p)
			}

			results[idx] = pr
		}(i, port)
	}

	wg.Wait()
	return results
}

// ProbeQUIC tests if UDP/443 (QUIC/HTTP3) passes through the portal.
func ProbeQUIC(targetIP string, stealth bool) PortProbeResult {
	result := PortProbeResult{Port: 443, Protocol: "udp", Service: "QUIC/HTTP3"}

	stealthSleep(stealth, 100, 300)

	if probeUDPPort(targetIP, 443, 2*time.Second) {
		result.IsOpen = true
		result.Details = fmt.Sprintf("UDP/443 (QUIC) open to %s", targetIP)
	} else {
		result.Details = "UDP/443 (QUIC) blocked"
	}
	return result
}

// ProbeNTP tests if NTP (UDP/123) reaches external NTP servers.
func ProbeNTP(stealth bool) PortProbeResult {
	result := PortProbeResult{Port: 123, Protocol: "udp", Service: "NTP"}

	ntpServers := []string{"pool.ntp.org", "time.google.com", "time.cloudflare.com"}

	for _, server := range ntpServers {
		stealthSleep(stealth, 100, 300)

		ips, err := net.LookupHost(server)
		if err != nil || len(ips) == 0 {
			continue
		}

		if probeUDPPort(ips[0], 123, 2*time.Second) {
			result.IsOpen = true
			result.Details = fmt.Sprintf("NTP open to %s (%s)", server, ips[0])
			return result
		}
	}

	result.Details = "NTP (UDP/123) blocked to all tested servers"
	return result
}

// ProbeDoH tests if DNS-over-HTTPS endpoints are reachable.
func ProbeDoH(stealth bool) PortProbeResult {
	result := PortProbeResult{Port: 443, Protocol: "doh", Service: "DNS-over-HTTPS"}

	endpoints := []struct {
		URL  string
		Name string
	}{
		{"https://cloudflare-dns.com/dns-query?name=example.com&type=A", "Cloudflare DoH"},
		{"https://dns.google/resolve?name=example.com&type=A", "Google DoH"},
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, ep := range endpoints {
		stealthSleep(stealth, 100, 300)

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ep.URL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			result.IsOpen = true
			result.Details = fmt.Sprintf("DoH reachable via %s", ep.Name)
			return result
		}
	}

	result.Details = "DoH endpoints not reachable"
	return result
}

// probeUDPPort sends a protocol-appropriate packet and checks for a response.
func probeUDPPort(targetIP string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(targetIP, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}

	var probe []byte
	switch port {
	case 443:
		// QUIC Initial packet header (triggers version negotiation).
		probe = []byte{
			0xC0,                   // Long header, fixed bit
			0x00, 0x00, 0x00, 0x01, // Version 1
			0x08,                                           // DCID length
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // DCID
			0x00,       // SCID length
			0x00, 0x00, // Token length
			0x00, 0x04, // Length
			0x00, 0x00, 0x00, 0x00, // Minimal payload
		}
	case 123:
		// NTP client request (mode 3, version 4): 48 bytes.
		probe = make([]byte, 48)
		probe[0] = 0x23
	default:
		probe = []byte{0x00}
	}

	if _, err := conn.Write(probe); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	return err == nil && n > 0
}

// ProbeTunnelServer scans the user's tunnel server for reachable ports.
//
// It first tries a DNS beacon to get the server's port list, then falls back
// to a tiered priority scan with early exit once a usable port is found.
func ProbeTunnelServer(serverIP string, stealth bool) []PortProbeResult {
	// Phase 1: DNS beacon.
	beaconPorts := tryDNSBeacon(serverIP)
	if len(beaconPorts) > 0 {
		results := probeBatch(beaconPorts, serverIP, 2*time.Second)
		hasOpen := false
		for _, r := range results {
			if r.IsOpen {
				hasOpen = true
				break
			}
		}
		if hasOpen {
			return results
		}
	}

	// Phase 2: tiered priority scan.
	priorityPorts := []int{
		443, 80, 8443, 8080,
		53, 123, 853, 5223,
		993, 995, 587, 465, 22,
		500, 4500, 1194, 1723, 51820,
		3478, 5060, 5061, 41641, 143, 110, 25,
	}
	// Randomize within tiers.
	shufflePorts(priorityPorts[:4])
	shufflePorts(priorityPorts[4:8])

	batchSize := 4
	if !stealth {
		batchSize = 8
	}

	var results []PortProbeResult
	for i := 0; i < len(priorityPorts); i += batchSize {
		end := i + batchSize
		if end > len(priorityPorts) {
			end = len(priorityPorts)
		}
		batch := priorityPorts[i:end]
		batchResults := probeBatch(batch, serverIP, 1500*time.Millisecond)
		results = append(results, batchResults...)

		// Early exit: found at least one open port.
		hasOpen := false
		for _, r := range batchResults {
			if r.IsOpen {
				hasOpen = true
				break
			}
		}
		if hasOpen {
			// Do one more batch to find alternatives, then stop.
			nextEnd := end + batchSize
			if nextEnd > len(priorityPorts) {
				nextEnd = len(priorityPorts)
			}
			if end < nextEnd {
				results = append(results, probeBatch(priorityPorts[end:nextEnd], serverIP, 1500*time.Millisecond)...)
			}
			break
		}

		stealthSleep(stealth, 100, 300)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}

// tryDNSBeacon attempts to get the tunnel server's available ports via a
// DNS TXT record. Returns the list of ports if found, nil otherwise.
func tryDNSBeacon(serverIP string) []int {
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	domain := fmt.Sprintf("_nowifi.%s.nowifish.com",
		strings.ReplaceAll(serverIP, ".", "-"))

	for _, resolver := range resolvers {
		conn, err := net.DialTimeout("udp", resolver, 3*time.Second)
		if err != nil {
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			conn.Close()
			continue
		}

		// Build TXT query.
		query := buildDNSTXTQuery(domain)
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			continue
		}

		if ports := parseTXTResponse(buf[:n]); len(ports) > 0 {
			return ports
		}
	}
	return nil
}

// buildDNSTXTQuery constructs a DNS TXT query packet.
func buildDNSTXTQuery(domain string) []byte {
	var pkt []byte
	pkt = append(pkt, 0xAB, 0xCD) // ID
	pkt = append(pkt, 0x01, 0x00) // Flags: standard query, recursion desired
	pkt = append(pkt, 0x00, 0x01) // QDCOUNT: 1
	pkt = append(pkt, 0x00, 0x00) // ANCOUNT: 0
	pkt = append(pkt, 0x00, 0x00) // NSCOUNT: 0
	pkt = append(pkt, 0x00, 0x00) // ARCOUNT: 0

	for _, label := range strings.Split(domain, ".") {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0x00)       // Root label
	pkt = append(pkt, 0x00, 0x10) // QTYPE: TXT (16)
	pkt = append(pkt, 0x00, 0x01) // QCLASS: IN

	return pkt
}

// parseTXTResponse extracts port numbers from a DNS TXT response
// with format "ports=80,443,8080".
func parseTXTResponse(data []byte) []int {
	// Very simplified TXT record parser: look for "ports=" in the response.
	s := string(data)
	idx := strings.Index(s, "ports=")
	if idx < 0 {
		return nil
	}

	// Extract the value after "ports=".
	val := s[idx+6:]
	// Find the end (null byte or non-printable).
	endIdx := strings.IndexFunc(val, func(r rune) bool {
		return r < 32 || r > 126
	})
	if endIdx > 0 {
		val = val[:endIdx]
	}

	var ports []int
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n := 0
		valid := true
		for _, c := range part {
			if c < '0' || c > '9' {
				valid = false
				break
			}
			n = n*10 + int(c-'0')
		}
		if valid && n > 0 && n <= 65535 {
			ports = append(ports, n)
		}
	}
	return ports
}

// stealthSleep sleeps for a random duration between minMs and maxMs
// milliseconds, but only if stealth mode is enabled.
func stealthSleep(stealth bool, minMs, maxMs int) {
	if !stealth {
		return
	}
	rangeMs := maxMs - minMs
	if rangeMs <= 0 {
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(rangeMs)))
	if err != nil {
		time.Sleep(time.Duration(minMs) * time.Millisecond)
		return
	}
	time.Sleep(time.Duration(minMs+int(n.Int64())) * time.Millisecond)
}

// shufflePorts randomizes the order of a port slice using crypto/rand.
func shufflePorts(ports []int) {
	for i := len(ports) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			continue
		}
		j := int(n.Int64())
		ports[i], ports[j] = ports[j], ports[i]
	}
}

// SubnetTopology holds the result of cross-subnet analysis.
type SubnetTopology struct {
	ClientSubnet  string `json:"client_subnet"`
	GatewayIP     string `json:"gateway_ip"`
	PortalIP      string `json:"portal_ip,omitempty"`
	IsCrossSubnet bool   `json:"is_cross_subnet"`
	Details       string `json:"details"`
}

// ProbeTopology analyzes the network topology to identify cross-subnet
// portals and potential routing leaks. Inflight WiFi often places the
// portal on a different VLAN/subnet (e.g., portal at 172.16.x.x, clients
// at 172.19.x.x).
func ProbeTopology(iface string, portalIP string) SubnetTopology {
	result := SubnetTopology{PortalIP: portalIP}

	// Get client IP and subnet.
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 3*time.Second)
	if err != nil {
		result.Details = "Cannot determine local IP"
		return result
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr).IP.String()
	conn.Close()
	result.ClientSubnet = localAddr

	// Get gateway.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netstat", "-rn").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "default" {
				result.GatewayIP = fields[1]
				break
			}
		}
	}

	if portalIP == "" || result.GatewayIP == "" {
		result.Details = "Insufficient data for topology analysis"
		return result
	}

	// Check if portal and client are on different /16 subnets.
	clientParts := strings.Split(localAddr, ".")
	portalParts := strings.Split(portalIP, ".")
	if len(clientParts) >= 2 && len(portalParts) >= 2 {
		if clientParts[0] == portalParts[0] && clientParts[1] != portalParts[1] {
			result.IsCrossSubnet = true
			result.Details = fmt.Sprintf("Portal (%s) on different subnet from clients (%s) — separate management VLAN detected", portalIP, localAddr)
		} else if clientParts[0] != portalParts[0] {
			result.IsCrossSubnet = true
			result.Details = fmt.Sprintf("Portal (%s) on entirely different network from clients (%s)", portalIP, localAddr)
		} else {
			result.Details = fmt.Sprintf("Portal (%s) and clients (%s) on same subnet", portalIP, localAddr)
		}
	}

	return result
}

// isTimeout reports whether an error is a network timeout.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	// Unwrap url.Error to get at the underlying net.Error.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
