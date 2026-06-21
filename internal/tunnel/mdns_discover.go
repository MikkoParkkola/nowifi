// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ----------------------------------------------------------------------------
// mDNS/DNS-SD auto-discovery for nowifi tunnel servers.
//
// When a user runs `nowifi server listen`, the server advertises itself via
// mDNS (Bonjour on macOS, Avahi on Linux) as _nowifi._tcp.local. Clients
// running `sudo nowifi` automatically discover nearby servers and configure
// the appropriate tunnel technique.
//
// This is the discovery client. The server-side advertisement is in
// mdns_advertise.go.
//
// Service types:
//   _nowifi-quic._udp.local.      → raw QUIC tunnel
//   _nowifi-h3._udp.local.        → MASQUE + WebTransport
//   _nowifi-h2._tcp.local.        → HTTP/2 CONNECT
//   _nowifi-sse._tcp.local.       → SSE relay
//   _nowifi-grpc._tcp.local.      → gRPC tunnel
//   _nowifi-connectip._udp.local. → CONNECT-IP
// ----------------------------------------------------------------------------

// DiscoveredServer represents a nowifi server found via mDNS.
type DiscoveredServer struct {
	Mode     string // "quic", "h3", "h2", "sse", "grpc", "connectip"
	Host     string // hostname or IP
	Port     int
	URL      string // fully-formed URL for the CLI flag
	Instance string // mDNS instance name
}

// DiscoverServers scans the local network for nowifi tunnel servers
// using DNS-SD queries. Returns all discovered servers within the timeout.
func DiscoverServers(timeout time.Duration) ([]DiscoveredServer, error) {
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// DNS-SD service types to look for.
	services := []struct {
		srvType string
		mode    string
		scheme  string
	}{
		{"_nowifi-h2._tcp.local.", "h2", "https"},
		{"_nowifi-sse._tcp.local.", "sse", "https"},
		{"_nowifi-grpc._tcp.local.", "grpc", "https"},
		{"_nowifi-h3._udp.local.", "h3", "https"},
		{"_nowifi-quic._udp.local.", "quic", "https"},
		{"_nowifi-connectip._udp.local.", "connectip", "https"},
	}

	var results []DiscoveredServer

	for _, svc := range services {
		servers := queryMDNSService(ctx, svc.srvType)
		for _, s := range servers {
			ds := DiscoveredServer{
				Mode:     svc.mode,
				Host:     s.host,
				Port:     s.port,
				Instance: s.instance,
			}
			if s.port == 443 {
				ds.URL = fmt.Sprintf("%s://%s", svc.scheme, s.host)
			} else {
				ds.URL = fmt.Sprintf("%s://%s:%d", svc.scheme, s.host, s.port)
			}
			results = append(results, ds)
		}
	}

	return results, nil
}

type mdnsResult struct {
	host     string
	port     int
	instance string
}

// queryMDNSService performs a simple DNS-SD query for a service type.
// Uses multicast DNS on 224.0.0.251:5353.
func queryMDNSService(ctx context.Context, serviceType string) []mdnsResult {
	// Simplified mDNS query: send a PTR question, parse responses.
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	// Set deadline from context.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Multicast address for mDNS.
	mcastAddr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

	// Build a minimal DNS PTR query.
	query := buildDNSQuery(serviceType)
	if _, err := conn.WriteTo(query, mcastAddr); err != nil {
		return nil
	}

	// Collect responses.
	var results []mdnsResult
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break // timeout or context done
		}
		if servers := parseMDNSResponse(buf[:n], serviceType); len(servers) > 0 {
			results = append(results, servers...)
		}
	}

	return results
}

// buildDNSQuery creates a minimal DNS query packet for a PTR record.
func buildDNSQuery(name string) []byte {
	// DNS header: ID=0x1234, flags=0x0000, questions=1.
	buf := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // Flags (standard query)
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}
	// Encode the name as DNS labels.
	for _, part := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(part) == 0 || len(part) > 63 {
			return nil
		}
		buf = append(buf, byte(len(part))) // #nosec G115 -- DNS label length is checked above.
		buf = append(buf, part...)
	}
	buf = append(buf, 0x00)       // null terminator
	buf = append(buf, 0x00, 0x0c) // QTYPE: PTR (12)
	buf = append(buf, 0x00, 0x01) // QCLASS: IN (1)
	return buf
}

// parseMDNSResponse extracts server info from DNS response packets.
// This is a simplified parser that looks for SRV and A records.
func parseMDNSResponse(data []byte, serviceType string) []mdnsResult {
	if len(data) < 12 {
		return nil
	}

	// Parse header.
	answerCount := int(data[6])<<8 | int(data[7])
	additionalCount := int(data[10])<<8 | int(data[11])

	if answerCount == 0 && additionalCount == 0 {
		return nil
	}

	// Simplified: scan for SRV record patterns in the raw data.
	// A full DNS parser would be better, but for mDNS discovery of our
	// own service types, we can look for known patterns.
	var results []mdnsResult

	// Look for the service type string in the response.
	svcName := strings.TrimSuffix(serviceType, ".")
	if !strings.Contains(string(data), strings.Split(svcName, ".")[0][1:]) {
		return nil
	}

	// Extract IP addresses from the packet (A records: type 1, 4 bytes).
	for i := 12; i+14 <= len(data); i++ {
		// Look for A record pattern: type=0x0001, class=0x0001, TTL(4), rdlen=4
		if data[i] == 0x00 && data[i+1] == 0x01 && // type A
			data[i+2] == 0x80 && data[i+3] == 0x01 { // class IN + cache flush
			rdlen := int(data[i+8])<<8 | int(data[i+9])
			if rdlen == 4 {
				ip := net.IPv4(data[i+10], data[i+11], data[i+12], data[i+13])
				results = append(results, mdnsResult{
					host:     ip.String(),
					port:     443, // default
					instance: svcName,
				})
			}
		}
	}

	return results
}
