// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Package forensics captures a portable, read-only diagnostic package that
// records which egress channels survive captive-portal enforcement, so an
// unsolved environment can be analyzed offline to build a working bypass.
//
// This is a Go port of forensics/captive-forensics.sh (sections 1-10 plus the
// pax-api enforcement control-plane sweep). It is collection-only: no MAC
// changes, no tunnels, no proxy, no network mutation, and it never uploads or
// phones home. Output is written to disk and the saved paths are returned.
//
// Probing reuses the internal/probe package rather than reimplementing it.
// Every probe degrades gracefully on missing privilege or timeout — a hung
// probe never fails the whole run; the limitation is recorded in the package.
package forensics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/probe"
)

const (
	// DefaultTotalTimeout is the hard wall-clock cap for live collection.
	// An offline, frustrated user must get a package fast even when some
	// probes hang. Flag-overridable from the CLI.
	DefaultTotalTimeout = 90 * time.Second

	// paxAPITimeout bounds each individual pax-api control-plane request.
	paxAPITimeout = 7 * time.Second

	// paxBodyTruncate is the per-endpoint body cap (~2KB) for pax-api probes,
	// except swagger.json which is captured fully (it is the enforcement model).
	paxBodyTruncate = 2048
)

// Severity levels mirror the shell script's HIGH/MED/LOW taxonomy.
const (
	SeverityHigh = "HIGH"
	SeverityMed  = "MED"
	SeverityLow  = "LOW"
)

// Hole is a single exploitable egress channel that survived enforcement.
// It maps to a nowifi bypass technique. This is the heart of the port:
// the holes taxonomy, not the raw dumps.
type Hole struct {
	Technique string `json:"technique"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
}

// PaxEndpoint records one pax-api / enforcement control-plane probe.
type PaxEndpoint struct {
	Path        string `json:"path"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
	Error       string `json:"error,omitempty"`
}

// RawSections holds the additive captured state (sections 1-10) that
// accompanies the ranked holes in the machine-readable package.
type RawSections struct {
	// Section 1: network state.
	DNS  probe.DnsProbeResult  `json:"dns"`
	IPv6 probe.Ipv6ProbeResult `json:"ipv6"`
	// Section 2: authenticated-device enumeration (MAC-clone candidates).
	ARP []platform.ArpEntry `json:"arp,omitempty"`
	// Section 3: egress channel sweep under enforcement.
	OpenPorts []probe.PortProbeResult `json:"open_ports,omitempty"`
	QUIC      probe.PortProbeResult   `json:"quic"`
	NTP       probe.PortProbeResult   `json:"ntp"`
	// Section 4-6: recursion, DoH, ICMP.
	ICMP probe.IcmpProbeResult `json:"icmp"`
	DoH  probe.PortProbeResult `json:"doh"`
	// Section 7: allowlist + SNI/domain-fronting.
	Whitelists []probe.WhitelistResult `json:"whitelists,omitempty"`
	Cloudflare probe.HttpsProbeResult  `json:"cloudflare"`
	// Section 8/8c: portal/Kong surface + pax-api control plane.
	PaxAPI []PaxEndpoint `json:"pax_api,omitempty"`
	// PaxAPIAnalysis is the recon verdict over PaxAPI: whether it is a real
	// enforcement API versus the SPA HTML fallback, plus candidate reset
	// vectors from a real swagger doc.
	PaxAPIAnalysis *PaxAPIAnalysis `json:"pax_api_analysis,omitempty"`
	// Section 9: enforcement model.
	SelfMAC string `json:"self_mac,omitempty"`
	// Topology context.
	Topology probe.SubnetTopology `json:"topology"`
	// Limitations records degradations (missing privilege, timeouts) so the
	// package is honest about what could not be captured.
	Limitations []string `json:"limitations,omitempty"`
}

// Package is the complete forensic capture. The JSON form mirrors
// forensics/holes-*.json: {ts, provider, iface, gw, holes[]} plus the raw
// captured sections.
type Package struct {
	TS       string      `json:"ts"`
	Provider string      `json:"provider"`
	Iface    string      `json:"iface"`
	GW       string      `json:"gw"`
	Holes    []Hole      `json:"holes"`
	Raw      RawSections `json:"raw"`
}

// Options configures a live collection run.
type Options struct {
	Iface    string
	Stealth  bool
	Provider string // optional override; derived from portal vendor otherwise
	// PortalBase is the base URL for pax-api probes (e.g. https://portal.host).
	// When empty it is derived from detected portal info, falling back to the
	// gateway IP.
	PortalBase string
	// TotalTimeout is the hard wall-clock cap. Zero uses DefaultTotalTimeout.
	TotalTimeout time.Duration
	// httpClient is injectable for tests; nil uses a real short-timeout client.
	httpClient *http.Client
	// probes, when non-nil, is used instead of running a live ProbeAll sweep.
	// The audit auto-trigger passes the probes already in scope; tests inject
	// a fixed ProbeResults for deterministic, network-free runs.
	probes *probe.ProbeResults
	// arp, when non-nil, is used instead of platform.GetARPTable.
	arp []platform.ArpEntry
	// portal, when non-nil, is used instead of detect.DetectPortal.
	portal *detect.PortalInfo
	// selfMAC, when non-empty, is used instead of platform.GetCurrentMAC.
	selfMAC string
	// gateway, when non-empty, is used instead of platform.GetGateway.
	gateway string
	// now is injectable for deterministic timestamps in tests.
	now func() time.Time
}

// WithProbes returns a copy of opts that reuses pre-built probe results
// instead of running a live ProbeAll sweep. The audit auto-trigger uses this
// to pass the probes already in scope, avoiding a fresh sweep inside the
// session maintain loop.
func (o Options) WithProbes(probes *probe.ProbeResults) Options {
	o.probes = probes
	return o
}

// paxEndpoints is the enforcement control-plane surface (section 8c).
// swagger.json is captured fully; the rest truncate to ~2KB.
var paxEndpoints = []string{
	"/pax-api-service/session",
	"/pax-api-service/device",
	"/pax-api-service/status",
	"/pax-api-service/quota",
	"/pax-api-service/plans",
	"/pax-api-service/health",
	"/pax-api-service/api-docs",
	"/pax-api-service/swagger.json",
	"/portal-versions.json",
}

// Collect runs a live, read-only forensic capture under a hard time cap and
// returns the assembled package. Partial results still serialize: on timeout
// it records the limitation and returns whatever sections completed.
func Collect(opts Options) *Package {
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = DefaultTotalTimeout
	}
	ts := opts.now().UTC().Format("20060102T150405Z")

	pkg := &Package{TS: ts, Iface: opts.Iface}

	// raw is filled incrementally by the worker goroutine under mu. On timeout
	// the main path locks and snapshots whatever has completed so far, so a
	// hung pax-api fetch never discards the probe sweep, ARP, or MAC that
	// already landed. The package is genuinely partial, not empty.
	var mu sync.Mutex
	raw := &RawSections{}
	var portal *detect.PortalInfo

	deadline := time.After(opts.TotalTimeout)
	done := make(chan struct{})

	go func() {
		// Portal detection (section 8) — also feeds provider + pax base.
		p := opts.portal
		if p == nil {
			p = detect.DetectPortal(opts.Iface)
		}
		mu.Lock()
		portal = p
		mu.Unlock()

		// Section 9: enforcement model — your MAC.
		selfMAC := opts.selfMAC
		var selfMACLimit string
		if selfMAC == "" {
			if mac, err := platform.GetCurrentMAC(opts.Iface); err == nil {
				selfMAC = mac
			} else {
				selfMACLimit = "self MAC unavailable (interface query failed): " + err.Error()
			}
		}
		mu.Lock()
		raw.SelfMAC = selfMAC
		if selfMACLimit != "" {
			raw.Limitations = append(raw.Limitations, selfMACLimit)
		}
		mu.Unlock()

		// Sections 1,3-7: reuse the probe sweep. Never reimplement probing.
		var probes *probe.ProbeResults
		if opts.probes != nil {
			probes = opts.probes
		} else {
			probes = probe.ProbeAll(opts.Iface, opts.Stealth, "")
		}
		// Topology (cross-subnet portal detection).
		portalIP := ""
		if p != nil {
			portalIP = p.PortalIP
		}
		topology := probe.ProbeTopology(opts.Iface, portalIP)
		mu.Lock()
		raw.DNS = probes.DNS
		raw.ICMP = probes.ICMP
		raw.IPv6 = probes.IPv6
		raw.Cloudflare = probes.Cloudflare
		raw.Whitelists = probes.Whitelists
		raw.OpenPorts = probes.OpenPorts
		raw.QUIC = probes.QUIC
		raw.NTP = probes.NTP
		raw.DoH = probes.DoH
		raw.Topology = topology
		mu.Unlock()

		// Section 2: ARP table = MAC-clone candidates. We do NOT replicate the
		// shell's /24 ping-sweep — that fights "reuse, don't reimplement",
		// risks the time cap, and flirts with the no-mutation rule. We read the
		// existing ARP cache and record the degradation.
		arp := opts.arp
		var arpLimit string
		if arp == nil {
			var err error
			arp, err = platform.GetARPTable()
			if err != nil {
				arpLimit = "ARP table unavailable: " + err.Error()
			}
		}
		mu.Lock()
		raw.ARP = arp
		if arpLimit != "" {
			raw.Limitations = append(raw.Limitations, arpLimit)
		}
		raw.Limitations = append(raw.Limitations,
			"neighbor set limited to existing ARP cache (no active subnet sweep — read-only)")
		mu.Unlock()

		// Section 8c: pax-api enforcement control plane (the slowest section —
		// the realistic timeout trigger on a high-RTT link).
		base := opts.PortalBase
		if base == "" {
			base = derivePortalBase(p, opts.gateway, opts.Iface)
		}
		var pax []PaxEndpoint
		var paxLimit string
		if base != "" {
			pax = probePaxAPI(opts.httpClient, base)
		} else {
			paxLimit = "pax-api base URL could not be derived (no portal host or gateway)"
		}
		mu.Lock()
		raw.PaxAPI = pax
		raw.PaxAPIAnalysis = AnalyzePaxAPI(pax)
		if paxLimit != "" {
			raw.Limitations = append(raw.Limitations, paxLimit)
		}
		mu.Unlock()

		close(done)
	}()

	timedOut := false
	select {
	case <-done:
	case <-deadline:
		timedOut = true
	}

	// Snapshot the (possibly partial) raw sections under the lock.
	mu.Lock()
	if timedOut {
		raw.Limitations = append(raw.Limitations, fmt.Sprintf(
			"collection exceeded total time cap (%s) — package is partial; some sections may be missing",
			opts.TotalTimeout))
	}
	pkg.Raw = *raw
	portalSnapshot := portal
	mu.Unlock()
	portal = portalSnapshot

	// Gateway.
	pkg.GW = opts.gateway
	if pkg.GW == "" {
		if portal != nil && portal.Gateway != "" {
			pkg.GW = portal.Gateway
		} else if gw, err := platform.GetGateway(opts.Iface); err == nil {
			pkg.GW = gw
		}
	}

	// Provider.
	pkg.Provider = opts.Provider
	if pkg.Provider == "" {
		pkg.Provider = deriveProvider(portal)
	}

	pkg.Holes = MapHoles(&pkg.Raw)
	return pkg
}

// deriveProvider produces a stable provider slug from portal vendor, avoiding
// any import back into the cli package (cli imports forensics, not vice-versa).
func deriveProvider(portal *detect.PortalInfo) string {
	if portal == nil || portal.Vendor == "" {
		return "unknown"
	}
	slug := strings.ToLower(portal.Vendor)
	slug = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r == ' ', r == '-', r == '/', r == '.':
			return '_'
		default:
			return -1
		}
	}, slug)
	for strings.Contains(slug, "__") {
		slug = strings.ReplaceAll(slug, "__", "_")
	}
	slug = strings.Trim(slug, "_")
	if slug == "" {
		return "unknown"
	}
	return slug
}

// derivePortalBase builds the pax-api base URL from detected portal info,
// falling back to the gateway IP.
func derivePortalBase(portal *detect.PortalInfo, gateway, iface string) string {
	if portal != nil {
		if portal.PortalURL != "" {
			if u, err := url.Parse(portal.PortalURL); err == nil && u.Host != "" {
				return u.Scheme + "://" + u.Host
			}
		}
		if portal.PortalIP != "" {
			return "https://" + portal.PortalIP
		}
		if portal.Gateway != "" {
			return "https://" + portal.Gateway
		}
	}
	if gateway != "" {
		return "https://" + gateway
	}
	if gw, err := platform.GetGateway(iface); err == nil && gw != "" {
		return "https://" + gw
	}
	return ""
}

// probePaxAPI fetches the enforcement control-plane endpoints with a short
// per-request timeout, capturing status and a truncated body (full for
// swagger.json). Read-only GETs; never mutates anything.
func probePaxAPI(client *http.Client, base string) []PaxEndpoint {
	if client == nil {
		client = &http.Client{Timeout: paxAPITimeout}
	}
	base = strings.TrimRight(base, "/")
	out := make([]PaxEndpoint, 0, len(paxEndpoints))
	for _, ep := range paxEndpoints {
		out = append(out, fetchPaxEndpoint(client, base, ep))
	}
	return out
}

func fetchPaxEndpoint(client *http.Client, base, ep string) PaxEndpoint {
	res := PaxEndpoint{Path: ep}
	ctx, cancel := context.WithTimeout(context.Background(), paxAPITimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+ep, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	res.StatusCode = resp.StatusCode
	res.ContentType = resp.Header.Get("Content-Type")

	// swagger.json is the enforcement model — capture it fully. Others truncate.
	full := strings.HasSuffix(ep, "swagger.json")
	limit := int64(paxBodyTruncate)
	if full {
		limit = 1 << 20 // 1MB safety ceiling even for "full".
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if !full && int64(len(body)) > int64(paxBodyTruncate) {
		body = body[:paxBodyTruncate]
		res.Truncated = true
	}
	res.Body = string(body)
	return res
}
