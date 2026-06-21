// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package forensics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MikkoParkkola/nowifi/internal/detect"
	"github.com/MikkoParkkola/nowifi/internal/platform"
	"github.com/MikkoParkkola/nowifi/internal/probe"
)

// fullRaw builds a RawSections fixture in which every channel is open, so the
// full holes taxonomy is exercised without touching the network.
func fullRaw() *RawSections {
	return &RawSections{
		DNS: probe.DnsProbeResult{IsOpen: true, Resolvers: []probe.ResolverResult{
			{IP: "8.8.8.8", Name: "Google", Resolved: "93.184.216.34"},
			{IP: "1.1.1.1", Name: "Cloudflare", Resolved: "93.184.216.34"},
		}},
		ICMP: probe.IcmpProbeResult{IsOpen: true, Details: "echo reaches 1.1.1.1"},
		IPv6: probe.Ipv6ProbeResult{IsOpen: true, Address: "2001:db8::1"},
		DoH:  probe.PortProbeResult{Port: 443, Protocol: "doh", IsOpen: true},
		QUIC: probe.PortProbeResult{Port: 443, Protocol: "udp", IsOpen: true},
		NTP:  probe.PortProbeResult{Port: 123, Protocol: "udp", IsOpen: true},
		OpenPorts: []probe.PortProbeResult{
			{Port: 53, Protocol: "tcp", IsOpen: true, Service: "DNS"},
			{Port: 443, Protocol: "tcp", IsOpen: true, Service: "HTTPS"},
			{Port: 22, Protocol: "tcp", IsOpen: true, Service: "SSH"},
			{Port: 80, Protocol: "tcp", IsOpen: false, Service: "HTTP"},
		},
		Whitelists: []probe.WhitelistResult{
			{Domain: "cloudflare.com", IsOpen: true, StatusCode: 200},
			{Domain: "blocked.example", IsOpen: false},
		},
		ARP: []platform.ArpEntry{
			{IP: "172.19.248.1", MAC: "aa:bb:cc:dd:ee:01", Interface: "en0"},
			{IP: "172.19.248.2", MAC: "aa:bb:cc:dd:ee:02", Interface: "en0"},
			{IP: "172.19.248.9", MAC: "de:ad:be:ef:00:00", Interface: "en0"}, // self
		},
		SelfMAC: "de:ad:be:ef:00:00",
		PaxAPI: []PaxEndpoint{
			{Path: "/pax-api-service/session", StatusCode: 200, ContentType: "application/json"},
			{Path: "/pax-api-service/quota", StatusCode: 404},
			{Path: "/pax-api-service/swagger.json", StatusCode: 200, ContentType: "application/json"},
		},
	}
}

func techniqueCounts(holes []Hole) map[string]int {
	m := map[string]int{}
	for _, h := range holes {
		m[h.Technique]++
	}
	return m
}

func TestMapHoles_FullTaxonomy(t *testing.T) {
	holes := MapHoles(fullRaw())
	counts := techniqueCounts(holes)

	tests := []struct {
		technique string
		wantMin   int
	}{
		{"mac_clone_idle", 1},
		{"tcp53_tunnel", 1},
		{"tcp443_tunnel", 1},
		{"ssh_egress", 1},
		{"quic_tunnel", 1}, // from QUIC probe and/or UDP/443 port
		{"ntp_tunnel", 1},
		{"dns_tunnel", 2}, // one per recursive resolver
		{"doh_tunnel", 1},
		{"icmp_tunnel", 1},
		{"domain_front", 1},
		{"portal_api_session", 1},
		{"mac_rotate", 1},
	}
	for _, tt := range tests {
		if counts[tt.technique] < tt.wantMin {
			t.Errorf("technique %q: got %d, want >= %d", tt.technique, counts[tt.technique], tt.wantMin)
		}
	}
}

func TestMapHoles_RankingHighBeforeMed(t *testing.T) {
	holes := MapHoles(fullRaw())
	seenMed := false
	for _, h := range holes {
		if h.Severity == SeverityMed {
			seenMed = true
		}
		if h.Severity == SeverityHigh && seenMed {
			t.Errorf("HIGH hole %q appeared after a MED hole — ranking broken", h.Technique)
		}
	}
}

func TestMapHoles_EmptyAndNil(t *testing.T) {
	if got := MapHoles(nil); len(got) != 0 {
		t.Errorf("MapHoles(nil) = %d holes, want 0", len(got))
	}
	if got := MapHoles(&RawSections{}); len(got) != 0 {
		t.Errorf("MapHoles(empty) = %d holes, want 0", len(got))
	}
}

func TestMapHoles_SelfMACNotCounted(t *testing.T) {
	raw := &RawSections{
		SelfMAC: "de:ad:be:ef:00:00",
		ARP: []platform.ArpEntry{
			{IP: "10.0.0.1", MAC: "DE:AD:BE:EF:00:00", Interface: "en0"}, // self, uppercase
		},
	}
	for _, h := range MapHoles(raw) {
		if h.Technique == "mac_clone_idle" {
			t.Error("self MAC (case-insensitive) was counted as a clone candidate")
		}
	}
}

func TestDiffBaseline(t *testing.T) {
	tests := []struct {
		name     string
		current  []Hole
		baseline []Hole
		want     []string
	}{
		{
			name:     "intersection only",
			current:  []Hole{{Technique: "dns_tunnel", Severity: SeverityHigh}, {Technique: "icmp_tunnel", Severity: SeverityHigh}},
			baseline: []Hole{{Technique: "dns_tunnel", Severity: SeverityHigh}, {Technique: "doh_tunnel", Severity: SeverityHigh}},
			want:     []string{"dns_tunnel"},
		},
		{
			name:     "no overlap",
			current:  []Hole{{Technique: "ssh_egress", Severity: SeverityHigh}},
			baseline: []Hole{{Technique: "ntp_tunnel", Severity: SeverityMed}},
			want:     nil,
		},
		{
			name:     "dedup repeated technique",
			current:  []Hole{{Technique: "dns_tunnel"}, {Technique: "dns_tunnel"}},
			baseline: []Hole{{Technique: "dns_tunnel"}},
			want:     []string{"dns_tunnel"},
		},
		{
			name:     "empty baseline yields nothing",
			current:  []Hole{{Technique: "dns_tunnel"}},
			baseline: nil,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiffBaseline(tt.current, tt.baseline)
			var names []string
			for _, h := range got {
				names = append(names, h.Technique)
			}
			if strings.Join(names, ",") != strings.Join(tt.want, ",") {
				t.Errorf("DiffBaseline() = %v, want %v", names, tt.want)
			}
		})
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	pkg := &Package{TS: "20260530T120000Z", Iface: "en0", GW: "10.0.0.1", Provider: "panasonic"}
	pkg.Raw = *fullRaw()
	pkg.Holes = MapHoles(&pkg.Raw)

	parsed := ParseBaseline(pkg.Baseline())
	if len(parsed) != len(pkg.Holes) {
		t.Fatalf("round-trip hole count: got %d, want %d", len(parsed), len(pkg.Holes))
	}
	// Every original technique must survive the round trip.
	orig := techniqueCounts(pkg.Holes)
	got := techniqueCounts(parsed)
	for k, v := range orig {
		if got[k] != v {
			t.Errorf("technique %q: round-trip got %d, want %d", k, got[k], v)
		}
	}
}

func TestParseBaseline_SkipsCommentsAndBlanks(t *testing.T) {
	in := "# header\n\ndns_tunnel|HIGH|works\n   \nicmp_tunnel|HIGH\nbad-no-pipe\n"
	got := ParseBaseline(in)
	if len(got) != 2 {
		t.Fatalf("ParseBaseline got %d holes, want 2: %+v", len(got), got)
	}
	if got[0].Technique != "dns_tunnel" || got[0].Detail != "works" {
		t.Errorf("unexpected first hole: %+v", got[0])
	}
}

func TestPackageJSON_MirrorsReferenceShape(t *testing.T) {
	pkg := &Package{TS: "20260530T120000Z", Provider: "panasonic_nordic_sky", Iface: "en0", GW: "172.19.248.1"}
	pkg.Raw = *fullRaw()
	pkg.Holes = MapHoles(&pkg.Raw)

	data, err := pkg.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"ts", "provider", "iface", "gw", "holes", "raw"} {
		if _, ok := top[key]; !ok {
			t.Errorf("JSON missing top-level key %q", key)
		}
	}
	// holes[] entries must carry technique/severity/detail.
	var holes []Hole
	if err := json.Unmarshal(top["holes"], &holes); err != nil {
		t.Fatalf("unmarshal holes: %v", err)
	}
	if len(holes) == 0 {
		t.Fatal("expected non-empty holes")
	}
	if holes[0].Technique == "" || holes[0].Severity == "" {
		t.Errorf("hole missing fields: %+v", holes[0])
	}
}

func TestText_NoPanicAndContainsSections(t *testing.T) {
	pkg := &Package{TS: "20260530T120000Z", Iface: "en0", GW: "10.0.0.1", Provider: "test"}
	pkg.Raw = *fullRaw()
	pkg.Holes = MapHoles(&pkg.Raw)
	txt := pkg.Text()
	for _, want := range []string{"NETWORK STATE", "MAC-CLONE CANDIDATES", "HOLES FOUND", "pax-api"} {
		if !strings.Contains(txt, want) {
			t.Errorf("Text() missing section %q", want)
		}
	}
}

func TestWrite_ProducesBothFiles(t *testing.T) {
	dir := t.TempDir()
	pkg := &Package{TS: "20260530T120000Z", Iface: "en0", GW: "10.0.0.1", Provider: "test"}
	pkg.Raw = *fullRaw()
	pkg.Holes = MapHoles(&pkg.Raw)

	res, err := pkg.Write(dir, WriteOptions{Format: "both", Baseline: true})
	if err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	for _, p := range []string{res.TextPath, res.JSONPath, res.BaselinePath} {
		if p == "" {
			t.Fatal("Write() returned an empty path")
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file %s: %v", p, err)
		}
	}
	if filepath.Base(res.TextPath) != "holes-20260530T120000Z.txt" {
		t.Errorf("unexpected text filename: %s", res.TextPath)
	}
	if filepath.Base(res.JSONPath) != "holes-20260530T120000Z.json" {
		t.Errorf("unexpected json filename: %s", res.JSONPath)
	}
}

func TestProbePaxAPI_TruncatesAndCapturesSwaggerFully(t *testing.T) {
	bigBody := strings.Repeat("A", paxBodyTruncate*3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "swagger.json"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(bigBody))
		case strings.HasSuffix(r.URL.Path, "/quota"):
			w.WriteHeader(404)
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(bigBody))
		}
	}))
	defer srv.Close()

	eps := probePaxAPI(srv.Client(), srv.URL)
	var swagger, session *PaxEndpoint
	for i := range eps {
		switch {
		case strings.HasSuffix(eps[i].Path, "swagger.json"):
			swagger = &eps[i]
		case strings.HasSuffix(eps[i].Path, "/session"):
			session = &eps[i]
		}
	}
	if swagger == nil || session == nil {
		t.Fatal("expected swagger and session endpoints in results")
	}
	if swagger.Truncated {
		t.Error("swagger.json must be captured fully, not truncated")
	}
	if len(swagger.Body) != len(bigBody) {
		t.Errorf("swagger body len = %d, want %d (full)", len(swagger.Body), len(bigBody))
	}
	if !session.Truncated || len(session.Body) != paxBodyTruncate {
		t.Errorf("session body should be truncated to %d, got len %d truncated=%t",
			paxBodyTruncate, len(session.Body), session.Truncated)
	}
}

// TestCollect_NetworkFree_InjectedProbes verifies that Collect assembles a
// complete package from injected probes + ARP + portal + a fake pax-api,
// with zero live network access.
func TestCollect_NetworkFree_InjectedProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	raw := fullRaw()
	probes := &probe.ProbeResults{
		DNS: raw.DNS, ICMP: raw.ICMP, IPv6: raw.IPv6, Cloudflare: raw.Cloudflare,
		Whitelists: raw.Whitelists, OpenPorts: raw.OpenPorts,
		QUIC: raw.QUIC, NTP: raw.NTP, DoH: raw.DoH,
	}
	opts := Options{
		Iface:      "en0",
		Provider:   "test_provider",
		PortalBase: srv.URL,
		httpClient: srv.Client(),
		probes:     probes,
		arp:        raw.ARP,
		selfMAC:    raw.SelfMAC,
		gateway:    "172.19.248.1",
		portal:     &detect.PortalInfo{IsCaptive: true, Vendor: "Test", PortalIP: "172.19.248.1"},
		now:        func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) },
	}
	pkg := Collect(opts)

	if pkg.TS != "20260530T120000Z" {
		t.Errorf("TS = %q, want injected timestamp", pkg.TS)
	}
	if pkg.Provider != "test_provider" || pkg.GW != "172.19.248.1" || pkg.Iface != "en0" {
		t.Errorf("metadata wrong: %+v", pkg)
	}
	if len(pkg.Holes) == 0 {
		t.Error("expected holes from injected open channels")
	}
	if len(pkg.Raw.PaxAPI) != len(paxEndpoints) {
		t.Errorf("pax-api endpoints = %d, want %d", len(pkg.Raw.PaxAPI), len(paxEndpoints))
	}
	// A live 200 endpoint should surface a portal_api_session hole.
	if techniqueCounts(pkg.Holes)["portal_api_session"] == 0 {
		t.Error("expected portal_api_session hole from live pax-api endpoint")
	}
}

// slowRoundTripper sleeps before every response, making pax-api the slow
// section so a tight TotalTimeout fires during pax fetches.
type slowRoundTripper struct{ delay time.Duration }

func (s slowRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	time.Sleep(s.delay)
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader("{}")),
		Request:    req,
	}, nil
}

// TestCollect_TimeoutSalvagesCompletedSections proves the timeout path is
// genuinely partial, not empty: probes/ARP/MAC are injected and complete
// instantly, only pax-api is slow, so on a tight cap the package retains the
// salvaged sections and records the cap limitation.
func TestCollect_TimeoutSalvagesCompletedSections(t *testing.T) {
	raw := fullRaw()
	probes := &probe.ProbeResults{
		DNS: raw.DNS, ICMP: raw.ICMP, IPv6: raw.IPv6, Cloudflare: raw.Cloudflare,
		Whitelists: raw.Whitelists, OpenPorts: raw.OpenPorts,
		QUIC: raw.QUIC, NTP: raw.NTP, DoH: raw.DoH,
	}
	opts := Options{
		Iface:        "en0",
		Provider:     "test_provider",
		PortalBase:   "https://portal.example",
		httpClient:   &http.Client{Transport: slowRoundTripper{delay: 500 * time.Millisecond}},
		probes:       probes,
		arp:          raw.ARP,
		selfMAC:      raw.SelfMAC,
		gateway:      "10.0.0.1",
		portal:       &detect.PortalInfo{IsCaptive: true, Vendor: "Test"},
		TotalTimeout: 30 * time.Millisecond,
		now:          func() time.Time { return time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC) },
	}
	pkg := Collect(opts)

	// Salvaged section: SelfMAC must survive the timeout.
	if pkg.Raw.SelfMAC != raw.SelfMAC {
		t.Errorf("timeout discarded SelfMAC: got %q, want %q (package should be partial, not empty)",
			pkg.Raw.SelfMAC, raw.SelfMAC)
	}
	// Metadata always survives.
	if pkg.Provider != "test_provider" || pkg.GW != "10.0.0.1" {
		t.Errorf("timeout lost metadata: %+v", pkg)
	}
	// The cap limitation must be recorded.
	found := false
	for _, l := range pkg.Raw.Limitations {
		if strings.Contains(l, "total time cap") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a time-cap limitation note, got %v", pkg.Raw.Limitations)
	}
}

func TestDeriveProvider(t *testing.T) {
	tests := []struct {
		vendor string
		want   string
	}{
		{"Panasonic Avionics", "panasonic_avionics"},
		{"Nordic-Sky", "nordic_sky"},
		{"", "unknown"},
		{"Kong/Squid", "kong_squid"},
	}
	for _, tt := range tests {
		got := deriveProvider(&detect.PortalInfo{Vendor: tt.vendor})
		if got != tt.want {
			t.Errorf("deriveProvider(%q) = %q, want %q", tt.vendor, got, tt.want)
		}
	}
	if got := deriveProvider(nil); got != "unknown" {
		t.Errorf("deriveProvider(nil) = %q, want unknown", got)
	}
}

func TestDerivePortalBase(t *testing.T) {
	tests := []struct {
		name    string
		portal  *detect.PortalInfo
		gateway string
		want    string
	}{
		{"from portal URL", &detect.PortalInfo{PortalURL: "https://portal.example.com/login"}, "", "https://portal.example.com"},
		{"from portal IP", &detect.PortalInfo{PortalIP: "172.16.0.1"}, "", "https://172.16.0.1"},
		{"from gateway fallback", &detect.PortalInfo{}, "10.0.0.1", "https://10.0.0.1"},
		{"nil portal gateway fallback", nil, "10.0.0.1", "https://10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := derivePortalBase(tt.portal, tt.gateway, "")
			if got != tt.want {
				t.Errorf("derivePortalBase() = %q, want %q", got, tt.want)
			}
		})
	}
}
