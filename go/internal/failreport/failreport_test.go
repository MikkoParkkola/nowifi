// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package failreport

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/config"
	"github.com/MikkoParkkola/nowifi/internal/forensics"
	"github.com/MikkoParkkola/nowifi/internal/platform"
)

// fullMACRE matches a complete 6-octet MAC (the thing we must NEVER leak).
var fullMACRE = regexp.MustCompile(`(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b`)

func samplePackage() *forensics.Package {
	return &forensics.Package{
		TS:       "20260529T182618Z",
		Provider: "panasonic_nordic_sky",
		Iface:    "en0",
		GW:       "172.19.248.1",
		Holes: []forensics.Hole{
			{Technique: "mac_clone_idle", Severity: "HIGH", Detail: "34 paid devices"},
			{Technique: "dns_tunnel", Severity: "HIGH", Detail: "UDP/53 open to 8.8.8.8"},
		},
		Raw: forensics.RawSections{
			ARP: []platform.ArpEntry{
				{IP: "172.19.248.8", MAC: "82:f8:d8:89:da:ea", Interface: "en0"},
				{IP: "172.19.248.9", MAC: "7e:95:9d:cb:25:ed", Interface: "en0"},
			},
			SelfMAC: "fa:0a:71:0b:ba:19",
			PaxAPI: []forensics.PaxEndpoint{
				{Path: "/pax-api-service/swagger.json", StatusCode: 200},
				{Path: "/pax-api-service/quota", StatusCode: 200},
			},
		},
	}
}

// TestSanitize_NoFullMACSurvives is the privacy-critical gate: after
// sanitization no full 6-octet MAC may remain anywhere in the serialized
// package (ARP third-party devices + the user's own SelfMAC).
func TestSanitize_NoFullMACSurvives(t *testing.T) {
	p := samplePackage()
	san := Sanitize(p)

	// Original must still contain full MACs (we didn't mutate the input).
	if san == p {
		t.Fatal("Sanitize returned the same pointer; must deep-copy")
	}
	if p.Raw.ARP[0].MAC != "82:f8:d8:89:da:ea" {
		t.Errorf("input was mutated: %s", p.Raw.ARP[0].MAC)
	}

	for i, e := range san.Raw.ARP {
		if fullMACRE.MatchString(e.MAC) {
			t.Errorf("ARP[%d] still has a full MAC: %s", i, e.MAC)
		}
		if !strings.HasSuffix(e.MAC, ":xx:xx:xx") {
			t.Errorf("ARP[%d] not redacted to OUI: %s", i, e.MAC)
		}
	}
	if fullMACRE.MatchString(san.Raw.SelfMAC) {
		t.Errorf("SelfMAC still full: %s", san.Raw.SelfMAC)
	}

	// Belt-and-suspenders: scan the whole serialized issue body.
	body := IssueBody(san, "Nordic Sky")
	if fullMACRE.MatchString(body) {
		t.Errorf("issue body leaks a full MAC:\n%s", body)
	}
}

func TestRedactMAC(t *testing.T) {
	cases := map[string]string{
		"82:f8:d8:89:da:ea": "82:f8:d8:xx:xx:xx",
		"fa:0a:71:0b:ba:19": "fa:0a:71:xx:xx:xx",
		"":                  "",
		"not-a-mac":         "not-a-mac",
		"172.19.248.1":      "172.19.248.1",
	}
	for in, want := range cases {
		if got := redactMAC(in); got != want {
			t.Errorf("redactMAC(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIssueBody_ContainsSolveItDetail(t *testing.T) {
	san := Sanitize(samplePackage())
	body := IssueBody(san, "Nordic Sky")
	for _, want := range []string{"panasonic_nordic_sky", "Nordic Sky", "mac_clone_idle", "dns_tunnel", "swagger.json", "quota", "172.19.248.1"} {
		if !strings.Contains(body, want) {
			t.Errorf("issue body missing %q", want)
		}
	}
	// Third-party device IP kept (useful), but its MAC must be redacted.
	if strings.Contains(body, "82:f8:d8:89:da:ea") {
		t.Error("issue body leaked a raw third-party MAC")
	}
}

func TestQueueRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	id, err := Enqueue(samplePackage(), "Nordic Sky")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if PendingCount() != 1 {
		t.Fatalf("PendingCount=%d want 1", PendingCount())
	}
	list, err := List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List=%v err=%v", list, err)
	}
	if list[0].SSID != "Nordic Sky" || list[0].HolesCount != 2 {
		t.Errorf("meta wrong: %+v", list[0])
	}
	pkg, ent, err := Load(id)
	if err != nil || pkg.Provider != "panasonic_nordic_sky" || ent.SSID != "Nordic Sky" {
		t.Fatalf("Load mismatch: pkg=%v ent=%v err=%v", pkg, ent, err)
	}
	if err := MarkSubmitted(id, "https://github.com/MikkoParkkola/nowifi/issues/1"); err != nil {
		t.Fatalf("MarkSubmitted: %v", err)
	}
	if PendingCount() != 0 {
		t.Errorf("PendingCount=%d want 0 after submit", PendingCount())
	}
	list2, _ := List()
	if !list2[0].Submitted || list2[0].IssueURL == "" {
		t.Errorf("submitted state not persisted: %+v", list2[0])
	}
}

func TestSubmitEntry_UsesSanitizedBodyAndMarks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	id, _ := Enqueue(samplePackage(), "Nordic Sky")

	var capturedBody string
	orig := submitFunc
	submitFunc = func(title, body string) (string, error) {
		capturedBody = body
		if !strings.Contains(title, "panasonic_nordic_sky") {
			t.Errorf("title missing provider: %s", title)
		}
		return "https://github.com/MikkoParkkola/nowifi/issues/7", nil
	}
	defer func() { submitFunc = orig }()

	url, _, err := SubmitEntry(id)
	if err != nil {
		t.Fatalf("SubmitEntry: %v", err)
	}
	if url == "" {
		t.Error("no URL returned")
	}
	if fullMACRE.MatchString(capturedBody) {
		t.Errorf("submitted body leaked a full MAC:\n%s", capturedBody)
	}
	if PendingCount() != 0 {
		t.Errorf("entry not marked submitted")
	}
}

func TestMaybeOfferPending_ConsentYesAndNo(t *testing.T) {
	orig := submitFunc
	var calls int
	submitFunc = func(title, body string) (string, error) {
		calls++
		return "https://github.com/MikkoParkkola/nowifi/issues/9", nil
	}
	defer func() { submitFunc = orig }()
	origNet := hasInternet
	hasInternet = func() bool { return true } // deterministic: pretend online
	defer func() { hasInternet = origNet }()

	// Non-*os.File reader is treated as non-interactive → prints notice,
	// does not submit. This asserts the no-silent-egress guarantee.
	t.Run("non-interactive never submits", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		config.InvalidateCache()
		_, _ = Enqueue(samplePackage(), "Nordic Sky")
		calls = 0
		var out bytes.Buffer
		if err := MaybeOfferPending(strings.NewReader("y\n"), &out); err != nil {
			t.Fatalf("err: %v", err)
		}
		if calls != 0 {
			t.Errorf("submitted without an interactive TTY (calls=%d)", calls)
		}
		if PendingCount() != 1 {
			t.Errorf("report should remain pending")
		}
		if !strings.Contains(out.String(), "pending") {
			t.Errorf("expected a pending notice, got: %q", out.String())
		}
	})
}
