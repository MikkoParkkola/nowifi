// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package tunnel

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestResolveECHConfigList_Base64StandardPadded(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	got, err := resolveECHConfigList(ECHServerConfig{
		ECHConfigListBase64: base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("got %x, want %x", got, raw)
	}
}

func TestResolveECHConfigList_Base64URLNoPadding(t *testing.T) {
	raw := []byte{0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad}
	got, err := resolveECHConfigList(ECHServerConfig{
		ECHConfigListBase64: base64.RawURLEncoding.EncodeToString(raw),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("got %x, want %x", got, raw)
	}
}

func TestResolveECHConfigList_Raw(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}
	got, err := resolveECHConfigList(ECHServerConfig{ECHConfigList: raw})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("got %x, want %x", got, raw)
	}
}

func TestResolveECHConfigList_EmptyIsError(t *testing.T) {
	_, err := resolveECHConfigList(ECHServerConfig{})
	if err == nil {
		t.Error("expected error for empty config")
	}
}

func TestResolveECHConfigList_BothFieldsIsError(t *testing.T) {
	_, err := resolveECHConfigList(ECHServerConfig{
		ECHConfigList:       []byte{0x01},
		ECHConfigListBase64: "AQ==",
	})
	if err == nil {
		t.Error("expected error when both fields set")
	}
}

func TestResolveECHConfigList_InvalidBase64(t *testing.T) {
	_, err := resolveECHConfigList(ECHServerConfig{
		ECHConfigListBase64: "not valid base64!!@@##",
	})
	if err == nil {
		t.Error("expected error on invalid base64")
	}
}

func TestParseECHEndpoint_Variants(t *testing.T) {
	tests := []struct {
		in           string
		wantAddr     string
		wantSNI      string
		wantErr      bool
		wantErrSubst string
	}{
		{"https://ech.example.com", "ech.example.com:443", "ech.example.com", false, ""},
		{"https://ech.example.com:8443", "ech.example.com:8443", "ech.example.com", false, ""},
		{"ech.example.com", "ech.example.com:443", "ech.example.com", false, ""},
		{"ech.example.com:9443", "ech.example.com:9443", "ech.example.com", false, ""},
		{"http://ech.example.com", "", "", true, "https"},
		{"ftp://bad.example.com", "", "", true, "https"},
		{"", "", "", true, "invalid endpoint"},
	}
	for _, tc := range tests {
		addr, sni, err := parseECHEndpoint(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseECHEndpoint(%q): expected error, got nil", tc.in)
				continue
			}
			if tc.wantErrSubst != "" && !strings.Contains(err.Error(), tc.wantErrSubst) {
				t.Errorf("parseECHEndpoint(%q): err=%q, want substring %q", tc.in, err, tc.wantErrSubst)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseECHEndpoint(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if addr != tc.wantAddr || sni != tc.wantSNI {
			t.Errorf("parseECHEndpoint(%q) = (%q,%q), want (%q,%q)", tc.in, addr, sni, tc.wantAddr, tc.wantSNI)
		}
	}
}

func TestStartECHProxy_MissingConfigIsError(t *testing.T) {
	// No ECH config means we can't even form a valid TLS config — must fail
	// before attempting any network call.
	_, err := StartECHProxy(ECHServerConfig{ServerURL: "https://example.com"}, 0)
	if err == nil {
		t.Error("expected error with missing ECH config")
	}
}

func TestStartECHProxy_EmptyServerIsError(t *testing.T) {
	_, err := StartECHProxy(ECHServerConfig{ECHConfigListBase64: "AQID"}, 0)
	if err == nil {
		t.Error("expected error with empty server URL")
	}
}

func TestReadHTTP2xxStatus(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"HTTP/1.1 200 OK\r\n", true},
		{"HTTP/1.1 204 No Content\r\n", true},
		{"HTTP/1.1 302 Found\r\n", false},
		{"HTTP/1.1 403 Forbidden\r\n", false},
		{"HTTP/1.1 500 Internal Server Error\r\n", false},
	}
	for _, tc := range tests {
		got := readHTTP2xxStatus(strings.NewReader(tc.in))
		if got != tc.want {
			t.Errorf("readHTTP2xxStatus(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestDrainHTTPHeaders(t *testing.T) {
	in := "X-Proxy: nowifi\r\nContent-Length: 0\r\n\r\n"
	if err := drainHTTPHeaders(strings.NewReader(in)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
