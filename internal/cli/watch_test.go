package cli

import (
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/detect"
)

func assertStringEqual(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveWatchPortalURLUsesConfiguredURL(t *testing.T) {
	originalPortalURL := flagPortalURL
	originalDetectPortal := detectPortal
	t.Cleanup(func() {
		flagPortalURL = originalPortalURL
		detectPortal = originalDetectPortal
	})

	flagPortalURL = "https://configured.example/login"
	detectCalled := false
	detectPortal = func(string) *detect.PortalInfo {
		detectCalled = true
		return &detect.PortalInfo{PortalURL: "https://detected.example/login"}
	}

	assertStringEqual(t, resolveWatchPortalURL("wlan0"), "https://configured.example/login")
	if detectCalled {
		t.Fatal("detectPortal should not be called when flagPortalURL is already set")
	}
}

func TestResolveWatchPortalURLCachesDetectedURL(t *testing.T) {
	originalPortalURL := flagPortalURL
	originalDetectPortal := detectPortal
	t.Cleanup(func() {
		flagPortalURL = originalPortalURL
		detectPortal = originalDetectPortal
	})

	flagPortalURL = ""
	detectCalls := 0
	detectPortal = func(string) *detect.PortalInfo {
		detectCalls++
		return &detect.PortalInfo{PortalURL: "https://detected.example/login"}
	}

	assertStringEqual(t, resolveWatchPortalURL("wlan0"), "https://detected.example/login")
	assertStringEqual(t, resolveWatchPortalURL("wlan0"), "https://detected.example/login")
	if detectCalls != 1 {
		t.Fatalf("detectPortal calls = %d, want 1", detectCalls)
	}
	assertStringEqual(t, flagPortalURL, "https://detected.example/login")
}

func TestResolveWatchPortalURLIgnoresMissingDetection(t *testing.T) {
	originalPortalURL := flagPortalURL
	originalDetectPortal := detectPortal
	t.Cleanup(func() {
		flagPortalURL = originalPortalURL
		detectPortal = originalDetectPortal
	})

	flagPortalURL = ""
	detectPortal = func(string) *detect.PortalInfo {
		return &detect.PortalInfo{}
	}

	assertStringEqual(t, resolveWatchPortalURL("wlan0"), "")
	assertStringEqual(t, flagPortalURL, "")
}

func TestResolveWatchPortalURLHandlesNilPortalDetection(t *testing.T) {
	originalPortalURL := flagPortalURL
	originalDetectPortal := detectPortal
	t.Cleanup(func() {
		flagPortalURL = originalPortalURL
		detectPortal = originalDetectPortal
	})

	flagPortalURL = ""
	detectPortal = func(string) *detect.PortalInfo {
		return nil
	}

	assertStringEqual(t, resolveWatchPortalURL("wlan0"), "")
	assertStringEqual(t, flagPortalURL, "")
}
