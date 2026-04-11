package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MikkoParkkola/nowifi/internal/detect"
)

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

	require.Equal(t, "https://configured.example/login", resolveWatchPortalURL("wlan0"))
	require.False(t, detectCalled)
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

	require.Equal(t, "https://detected.example/login", resolveWatchPortalURL("wlan0"))
	require.Equal(t, "https://detected.example/login", resolveWatchPortalURL("wlan0"))
	require.Equal(t, 1, detectCalls)
	require.Equal(t, "https://detected.example/login", flagPortalURL)
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

	require.Empty(t, resolveWatchPortalURL("wlan0"))
	require.Empty(t, flagPortalURL)
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

	require.Empty(t, resolveWatchPortalURL("wlan0"))
	require.Empty(t, flagPortalURL)
}
