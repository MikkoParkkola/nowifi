// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package bypass

import (
	"testing"

	"github.com/MikkoParkkola/nowifi/internal/inflight"
)

func TestOrderedTechniqueRunnersFor_NilConfigReturnsCanonicalOrder(t *testing.T) {
	canonical := orderedTechniqueRunners()
	withNilCfg := orderedTechniqueRunnersFor(nil)

	if len(canonical) != len(withNilCfg) {
		t.Fatalf("nil-config length = %d, canonical length = %d", len(withNilCfg), len(canonical))
	}

	for i := range canonical {
		if canonical[i].runName != withNilCfg[i].runName {
			t.Errorf("position %d: canonical=%q, nil-config=%q",
				i, canonical[i].runName, withNilCfg[i].runName)
		}
	}
}

func TestOrderedTechniqueRunnersFor_EmptyProviderReturnsCanonicalOrder(t *testing.T) {
	canonical := orderedTechniqueRunners()
	cfg := &Config{InflightProvider: ""}
	runners := orderedTechniqueRunnersFor(cfg)

	if len(runners) != len(canonical) {
		t.Fatalf("empty-provider length = %d, canonical = %d", len(runners), len(canonical))
	}
}

func TestOrderedTechniqueRunnersFor_UnknownProviderFallsBackToCanonical(t *testing.T) {
	canonical := orderedTechniqueRunners()
	cfg := &Config{InflightProvider: "nonexistent_airline_provider_xyz"}
	runners := orderedTechniqueRunnersFor(cfg)

	if len(runners) != len(canonical) {
		t.Errorf("unknown-provider length = %d, canonical = %d", len(runners), len(canonical))
	}
}

func TestOrderedTechniqueRunnersFor_PanasonicPrioritizesMACClone(t *testing.T) {
	cfg := &Config{InflightProvider: string(inflight.Panasonic)}
	runners := orderedTechniqueRunnersFor(cfg)

	// Panasonic profile recommends mac_clone_idle first.
	// The canonical order has IPv6 bypass first (#1), so reordering is
	// observable: first runner should NOT be IPv6 bypass.
	profile := inflight.GetProfile(inflight.Panasonic)
	if profile == nil {
		t.Skip("Panasonic profile not found (test data changed?)")
	}
	if len(profile.RecommendedOrder) == 0 {
		t.Skip("Panasonic RecommendedOrder is empty")
	}

	// The first runner's Method should match the provider's first recommended.
	expectedFirstID := profile.RecommendedOrder[0]
	firstRunner := runners[0]

	// Map the runner back to its method ID by iterating the runner map.
	// (We don't expose Method on techniqueRunner, so we verify by name.)
	// Panasonic's first recommended is "mac_clone_idle" (MAC clone (idle)).
	if expectedFirstID == "mac_clone_idle" && firstRunner.runName != "MAC clone (idle)" {
		t.Errorf("Panasonic should run MAC clone (idle) first; got %q", firstRunner.runName)
	}
}

func TestOrderedTechniqueRunnersFor_SkipsIneffectiveTechniques(t *testing.T) {
	// Panasonic lists "ipv6_bypass" as ineffective — it should not appear
	// in the reordered runner list.
	cfg := &Config{InflightProvider: string(inflight.Panasonic)}
	runners := orderedTechniqueRunnersFor(cfg)

	profile := inflight.GetProfile(inflight.Panasonic)
	if profile == nil {
		t.Skip("Panasonic profile not found")
	}

	// Build set of ineffective names to check.
	ineffective := make(map[string]bool)
	for _, id := range profile.IneffectiveTechniques {
		ineffective[id] = true
	}

	// IPv6 bypass is ineffective for Panasonic.
	if !ineffective["ipv6_bypass"] {
		t.Skip("Panasonic no longer lists ipv6_bypass as ineffective")
	}

	// Verify no runner has "IPv6 bypass" name.
	for _, r := range runners {
		if r.runName == "IPv6 bypass" {
			t.Errorf("IPv6 bypass should be skipped for Panasonic (listed as ineffective)")
		}
	}
}

func TestOrderedTechniqueRunnersFor_AllProvidersProduceValidRunners(t *testing.T) {
	// Every profile's RecommendedOrder technique IDs should map to valid
	// runners. If a provider lists a nonexistent technique, we silently
	// skip it (as the implementation does), but verify no crashes.
	for providerID := range inflight.Profiles {
		cfg := &Config{InflightProvider: string(providerID)}
		runners := orderedTechniqueRunnersFor(cfg)
		if len(runners) == 0 {
			t.Errorf("provider %q produced zero runners", providerID)
		}
		// Each runner must have a runName.
		for i, r := range runners {
			if r.runName == "" {
				t.Errorf("provider %q runner[%d] has empty runName", providerID, i)
			}
		}
	}
}

func TestOrderedTechniqueRunnersFor_NoDuplicatesInOutput(t *testing.T) {
	for providerID := range inflight.Profiles {
		cfg := &Config{InflightProvider: string(providerID)}
		runners := orderedTechniqueRunnersFor(cfg)

		seen := make(map[string]bool)
		for _, r := range runners {
			if seen[r.runName] {
				t.Errorf("provider %q: duplicate runner %q", providerID, r.runName)
			}
			seen[r.runName] = true
		}
	}
}
