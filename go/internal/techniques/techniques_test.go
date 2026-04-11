// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package techniques

import "testing"

func TestBypassTechniqueInfosAreOrderedAndUnique(t *testing.T) {
	infos := BypassTechniqueInfos()
	if len(infos) != 19 {
		t.Fatalf("BypassTechniqueInfos() length = %d, want 19", len(infos))
	}

	seen := make(map[ID]bool, len(infos))
	for i, info := range infos {
		wantNumber := i + 1
		if info.Number != wantNumber {
			t.Fatalf("infos[%d].Number = %d, want %d", i, info.Number, wantNumber)
		}
		if info.ID == "" {
			t.Fatalf("infos[%d].ID is empty", i)
		}
		if seen[info.ID] {
			t.Fatalf("duplicate technique ID %q", info.ID)
		}
		seen[info.ID] = true
		if info.Name == "" || info.HelpName == "" {
			t.Fatalf("infos[%d] missing display names: %+v", i, info)
		}
	}
}

func TestServerRequirementSplitMatchesCurrentTechniqueContract(t *testing.T) {
	serverless := ServerlessBypassTechniqueInfos()
	serverRequired := ServerRequiredBypassTechniqueInfos()

	if len(serverless) != 10 {
		t.Fatalf("len(ServerlessBypassTechniqueInfos()) = %d, want 10", len(serverless))
	}
	if len(serverRequired) != 9 {
		t.Fatalf("len(ServerRequiredBypassTechniqueInfos()) = %d, want 9", len(serverRequired))
	}

	foundWhitelist := false
	for _, info := range serverRequired {
		if info.ID == WhitelistDomain {
			foundWhitelist = true
			break
		}
	}
	if !foundWhitelist {
		t.Fatal("WhitelistDomain should be classified as server-required")
	}
}

func TestCountFeasibleBypassTechniquesMatchesCurrentRules(t *testing.T) {
	allOpen := BypassTechniqueSignals{
		PortalDetected:     true,
		IPv6Open:           true,
		DNSOpen:            true,
		ICMPOpen:           true,
		CloudflareOpen:     true,
		QUICOpen:           true,
		NTPOpen:            true,
		DoHOpen:            true,
		WhitelistReachable: true,
		HTTP443Open:        true,
		HTTP8080Open:       true,
	}
	if got := CountFeasibleBypassTechniques(allOpen); got != 19 {
		t.Fatalf("CountFeasibleBypassTechniques(allOpen) = %d, want 19", got)
	}

	captiveOnly := BypassTechniqueSignals{PortalDetected: true}
	if got := CountFeasibleBypassTechniques(captiveOnly); got != 8 {
		t.Fatalf("CountFeasibleBypassTechniques(captiveOnly) = %d, want 8", got)
	}

	allClosed := BypassTechniqueSignals{}
	if got := CountFeasibleBypassTechniques(allClosed); got != 4 {
		t.Fatalf("CountFeasibleBypassTechniques(allClosed) = %d, want 4", got)
	}
}
