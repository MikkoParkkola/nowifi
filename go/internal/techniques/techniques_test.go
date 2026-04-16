// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package techniques

import "testing"

func TestBypassTechniqueInfosAreOrderedAndUnique(t *testing.T) {
	infos := BypassTechniqueInfos()
	if len(infos) != 23 {
		t.Fatalf("BypassTechniqueInfos() length = %d, want 23", len(infos))
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

	if len(serverless) != 12 {
		t.Fatalf("len(ServerlessBypassTechniqueInfos()) = %d, want 12", len(serverless))
	}
	if len(serverRequired) != 11 {
		t.Fatalf("len(ServerRequiredBypassTechniqueInfos()) = %d, want 11", len(serverRequired))
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

func TestBypassTechniqueResultMetadataCoverage(t *testing.T) {
	for _, info := range BypassTechniqueInfos() {
		success, hasSuccess := SuccessResultMetadataByID(info.ID)
		finding, hasFinding := FindingResultMetadataByID(info.ID)
		if !hasSuccess && !hasFinding {
			t.Fatalf("technique %q is missing canonical result metadata", info.ID)
		}
		if hasSuccess {
			if success.Severity == "" {
				t.Fatalf("technique %q success metadata missing severity", info.ID)
			}
			if success.Impact == "" {
				t.Fatalf("technique %q success metadata missing impact", info.ID)
			}
			if success.Remediation == "" {
				t.Fatalf("technique %q success metadata missing remediation", info.ID)
			}
		}
		if hasFinding {
			if finding.Severity == "" {
				t.Fatalf("technique %q finding metadata missing severity", info.ID)
			}
			if finding.Remediation == "" {
				t.Fatalf("technique %q finding metadata missing remediation", info.ID)
			}
		}
	}
}
