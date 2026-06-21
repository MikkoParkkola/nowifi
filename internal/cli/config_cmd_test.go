// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"strings"
	"testing"

	cfgpkg "github.com/MikkoParkkola/nowifi/internal/config"
)

func TestConfigCFWorkersAliasAndRedaction(t *testing.T) {
	entry, ok := lookupConfigEntry("cf_workers")
	if !ok {
		t.Fatal("cf_workers alias should resolve")
	}

	cfg := cfgpkg.Defaults()
	raw := "https://worker.example.dev/proxy?nowifi_token=secret-token"
	if err := entry.Set(cfg, raw); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if cfg.CFWorkers != raw || cfg.CFWorkersURL != raw {
		t.Fatalf("CF worker aliases not both set: %q / %q", cfg.CFWorkers, cfg.CFWorkersURL)
	}

	redacted := redactConfigValue(entry.Get(cfg))
	if strings.Contains(redacted, "secret-token") {
		t.Fatalf("redacted config value leaked token: %q", redacted)
	}
	if !strings.Contains(redacted, "nowifi_token=REDACTED") {
		t.Fatalf("redacted config value = %q, want REDACTED token", redacted)
	}
}

func TestConfigBooleanValidation(t *testing.T) {
	entry, ok := lookupConfigEntry("stealth")
	if !ok {
		t.Fatal("stealth config entry should resolve")
	}

	cfg := cfgpkg.Defaults()
	if err := entry.Set(cfg, "false"); err != nil {
		t.Fatalf("Set(false) error = %v", err)
	}
	if cfg.Stealth {
		t.Fatal("Stealth should be false")
	}
	if err := entry.Set(cfg, "not-bool"); err == nil {
		t.Fatal("Set(not-bool) should fail")
	}
}
