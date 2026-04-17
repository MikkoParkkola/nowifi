// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"github.com/MikkoParkkola/nowifi/internal/bypass"
	"github.com/MikkoParkkola/nowifi/internal/telemetry"
)

// submitBypassTelemetry emits opt-in anonymous telemetry for a set of bypass
// results. No-op when telemetry is disabled (opt-in required). Non-blocking.
//
// Duration is divided evenly across attempts — good enough for aggregation.
func submitBypassTelemetry(results []bypass.Result, provider string, totalMs int) {
	if !telemetry.IsEnabled() || len(results) == 0 {
		return
	}

	// Divide total bypass duration across attempts for rough per-technique timing.
	perAttempt := totalMs / len(results)

	for _, r := range results {
		telemetry.Submit(telemetry.Event{
			Technique:  string(r.Method),
			Success:    r.Success,
			Provider:   provider,
			DurationMs: perAttempt,
		}, version)
	}
}
