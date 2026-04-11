// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package ui

import "testing"

func TestAssessMethodsUsesExactOpenPortFacts(t *testing.T) {
	oldState := state
	state = &State{
		Status: "idle",
		Probes: map[string]ProbeStatus{
			"cloudflare": {Status: "closed"},
		},
		OpenPorts: map[int]bool{443: true},
	}
	t.Cleanup(func() { state = oldState })

	methods := assessMethods()

	httpsTunnel := methodStateByNumber(t, methods, 2)
	if !httpsTunnel.Feasible {
		t.Fatalf("HTTPS/WS tunnel should be feasible when port 443 is open: %+v", httpsTunnel)
	}

	httpConnect := methodStateByNumber(t, methods, 5)
	if !httpConnect.Feasible {
		t.Fatalf("HTTP CONNECT abuse should be feasible when port 443 is open: %+v", httpConnect)
	}

	cfWorkers := methodStateByNumber(t, methods, 17)
	if cfWorkers.Feasible {
		t.Fatalf("CF Workers proxy should still depend on Cloudflare probe truth: %+v", cfWorkers)
	}
}

func TestAssessMethodsUsesPort8080ForHTTPConnect(t *testing.T) {
	oldState := state
	state = &State{
		Status: "idle",
		Probes: map[string]ProbeStatus{
			"cloudflare": {Status: "closed"},
		},
		OpenPorts: map[int]bool{8080: true},
	}
	t.Cleanup(func() { state = oldState })

	methods := assessMethods()

	httpsTunnel := methodStateByNumber(t, methods, 2)
	if httpsTunnel.Feasible {
		t.Fatalf("HTTPS/WS tunnel should not be feasible without port 443: %+v", httpsTunnel)
	}

	httpConnect := methodStateByNumber(t, methods, 5)
	if !httpConnect.Feasible {
		t.Fatalf("HTTP CONNECT abuse should be feasible when port 8080 is open: %+v", httpConnect)
	}
}

func methodStateByNumber(t *testing.T, methods []MethodState, number int) MethodState {
	t.Helper()
	for _, method := range methods {
		if method.Number == number {
			return method
		}
	}
	t.Fatalf("method number %d not found", number)
	return MethodState{}
}
