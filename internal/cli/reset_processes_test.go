// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestStopOrphanedProcessesWith_DeduplicatesPIDs(t *testing.T) {
	t.Parallel()

	findCalls := []string{}
	stopped := []int{}

	find := func(name string) ([]int, error) {
		findCalls = append(findCalls, name)
		switch name {
		case "chisel":
			return []int{101, 202}, nil
		case "iodine":
			return []int{202, 303}, nil
		default:
			return nil, nil
		}
	}

	stop := func(pid int) error {
		stopped = append(stopped, pid)
		return nil
	}

	killed, warnings := stopOrphanedProcessesWith([]string{"chisel", "iodine"}, find, stop)
	if killed != 3 {
		t.Fatalf("killed = %d, want 3", killed)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %d, want 0", len(warnings))
	}
	if len(findCalls) != 2 {
		t.Fatalf("find called %d times, want 2", len(findCalls))
	}
	if got, want := stopped, []int{101, 202, 303}; len(got) != len(want) {
		t.Fatalf("stopped = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("stopped = %v, want %v", got, want)
			}
		}
	}
}

func TestStopOrphanedProcessesWith_CollectsLookupAndStopWarnings(t *testing.T) {
	t.Parallel()

	find := func(name string) ([]int, error) {
		switch name {
		case "chisel":
			return nil, errors.New("pgrep failed")
		case "iodine":
			return []int{42, 43}, nil
		default:
			return nil, nil
		}
	}

	stop := func(pid int) error {
		if pid == 42 {
			return errors.New("permission denied")
		}
		return nil
	}

	killed, warnings := stopOrphanedProcessesWith([]string{"chisel", "iodine"}, find, stop)
	if killed != 1 {
		t.Fatalf("killed = %d, want 1", killed)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %d, want 2", len(warnings))
	}
	if !strings.Contains(warnings[0].Error(), "lookup chisel") {
		t.Fatalf("lookup warning = %q, want lookup chisel context", warnings[0])
	}
	if !strings.Contains(warnings[1].Error(), "stop iodine pid 42") {
		t.Fatalf("stop warning = %q, want stop iodine pid 42 context", warnings[1])
	}
}
