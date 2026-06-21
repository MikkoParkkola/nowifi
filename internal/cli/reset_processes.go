// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	findProcessIDsByName = defaultFindProcessIDsByName
	terminateProcessByID = defaultTerminateProcessByID
)

func stopOrphanedProcesses(processNames []string) (int, []error) {
	return stopOrphanedProcessesWith(processNames, findProcessIDsByName, terminateProcessByID)
}

func stopOrphanedProcessesWith(
	processNames []string,
	find func(string) ([]int, error),
	stop func(int) error,
) (int, []error) {
	var warnings []error
	seen := make(map[int]struct{})
	killed := 0

	for _, name := range processNames {
		pids, err := find(name)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("lookup %s: %w", name, err))
			continue
		}
		for _, pid := range pids {
			if _, ok := seen[pid]; ok {
				continue
			}
			seen[pid] = struct{}{}
			if err := stop(pid); err != nil {
				warnings = append(warnings, fmt.Errorf("stop %s pid %d: %w", name, pid, err))
				continue
			}
			killed++
		}
	}

	return killed, warnings
}

func defaultFindProcessIDsByName(name string) ([]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "pgrep", "-x", name).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}

	lines := strings.Fields(string(out))
	pids := make([]int, 0, len(lines))
	for _, line := range lines {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			return nil, fmt.Errorf("parse pid %q: %w", line, err)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func defaultTerminateProcessByID(pid int) error {
	pidText := strconv.Itoa(pid)
	if err := runSignalCommand("-TERM", pidText, 2*time.Second); err != nil {
		return err
	}
	if waitForProcessExit(pidText, 5*time.Second) {
		return nil
	}
	if err := runSignalCommand("-KILL", pidText, 2*time.Second); err != nil {
		return err
	}
	if waitForProcessExit(pidText, 2*time.Second) {
		return nil
	}
	return fmt.Errorf("process %d did not exit after SIGKILL", pid)
}

func runSignalCommand(signal, pid string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, "kill", signal, pid).Run()
}

func waitForProcessExit(pid string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processExists(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !processExists(pid)
}

func processExists(pid string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := exec.CommandContext(ctx, "kill", "-0", pid).Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false
	}
	return err == nil
}
