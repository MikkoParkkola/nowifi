// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package crack

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// RateLimiter presets
// ---------------------------------------------------------------------------

func TestWPSRateLimiter(t *testing.T) {
	rl := WPSRateLimiter()
	if rl.BaseDelay != 3*time.Second {
		t.Errorf("BaseDelay = %v, want 3s", rl.BaseDelay)
	}
	if rl.MaxDelay != 5*time.Minute {
		t.Errorf("MaxDelay = %v, want 5m", rl.MaxDelay)
	}
	if rl.BackoffFactor != 2.0 {
		t.Errorf("BackoffFactor = %v, want 2.0", rl.BackoffFactor)
	}
	if rl.MaxConsecFails != 3 {
		t.Errorf("MaxConsecFails = %d, want 3", rl.MaxConsecFails)
	}
	if rl.LockoutPause != 120*time.Second {
		t.Errorf("LockoutPause = %v, want 120s", rl.LockoutPause)
	}
	if rl.MaxLockouts != 5 {
		t.Errorf("MaxLockouts = %d, want 5", rl.MaxLockouts)
	}
}

func TestOnlineBruteRateLimiter(t *testing.T) {
	rl := OnlineBruteRateLimiter()
	if rl.BaseDelay != 100*time.Millisecond {
		t.Errorf("BaseDelay = %v, want 100ms", rl.BaseDelay)
	}
	if rl.MaxConsecFails != 10 {
		t.Errorf("MaxConsecFails = %d, want 10", rl.MaxConsecFails)
	}
	if rl.MaxLockouts != 10 {
		t.Errorf("MaxLockouts = %d, want 10", rl.MaxLockouts)
	}
}

func TestPortalLoginRateLimiter(t *testing.T) {
	rl := PortalLoginRateLimiter()
	if rl.BaseDelay != 500*time.Millisecond {
		t.Errorf("BaseDelay = %v, want 500ms", rl.BaseDelay)
	}
	if rl.MaxConsecFails != 5 {
		t.Errorf("MaxConsecFails = %d, want 5", rl.MaxConsecFails)
	}
	if rl.MaxLockouts != 3 {
		t.Errorf("MaxLockouts = %d, want 3", rl.MaxLockouts)
	}
}

// ---------------------------------------------------------------------------
// RecordSuccess / RecordFailure
// ---------------------------------------------------------------------------

func TestRecordSuccess_ResetsConsecFails(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:      10 * time.Millisecond,
		MaxDelay:       1 * time.Second,
		BackoffFactor:  2.0,
		MaxConsecFails: 5,
		LockoutPause:   1 * time.Second,
		MaxLockouts:    3,
		currentDelay:   100 * time.Millisecond,
	}

	// Record some failures.
	rl.RecordFailure(false)
	rl.RecordFailure(false)

	// Then a success.
	rl.RecordSuccess()

	// consecFails should be 0, delay reduced.
	_, _, delay := rl.Stats()
	if delay > 100*time.Millisecond {
		t.Errorf("delay after success should be reduced, got %v", delay)
	}
}

func TestRecordSuccess_DelayFloor(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:    100 * time.Millisecond,
		currentDelay: 50 * time.Millisecond, // Below base.
	}

	rl.RecordSuccess()

	_, _, delay := rl.Stats()
	if delay < rl.BaseDelay {
		t.Errorf("delay should not go below BaseDelay, got %v", delay)
	}
}

func TestRecordFailure_TriggersLockout(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:      10 * time.Millisecond,
		MaxDelay:       1 * time.Second,
		BackoffFactor:  2.0,
		MaxConsecFails: 3,
		LockoutPause:   1 * time.Second,
		MaxLockouts:    5,
		currentDelay:   10 * time.Millisecond,
	}

	// Record failures up to lockout threshold.
	rl.RecordFailure(false) // 1
	rl.RecordFailure(false) // 2
	lockoutErr := rl.RecordFailure(false) // 3 -> lockout

	if lockoutErr == nil {
		t.Fatal("expected lockout error after MaxConsecFails failures")
	}
	if lockoutErr.Permanent {
		t.Error("first lockout should not be permanent")
	}
	if lockoutErr.WaitTime != 1*time.Second {
		t.Errorf("WaitTime = %v, want 1s", lockoutErr.WaitTime)
	}

	_, lockouts, _ := rl.Stats()
	if lockouts != 1 {
		t.Errorf("lockoutCount = %d, want 1", lockouts)
	}
}

func TestRecordFailure_TimeoutCountsTriple(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:      10 * time.Millisecond,
		MaxDelay:       1 * time.Second,
		BackoffFactor:  2.0,
		MaxConsecFails: 3,
		LockoutPause:   1 * time.Second,
		MaxLockouts:    5,
		currentDelay:   10 * time.Millisecond,
	}

	// A single timeout (isTimeout=true) should count as 3 failures.
	lockoutErr := rl.RecordFailure(true)

	if lockoutErr == nil {
		t.Fatal("timeout should trigger lockout (counts as 3)")
	}
}

func TestRecordFailure_PermanentLockout(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:      1 * time.Millisecond,
		MaxDelay:       100 * time.Millisecond,
		BackoffFactor:  1.5,
		MaxConsecFails: 1,
		LockoutPause:   10 * time.Millisecond,
		MaxLockouts:    2,
		currentDelay:   1 * time.Millisecond,
	}

	// First lockout.
	rl.RecordFailure(false) // lockout #1
	// Reset consec (lockout resets it).

	// Second lockout -> permanent.
	lockoutErr := rl.RecordFailure(false) // lockout #2

	if lockoutErr == nil {
		t.Fatal("expected permanent lockout error")
	}
	if !lockoutErr.Permanent {
		t.Error("expected Permanent=true after MaxLockouts reached")
	}
	if !rl.IsAborted() {
		t.Error("expected IsAborted()=true")
	}
}

func TestIsAborted_InitiallyFalse(t *testing.T) {
	rl := WPSRateLimiter()
	if rl.IsAborted() {
		t.Error("new RateLimiter should not be aborted")
	}
}

func TestStats_Initial(t *testing.T) {
	rl := WPSRateLimiter()
	attempts, lockouts, delay := rl.Stats()
	if attempts != 0 {
		t.Errorf("initial attempts = %d, want 0", attempts)
	}
	if lockouts != 0 {
		t.Errorf("initial lockouts = %d, want 0", lockouts)
	}
	if delay != 3*time.Second {
		t.Errorf("initial delay = %v, want 3s", delay)
	}
}

func TestRecordFailure_BackoffIncreasesDelay(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:      10 * time.Millisecond,
		MaxDelay:       1 * time.Second,
		BackoffFactor:  2.0,
		MaxConsecFails: 2,
		LockoutPause:   10 * time.Millisecond,
		MaxLockouts:    10,
		currentDelay:   10 * time.Millisecond,
	}

	// Trigger first lockout.
	rl.RecordFailure(false)
	rl.RecordFailure(false)

	_, _, delay := rl.Stats()
	if delay != 20*time.Millisecond {
		t.Errorf("delay after backoff = %v, want 20ms", delay)
	}
}

func TestRecordFailure_DelayCappedAtMax(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:      100 * time.Millisecond,
		MaxDelay:       200 * time.Millisecond,
		BackoffFactor:  10.0,
		MaxConsecFails: 1,
		LockoutPause:   1 * time.Millisecond,
		MaxLockouts:    100,
		currentDelay:   100 * time.Millisecond,
	}

	rl.RecordFailure(false) // lockout, delay *= 10 but capped

	_, _, delay := rl.Stats()
	if delay > rl.MaxDelay {
		t.Errorf("delay %v exceeds MaxDelay %v", delay, rl.MaxDelay)
	}
}

// ---------------------------------------------------------------------------
// LockoutError formatting
// ---------------------------------------------------------------------------

func TestLockoutError_Permanent(t *testing.T) {
	err := &LockoutError{Permanent: true, Message: "locked out forever"}
	s := err.Error()
	if !strings.Contains(s, "permanent") {
		t.Errorf("permanent error should mention permanent: %q", s)
	}
	if !strings.Contains(s, "locked out forever") {
		t.Errorf("error should contain message: %q", s)
	}
}

func TestLockoutError_Temporary(t *testing.T) {
	err := &LockoutError{Permanent: false, Message: "pause", WaitTime: 30 * time.Second}
	s := err.Error()
	if !strings.Contains(s, "temporary") {
		t.Errorf("temporary error should mention temporary: %q", s)
	}
	if !strings.Contains(s, "30s") {
		t.Errorf("error should contain wait time: %q", s)
	}
}

// ---------------------------------------------------------------------------
// DetectLockoutSignal
// ---------------------------------------------------------------------------

func TestDetectLockoutSignal(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"reaver rate limiting", "WARNING: Detected AP rate limiting", true},
		{"wps transaction failed", "WPS transaction failed (code: 0x02)", true},
		{"receive timeout", "Receive timeout occurred", true},
		{"ap locked wps", "AP has locked its WPS state", true},
		{"ap appears locked", "WARNING: AP appears to be locked", true},
		{"rate limit generic", "Error: rate limit exceeded", true},
		{"too many attempts", "Too many attempts, please wait", true},
		{"temporarily blocked", "Your IP is temporarily blocked", true},
		{"try again later", "Please try again later", true},
		{"account locked", "Account locked due to failed attempts", true},
		{"eapol timeout", "EAPOL timeout", true},
		{"auth timed out", "Authentication timed out", true},
		{"case insensitive", "warning: detected ap RATE LIMITING", true},
		{"normal output", "PIN: 12345678", false},
		{"empty", "", false},
		{"success message", "WPS PIN found: 12345670", false},
		{"partial match no", "This is a rate discussion", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectLockoutSignal(tt.output)
			if got != tt.want {
				t.Errorf("DetectLockoutSignal(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Wait after abort
// ---------------------------------------------------------------------------

func TestWait_NormalOperation(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:    1 * time.Millisecond,
		currentDelay: 1 * time.Millisecond,
	}

	err := rl.Wait()
	if err != nil {
		t.Fatalf("Wait should not error: %v", err)
	}

	attempts, _, _ := rl.Stats()
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}

func TestWait_RespectsDelay(t *testing.T) {
	rl := &RateLimiter{
		BaseDelay:    50 * time.Millisecond,
		currentDelay: 50 * time.Millisecond,
		lastAttempt:  time.Now(),
	}

	start := time.Now()
	err := rl.Wait()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Wait error: %v", err)
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("Wait should respect delay, elapsed = %v", elapsed)
	}
}

func TestHandleLockout_Nil(t *testing.T) {
	rl := WPSRateLimiter()
	// Should not panic.
	rl.HandleLockout(nil)
}

func TestHandleLockout_PermanentNoop(t *testing.T) {
	rl := WPSRateLimiter()
	// Permanent lockout should not sleep.
	rl.HandleLockout(&LockoutError{Permanent: true, Message: "permanent"})
}

func TestWait_AfterAbort(t *testing.T) {
	rl := &RateLimiter{
		aborted:     true,
		abortReason: "test abort",
	}

	err := rl.Wait()
	if err == nil {
		t.Fatal("Wait should return error after abort")
	}

	lockoutErr, ok := err.(*LockoutError)
	if !ok {
		t.Fatalf("expected *LockoutError, got %T", err)
	}
	if !lockoutErr.Permanent {
		t.Error("aborted Wait should return permanent lockout")
	}
}
