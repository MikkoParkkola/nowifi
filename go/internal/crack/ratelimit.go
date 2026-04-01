// Rate limiting and exponential backoff for brute force operations.
//
// WiFi access points and captive portals commonly rate-limit authentication:
//   - WPA online brute: APs may ignore or block after N failed 4-way handshakes
//   - WPS PIN brute: APs lock WPS after 3-10 failed PINs (sometimes permanently)
//   - Portal login: portals may block IP/MAC after N failed login attempts
//
// This module provides adaptive rate limiting that:
//   1. Starts at a safe rate (configurable per technique)
//   2. Detects lockout signals (timeout increase, connection refused, explicit lock message)
//   3. Backs off exponentially when lockout is detected
//   4. Optionally pauses and retries (WPS lock often clears after 60-300s)
//   5. Aborts if the AP appears permanently locked
package crack

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// RateLimiter controls the pace of brute force attempts with adaptive backoff.
type RateLimiter struct {
	mu sync.Mutex

	// Configuration
	BaseDelay      time.Duration // Delay between attempts (e.g., 3s for WPS, 100ms for online)
	MaxDelay       time.Duration // Maximum backoff delay (e.g., 5 min)
	BackoffFactor  float64       // Multiplier on each lockout signal (e.g., 2.0)
	MaxConsecFails int           // Consecutive failures before assuming lockout
	LockoutPause   time.Duration // How long to wait when lockout detected (e.g., 60s for WPS)
	MaxLockouts    int           // Max lockout events before aborting (e.g., 3)

	// State
	currentDelay  time.Duration
	consecFails   int
	lockoutCount  int
	totalAttempts int
	lastAttempt   time.Time
	aborted       bool
	abortReason   string
}

// LockoutError indicates the target has locked us out.
type LockoutError struct {
	Permanent bool
	Message   string
	WaitTime  time.Duration
}

func (e *LockoutError) Error() string {
	if e.Permanent {
		return fmt.Sprintf("permanent lockout: %s", e.Message)
	}
	return fmt.Sprintf("temporary lockout (wait %s): %s", e.WaitTime, e.Message)
}

// Presets for common scenarios.

// WPSRateLimiter returns a rate limiter tuned for WPS PIN brute force.
// APs typically lock after 3-10 failed attempts, unlock after 60-300 seconds.
func WPSRateLimiter() *RateLimiter {
	return &RateLimiter{
		BaseDelay:      3 * time.Second,  // WPS exchange takes ~2-3s anyway
		MaxDelay:       5 * time.Minute,
		BackoffFactor:  2.0,
		MaxConsecFails: 3,                // Most APs lock after 3 failures
		LockoutPause:   120 * time.Second, // Wait 2 min for WPS unlock
		MaxLockouts:    5,                // Give up after 5 lockout cycles
		currentDelay:   3 * time.Second,
	}
}

// OnlineBruteRateLimiter returns a rate limiter for wpa_supplicant PSK attempts.
// APs don't usually rate-limit 4-way handshake, but may start ignoring.
func OnlineBruteRateLimiter() *RateLimiter {
	return &RateLimiter{
		BaseDelay:      100 * time.Millisecond, // ~10 attempts/sec initially
		MaxDelay:       10 * time.Second,
		BackoffFactor:  1.5,
		MaxConsecFails: 10,                // APs are more tolerant
		LockoutPause:   30 * time.Second,
		MaxLockouts:    10,
		currentDelay:   100 * time.Millisecond,
	}
}

// PortalLoginRateLimiter returns a rate limiter for captive portal credential testing.
func PortalLoginRateLimiter() *RateLimiter {
	return &RateLimiter{
		BaseDelay:      500 * time.Millisecond,
		MaxDelay:       30 * time.Second,
		BackoffFactor:  2.0,
		MaxConsecFails: 5,
		LockoutPause:   60 * time.Second,
		MaxLockouts:    3,
		currentDelay:   500 * time.Millisecond,
	}
}

// Wait blocks until the next attempt is allowed. Returns error if aborted.
func (rl *RateLimiter) Wait() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.aborted {
		return &LockoutError{Permanent: true, Message: rl.abortReason}
	}

	// Calculate time to wait since last attempt
	since := time.Since(rl.lastAttempt)
	if since < rl.currentDelay {
		wait := rl.currentDelay - since
		rl.mu.Unlock()
		time.Sleep(wait)
		rl.mu.Lock()
	}

	rl.totalAttempts++
	rl.lastAttempt = time.Now()
	return nil
}

// RecordSuccess resets the failure counter and reduces delay back toward base.
func (rl *RateLimiter) RecordSuccess() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.consecFails = 0
	// Gradually reduce delay back to base (don't snap back instantly)
	rl.currentDelay = time.Duration(float64(rl.currentDelay) * 0.5)
	if rl.currentDelay < rl.BaseDelay {
		rl.currentDelay = rl.BaseDelay
	}
}

// RecordFailure records a failed attempt. Returns a LockoutError if lockout detected.
func (rl *RateLimiter) RecordFailure(isTimeout bool) *LockoutError {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.consecFails++

	// Timeout is a stronger lockout signal than auth failure
	if isTimeout {
		rl.consecFails += 2 // Count timeouts as 3 failures
	}

	// Check for lockout condition
	if rl.consecFails >= rl.MaxConsecFails {
		rl.lockoutCount++
		rl.consecFails = 0

		// Check if permanently locked out
		if rl.lockoutCount >= rl.MaxLockouts {
			rl.aborted = true
			rl.abortReason = fmt.Sprintf("target locked out %d times — likely permanent or heavily rate-limited", rl.lockoutCount)
			return &LockoutError{
				Permanent: true,
				Message:   rl.abortReason,
			}
		}

		// Exponential backoff on the base delay
		rl.currentDelay = time.Duration(float64(rl.currentDelay) * rl.BackoffFactor)
		if rl.currentDelay > rl.MaxDelay {
			rl.currentDelay = rl.MaxDelay
		}

		// Pause for lockout recovery
		return &LockoutError{
			Permanent: false,
			Message:   fmt.Sprintf("lockout #%d detected, pausing %s", rl.lockoutCount, rl.LockoutPause),
			WaitTime:  rl.LockoutPause,
		}
	}

	return nil
}

// HandleLockout pauses for the lockout duration. Call this when RecordFailure returns a LockoutError.
func (rl *RateLimiter) HandleLockout(err *LockoutError) {
	if err == nil || err.Permanent {
		return
	}
	// Log the pause
	fmt.Printf("    Rate limited — waiting %s for lockout to clear...\n", err.WaitTime)

	// Wait with exponential increase for subsequent lockouts
	wait := err.WaitTime * time.Duration(math.Pow(float64(rl.lockoutCount), 1.5))
	if wait > 10*time.Minute {
		wait = 10 * time.Minute
	}
	time.Sleep(wait)

	// Reset consecutive failures after pause
	rl.mu.Lock()
	rl.consecFails = 0
	rl.mu.Unlock()
}

// Stats returns current rate limiter statistics.
func (rl *RateLimiter) Stats() (attempts int, lockouts int, currentDelay time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.totalAttempts, rl.lockoutCount, rl.currentDelay
}

// IsAborted returns true if the rate limiter has given up.
func (rl *RateLimiter) IsAborted() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.aborted
}

// DetectLockoutSignal checks common lockout indicators in tool output.
func DetectLockoutSignal(output string) bool {
	lockoutPatterns := []string{
		"WARNING: Detected AP rate limiting",   // reaver
		"WPS transaction failed",               // reaver
		"Receive timeout occurred",             // reaver
		"AP has locked its WPS state",          // reaver
		"WARNING: AP appears to be locked",     // reaver
		"rate limit",                           // generic
		"too many attempts",                    // generic portal
		"temporarily blocked",                  // generic portal
		"try again later",                      // generic portal
		"account locked",                       // generic portal
		"EAPOL timeout",                        // wpa_supplicant
		"Authentication timed out",             // wpa_supplicant
	}
	lower := strings.ToLower(output)
	for _, p := range lockoutPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
