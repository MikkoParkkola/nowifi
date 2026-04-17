// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

// Shared G1 authorization guardrail for tunnel providers.
//
// cloudflare_quick.go owns the canonical implementations of:
//   - stdinReader  (package-level io.Reader, test-injectable)
//   - ErrAuthorizationDeclined
//   - auditEntry   (JSON struct)
//   - appendAuditLog(localTarget)  — always tags provider "cloudflare_quick"
//
// This file adds assertAuthorizationFor(provider, localTarget) so that
// providers other than cloudflare_quick can run the same G1 prompt while
// writing their own provider name to the audit log.  It shares stdinReader
// and ErrAuthorizationDeclined from cloudflare_quick.go; it has its own
// audit-write path to support arbitrary provider names.
package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// assertAuthorizationFor prompts the operator for authorization and appends
// an audit log entry tagged with the given provider name.
// It shares stdinReader and ErrAuthorizationDeclined from cloudflare_quick.go.
func assertAuthorizationFor(provider, localTarget string) error {
	fmt.Print("   I confirm I am authorized to test this network. [yes/NO]: ")

	scanner := bufio.NewScanner(stdinReader)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))

	if answer != "yes" {
		return ErrAuthorizationDeclined
	}

	if err := appendAuditLogFor(provider, localTarget); err != nil {
		fmt.Fprintf(os.Stderr, "   warn: could not write audit log: %v\n", err)
	}
	return nil
}

// appendAuditLogFor writes a JSON audit entry with the given provider name.
// The cloudflare_quick.go appendAuditLog() calls this with provider="cloudflare_quick".
func appendAuditLogFor(provider, localTarget string) error {
	dir := nowifiDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create ~/.nowifi: %w", err)
	}

	logPath := filepath.Join(dir, "audit.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit.log: %w", err)
	}
	defer f.Close()

	h := sha256.Sum256([]byte(localTarget))
	// auditEntry type is defined in cloudflare_quick.go and shared here.
	entry := auditEntry{
		TS:       time.Now().UTC().Format(time.RFC3339),
		Event:    "tunnel_auth_asserted",
		Provider: provider,
		Target:   fmt.Sprintf("%x", h),
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	_, err = fmt.Fprintf(f, "%s\n", line)
	return err
}
