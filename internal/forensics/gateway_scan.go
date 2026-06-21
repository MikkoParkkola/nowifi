// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package forensics

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Section 8b — gateway attack surface.
//
// The single highest-value finding in the shell collector's 8b is an exposed
// Kong admin API: if :8001 / :8444 answer, the captive gateway's control plane
// is open and a permissive route can be added to bypass enforcement outright.
// That probe is pure-Go and always runs (two short HTTP GETs).
//
// The heavier nmap service/version sweep is opt-in (Options.RunNmap): nmap -sV
// can take ~90s and would blow the forensics time cap for an offline user who
// needs a package fast. It degrades gracefully when nmap is absent.

const (
	kongProbeTimeout = 5 * time.Second
	nmapTimeout      = 90 * time.Second
)

// kongAdminPorts are the Kong gateway control-plane ports.
var kongAdminPorts = []int{8001, 8444}

// KongProbe is the result of probing one Kong admin port.
type KongProbe struct {
	Port       int  `json:"port"`
	StatusCode int  `json:"status_code"`
	Exposed    bool `json:"exposed"`
}

// probeKongAdmin checks whether the gateway exposes the Kong admin API. A 200
// on :8001 / :8444 means full gateway control. Read-only GETs only.
func probeKongAdmin(client *http.Client, gwIP string) []KongProbe {
	if gwIP == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: kongProbeTimeout}
	}
	out := make([]KongProbe, 0, len(kongAdminPorts))
	for _, port := range kongAdminPorts {
		scheme := "http"
		if port == 8444 {
			scheme = "https"
		}
		kp := KongProbe{Port: port}
		ctx, cancel := context.WithTimeout(context.Background(), kongProbeTimeout)
		url := fmt.Sprintf("%s://%s:%d/", scheme, gwIP, port)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			out = append(out, kp)
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			kp.StatusCode = resp.StatusCode
			kp.Exposed = resp.StatusCode == 200
			resp.Body.Close()
		}
		cancel()
		out = append(out, kp)
	}
	return out
}

// runNmapGateway runs a bounded nmap service/version sweep of the gateway when
// nmap is installed. Returns ("", nil) with a caller-recorded limitation when
// nmap is absent. Best-effort: a non-zero nmap exit still returns whatever it
// printed.
func runNmapGateway(gwIP string) (string, bool) {
	if gwIP == "" {
		return "", false
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), nmapTimeout+10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nmap",
		"-Pn", "-n", "-T4", "--host-timeout", "80s",
		"-p", "22,53,67,80,123,443,3128,5353,8000,8001,8080,8443,8444,9000",
		"-sV", gwIP)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run() // best-effort: capture output regardless of exit code
	return strings.TrimSpace(buf.String()), true
}
