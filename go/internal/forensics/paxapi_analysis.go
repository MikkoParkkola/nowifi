// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package forensics

import (
	"encoding/json"
	"sort"
	"strings"
)

// PaxAPIAnalysis is the recon verdict over the captured pax-api control-plane
// endpoints. Its central job is to answer the question the 2026-05-29 flight
// raised: are the Panasonic "/pax-api-service/*" 200s a REAL enforcement API
// (an attack surface worth a quota/session reset), versus just the
// single-page-app returning index.html for every unknown route (no API
// surface at all)?
//
// It is pure analysis over already-captured responses — no network — so it is
// fully deterministic and testable from fixtures.
type PaxAPIAnalysis struct {
	// IsRealAPI is true when at least one endpoint behaves like a real API
	// (JSON body / an OpenAPI doc / an auth-gated 401/403) rather than the
	// SPA HTML fallback.
	IsRealAPI bool `json:"is_real_api"`
	// SwaggerIsOpenAPI is true when swagger.json parsed as a genuine OpenAPI /
	// Swagger document (not the SPA HTML).
	SwaggerIsOpenAPI bool `json:"swagger_is_openapi"`
	// EndpointKinds classifies each captured endpoint.
	EndpointKinds []EndpointKind `json:"endpoint_kinds"`
	// EnforcementOps lists "METHOD path" operations from a real swagger doc
	// that touch the device / session / quota / plan surface.
	EnforcementOps []string `json:"enforcement_ops,omitempty"`
	// CandidateResetVectors lists mutating operations (POST/PUT/PATCH/DELETE)
	// on the enforcement surface — the places a quota/session reset would be
	// attempted next (NOT attempted here; recon only).
	CandidateResetVectors []string `json:"candidate_reset_vectors,omitempty"`
	// Notes carries the human-readable verdict + caveats.
	Notes []string `json:"notes,omitempty"`
}

// EndpointKind is the classification of one captured pax-api response.
type EndpointKind struct {
	Path string `json:"path"`
	// Kind is one of: openapi-json, json-api, auth-gated, html-spa, error,
	// error-status, empty, other.
	Kind string `json:"kind"`
}

// enforcementMarkers are the path substrings that matter for a quota/session
// reset bypass on Panasonic-style portals.
var enforcementMarkers = []string{"device", "session", "quota", "plan"}

// mutatingMethods are HTTP methods that could change enforcement state.
var mutatingMethods = map[string]bool{
	"post": true, "put": true, "patch": true, "delete": true,
}

// AnalyzePaxAPI classifies the captured endpoints and derives the recon
// verdict. Returns nil when there is nothing to analyze.
func AnalyzePaxAPI(eps []PaxEndpoint) *PaxAPIAnalysis {
	if len(eps) == 0 {
		return nil
	}
	a := &PaxAPIAnalysis{}
	for _, ep := range eps {
		kind := classifyEndpoint(ep)
		a.EndpointKinds = append(a.EndpointKinds, EndpointKind{Path: ep.Path, Kind: kind})
		switch kind {
		case "json-api", "auth-gated":
			a.IsRealAPI = true
		case "openapi-json":
			a.IsRealAPI = true
			a.SwaggerIsOpenAPI = true
			ops, resets := extractSwaggerOps(ep.Body)
			a.EnforcementOps = append(a.EnforcementOps, ops...)
			a.CandidateResetVectors = append(a.CandidateResetVectors, resets...)
		}
	}
	sort.Strings(a.EnforcementOps)
	sort.Strings(a.CandidateResetVectors)
	a.Notes = verdictNotes(a)
	return a
}

// classifyEndpoint decides what a single captured response actually is.
func classifyEndpoint(ep PaxEndpoint) string {
	if ep.Error != "" {
		return "error"
	}
	if ep.StatusCode == 401 || ep.StatusCode == 403 {
		// An auth challenge is a strong signal of a REAL protected API.
		return "auth-gated"
	}
	body := strings.TrimSpace(ep.Body)
	if ep.StatusCode == 0 && body == "" {
		return "empty"
	}
	ct := strings.ToLower(ep.ContentType)
	isSwagger := strings.HasSuffix(ep.Path, "swagger.json")
	if isSwagger && looksLikeOpenAPI(body) {
		return "openapi-json"
	}
	if strings.HasPrefix(body, "<") || strings.Contains(ct, "text/html") {
		return "html-spa"
	}
	if strings.Contains(ct, "json") || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		return "json-api"
	}
	if ep.StatusCode >= 400 {
		return "error-status"
	}
	if body == "" {
		return "empty"
	}
	return "other"
}

// looksLikeOpenAPI reports whether a body is a genuine OpenAPI / Swagger doc.
func looksLikeOpenAPI(body string) bool {
	var doc struct {
		OpenAPI string `json:"openapi"`
		Swagger string `json:"swagger"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return false
	}
	return doc.OpenAPI != "" || doc.Swagger != ""
}

// extractSwaggerOps pulls "METHOD path" operations from a real swagger doc that
// touch the enforcement surface, and the mutating subset as reset candidates.
func extractSwaggerOps(body string) (ops, resets []string) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil, nil
	}
	for path, methods := range doc.Paths {
		if !hasEnforcementMarker(path) {
			continue
		}
		for method := range methods {
			m := strings.ToLower(method)
			if m == "parameters" { // shared params object, not a verb
				continue
			}
			op := strings.ToUpper(m) + " " + path
			ops = append(ops, op)
			if mutatingMethods[m] {
				resets = append(resets, op)
			}
		}
	}
	return ops, resets
}

func hasEnforcementMarker(path string) bool {
	lp := strings.ToLower(path)
	for _, m := range enforcementMarkers {
		if strings.Contains(lp, m) {
			return true
		}
	}
	return false
}

// verdictNotes renders the human-readable conclusion.
func verdictNotes(a *PaxAPIAnalysis) []string {
	var n []string
	switch {
	case a.SwaggerIsOpenAPI:
		n = append(n, "pax-api exposes a REAL OpenAPI spec — a genuine enforcement control plane. Map the device/session/quota operations below for a reset vector.")
		if len(a.CandidateResetVectors) == 0 {
			n = append(n, "No mutating enforcement operations found in swagger — a reset may require an auth token / a non-documented endpoint.")
		}
	case a.IsRealAPI:
		n = append(n, "pax-api responds as a real API (JSON / auth-gated) but swagger.json was not a usable OpenAPI doc — probe the device/session/quota endpoints directly for a client-controllable id.")
	default:
		n = append(n, "pax-api endpoints all returned the SPA HTML fallback — the '200' responses are client-side routing, NOT a real enforcement control plane. A pax-api quota/session reset is NOT a viable vector here; pursue MAC/tunnel techniques instead.")
	}
	return n
}
