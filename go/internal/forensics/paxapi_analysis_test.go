// Copyright (C) 2026 Mikko Parkkola. All rights reserved.
// Licensed under AGPL-3.0. See LICENSE file.

package forensics

import (
	"strings"
	"testing"
)

// htmlSPABody mirrors what the 2026-05-29 Finnair flight actually captured:
// every /pax-api-service/* path returned the single-page-app index.html, not
// a real API response.
const htmlSPABody = `<!DOCTYPE html>
<html lang="en"><head><title>Finnair Nordic Sky</title></head>
<body><div class="loader-container"></div></body></html>`

// realSwaggerBody is a synthetic-but-realistic OpenAPI doc exposing an
// enforcement surface with a mutating reset operation.
const realSwaggerBody = `{
  "openapi": "3.0.1",
  "info": {"title": "pax-api", "version": "1"},
  "paths": {
    "/pax-api-service/device": {"get": {}, "post": {}},
    "/pax-api-service/quota": {"get": {}},
    "/pax-api-service/session": {"delete": {}},
    "/pax-api-service/unrelated": {"get": {}}
  }
}`

func TestAnalyzePaxAPI_SPAFallback_NotViable(t *testing.T) {
	eps := []PaxEndpoint{
		{Path: "/pax-api-service/quota", StatusCode: 200, ContentType: "text/html", Body: htmlSPABody},
		{Path: "/pax-api-service/device", StatusCode: 200, ContentType: "text/html", Body: htmlSPABody},
		{Path: "/pax-api-service/swagger.json", StatusCode: 200, ContentType: "text/html", Body: htmlSPABody},
	}
	a := AnalyzePaxAPI(eps)
	if a == nil {
		t.Fatal("nil analysis")
	}
	if a.IsRealAPI {
		t.Error("HTML-only responses must NOT be classified as a real API")
	}
	if a.SwaggerIsOpenAPI {
		t.Error("HTML swagger.json must not be treated as OpenAPI")
	}
	if len(a.CandidateResetVectors) != 0 {
		t.Errorf("no reset vectors expected for SPA fallback, got %v", a.CandidateResetVectors)
	}
	joined := strings.Join(a.Notes, " ")
	if !strings.Contains(joined, "SPA HTML fallback") || !strings.Contains(joined, "NOT a viable vector") {
		t.Errorf("verdict should declare the SPA fallback non-viable, got: %s", joined)
	}
	for _, k := range a.EndpointKinds {
		if k.Kind != "html-spa" {
			t.Errorf("%s classified as %s, want html-spa", k.Path, k.Kind)
		}
	}
}

func TestAnalyzePaxAPI_RealSwagger_FindsResetVectors(t *testing.T) {
	eps := []PaxEndpoint{
		{Path: "/pax-api-service/swagger.json", StatusCode: 200, ContentType: "application/json", Body: realSwaggerBody},
		{Path: "/pax-api-service/quota", StatusCode: 200, ContentType: "application/json", Body: `{"remaining":0}`},
	}
	a := AnalyzePaxAPI(eps)
	if !a.IsRealAPI || !a.SwaggerIsOpenAPI {
		t.Fatalf("expected real OpenAPI; got IsRealAPI=%v Swagger=%v", a.IsRealAPI, a.SwaggerIsOpenAPI)
	}
	// POST /device and DELETE /session are mutating enforcement ops.
	want := map[string]bool{
		"POST /pax-api-service/device":      false,
		"DELETE /pax-api-service/session":   false,
		"GET /pax-api-service/quota":        false,
		"GET /pax-api-service/device":       false,
		"DELETE /pax-api-service/unrelated": false, // must be EXCLUDED (no marker)
	}
	for _, op := range a.EnforcementOps {
		if _, ok := want[op]; ok {
			want[op] = true
		}
	}
	if !want["POST /pax-api-service/device"] || !want["DELETE /pax-api-service/session"] {
		t.Errorf("missing enforcement ops; got %v", a.EnforcementOps)
	}
	// The /unrelated path has no enforcement marker → never an op.
	for _, op := range a.EnforcementOps {
		if strings.Contains(op, "unrelated") {
			t.Errorf("non-enforcement path leaked into ops: %s", op)
		}
	}
	resets := strings.Join(a.CandidateResetVectors, " ")
	if !strings.Contains(resets, "POST /pax-api-service/device") || !strings.Contains(resets, "DELETE /pax-api-service/session") {
		t.Errorf("expected mutating ops as reset vectors, got %v", a.CandidateResetVectors)
	}
	if strings.Contains(resets, "GET ") {
		t.Errorf("GET must not be a reset vector: %v", a.CandidateResetVectors)
	}
}

func TestAnalyzePaxAPI_AuthGatedIsReal(t *testing.T) {
	eps := []PaxEndpoint{
		{Path: "/pax-api-service/device", StatusCode: 403, ContentType: "application/json", Body: `{"error":"forbidden"}`},
		{Path: "/pax-api-service/swagger.json", StatusCode: 404, ContentType: "text/html", Body: htmlSPABody},
	}
	a := AnalyzePaxAPI(eps)
	if !a.IsRealAPI {
		t.Error("a 401/403 challenge is a real protected API and must set IsRealAPI")
	}
	if a.SwaggerIsOpenAPI {
		t.Error("404 HTML swagger must not be OpenAPI")
	}
}

func TestClassifyEndpoint(t *testing.T) {
	cases := []struct {
		ep   PaxEndpoint
		want string
	}{
		{PaxEndpoint{Path: "/x", Error: "timeout"}, "error"},
		{PaxEndpoint{Path: "/x", StatusCode: 401}, "auth-gated"},
		{PaxEndpoint{Path: "/x", StatusCode: 200, ContentType: "text/html", Body: "<html>"}, "html-spa"},
		{PaxEndpoint{Path: "/x", StatusCode: 200, ContentType: "application/json", Body: `{"a":1}`}, "json-api"},
		{PaxEndpoint{Path: "/x/swagger.json", StatusCode: 200, Body: realSwaggerBody}, "openapi-json"},
		{PaxEndpoint{Path: "/x", StatusCode: 500, Body: "boom"}, "error-status"},
		{PaxEndpoint{Path: "/x", StatusCode: 0, Body: ""}, "empty"},
	}
	for _, c := range cases {
		if got := classifyEndpoint(c.ep); got != c.want {
			t.Errorf("classify(%+v)=%q want %q", c.ep, got, c.want)
		}
	}
}

func TestAnalyzePaxAPI_Empty(t *testing.T) {
	if AnalyzePaxAPI(nil) != nil {
		t.Error("nil input should yield nil analysis")
	}
}
