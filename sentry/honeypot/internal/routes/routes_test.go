package routes

import (
	"encoding/json"
	"log/slog"
	"testing"
)

func table(signed bool, routes map[string]Route) *Table {
	return &Table{
		log:    slog.Default(),
		routes: routes,
		signed: signed,
	}
}

func TestNoRouteIsServedWithoutLegalSignOff(t *testing.T) {
	// The guardrail as a refusal: an institution that has not signed off gets a
	// working decommission with 410 and no honeypot.
	tbl := table(false, map[string]Route{
		"GET /api/v1/legacy-balance": {EndpointID: "ep_1", Method: "GET"},
	})

	if _, ok := tbl.Lookup("GET", "/api/v1/legacy-balance"); ok {
		t.Error("route served despite no legal sign-off")
	}
}

func TestSignedTableServesItsRoutes(t *testing.T) {
	tbl := table(true, map[string]Route{
		"GET /api/v1/legacy-balance": {EndpointID: "ep_1", Method: "GET",
			PathRaw: "/api/v1/legacy-balance"},
	})

	r, ok := tbl.Lookup("GET", "/api/v1/legacy-balance")
	if !ok {
		t.Fatal("signed table did not serve a loaded route")
	}
	if r.EndpointID != "ep_1" {
		t.Errorf("endpoint id = %q", r.EndpointID)
	}
}

func TestUnknownPathIsNotAnswered(t *testing.T) {
	// The honeypot answers only for what it was explicitly given. Answering
	// broadly would make it a wildcard responder rather than a trap.
	tbl := table(true, map[string]Route{
		"GET /api/v1/legacy-balance": {EndpointID: "ep_1"},
	})

	if _, ok := tbl.Lookup("GET", "/api/v1/something-else"); ok {
		t.Error("honeypot answered for a path it was never given")
	}
}

func TestMethodIsPartOfTheMatch(t *testing.T) {
	tbl := table(true, map[string]Route{
		"GET /api/v1/legacy-balance": {EndpointID: "ep_1"},
	})
	if _, ok := tbl.Lookup("POST", "/api/v1/legacy-balance"); ok {
		t.Error("POST matched a GET-only route")
	}
}

func TestLookupIsCaseInsensitiveOnMethod(t *testing.T) {
	tbl := table(true, map[string]Route{
		"GET /x": {EndpointID: "ep_1"},
	})
	if _, ok := tbl.Lookup("get", "/x"); !ok {
		t.Error("lowercase method should match")
	}
}

func TestSchemaIsReadFromTheCapturedFingerprint(t *testing.T) {
	features, _ := json.Marshal(map[string]any{
		"response_fields": []string{"accountNumber", "balance"},
	})
	got := schemaFrom(features)
	if len(got) != 2 || got[0] != "accountNumber" {
		t.Errorf("schema = %v", got)
	}
}

func TestMissingFingerprintYieldsNoSchemaRatherThanAnError(t *testing.T) {
	if got := schemaFrom(nil); got != nil {
		t.Errorf("expected nil schema, got %v", got)
	}
	if got := schemaFrom([]byte("not json")); got != nil {
		t.Errorf("expected nil schema on malformed features, got %v", got)
	}
}
