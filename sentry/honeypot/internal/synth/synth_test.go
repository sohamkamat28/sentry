package synth

import (
	"strings"
	"testing"
	"time"
)

func TestEveryGeneratedAccountNumberIsInTheReservedRange(t *testing.T) {
	// The guardrail that makes fabricated financial data defensible: nothing
	// returned corresponds to a real customer, by construction.
	for i := 0; i < 10_000; i++ {
		n := AccountNumber()
		if !IsSynthetic(n) {
			t.Fatalf("account number %q is outside the reserved range", n)
		}
		if len(n) != len(ReservedPrefix)+8 {
			t.Fatalf("account number %q has unexpected length", n)
		}
	}
}

func TestWatermarksAreUniquePerResponse(t *testing.T) {
	// A repeated watermark would break leak attribution: two interactions would
	// be indistinguishable in an investigation.
	seen := make(map[string]bool, 5000)
	for i := 0; i < 5000; i++ {
		w := Watermark()
		if seen[w] {
			t.Fatalf("watermark %q issued twice", w)
		}
		seen[w] = true
	}
}

func TestWatermarkIsRecoverableFromTheBody(t *testing.T) {
	w := Watermark()
	body := Response("/api/v1/legacy-balance", nil, w)
	if body["traceId"] != w {
		t.Errorf("watermark not present in body: got %v", body["traceId"])
	}
}

func TestResponseFollowsTheCapturedSchema(t *testing.T) {
	// The response must be structurally indistinguishable from what the endpoint
	// returned before retirement, or a prober learns they found a trap.
	schema := []string{"accountNumber", "balance", "currency", "asOf"}
	body := Response("/x", schema, Watermark())

	for _, f := range schema {
		if _, ok := body[f]; !ok {
			t.Errorf("field %q missing from response", f)
		}
	}
}

func TestAccountShapedFieldsGetReservedNumbers(t *testing.T) {
	for _, field := range []string{"accountNumber", "acctNo", "beneficiaryAccount"} {
		v, ok := valueFor(field).(string)
		if !ok || !IsSynthetic(v) {
			t.Errorf("field %q produced %v, expected a reserved-range number", field, v)
		}
	}
}

func TestFallbackBodyIsStillFullySynthetic(t *testing.T) {
	body := Response("/unknown", nil, Watermark())
	acct, _ := body["accountNumber"].(string)
	if !IsSynthetic(acct) {
		t.Errorf("fallback body emitted %q, outside the reserved range", acct)
	}
	name, _ := body["accountHolder"].(string)
	if !strings.Contains(name, ".") {
		t.Errorf("account holder %q does not look like the fictional list", name)
	}
}

func TestPackageHasNoRouteToCustomerData(t *testing.T) {
	// This is asserted structurally elsewhere (the package imports nothing that
	// could reach a database); the test documents the intent so a future import
	// is a visible decision rather than an accident.
	body := Response("/x", []string{"accountNumber"}, Watermark())
	acct := body["accountNumber"].(string)
	if !strings.HasPrefix(acct, ReservedPrefix) {
		t.Fatal("synthetic generator produced a value outside the reserved range")
	}
}

func TestFieldHeuristicsDoNotCollide(t *testing.T) {
	// A response that returns a timestamp for "status" tells a prober they have
	// found a trap. Substring matching produced exactly that, because "status"
	// contains "at".
	cases := map[string]func(any) bool{
		"status":      func(v any) bool { return v == "ACTIVE" },
		"statusCode":  func(v any) bool { return v == "ACTIVE" },
		"asOf":        isRFC3339,
		"createdAt":   isRFC3339,
		"updatedDate": isRFC3339,
		"accountNo":   func(v any) bool { s, _ := v.(string); return IsSynthetic(s) },
		"currency":    func(v any) bool { s, _ := v.(string); return len(s) == 3 },
	}
	for field, ok := range cases {
		if got := valueFor(field); !ok(got) {
			t.Errorf("valueFor(%q) = %v — wrong shape for that field name", field, got)
		}
	}
}

func isRFC3339(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}
