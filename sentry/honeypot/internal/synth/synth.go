// Package synth generates the responses a retired endpoint returns.
//
// A bank returning fabricated financial data is a fair thing to be challenged
// on. Two of the four guardrails that make it defensible live here and are
// enforced by construction rather than by policy:
//
//   - Synthetic and non-resolvable. Account numbers come from a reserved range
//     that maps to no real customer. This package has no database handle to any
//     customer system; it cannot emit a real value because it cannot read one.
//   - Watermarked. Every response carries a token recorded with the probe, so a
//     fabricated account number appearing in a leak is traceable to the exact
//     interaction that produced it.
//
// The other two — activation only in phase D, and the recorded legal sign-off —
// are enforced in the routes package, which refuses to serve a route that has
// not earned them.
package synth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ReservedPrefix marks every generated account number. The range is reserved and
// maps to no real customer record.
const ReservedPrefix = "9999"

var fictionalNames = []string{
	"A. Placeholder", "B. Fictitious", "C. Notional", "D. Sample",
	"E. Illustrative", "F. Nominal", "G. Hypothetical", "H. Specimen",
}

var currencies = []string{"INR", "USD", "EUR", "GBP"}

// Watermark returns a token unique to one response.
func Watermark() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("wm_%d", time.Now().UnixNano())
	}
	return "wm_" + hex.EncodeToString(b)
}

func randInt(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

// AccountNumber returns a number inside the reserved range.
//
// The prefix is not decorative: it is what lets an investigator tell a
// honeypot-emitted number from a real one at a glance, and what guarantees the
// value resolves to nothing in any downstream system.
func AccountNumber() string {
	return fmt.Sprintf("%s%08d", ReservedPrefix, randInt(100_000_000))
}

// Response builds a plausible body for a retired endpoint.
//
// The shape follows the schema observed before retirement, so the response is
// structurally indistinguishable from what the endpoint used to return. Only the
// values are fabricated.
func Response(path string, schema []string, watermark string) map[string]any {
	body := map[string]any{}

	if len(schema) > 0 {
		for _, field := range schema {
			body[field] = valueFor(field)
		}
	} else {
		// No captured schema: fall back to a generic account-shaped body rather
		// than returning something obviously empty, which would tell a prober
		// they had found a trap.
		body["accountNumber"] = AccountNumber()
		body["balance"] = fmt.Sprintf("%d.%02d", randInt(500_000), randInt(100))
		body["currency"] = currencies[randInt(int64(len(currencies)))]
		body["accountHolder"] = fictionalNames[randInt(int64(len(fictionalNames)))]
		body["asOf"] = time.Now().UTC().Format(time.RFC3339)
	}

	// The watermark rides in a field that reads as ordinary metadata.
	body["traceId"] = watermark
	return body
}

// dateHints are matched as suffixes or whole tokens, never as substrings.
//
// Substring matching gets this wrong in the way that matters most: "status"
// contains "at", so a naive Contains check returns a timestamp for a status
// field. A response carrying "status": "2026-07-28T14:01:03Z" is exactly the
// tell that shows a prober they have found a trap, which defeats the point of
// generating a plausible body at all.
var dateHints = []string{"date", "time", "timestamp", "asof", "since", "expiry", "dob"}

func looksLikeDate(f string) bool {
	for _, h := range dateHints {
		if f == h || strings.HasSuffix(f, h) || strings.HasPrefix(f, h) {
			return true
		}
	}
	// "createdAt", "updatedAt", "postedAt" — an "at" suffix, not an "at" anywhere.
	return strings.HasSuffix(f, "at") && len(f) > 2
}

func valueFor(field string) any {
	f := strings.ToLower(field)
	switch {
	// Most specific first: a field can satisfy several of these.
	case strings.Contains(f, "status"), strings.Contains(f, "state"):
		return "ACTIVE"
	case strings.Contains(f, "currency"), strings.Contains(f, "ccy"):
		return currencies[randInt(int64(len(currencies)))]
	case strings.Contains(f, "account"), strings.Contains(f, "acct"):
		return AccountNumber()
	case strings.Contains(f, "balance"), strings.Contains(f, "amount"),
		strings.Contains(f, "amt"):
		return fmt.Sprintf("%d.%02d", randInt(500_000), randInt(100))
	case strings.Contains(f, "name"), strings.Contains(f, "holder"):
		return fictionalNames[randInt(int64(len(fictionalNames)))]
	case looksLikeDate(f):
		return time.Now().UTC().Format(time.RFC3339)
	case strings.Contains(f, "count"), strings.Contains(f, "qty"):
		return randInt(1000)
	case strings.HasSuffix(f, "id"), strings.Contains(f, "ref"):
		return fmt.Sprintf("REF%09d", randInt(1_000_000_000))
	default:
		return fmt.Sprintf("SYN%06d", randInt(1_000_000))
	}
}

// IsSynthetic reports whether a value came from this package.
//
// Used by the verification run to prove no honeypot response ever carried a
// value outside the reserved range.
func IsSynthetic(accountNumber string) bool {
	return strings.HasPrefix(accountNumber, ReservedPrefix)
}
