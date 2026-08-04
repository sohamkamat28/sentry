package ship

import (
	"reflect"
	"testing"

	"github.com/sentry/agent/internal/config"
)

func shipper() *Shipper {
	return &Shipper{cfg: &config.Config{QueueMB: 1, BatchSize: 100}}
}

func TestBodyContinuationMergesIntoItsHeader(t *testing.T) {
	// HTTP framing does not follow SSL_write boundaries: a server writes headers
	// and body separately, so the classes found in a response body arrive as a
	// distinct kernel event. Without this merge the body was dropped outright and
	// CDRI's data-exposure weight had no input at all.
	s := shipper()
	s.Enqueue(Observation{ConnKey: 0xAA, Status: 200, WallUnixNS: 1})
	s.Enqueue(Observation{ConnKey: 0xAA, Continuation: true,
		DataClasses: []string{"AADHAAR", "PAN"}})

	if len(s.pending) != 1 {
		t.Fatalf("continuation should merge, not append: %d pending", len(s.pending))
	}
	if !reflect.DeepEqual(s.pending[0].DataClasses, []string{"AADHAAR", "PAN"}) {
		t.Errorf("classes = %v", s.pending[0].DataClasses)
	}
	if s.Merged() != 1 {
		t.Errorf("merged = %d, want 1", s.Merged())
	}
}

func TestContinuationMatchesOnlyItsOwnConnection(t *testing.T) {
	s := shipper()
	s.Enqueue(Observation{ConnKey: 0xAA, Status: 200})
	s.Enqueue(Observation{ConnKey: 0xBB, Status: 200})
	s.Enqueue(Observation{ConnKey: 0xAA, Continuation: true, DataClasses: []string{"PAN"}})

	if got := s.pending[0].DataClasses; !reflect.DeepEqual(got, []string{"PAN"}) {
		t.Errorf("conn AA classes = %v", got)
	}
	if got := s.pending[1].DataClasses; len(got) != 0 {
		t.Errorf("conn BB should be untouched, got %v", got)
	}
}

func TestOrphanedContinuationIsKeptNotDiscarded(t *testing.T) {
	// If the header already shipped, dropping the classes would lose the
	// finding. It goes as its own record instead and correlates downstream.
	s := shipper()
	s.Enqueue(Observation{ConnKey: 0xCC, Continuation: true, DataClasses: []string{"CARD"}})

	if len(s.pending) != 1 {
		t.Fatalf("orphaned continuation should still be queued")
	}
	if s.Orphaned() != 1 {
		t.Errorf("orphaned = %d, want 1", s.Orphaned())
	}
}

func TestMergeDeduplicatesClasses(t *testing.T) {
	s := shipper()
	s.Enqueue(Observation{ConnKey: 0xDD, Status: 200, DataClasses: []string{"AADHAAR"}})
	s.Enqueue(Observation{ConnKey: 0xDD, Continuation: true,
		DataClasses: []string{"AADHAAR", "PAN"}})

	if got := s.pending[0].DataClasses; !reflect.DeepEqual(got, []string{"AADHAAR", "PAN"}) {
		t.Errorf("classes = %v, want deduplicated union", got)
	}
}

func TestContinuationNeverCarriesBodyBytesOnTheWire(t *testing.T) {
	// The body is scanned in kernel and discarded there. A continuation exists to
	// carry a class mask and nothing else.
	typ := reflect.TypeOf(Observation{})
	for _, name := range []string{"ConnKey", "Continuation"} {
		f, ok := typ.FieldByName(name)
		if !ok {
			t.Fatalf("field %s missing", name)
		}
		if f.Tag.Get("json") != "-" {
			t.Errorf("%s must not be serialised; tag is %q", name, f.Tag.Get("json"))
		}
	}
}

func TestResponseMergesIntoItsRequest(t *testing.T) {
	// One observation per exchange. Separate rows leave the response — which is
	// what carries the body's data classes — with no method, no path and so no
	// endpoint identity for correlation to attach them to.
	s := shipper()
	s.Enqueue(Observation{ConnKey: 0x11, Method: "GET", PathRaw: "/api/v1/kyc/9902"})
	s.Enqueue(Observation{ConnKey: 0x11, Status: 200, RespBytes: 113,
		DataClasses: []string{"PAN", "AADHAAR"}})

	if len(s.pending) != 1 {
		t.Fatalf("response should merge into its request: %d pending", len(s.pending))
	}
	got := s.pending[0]
	if got.Method != "GET" || got.Status != 200 {
		t.Errorf("merged row = %s status %d", got.Method, got.Status)
	}
	if len(got.DataClasses) != 2 {
		t.Errorf("classes = %v", got.DataClasses)
	}
}

func TestResponseWithoutAMatchingRequestIsStillKept(t *testing.T) {
	s := shipper()
	s.Enqueue(Observation{ConnKey: 0x99, Status: 500})
	if len(s.pending) != 1 {
		t.Error("an unmatched response must not be discarded")
	}
}
