package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentry/ingest/internal/config"
	"github.com/sentry/ingest/internal/store"
)

// noClockStore stands in for a database that is reachable but whose vclock row
// has not been seeded yet — the real state the platform passes through on every
// cold start, and the one that silently discarded live capture.
type noClockStore struct{ refused uint64 }

var errNoClock = errors.New("no rows in result set")

func (s *noClockStore) Enqueue(context.Context, []store.Observation) (int, int, error) {
	s.refused++
	return 0, 0, errNoClock
}
func (s *noClockStore) CurrentVday(context.Context) (int32, error) { return 0, errNoClock }
func (s *noClockStore) Ping(context.Context) error                { return nil }
func (s *noClockStore) Stats() (uint64, uint64, uint64, int)      { return 0, 0, 0, 0 }
func (s *noClockStore) ClockErrors() uint64                       { return s.refused }

func unusableStore() *noClockStore { return &noClockStore{} }

func post(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/observations", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

const oneObservation = `{"agent_id":"a","items":[
  {"wall_unix_ns":1785000000000000000,"method":"GET","path_raw":"/x","host":"h","status":200}
]}`

// The shipper keeps a batch only when the response is an error. Acknowledging
// one the store could not take discards live capture permanently, for a
// condition that clears as soon as the platform finishes bootstrapping.
func TestABatchTheStoreCannotTakeIsRefusedNotAcknowledged(t *testing.T) {
	s := New(&config.Config{MaxBodyBytes: 1 << 20}, unusableStore(), slog.Default(), "test")

	rec := post(t, s, oneObservation)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 so the agent redelivers", rec.Code)
	}
	var ack Ack
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Accepted != 0 || ack.Reason == "" {
		t.Errorf("ack = %+v, want zero accepted and a stated reason", ack)
	}
}

func TestReadinessFailsWhenTheClockIsUnreadable(t *testing.T) {
	s := New(&config.Config{MaxBodyBytes: 1 << 20}, unusableStore(), slog.Default(), "test")

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	// Reachable but unable to accept anything. Reporting ready would put a
	// service that discards all input behind a green check.
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "vclock") {
		t.Errorf("body = %s, want the failing check named", rec.Body.String())
	}
}

func TestAnEmptyBatchIsAcknowledged(t *testing.T) {
	s := New(&config.Config{MaxBodyBytes: 1 << 20}, unusableStore(), slog.Default(), "test")

	rec := post(t, s, `{"agent_id":"a","items":[]}`)

	// Nothing to store, so nothing to refuse. This must not be conflated with
	// the case above, or an idle agent would look like a broken one.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
