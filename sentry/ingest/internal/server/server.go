// Package server exposes the observation intake endpoint.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/sentry/ingest/internal/config"
	"github.com/sentry/ingest/internal/store"
)

type Batch struct {
	AgentID      string              `json:"agent_id"`
	AgentVersion string              `json:"agent_version"`
	Node         string              `json:"node"`
	Items        []store.Observation `json:"items"`
}

type Ack struct {
	Accepted uint64 `json:"accepted"`
	Rejected uint64 `json:"rejected"`
	Reason   string `json:"reason,omitempty"`
}

// Store is the part of the observation store this HTTP surface uses.
//
// An interface rather than the concrete type so the failure paths can be
// exercised. The condition that matters most here — a database that answers but
// has no clock row yet — is a state a real pool will not hold still in, and the
// behaviour it triggers is the difference between redelivering live capture and
// discarding it.
type Store interface {
	Enqueue(ctx context.Context, items []store.Observation) (accepted, rejected int, err error)
	CurrentVday(ctx context.Context) (int32, error)
	Ping(ctx context.Context) error
	Stats() (accepted, rejected, written uint64, queued int)
	ClockErrors() uint64
}

type Server struct {
	cfg     *config.Config
	store   Store
	log     *slog.Logger
	version string
}

func New(cfg *config.Config, st Store, log *slog.Logger, version string) *Server {
	return &Server{cfg: cfg, store: st, log: log, version: version}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/observations", s.postObservations)
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /metrics", s.metrics)
	return mux
}

func (s *Server) postObservations(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)

	var b Batch
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, Ack{Reason: "malformed batch: " + err.Error()})
		return
	}
	if len(b.Items) == 0 {
		writeJSON(w, http.StatusOK, Ack{})
		return
	}

	accepted, rejected, err := s.store.Enqueue(r.Context(), b.Items)
	if err != nil {
		// 503, not 202. The shipper keeps a batch only when the response is an
		// error, so acknowledging one this store could not take would discard
		// live capture permanently for a condition that clears on its own.
		writeJSON(w, http.StatusServiceUnavailable, Ack{
			Reason: "batch not taken: " + err.Error(),
		})
		return
	}

	// A partial accept is reported honestly: the agent needs to know how many of
	// its observations survived, not just that the request succeeded.
	writeJSON(w, http.StatusAccepted, Ack{
		Accepted: uint64(accepted),
		Rejected: uint64(rejected),
	})
}

// healthz never touches a dependency. Conflating it with readiness causes
// restart loops when the database is merely slow.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.version})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 3*time.Second)
	defer cancel()

	checks := map[string]string{"postgres": "ok", "vclock": "ok"}
	code := http.StatusOK
	if err := s.store.Ping(ctx); err != nil {
		checks["postgres"] = "unreachable: " + err.Error()
		code = http.StatusServiceUnavailable
	} else if _, err := s.store.CurrentVday(ctx); err != nil {
		// Reachable but unusable. Every observation carries a vday, so a store
		// that cannot read the clock can accept nothing — reporting it ready
		// would put a service that discards all input behind a green check.
		checks["vclock"] = "unreadable: " + err.Error()
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"ready": code == http.StatusOK, "checks": checks})
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	accepted, rejected, written, queued := s.store.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintf(w, "# HELP sentry_observations_accepted_total Observations accepted from agents.\n")
	fmt.Fprintf(w, "# TYPE sentry_observations_accepted_total counter\n")
	fmt.Fprintf(w, "sentry_observations_accepted_total %d\n", accepted)

	// Rejections are exported rather than swallowed: a rising count is the
	// signal that the estate is being undercounted.
	fmt.Fprintf(w, "# HELP sentry_observations_rejected_total Observations dropped as invalid or over queue.\n")
	fmt.Fprintf(w, "# TYPE sentry_observations_rejected_total counter\n")
	fmt.Fprintf(w, "sentry_observations_rejected_total %d\n", rejected)

	fmt.Fprintf(w, "# HELP sentry_observations_written_total Observations written to Postgres.\n")
	fmt.Fprintf(w, "# TYPE sentry_observations_written_total counter\n")
	fmt.Fprintf(w, "sentry_observations_written_total %d\n", written)

	// Nonzero here means observations are being handed back, not stored. It is
	// the difference between an estate that is quiet and one that is unrecorded.
	fmt.Fprintf(w, "# HELP sentry_ingest_clock_errors_total Batches refused because the virtual clock was unreadable.\n")
	fmt.Fprintf(w, "# TYPE sentry_ingest_clock_errors_total counter\n")
	fmt.Fprintf(w, "sentry_ingest_clock_errors_total %d\n", s.store.ClockErrors())

	fmt.Fprintf(w, "# HELP sentry_ingest_queue_depth Rows buffered awaiting COPY.\n")
	fmt.Fprintf(w, "# TYPE sentry_ingest_queue_depth gauge\n")
	fmt.Fprintf(w, "sentry_ingest_queue_depth %d\n", queued)
}

// contextWithTimeout bounds a readiness probe so a hung database cannot hold the
// handler open past the orchestrator's own probe timeout.
func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
