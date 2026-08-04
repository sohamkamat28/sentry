// Package store writes observations to Postgres.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentry/ingest/internal/config"
)

// Observation mirrors the agent's wire record.
//
// No body or payload field, matching the agent and the database. The privacy
// property holds because there is nowhere in this path capable of carrying a
// payload, not because a policy forbids it.
type Observation struct {
	WallUnixNS  int64    `json:"wall_unix_ns"`
	Method      string   `json:"method"`
	PathRaw     string   `json:"path_raw"`
	Host        string   `json:"host"`
	Port        uint32   `json:"port"`
	Status      uint32   `json:"status"`
	LatencyUS   uint32   `json:"latency_us"`
	ReqBytes    uint32   `json:"req_bytes"`
	RespBytes   uint32   `json:"resp_bytes"`
	AuthPresent bool     `json:"auth_present"`
	AuthScheme  string   `json:"auth_scheme"`
	TLSVersion  string   `json:"tls_version"`
	DataClasses []string `json:"data_classes"`
	// Names of the JSON keys in the response body. Schema, never content —
	// the same guarantee data_classes carries, for the same reason.
	ResponseFields []string `json:"response_fields"`
	PeerService    string   `json:"peer_service"`
	PeerIP         string   `json:"peer_ip"`
	PID            uint32   `json:"pid"`
	CgroupID       uint64   `json:"cgroup_id"`
	Direction      string   `json:"direction"`
	Synthetic      bool     `json:"synthetic"`
	TLSLibrary     string   `json:"tls_library"`
}

type Store struct {
	pool *pgxpool.Pool
	cfg  *config.Config

	mu    sync.Mutex
	queue []row

	accepted atomic.Uint64
	rejected atomic.Uint64
	written  atomic.Uint64
	// Batches handed back to the agent because the clock could not be read.
	// Exported so a stalled bootstrap is visible as a number rather than as an
	// empty observation table nobody can explain.
	clockErrors atomic.Uint64

	// vday is cached: reading the clock per batch would make the hot path do a
	// query per write for a value that changes once per virtual day.
	vdayVal    atomic.Int64
	vdayLoaded atomic.Int64
	cacheMS    atomic.Int64

	// Redis counters feeding the console's capture stream. A cache, never a
	// system of record: every figure it holds is also derivable from the
	// observation table.
	live *live
}

type row struct {
	vday           int32
	wallTS         time.Time
	method         string
	pathRaw        string
	host           *string
	port           *int32
	status         *int16
	latencyUS      *int32
	reqBytes       *int32
	respBytes      *int32
	authPresent    bool
	authScheme     *string
	tlsVersion     *string
	dataClasses    []byte
	responseFields []byte
	direction      *string
	synthetic      bool
	peerService    *string
	peerIP         *string
	pid            *int32
	cgroupID       *int64
}

func New(ctx context.Context, cfg *config.Config) (*Store, error) {
	pcfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	pcfg.MaxConns = int32(cfg.MaxConns)

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}

	s := &Store{pool: pool, cfg: cfg, live: newLive()}
	s.cacheMS.Store(1000)
	slog.Default().Info("ingest store ready", "live_counters", s.live.enabled())
	go s.flushLoop(ctx)
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Stats() (accepted, rejected, written uint64, queued int) {
	s.mu.Lock()
	queued = len(s.queue)
	s.mu.Unlock()
	return s.accepted.Load(), s.rejected.Load(), s.written.Load(), queued
}

// ClockErrors counts batches refused because the virtual clock was unreadable.
func (s *Store) ClockErrors() uint64 { return s.clockErrors.Load() }

// CurrentVday reads the shared clock.
//
// vday is stamped here rather than taken from the agent, so a node with a skewed
// clock cannot corrupt the analysis time base for the whole estate.
func (s *Store) CurrentVday(ctx context.Context) (int32, error) {
	// Cache lifetime tracks the clock scale. A fixed five-second cache
	// misattributes observations whenever a virtual day is shorter than that,
	// which is exactly the compressed-timeline case the clock exists to serve.
	now := time.Now().UnixMilli()
	if last := s.vdayLoaded.Load(); now-last < s.cacheMS.Load() {
		return int32(s.vdayVal.Load()), nil
	}

	// An error, not a panic on the hot path. Every caller of this already has to
	// handle an unreadable clock, and there is no useful difference between a
	// store with no pool and one whose pool cannot answer.
	if s.pool == nil {
		return 0, errors.New("no database pool")
	}

	var epoch time.Time
	var scale int32
	var pausedVday *int32
	err := s.pool.QueryRow(ctx,
		`SELECT epoch_wall, scale_seconds, paused_vday FROM vclock WHERE id = 1`,
	).Scan(&epoch, &scale, &pausedVday)
	if err != nil {
		return 0, err
	}

	var vday int32
	if pausedVday != nil {
		vday = *pausedVday
	} else {
		elapsed := time.Since(epoch).Seconds()
		vday = int32(math.Max(0, math.Floor(elapsed/float64(scale))))
	}

	cache := int64(scale) * 1000 / 4
	if cache > 5000 {
		cache = 5000
	}
	if cache < 100 {
		cache = 100
	}
	s.cacheMS.Store(cache)

	s.vdayVal.Store(int64(vday))
	s.vdayLoaded.Store(now)
	return vday, nil
}

// Enqueue validates and buffers a batch. Invalid items are counted and dropped;
// one malformed record must not fail an otherwise good batch.
//
// A non-nil error means nothing was taken and the batch is still the agent's to
// hold. That distinction is the whole point of the return: an item this store
// judged invalid is gone for good and counted as rejected, while a batch it
// could not stamp is not the agent's fault and must come back.
func (s *Store) Enqueue(ctx context.Context, items []Observation) (accepted, rejected int, err error) {
	vday, err := s.CurrentVday(ctx)
	if err != nil {
		// Every observation in the batch, dropped, with both counters left at
		// zero and nothing logged — that was the behaviour here, and it is the
		// exact failure this system is built not to have. An unseeded vclock
		// table made the sensor, the shipper and the ingest all report success
		// while the estate went entirely unrecorded.
		s.clockErrors.Add(1)
		slog.Default().Error("clock unreadable; batch returned to the agent",
			"err", err, "items", len(items),
			"remedy", "seed the vclock row (id=1); the platform bootstrap or `sentry_core.clock.ensure_vclock` creates it")
		return 0, 0, err
	}

	rows := make([]row, 0, len(items))
	for _, o := range items {
		r, ok := toRow(o, vday)
		if !ok {
			rejected++
			continue
		}
		rows = append(rows, r)
		accepted++
	}

	s.mu.Lock()
	s.queue = append(s.queue, rows...)
	over := len(s.queue) - s.cfg.QueueHigh
	if over > 0 {
		// Backpressure: drop oldest and count it. A silent overwrite would make
		// the estate look quieter than it is.
		s.queue = s.queue[over:]
		s.rejected.Add(uint64(over))
	}
	s.mu.Unlock()

	s.accepted.Add(uint64(accepted))
	s.rejected.Add(uint64(rejected))

	// After the rows are queued, so a slow or unreachable cache delays a
	// response and can never lose a batch.
	//
	// Always the kernel source: this path carries agent captures only. The
	// stage 01 collectors write their sightings to Postgres directly from the
	// worker and never reach here, which is why a per-source breakdown at this
	// point would report one source and imply it was the only one.
	if accepted > 0 {
		s.live.observed(ctx, vday, map[string]int{"ebpf": accepted})
	}
	return accepted, rejected, nil
}

// LiveCounterErrors backs sentry_ingest_live_counter_errors_total.
func (s *Store) LiveCounterErrors() uint64 { return s.live.Failures() }

func toRow(o Observation, vday int32) (row, bool) {
	if o.Method == "" && o.Status == 0 {
		return row{}, false
	}
	if o.WallUnixNS <= 0 {
		return row{}, false
	}
	if len(o.PathRaw) > 1024 {
		o.PathRaw = o.PathRaw[:1024]
	}

	r := row{
		vday:           vday,
		wallTS:         time.Unix(0, o.WallUnixNS).UTC(),
		method:         o.Method,
		pathRaw:        o.PathRaw,
		authPresent:    o.AuthPresent,
		dataClasses:    marshalClasses(o.DataClasses),
		responseFields: marshalClasses(o.ResponseFields),
	}
	r.host = strPtr(o.Host)
	// Anything the agent did not label is left NULL rather than defaulted: an
	// unlabelled row must not be silently counted as a server-side sighting.
	if o.Direction == "INGRESS" || o.Direction == "EGRESS" {
		r.direction = strPtr(o.Direction)
	}
	// Platform-generated traffic. Kept, but never counted as usage.
	r.synthetic = o.Synthetic
	r.authScheme = strPtr(o.AuthScheme)
	r.tlsVersion = strPtr(o.TLSVersion)
	r.peerService = strPtr(o.PeerService)
	r.peerIP = strPtr(o.PeerIP)
	r.port = u32Ptr(o.Port)
	r.latencyUS = u32Ptr(o.LatencyUS)
	r.reqBytes = u32Ptr(o.ReqBytes)
	r.respBytes = u32Ptr(o.RespBytes)
	r.pid = u32Ptr(o.PID)
	if o.Status > 0 && o.Status < 600 {
		v := int16(o.Status)
		r.status = &v
	}
	if o.CgroupID > 0 {
		v := int64(o.CgroupID)
		r.cgroupID = &v
	}
	return r, true
}

func (s *Store) flushLoop(ctx context.Context) {
	t := time.NewTicker(time.Duration(s.cfg.FlushIntervalMS) * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Flush(ctx)
		}
	}
}

// Flush writes buffered rows with COPY, which is an order of magnitude faster
// than individual inserts on the hot path.
func (s *Store) Flush(ctx context.Context) {
	s.mu.Lock()
	if len(s.queue) == 0 {
		s.mu.Unlock()
		return
	}
	n := len(s.queue)
	if n > s.cfg.CopyBatch {
		n = s.cfg.CopyBatch
	}
	batch := make([]row, n)
	copy(batch, s.queue[:n])
	s.mu.Unlock()

	written, err := s.copyRows(ctx, batch)
	if err != nil {
		// Leave the batch queued. Losing observations on a transient database
		// failure would understate the estate, which is the one error this
		// system must not make quietly.
		slog.Default().Warn("copy failed, retrying", "err", err, "rows", len(batch))
		return
	}

	s.mu.Lock()
	s.queue = s.queue[n:]
	s.mu.Unlock()
	s.written.Add(uint64(written))
}

func (s *Store) copyRows(ctx context.Context, rows []row) (int64, error) {
	src := pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
		r := rows[i]
		return []any{
			r.vday, r.wallTS, nil, "ebpf", r.method, r.pathRaw, r.host, r.port,
			r.status, r.latencyUS, r.reqBytes, r.respBytes, r.authPresent,
			r.authScheme, r.tlsVersion, r.dataClasses, r.responseFields, r.direction,
			r.synthetic,
			r.peerService, r.peerIP, r.pid, r.cgroupID, false,
		}, nil
	})

	return s.pool.CopyFrom(ctx,
		pgx.Identifier{"observation"},
		[]string{
			"vday", "wall_ts", "endpoint_id", "source", "method", "path_raw",
			"host", "port", "status", "latency_us", "req_bytes", "resp_bytes",
			"auth_present", "auth_scheme", "tls_version", "data_classes",
			"response_fields", "direction", "synthetic", "peer_service", "peer_ip", "pid", "cgroup_id",
			"backfill",
		},
		src)
}

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// marshalClasses encodes the data-class labels for the JSON column.
//
// Labels only: PAN, AADHAAR and the rest name what was seen, never what it was.
// The values were discarded in kernel and have no representation on this path.
func marshalClasses(classes []string) []byte {
	if len(classes) == 0 {
		return []byte("[]")
	}
	b, err := json.Marshal(classes)
	if err != nil {
		return []byte("[]")
	}
	return b
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func u32Ptr(v uint32) *int32 {
	if v == 0 {
		return nil
	}
	i := int32(v)
	return &i
}
