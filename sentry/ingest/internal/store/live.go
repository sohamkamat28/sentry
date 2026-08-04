package store

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Live counters.
//
// A cache, never a system of record. Every number here has an authoritative
// answer in Postgres behind it — `SELECT count(*) FROM observation` — and this
// exists so the console's capture stream does not have to run that query at
// several hundred rows a second.
//
// Two consequences follow, and both are deliberate:
//
//   - A failed increment is swallowed and counted, never returned. Propagating
//     it would convert a convenience dependency into an availability one: the
//     hot path would start refusing batches because a cache was down, and the
//     agent would queue and eventually drop captures over a counter.
//   - Keys carry a TTL of two virtual days. A counter that outlived its vday
//     would accumulate across a demonstration run and read as a much busier
//     estate than the one observed.
type live struct {
	rdb      *redis.Client
	ttl      time.Duration
	failures atomic.Uint64
}

func newLive() *live {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		// Unconfigured is not an error. The console falls back to Postgres and
		// says which source it served.
		return &live{}
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		slog.Default().Warn("REDIS_URL unparseable; live counters disabled", "err", err)
		return &live{}
	}
	opts.DialTimeout = 2 * time.Second
	opts.ReadTimeout = 2 * time.Second
	opts.WriteTimeout = 2 * time.Second

	scale := 30
	if v := os.Getenv("VCLOCK_SCALE_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			scale = n
		}
	}
	ttl := time.Duration(scale) * 2 * time.Second
	if ttl < time.Minute {
		ttl = time.Minute
	}

	return &live{rdb: redis.NewClient(opts), ttl: ttl}
}

// observed records n captures for a vday and a source.
//
// Called on the hot path after the rows are queued, so a slow cache delays a
// response but can never lose a batch.
func (l *live) observed(ctx context.Context, vday int32, bySource map[string]int) {
	if l == nil || l.rdb == nil || len(bySource) == 0 {
		return
	}

	// A short deadline of its own. Inheriting the request context would let a
	// generous client timeout hold the hot path open on a stalled cache.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()

	total := 0
	pipe := l.rdb.Pipeline()
	for source, n := range bySource {
		total += n
		key := "live:src:" + source
		pipe.IncrBy(ctx, key, int64(n))
		pipe.Expire(ctx, key, l.ttl)
	}
	obsKey := "live:obs:" + strconv.Itoa(int(vday))
	pipe.IncrBy(ctx, obsKey, int64(total))
	pipe.Expire(ctx, obsKey, l.ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		l.failures.Add(1)
	}
}

// Failures backs sentry_ingest_live_counter_errors_total. A silently degraded
// cache should be visible rather than inferred from a counter that stopped
// moving.
func (l *live) Failures() uint64 {
	if l == nil {
		return 0
	}
	return l.failures.Load()
}

func (l *live) enabled() bool { return l != nil && l.rdb != nil }
