// SENTRY honeypot.
//
// Serves retired endpoints. Every request is intelligence: by the time a route
// reaches this service, the sunset sequence has published notices, migrated or
// throttled traffic, run a quarantine in which every remaining caller was named
// and contacted, and returned 410. A request arriving after all of that is
// either an attacker or a dependency that survived every stage designed to
// surface it, and both are worth an alert.
//
// The service has no route to any estate system. Compromising it yields nothing.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentry/honeypot/internal/routes"
	"github.com/sentry/honeypot/internal/synth"
)

var version = "dev"

type app struct {
	pool   *pgxpool.Pool
	routes *routes.Table
	log    *slog.Logger

	probes  chan probe
	served  atomic.Uint64
	dropped atomic.Uint64
}

type probe struct {
	endpointID string
	sourceIP   string
	method     string
	path       string
	headers    map[string]string
	bodySHA    []byte
	watermark  string
	sessionFP  string
	at         time.Time
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	dbURL := normalise(os.Getenv("DATABASE_URL"))
	if dbURL == "" {
		log.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	a := &app{
		pool:   pool,
		routes: routes.New(pool, log),
		log:    log,
		probes: make(chan probe, envInt("HONEYPOT_QUEUE", 10_000)),
	}

	go a.routes.RefreshLoop(ctx, 30*time.Second)
	go a.captureLoop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /readyz", a.readyz)
	mux.HandleFunc("GET /metrics", a.metrics)
	mux.HandleFunc("/", a.serve)

	srv := &http.Server{
		Addr:              env("LISTEN", ":8088"),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		close(a.probes)
	}()

	log.Info("sentry-honeypot started", "version", version, "listen", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

func (a *app) serve(w http.ResponseWriter, r *http.Request) {
	route, ok := a.routes.Lookup(r.Method, r.URL.Path)
	if !ok {
		// Not a retired endpoint this service was given, or no legal sign-off.
		// Either way it is not ours to answer for.
		http.NotFound(w, r)
		return
	}

	watermark := synth.Watermark()
	body := synth.Response(route.PathRaw, route.Schema, watermark)

	a.record(r, route.EndpointID, watermark)

	// Deliberately no rate limiting on these routes: slowing an attacker down
	// would reduce the intelligence collected, which is the opposite of the
	// objective.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
	a.served.Add(1)
}

func (a *app) record(r *http.Request, endpointID, watermark string) {
	headers := map[string]string{}
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Probe bodies are hashed, never stored. The digest is enough to correlate
	// repeat attempts, and the body is attacker-supplied content this system has
	// no reason to retain.
	var sum []byte
	if r.Body != nil {
		if raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)); err == nil && len(raw) > 0 {
			h := sha256.Sum256(raw)
			sum = h[:]
		}
	}

	p := probe{
		endpointID: endpointID,
		sourceIP:   clientIP(r),
		method:     r.Method,
		path:       r.URL.Path,
		headers:    headers,
		bodySHA:    sum,
		watermark:  watermark,
		sessionFP:  sessionFingerprint(r),
		at:         time.Now().UTC(),
	}

	select {
	case a.probes <- p:
	default:
		// Bounded queue: a flood must not block responses or exhaust memory.
		// The drop is counted so the gap is visible.
		a.dropped.Add(1)
	}
}

func (a *app) captureLoop(ctx context.Context) {
	for p := range a.probes {
		vday, err := a.currentVday(ctx)
		if err != nil {
			a.log.Warn("probe capture: clock unavailable", "err", err)
			continue
		}
		headers, _ := json.Marshal(p.headers)
		_, err = a.pool.Exec(ctx, `
			INSERT INTO probe (vday, wall_ts, endpoint_id, source_ip, method,
			                   path_raw, headers, body_sha256, watermark, session_fp)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			vday, p.at, p.endpointID, p.sourceIP, p.method, p.path,
			headers, p.bodySHA, p.watermark, p.sessionFP)
		if err != nil {
			a.log.Warn("probe insert", "err", err)
		}
	}
}

func (a *app) currentVday(ctx context.Context) (int32, error) {
	var epoch time.Time
	var scale int32
	var paused *int32
	if err := a.pool.QueryRow(ctx,
		`SELECT epoch_wall, scale_seconds, paused_vday FROM vclock WHERE id = 1`,
	).Scan(&epoch, &scale, &paused); err != nil {
		return 0, err
	}
	if paused != nil {
		return *paused, nil
	}
	return int32(math.Max(0, math.Floor(time.Since(epoch).Seconds()/float64(scale)))), nil
}

func clientIP(r *http.Request) string {
	// X-Forwarded-For is honoured only from configured proxies: an attacker
	// setting it themselves must not be able to forge their own source.
	trusted := strings.Split(env("HONEYPOT_TRUSTED_PROXIES", ""), ",")
	remote, _, _ := net.SplitHostPort(r.RemoteAddr)
	for _, t := range trusted {
		if t = strings.TrimSpace(t); t != "" && t == remote {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				return strings.TrimSpace(strings.Split(xff, ",")[0])
			}
		}
	}
	if remote == "" {
		return r.RemoteAddr
	}
	return remote
}

// sessionFingerprint links multiple probes from one attacker session.
func sessionFingerprint(r *http.Request) string {
	h := sha256.New()
	h.Write([]byte(clientIP(r)))
	h.Write([]byte(r.UserAgent()))
	h.Write([]byte(r.Header.Get("Accept-Language")))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (a *app) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version})
}

func (a *app) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := map[string]string{"postgres": "ok"}
	code := http.StatusOK
	if err := a.pool.Ping(ctx); err != nil {
		checks["postgres"] = "unreachable"
		code = http.StatusServiceUnavailable
	}

	signed, ref := a.routes.Signed()
	writeJSON(w, code, map[string]any{
		"ready":  code == http.StatusOK,
		"checks": checks,
		// Surfaced so an operator expecting probe intelligence can see why none
		// is arriving.
		"legal_signoff": map[string]any{"signed": signed, "reference": ref},
		"routes":        a.routes.Len(),
	})
}

func (a *app) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	signed, _ := a.routes.Signed()
	sig := 0
	if signed {
		sig = 1
	}
	_, _ = w.Write([]byte(
		"# TYPE sentry_honeypot_responses_total counter\n" +
			"sentry_honeypot_responses_total " + strconv.FormatUint(a.served.Load(), 10) + "\n" +
			"# TYPE sentry_honeypot_probes_dropped_total counter\n" +
			"sentry_honeypot_probes_dropped_total " + strconv.FormatUint(a.dropped.Load(), 10) + "\n" +
			"# TYPE sentry_honeypot_routes gauge\n" +
			"sentry_honeypot_routes " + strconv.Itoa(a.routes.Len()) + "\n" +
			"# TYPE sentry_honeypot_legal_signoff gauge\n" +
			"sentry_honeypot_legal_signoff " + strconv.Itoa(sig) + "\n"))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func normalise(url string) string {
	for _, p := range []string{"postgresql+psycopg://", "postgresql+asyncpg://"} {
		if strings.HasPrefix(url, p) {
			return "postgresql://" + strings.TrimPrefix(url, p)
		}
	}
	return url
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
