// SENTRY ingest.
//
// Receives observation batches from agents, stamps them with the shared virtual
// clock, and bulk-writes them to Postgres.
//
// Transport is HTTP/JSON rather than the gRPC the design document specifies.
// The two must agree, and the agent's shipper is HTTP; matching it here keeps
// one wire format across the pair rather than two half-implemented ones. The
// protobuf contract in contracts/proto remains the schema of record and the
// migration path if batch throughput ever needs it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sentry/ingest/internal/config"
	"github.com/sentry/ingest/internal/server"
	"github.com/sentry/ingest/internal/store"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		log.Error("configuration", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.New(ctx, cfg)
	if err != nil {
		log.Error("database", "err", err, "remedy", "check DATABASE_URL and that migrations have run")
		os.Exit(1)
	}
	defer st.Close()

	srv := server.New(cfg, st, log, version)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Drain in-flight batches before exiting: an observation accepted and
		// then dropped on shutdown is a silent gap in the estate.
		_ = httpSrv.Shutdown(shutdownCtx)
		st.Flush(shutdownCtx)
	}()

	log.Info("sentry-ingest started", "version", version, "listen", cfg.Listen)

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	log.Info("stopped")
}
