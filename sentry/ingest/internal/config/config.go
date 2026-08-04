// Package config loads ingest settings from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Listen          string
	DatabaseURL     string
	MaxConns        int
	QueueHigh       int
	CopyBatch       int
	FlushIntervalMS int
	MaxBodyBytes    int64
	LogLevel        string
}

func Load() (*Config, error) {
	c := &Config{
		Listen:          env("LISTEN", ":9090"),
		MaxConns:        envInt("DB_MAX_CONNS", 8),
		QueueHigh:       envInt("INGEST_QUEUE_HIGH", 50_000),
		CopyBatch:       envInt("INGEST_COPY_BATCH", 5_000),
		FlushIntervalMS: envInt("INGEST_FLUSH_MS", 500),
		MaxBodyBytes:    int64(envInt("INGEST_MAX_BODY_BYTES", 8<<20)),
		LogLevel:        env("LOG_LEVEL", "info"),
	}

	c.DatabaseURL = os.Getenv("DATABASE_URL")
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	// SQLAlchemy's driver prefix is not valid for pgx, and the platform shares
	// one DATABASE_URL across services. Normalise rather than require two.
	c.DatabaseURL = Normalise(c.DatabaseURL)

	if c.CopyBatch > c.QueueHigh {
		return nil, fmt.Errorf("INGEST_COPY_BATCH (%d) exceeds INGEST_QUEUE_HIGH (%d)",
			c.CopyBatch, c.QueueHigh)
	}
	return c, nil
}

// Normalise converts a SQLAlchemy driver URL to one pgx accepts.
func Normalise(url string) string {
	for _, prefix := range []string{"postgresql+psycopg://", "postgresql+asyncpg://"} {
		if len(url) > len(prefix) && url[:len(prefix)] == prefix {
			return "postgresql://" + url[len(prefix):]
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
