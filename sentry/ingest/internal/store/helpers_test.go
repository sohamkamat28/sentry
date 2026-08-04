package store

import "github.com/sentry/ingest/internal/config"

func testCfg(queueHigh int) *config.Config {
	return &config.Config{QueueHigh: queueHigh, CopyBatch: queueHigh, FlushIntervalMS: 500}
}

// normaliseForTest exercises the URL normalisation through the config package's
// own loader path.
func normaliseForTest(url string) string { return config.Normalise(url) }

