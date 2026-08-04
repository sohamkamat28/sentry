// Package config loads agent settings from the environment.
//
// Every value that has no safe default is required and the process refuses to
// start without it. A sensor that starts with a guessed ingest endpoint fails
// silently, which is the failure mode this whole design exists to avoid.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	IngestEndpoint     string
	BTFPath            string
	TargetCgroupPrefix string
	ApproverPorts      []uint16
	ScanBytes          int
	RingbufSizeKB      int
	BatchSize          int
	BatchIntervalMS    int
	QueueMB            int
	ReconcileIntervalS int
	NodeName           string
	LogLevel           string
}

func Load() (*Config, error) {
	c := &Config{
		BTFPath:            env("BTF_PATH", "/sys/kernel/btf/vmlinux"),
		TargetCgroupPrefix: os.Getenv("TARGET_CGROUP_PREFIX"),  // empty = every task with a TLS library
		ScanBytes:          envInt("SCAN_BYTES", 4096),
		RingbufSizeKB:      envInt("RINGBUF_SIZE_KB", 4096),
		BatchSize:          envInt("BATCH_SIZE", 512),
		BatchIntervalMS:    envInt("BATCH_INTERVAL_MS", 500),
		QueueMB:            envInt("AGENT_QUEUE_MB", 256),
		ReconcileIntervalS: envInt("RECONCILE_INTERVAL_S", 10),
		NodeName:           env("NODE_NAME", hostname()),
		LogLevel:           env("LOG_LEVEL", "info"),
	}

	c.IngestEndpoint = os.Getenv("INGEST_ENDPOINT")
	if c.IngestEndpoint == "" {
		return nil, fmt.Errorf("INGEST_ENDPOINT is required")
	}

	ports, err := parsePorts(env("APPROVER_PORTS", "443,8443,8080,9443"))
	if err != nil {
		return nil, err
	}
	c.ApproverPorts = ports

	if c.ScanBytes < 512 || c.ScanBytes > 8192 {
		return nil, fmt.Errorf("SCAN_BYTES must be between 512 and 8192, got %d", c.ScanBytes)
	}
	if c.RingbufSizeKB&(c.RingbufSizeKB-1) != 0 {
		return nil, fmt.Errorf("RINGBUF_SIZE_KB must be a power of two, got %d", c.RingbufSizeKB)
	}

	return c, nil
}

func parsePorts(s string) ([]uint16, error) {
	var out []uint16
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("APPROVER_PORTS: %q is not a port: %w", p, err)
		}
		out = append(out, uint16(n))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("APPROVER_PORTS resolved to no ports; the sensor would capture nothing")
	}
	return out, nil
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

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
