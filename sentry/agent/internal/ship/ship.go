// Package ship batches observations and delivers them to the ingest service.
package ship

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sentry/agent/internal/config"
)

// Observation is the wire record.
//
// There is deliberately no body or payload field. Request and response bodies
// are matched against data-class patterns inside the BPF program and discarded
// in the same kernel operation. Making payload transport unrepresentable here is
// what turns the privacy property from a policy into a structural guarantee.
type Observation struct {
	WallUnixNS  int64    `json:"wall_unix_ns"`
	Method      string   `json:"method"`
	PathRaw     string   `json:"path_raw"`
	Host        string   `json:"host,omitempty"`
	Port        uint32   `json:"port,omitempty"`
	Status      uint32   `json:"status,omitempty"`
	LatencyUS   uint32   `json:"latency_us,omitempty"`
	ReqBytes    uint32   `json:"req_bytes,omitempty"`
	RespBytes   uint32   `json:"resp_bytes,omitempty"`
	AuthPresent bool     `json:"auth_present"`
	AuthScheme  string   `json:"auth_scheme,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	DataClasses []string `json:"data_classes,omitempty"`
	// Names of the JSON keys in the response body — schema, never content.
	//
	// Stage 12's fingerprint is specified to key on response shape and had none
	// available: the kernel classified bodies for data classes and discarded
	// everything else, so a redeployed endpoint had to be recognised on
	// behavioural features alone and scored 0.80 against a 0.85 threshold.
	ResponseFields []string `json:"response_fields,omitempty"`
	PeerService    string   `json:"peer_service,omitempty"`
	PeerIP      string   `json:"peer_ip,omitempty"`
	PID         uint32   `json:"pid,omitempty"`
	CgroupID    uint64   `json:"cgroup_id,omitempty"`
	Direction   string   `json:"direction,omitempty"`
	// Set when the request carried the platform's own synthetic marker.
	Synthetic   bool     `json:"synthetic,omitempty"`
	TLSLibrary  string   `json:"tls_library,omitempty"`

	// Internal correlation state. Never serialised: the ingest contract has no
	// place for a kernel pointer, and it would be meaningless outside this host.
	ConnKey      uint64 `json:"-"`
	Continuation bool   `json:"-"`
}

type batch struct {
	AgentID      string        `json:"agent_id"`
	AgentVersion string        `json:"agent_version"`
	Node         string        `json:"node"`
	Items        []Observation `json:"items"`
}

type Shipper struct {
	cfg     *config.Config
	version string
	client  *http.Client
	log     *slog.Logger

	mu      sync.Mutex
	pending []Observation

	dropped  atomic.Uint64
	sent     atomic.Uint64
	merged   atomic.Uint64
	orphaned atomic.Uint64
	stop    chan struct{}
	wg      sync.WaitGroup
}

// maxQueued bounds memory when ingest is unreachable. Overflow drops oldest and
// counts it; the count is what keeps a gap visible rather than silent.
func (s *Shipper) maxQueued() int {
	return (s.cfg.QueueMB * 1024 * 1024) / 512
}

func New(ctx context.Context, cfg *config.Config, version string) (*Shipper, error) {
	s := &Shipper{
		cfg:     cfg,
		version: version,
		client:  &http.Client{Timeout: 10 * time.Second},
		log:     slog.Default(),
		stop:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.loop(ctx)
	return s, nil
}

// Enqueue buffers an observation, merging body continuations into the message
// they belong to.
//
// HTTP framing does not follow SSL_write boundaries: a server writes headers and
// body separately, so the data classes found in a response body arrive as a
// separate kernel event from the response line. Merging happens here because the
// batch window already holds the header for a few hundred milliseconds — the
// body invariably arrives within microseconds of it.
func (s *Shipper) Enqueue(o Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A response completes the exchange its request opened. Merging them makes
	// one observation per request/response pair, which is what the schema models:
	// status, latency and response size belong on the row that carries the method
	// and path. Left separate, the data classes found in a response body sat on a
	// row with no endpoint identity and never reached the endpoint at all — CDRI
	// scored the data-exposure term at zero for endpoints demonstrably serving
	// Aadhaar and PAN.
	if !o.Continuation && o.Method == "" && o.Status > 0 {
		for i := len(s.pending) - 1; i >= 0; i-- {
			p := &s.pending[i]
			if p.ConnKey == o.ConnKey && p.Method != "" && p.Status == 0 {
				p.Status = o.Status
				p.RespBytes = o.RespBytes
				p.DataClasses = mergeClasses(p.DataClasses, o.DataClasses)
				p.ResponseFields = mergeClasses(p.ResponseFields, o.ResponseFields)
				s.merged.Add(1)
				return
			}
		}
	}

	if o.Continuation {
		// Scan backwards: the header is almost always the previous event on
		// this connection.
		for i := len(s.pending) - 1; i >= 0; i-- {
			if s.pending[i].ConnKey == o.ConnKey && !s.pending[i].Continuation {
				s.pending[i].DataClasses = mergeClasses(s.pending[i].DataClasses, o.DataClasses)
				s.pending[i].ResponseFields = mergeClasses(
					s.pending[i].ResponseFields, o.ResponseFields)
				s.merged.Add(1)
				return
			}
		}
		// The header already shipped. Dropping the classes would lose the
		// finding, so it goes as its own record and correlation happens at
		// stage 03 on the endpoint the connection resolved to.
		s.orphaned.Add(1)
	}

	if len(s.pending) >= s.maxQueued() {
		s.pending = s.pending[1:]
		s.dropped.Add(1)
	}
	s.pending = append(s.pending, o)
}

func mergeClasses(into, from []string) []string {
	seen := make(map[string]bool, len(into)+len(from))
	out := make([]string, 0, len(into)+len(from))
	for _, c := range append(append([]string{}, into...), from...) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func (s *Shipper) Dropped() uint64  { return s.dropped.Load() }
func (s *Shipper) Sent() uint64     { return s.sent.Load() }
func (s *Shipper) Merged() uint64   { return s.merged.Load() }
func (s *Shipper) Orphaned() uint64 { return s.orphaned.Load() }

func (s *Shipper) loop(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(time.Duration(s.cfg.BatchIntervalMS) * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			s.flush()
			return
		case <-s.stop:
			s.flush()
			return
		case <-t.C:
			s.flush()
		}
	}
}

func (s *Shipper) flush() {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	n := len(s.pending)
	if n > s.cfg.BatchSize {
		n = s.cfg.BatchSize
	}
	items := make([]Observation, n)
	copy(items, s.pending[:n])
	s.mu.Unlock()

	if err := s.send(items); err != nil {
		// Leave the batch queued for the next tick. Losing observations on a
		// transient ingest failure would understate the estate.
		s.log.Warn("ingest delivery failed, retrying", "err", err, "batch", len(items))
		return
	}

	s.mu.Lock()
	s.pending = s.pending[n:]
	s.mu.Unlock()
	s.sent.Add(uint64(n))
}

func (s *Shipper) send(items []Observation) error {
	body, err := json.Marshal(batch{
		AgentID:      s.cfg.NodeName,
		AgentVersion: s.version,
		Node:         s.cfg.NodeName,
		Items:        items,
	})
	if err != nil {
		return err
	}

	url := s.cfg.IngestEndpoint
	if len(url) < 4 || url[:4] != "http" {
		url = "http://" + url
	}

	resp, err := s.client.Post(url+"/v1/observations", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ingest returned %d", resp.StatusCode)
	}
	return nil
}

func (s *Shipper) Close() error {
	close(s.stop)
	s.wg.Wait()
	return nil
}
