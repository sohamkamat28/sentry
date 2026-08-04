// Package routes decides which paths the honeypot will answer.
//
// Two of the four guardrails are enforced here, and both are refusals rather
// than warnings:
//
//   - Activation only after full retirement. A route is served only if its
//     endpoint has retired=true and honeypot_active=true. A live endpoint can
//     never be served synthetic data, because the check reads the database at
//     load time instead of trusting whatever asked for the route.
//   - Recorded legal sign-off. Without the one-time policy record present, no
//     route loads at all. An institution that has not signed off gets a working
//     decommission with 410 and no honeypot, rather than a honeypot nobody
//     authorised.
package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Route struct {
	EndpointID string
	Method     string
	PathRaw    string
	Schema     []string
}

type Table struct {
	pool *pgxpool.Pool
	log  *slog.Logger

	mu     sync.RWMutex
	routes map[string]Route
	signed bool
	reason string
}

func New(pool *pgxpool.Pool, log *slog.Logger) *Table {
	return &Table{pool: pool, log: log, routes: map[string]Route{}}
}

func key(method, path string) string {
	return strings.ToUpper(method) + " " + path
}

// Lookup returns the route for a request, or false.
//
// A miss is a 404: the honeypot must not answer for anything it was not
// explicitly given.
func (t *Table) Lookup(method, path string) (Route, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.signed {
		return Route{}, false
	}
	r, ok := t.routes[key(method, path)]
	return r, ok
}

func (t *Table) Signed() (bool, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.signed, t.reason
}

func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.routes)
}

// Refresh reloads the table. Called on a timer so a newly retired endpoint
// starts being served without a restart.
func (t *Table) Refresh(ctx context.Context) error {
	signed, ref, err := t.legalSignOff(ctx)
	if err != nil {
		return err
	}

	if !signed {
		t.mu.Lock()
		t.routes = map[string]Route{}
		t.signed = false
		t.reason = "honeypot_legal_signoff policy is absent or unsigned"
		t.mu.Unlock()
		// Logged every refresh rather than once: an operator expecting probe
		// intelligence should be able to see why none is arriving.
		t.log.Warn("honeypot inactive: no legal sign-off recorded",
			"remedy", "set policy_setting.honeypot_legal_signoff with signed=true")
		return nil
	}

	// retired AND honeypot_active. Stage 11 sets the second only at phase D,
	// after 410 has been served through the whole sunset sequence.
	rows, err := t.pool.Query(ctx, `
		SELECT e.id, e.method, e.path_template, f.features
		  FROM endpoint e
		  LEFT JOIN fingerprint f ON f.endpoint_id = e.id
		 WHERE e.retired = true AND e.honeypot_active = true`)
	if err != nil {
		return err
	}
	defer rows.Close()

	next := map[string]Route{}
	for rows.Next() {
		var id, method, path string
		var features []byte
		if err := rows.Scan(&id, &method, &path, &features); err != nil {
			return err
		}
		next[key(method, path)] = Route{
			EndpointID: id,
			Method:     method,
			PathRaw:    path,
			Schema:     schemaFrom(features),
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	t.mu.Lock()
	prev := len(t.routes)
	t.routes = next
	t.signed = true
	t.reason = ref
	t.mu.Unlock()

	if prev != len(next) {
		t.log.Info("honeypot routes refreshed", "routes", len(next), "signoff", ref)
	}
	return nil
}

// legalSignOff reads the one-time policy record.
func (t *Table) legalSignOff(ctx context.Context) (bool, string, error) {
	var raw []byte
	err := t.pool.QueryRow(ctx,
		`SELECT value FROM policy_setting WHERE key = 'honeypot_legal_signoff'`).Scan(&raw)
	if err != nil {
		// Absent record is a definitive "not signed", not an error condition.
		return false, "", nil
	}

	var v struct {
		Reference *string `json:"reference"`
		Signed    bool    `json:"signed"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, "", nil
	}
	if !v.Signed || v.Reference == nil || *v.Reference == "" {
		return false, "", nil
	}
	return true, *v.Reference, nil
}

// schemaFrom pulls the response field list captured before retirement, so the
// synthetic response matches the shape the endpoint used to return.
func schemaFrom(features []byte) []string {
	if len(features) == 0 {
		return nil
	}
	var f struct {
		ResponseFields []string `json:"response_fields"`
	}
	if err := json.Unmarshal(features, &f); err != nil {
		return nil
	}
	return f.ResponseFields
}

func (t *Table) RefreshLoop(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	if err := t.Refresh(ctx); err != nil {
		t.log.Error("initial route load", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := t.Refresh(ctx); err != nil {
				t.log.Error("route refresh", "err", err)
			}
		}
	}
}

func (t *Table) String() string {
	signed, ref := t.Signed()
	return fmt.Sprintf("routes=%d signed=%t ref=%s", t.Len(), signed, ref)
}
