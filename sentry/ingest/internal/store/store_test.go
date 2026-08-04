package store

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const vday = int32(47)

func validObs() Observation {
	return Observation{
		WallUnixNS: time.Now().UnixNano(),
		Method:     "GET",
		PathRaw:    "/api/v1/accounts/8814/balance",
		Host:       "core-accounts",
		Port:       8443,
		Status:     200,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation: one bad record must not poison a batch
// ─────────────────────────────────────────────────────────────────────────────
func TestValidObservationConverts(t *testing.T) {
	r, ok := toRow(validObs(), vday)
	if !ok {
		t.Fatal("valid observation rejected")
	}
	if r.vday != vday {
		t.Errorf("vday = %d, want %d", r.vday, vday)
	}
	if r.method != "GET" {
		t.Errorf("method = %q", r.method)
	}
	if r.status == nil || *r.status != 200 {
		t.Error("status not carried through")
	}
}

func TestRecordsWithNeitherMethodNorStatusAreRejected(t *testing.T) {
	// A ring-buffer record that parsed as neither a request nor a response
	// carries nothing the pipeline can use.
	o := validObs()
	o.Method = ""
	o.Status = 0
	if _, ok := toRow(o, vday); ok {
		t.Error("record with no method and no status should be rejected")
	}
}

func TestRecordsWithoutATimestampAreRejected(t *testing.T) {
	o := validObs()
	o.WallUnixNS = 0
	if _, ok := toRow(o, vday); ok {
		t.Error("record without a wall timestamp should be rejected")
	}
}

func TestResponseOnlyRecordIsAccepted(t *testing.T) {
	// The response half of an exchange has a status and no method; it is still
	// a real observation.
	o := validObs()
	o.Method = ""
	if _, ok := toRow(o, vday); !ok {
		t.Error("response-only record should be accepted")
	}
}

func TestOverlongPathIsTruncatedNotRejected(t *testing.T) {
	o := validObs()
	o.PathRaw = "/" + strings.Repeat("a", 4000)
	r, ok := toRow(o, vday)
	if !ok {
		t.Fatal("overlong path should truncate, not reject")
	}
	if len(r.pathRaw) > 1024 {
		t.Errorf("path not truncated: %d bytes", len(r.pathRaw))
	}
}

func TestImplausibleStatusIsDroppedButRowSurvives(t *testing.T) {
	o := validObs()
	o.Status = 9999
	r, ok := toRow(o, vday)
	if !ok {
		t.Fatal("row should survive an implausible status")
	}
	if r.status != nil {
		t.Errorf("status %d should not have been stored", *r.status)
	}
}

func TestZeroValuedOptionalsBecomeNullNotZero(t *testing.T) {
	// Storing 0 for an unmeasured latency would be indistinguishable from a
	// measured zero, and every downstream percentile would be wrong.
	o := validObs()
	o.LatencyUS = 0
	o.RespBytes = 0
	r, _ := toRow(o, vday)
	if r.latencyUS != nil {
		t.Error("unmeasured latency should be NULL, not 0")
	}
	if r.respBytes != nil {
		t.Error("unmeasured response size should be NULL, not 0")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Data classes
// ─────────────────────────────────────────────────────────────────────────────
func TestDataClassesAreLabelsOnly(t *testing.T) {
	o := validObs()
	o.DataClasses = []string{"AADHAAR", "PAN"}
	r, _ := toRow(o, vday)

	var got []string
	if err := json.Unmarshal(r.dataClasses, &got); err != nil {
		t.Fatalf("data_classes is not valid JSON: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"AADHAAR", "PAN"}) {
		t.Errorf("data_classes = %v", got)
	}
}

func TestEmptyDataClassesEncodeAsAnEmptyArray(t *testing.T) {
	r, _ := toRow(validObs(), vday)
	if string(r.dataClasses) != "[]" {
		t.Errorf("empty classes encoded as %q, want []", r.dataClasses)
	}
}

func TestTheWireRecordCannotCarryAPayload(t *testing.T) {
	// The privacy property is structural: bodies are discarded in kernel, and
	// there is no field on this path capable of holding one. A field named for a
	// body appearing here would silently reopen that.
	typ := reflect.TypeOf(Observation{})
	banned := []string{"body", "payload", "content", "data", "raw"}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, b := range banned {
			if name == b {
				t.Errorf("Observation has a %q field; payloads must not be representable",
					typ.Field(i).Name)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Backpressure
// ─────────────────────────────────────────────────────────────────────────────
func TestQueueOverflowDropsOldestAndCountsIt(t *testing.T) {
	// A silent overwrite would make the estate look quieter than it is, so the
	// drop has to be counted.
	s := &Store{cfg: testCfg(10)}

	for i := 0; i < 25; i++ {
		r, _ := toRow(validObs(), vday)
		s.queue = append(s.queue, r)
	}
	over := len(s.queue) - s.cfg.QueueHigh
	s.queue = s.queue[over:]
	s.rejected.Add(uint64(over))

	if len(s.queue) != 10 {
		t.Errorf("queue depth = %d, want 10", len(s.queue))
	}
	if s.rejected.Load() != 15 {
		t.Errorf("rejected = %d, want 15", s.rejected.Load())
	}
}

func TestStatsReportQueueDepth(t *testing.T) {
	s := &Store{cfg: testCfg(100)}
	r, _ := toRow(validObs(), vday)
	s.queue = append(s.queue, r, r, r)

	_, _, _, queued := s.Stats()
	if queued != 3 {
		t.Errorf("queued = %d, want 3", queued)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────
func TestSQLAlchemyURLIsNormalisedForPgx(t *testing.T) {
	// The platform shares one DATABASE_URL across Python and Go services; pgx
	// does not accept SQLAlchemy's driver prefix.
	for _, tc := range []struct{ in, want string }{
		{"postgresql+psycopg://u:p@h:5432/d", "postgresql://u:p@h:5432/d"},
		{"postgresql+asyncpg://u:p@h:5432/d", "postgresql://u:p@h:5432/d"},
		{"postgresql://u:p@h:5432/d", "postgresql://u:p@h:5432/d"},
	} {
		if got := normaliseForTest(tc.in); got != tc.want {
			t.Errorf("normalise(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
