package store

import (
	"context"
	"testing"
)

// An unseeded vclock table put the whole platform in a state where the sensor
// reported capture, the shipper reported delivery, the ingest reported success,
// and the observation table stayed empty. Nothing anywhere counted the loss.
//
// These fix the two halves of that: the batch must not be taken, and the refusal
// must be visible.

func TestABatchIsNotTakenWhenTheClockCannotBeRead(t *testing.T) {
	s := &Store{cfg: testCfg(100)}

	accepted, rejected, err := s.Enqueue(context.Background(),
		[]Observation{validObs(), validObs(), validObs()})

	if err == nil {
		t.Fatal("expected an error when the clock is unreadable")
	}
	if accepted != 0 {
		t.Errorf("accepted = %d, want 0", accepted)
	}
	// Not rejected either. These observations are valid and still the agent's
	// to redeliver; counting them as rejected would report a data-quality
	// problem the estate does not have.
	if rejected != 0 {
		t.Errorf("rejected = %d, want 0", rejected)
	}
	if _, _, _, queued := s.Stats(); queued != 0 {
		t.Errorf("queued = %d, want 0 — a batch that was refused must not be buffered", queued)
	}
}

func TestARefusedBatchIsCounted(t *testing.T) {
	s := &Store{cfg: testCfg(100)}

	for i := 0; i < 3; i++ {
		_, _, _ = s.Enqueue(context.Background(), []Observation{validObs()})
	}

	if got := s.ClockErrors(); got != 3 {
		t.Fatalf("clock errors = %d, want 3 — a silent refusal is indistinguishable "+
			"from an estate with no traffic", got)
	}
	accepted, rejected, written, _ := s.Stats()
	if accepted != 0 || rejected != 0 || written != 0 {
		t.Errorf("accepted=%d rejected=%d written=%d, want all zero", accepted, rejected, written)
	}
}
