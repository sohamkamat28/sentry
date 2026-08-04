package bpfcontract

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

// The Go decoder's field offsets, asserted against the compiled object's BTF.
//
// internal/ringbuf decodes `struct event` by hand — no reflection, no
// binary.Read, one allocation saved per event on the hot path. The cost is that
// every offset is a hand-count of a C struct's alignment and padding, and a
// wrong one does not fail: it decodes neighbouring bytes into a plausible value.
// A misread cgroup id is a capture attributed to the wrong workload; a misread
// data_len is a truncated request line.
//
// Adding `fields_len` moved conn_key from 40 to 48 and the payload from 48 to
// 56, because a __u8 before a __u64 pulls in seven bytes of padding. That is
// exactly the kind of change that is invisible until the numbers are compared
// with the compiler's own layout, which is what this does.
//
// Mirrors the constants in internal/ringbuf/ringbuf.go, which is Linux-only and
// so cannot be imported here.
var wantOffsets = map[string]uint32{
	"wall_ns":         0,
	"pid":             8,
	"cgroup_id":       16,
	"data_len":        24,
	"dport":           28,
	"daddr":           32,
	"direction":       36,
	"data_classes":    37,
	"is_request":      38,
	"is_continuation": 39,
	"fields_len":      40,
	"conn_key":        48,
	"data":            56,
	"fields":          568,
}

func TestEventStructOffsetsMatchTheDecoder(t *testing.T) {
	spec, err := btf.LoadSpec(objectPath(t))
	if err != nil {
		t.Fatalf("load BTF from the compiled object: %v", err)
	}

	var ev *btf.Struct
	if err := spec.TypeByName("event", &ev); err != nil {
		t.Fatalf("struct event not found in the object's BTF: %v", err)
	}

	got := make(map[string]uint32, len(ev.Members))
	for _, m := range ev.Members {
		if m.Offset%8 != 0 {
			t.Fatalf("member %q is bit-packed at bit offset %d; the byte-offset "+
				"decoder in internal/ringbuf cannot address it", m.Name, m.Offset)
		}
		got[m.Name] = uint32(m.Offset / 8)
	}

	for name, want := range wantOffsets {
		have, ok := got[name]
		if !ok {
			t.Errorf("struct event has no member %q; the decoder reads one", name)
			continue
		}
		if have != want {
			t.Errorf("event.%s is at byte %d, the decoder reads byte %d",
				name, have, want)
		}
	}

	for name := range got {
		if _, ok := wantOffsets[name]; !ok {
			t.Errorf("struct event gained member %q that no offset asserts; add "+
				"it here and to internal/ringbuf, or the decoder is reading a "+
				"layout that no longer exists", name)
		}
	}

	if int(ev.Size) != 568+128 {
		t.Errorf("struct event is %d bytes, expected %d", ev.Size, 568+128)
	}
}
