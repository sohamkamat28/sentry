//go:build linux

package ringbuf

import (
	"strings"
	"testing"
)

// encode lays out a record the way the kernel does, so these tests exercise the
// real offsets rather than a convenient stand-in.
func encode(fields string, n int) []byte {
	raw := make([]byte, offFields+fieldsBytes)
	copy(raw[offFields:], fields)
	raw[offFieldsLen] = byte(n)
	return raw
}

func TestKeyNamesAreSplitOnNUL(t *testing.T) {
	blob := "accountnumber\x00balance\x00ifsc\x00"
	got := decodeFields(encode(blob, len(blob)), len(blob))

	want := []string{"accountnumber", "balance", "ifsc"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestNamesAreLowerCasedAndSorted(t *testing.T) {
	// Two services written by two teams describing the same surface. A casing
	// difference is not a schema difference, and the fingerprint compares these
	// as sets — so `accountNumber` and `accountnumber` have to be one shingle
	// or the resurrection scores lower against its own predecessor than it
	// should.
	blob := "IFSC\x00accountNumber\x00Balance\x00"
	got := decodeFields(encode(blob, len(blob)), len(blob))

	want := "accountnumber,balance,ifsc"
	if strings.Join(got, ",") != want {
		t.Errorf("got %q, want %q", strings.Join(got, ","), want)
	}
}

func TestDuplicateNamesCollapse(t *testing.T) {
	// An array of objects repeats its keys once per element. Left as-is, a
	// response with a two-element list and one with a three-element list carry
	// different multisets — but Jaccard is over sets, so the duplicates are
	// pure noise that also crowds out the 128-byte window.
	blob := "amount\x00merchant\x00amount\x00merchant\x00amount\x00"
	got := decodeFields(encode(blob, len(blob)), len(blob))

	if len(got) != 2 {
		t.Fatalf("got %v, want 2 distinct names", got)
	}
}

func TestNonPrintableBytesAreDropped(t *testing.T) {
	// The kernel rewinds a value out of the buffer before the next token, so
	// nothing here should ever be binary. This is the backstop: it is the last
	// point at which a value could enter the pipeline, and a truncated UTF-8
	// sequence from a body is not a field name.
	blob := "balance\x00\x01\x02\x03\x00ifsc\x00"
	got := decodeFields(encode(blob, len(blob)), len(blob))

	for _, name := range got {
		if strings.ContainsAny(name, "\x01\x02\x03") {
			t.Errorf("non-printable name survived: %q", name)
		}
	}
	if len(got) != 2 {
		t.Errorf("got %v, want just the two printable names", got)
	}
}

func TestAnOverlongTokenIsRejected(t *testing.T) {
	// A JSON string long enough to be a value rather than a key. No real field
	// name is 64 characters, and admitting one would put body content into a
	// column whose whole contract is that it holds none.
	long := strings.Repeat("x", 100)
	blob := long + "\x00ok\x00"
	got := decodeFields(encode(blob, len(blob)), len(blob))

	if len(got) != 1 || got[0] != "ok" {
		t.Errorf("got %v, want only [ok]", got)
	}
}

func TestZeroLengthYieldsNothing(t *testing.T) {
	if got := decodeFields(encode("", 0), 0); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestLengthIsClampedToTheWindow(t *testing.T) {
	// fields_len is a __u8 the kernel sets; a value past the buffer would read
	// whatever follows it in the record.
	blob := "balance\x00"
	got := decodeFields(encode(blob, len(blob)), 250)

	if len(got) != 1 || got[0] != "balance" {
		t.Errorf("got %v, want [balance]", got)
	}
}
