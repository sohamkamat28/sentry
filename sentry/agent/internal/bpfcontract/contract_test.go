// Package bpfcontract asserts that the compiled BPF object matches what the
// agent's loader binds.
//
// It lives outside internal/attach so it builds on any host: attach is
// Linux-only, but this check is just ELF parsing, and catching a renamed map on
// the build machine is worth more than catching it on the target.
package bpfcontract

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// wantPrograms and wantMaps mirror what LoadObjects binds.
//
// A rename on either side of this boundary is a load-time failure on the target
// host, which is the worst place to discover it: the agent exits, the sensor
// does not exist, and the estate looks empty. Asserting the contract at build
// time turns that into a failed build.
var (
	wantPrograms = []string{
		"ssl_write_enter", "ssl_write_exit",
		"ssl_read_enter", "ssl_read_exit",
		// CPython links against the _ex forms and nothing else. Without these
		// four an estate of Python services produces no capture whatsoever,
		// which is a failure the classic probes cannot reveal because they
		// attach cleanly and simply never fire.
		"ssl_write_ex_enter", "ssl_write_ex_exit",
		"ssl_read_ex_enter", "ssl_read_ex_exit",
		"go_tls_write", "go_tls_read_ret",
		"sock_connect",
	}
	wantMaps = []string{
		"active_ssl", "approver_ports", "approver_cgroups",
		"discarders", "sock_info", "events", "stats", "scratch",
	}
)

func objectPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "bin", "tls.bpf.o")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("compiled object not present at %s; run `make bpf` first", p)
	}
	return p
}

func TestObjectContract(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(objectPath(t))
	if err != nil {
		t.Fatalf("parse object: %v", err)
	}

	for _, name := range wantPrograms {
		if _, ok := spec.Programs[name]; !ok {
			t.Errorf("program %q missing from the compiled object", name)
		}
	}
	for _, name := range wantMaps {
		if _, ok := spec.Maps[name]; !ok {
			t.Errorf("map %q missing from the compiled object", name)
		}
	}
}

func TestFilterMapsHaveUsableShapes(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(objectPath(t))
	if err != nil {
		t.Fatalf("parse object: %v", err)
	}

	// The approver port map is keyed by uint16; SeedApprovers writes that type,
	// and a mismatch would fail silently at Put time leaving the sensor
	// capturing nothing.
	if m := spec.Maps["approver_ports"]; m.KeySize != 2 {
		t.Errorf("approver_ports key size = %d, want 2 (uint16 port)", m.KeySize)
	}

	// The discarder map must be an LRU so a stale signature ages out. A plain
	// hash here would let a bad entry blind the sensor permanently.
	if m := spec.Maps["discarders"]; m.Type != ebpf.LRUHash {
		t.Errorf("discarders type = %v, want LRUHash so signatures expire", m.Type)
	}

	if m := spec.Maps["events"]; m.Type != ebpf.RingBuf {
		t.Errorf("events type = %v, want RingBuf", m.Type)
	}
}

func TestProgramsFitWellWithinTheInstructionLimit(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(objectPath(t))
	if err != nil {
		t.Fatalf("parse object: %v", err)
	}

	// The verifier's ceiling is a million instructions, but the practical limit
	// is its path budget. An earlier revision unrolled the classification scan
	// and the branch offsets exceeded BPF's 16-bit range before it could even be
	// assembled. Staying far under is the point.
	const budget = 4096

	for name, p := range spec.Programs {
		if n := len(p.Instructions); n > budget {
			t.Errorf("program %s has %d instructions, over the %d budget", name, n, budget)
		}
	}
}
