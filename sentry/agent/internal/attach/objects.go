//go:build linux

package attach

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// ObjectPath is where the compiled BPF object lives in the agent image.
//
// The object is loaded from disk rather than embedded via bpf2go so that the Go
// binary and the BPF program compile independently: the Go side builds anywhere,
// and the BPF side is compiled by clang with a bpf target during the image
// build. Embedding would make every Go build require clang.
const ObjectPath = "/opt/sentry/bpf/tls.bpf.o"

// Objects holds the loaded programs and maps.
type Objects struct {
	coll *ebpf.Collection

	SslWriteEnter *ebpf.Program
	SslWriteExit  *ebpf.Program
	SslReadEnter  *ebpf.Program
	SslReadExit   *ebpf.Program
	// The _ex forms. CPython's ssl module calls only these, so without them a
	// Python estate produces no capture at all.
	SslWriteExEnter *ebpf.Program
	SslWriteExExit  *ebpf.Program
	SslReadExEnter  *ebpf.Program
	SslReadExExit   *ebpf.Program
	GoTlsWrite      *ebpf.Program
	GoTlsReadRet    *ebpf.Program
	SockConnect     *ebpf.Program

	ApproverPorts   *ebpf.Map
	ApproverCgroups *ebpf.Map
	Discarders      *ebpf.Map
	SockInfo        *ebpf.Map
	Events          *ebpf.Map
	Stats           *ebpf.Map
	Settings        *ebpf.Map
}

// LoadObjects loads and verifies the BPF program against the running kernel.
//
// A verifier rejection here is fatal and unrecoverable: the program either runs
// in the kernel or the sensor does not exist.
func LoadObjects(btfPath string) (*Objects, error) {
	path := os.Getenv("BPF_OBJECT_PATH")
	if path == "" {
		path = ObjectPath
	}

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}

	opts := ebpf.CollectionOptions{}
	if btfPath != "" && btfPath != "/sys/kernel/btf/vmlinux" {
		kernelBTF, err := btf.LoadSpec(btfPath)
		if err != nil {
			return nil, fmt.Errorf("load BTF from %s: %w", btfPath, err)
		}
		opts.Programs.KernelTypes = kernelBTF
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// The verifier log is the only useful diagnostic when a program is
			// rejected, so it is surfaced in full rather than summarised.
			return nil, fmt.Errorf("kernel verifier rejected the program:\n%+v", ve)
		}
		return nil, err
	}

	o := &Objects{coll: coll}

	prog := func(name string, dst **ebpf.Program) error {
		p, ok := coll.Programs[name]
		if !ok {
			return fmt.Errorf("program %q not found in %s", name, path)
		}
		*dst = p
		return nil
	}
	mp := func(name string, dst **ebpf.Map) error {
		m, ok := coll.Maps[name]
		if !ok {
			return fmt.Errorf("map %q not found in %s", name, path)
		}
		*dst = m
		return nil
	}

	for _, bind := range []func() error{
		func() error { return prog("ssl_write_enter", &o.SslWriteEnter) },
		func() error { return prog("ssl_write_exit", &o.SslWriteExit) },
		func() error { return prog("ssl_read_enter", &o.SslReadEnter) },
		func() error { return prog("ssl_read_exit", &o.SslReadExit) },
		func() error { return prog("ssl_write_ex_enter", &o.SslWriteExEnter) },
		func() error { return prog("ssl_write_ex_exit", &o.SslWriteExExit) },
		func() error { return prog("ssl_read_ex_enter", &o.SslReadExEnter) },
		func() error { return prog("ssl_read_ex_exit", &o.SslReadExExit) },
		func() error { return prog("go_tls_write", &o.GoTlsWrite) },
		func() error { return prog("go_tls_read_ret", &o.GoTlsReadRet) },
		func() error { return prog("sock_connect", &o.SockConnect) },
		func() error { return mp("approver_ports", &o.ApproverPorts) },
		func() error { return mp("approver_cgroups", &o.ApproverCgroups) },
		func() error { return mp("discarders", &o.Discarders) },
		func() error { return mp("sock_info", &o.SockInfo) },
		func() error { return mp("events", &o.Events) },
		func() error { return mp("stats", &o.Stats) },
		func() error { return mp("settings", &o.Settings) },
	} {
		if err := bind(); err != nil {
			coll.Close()
			return nil, err
		}
	}

	return o, nil
}

// SetCgroupFilter enables or disables cgroup scoping at runtime.
func SetCgroupFilter(o *Objects, enabled bool) error {
	key, val := uint32(0), uint64(0)
	if enabled {
		val = 1
	}
	return o.Settings.Put(&key, &val)
}

// LastObservedCgroupID reports the id this kernel reported for the most recent
// event, so an operator can configure scoping against a real value.
func LastObservedCgroupID(o *Objects) (uint64, error) {
	key := uint32(1)
	var v uint64
	err := o.Settings.Lookup(&key, &v)
	return v, err
}

func (o *Objects) Close() error {
	if o.coll != nil {
		o.coll.Close()
	}
	return nil
}

// ReadStats sums the per-CPU counters.
//
// The reduction ratio between captured and emitted is the measurement behind the
// CPU-cost claim, so it is exported rather than asserted.
func ReadStats(o *Objects) (StatsSnapshot, error) {
	var s StatsSnapshot
	var err error

	if s.Captured, err = readPerCPU(o.Stats, 0); err != nil {
		return s, err
	}
	if s.FilteredApprover, err = readPerCPU(o.Stats, 1); err != nil {
		return s, err
	}
	if s.FilteredDiscarder, err = readPerCPU(o.Stats, 2); err != nil {
		return s, err
	}
	if s.Emitted, err = readPerCPU(o.Stats, 3); err != nil {
		return s, err
	}
	if s.FilteredCgroup, err = readPerCPU(o.Stats, 4); err != nil {
		return s, err
	}
	return s, nil
}
