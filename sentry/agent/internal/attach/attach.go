//go:build linux

// Package attach resolves target processes and attaches uprobes across mount
// namespace boundaries.
package attach

import (
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/sentry/agent/internal/config"
	"github.com/sentry/agent/internal/elfsym"
)

// Target is one library (or static binary) an agent has probes on.
type Target struct {
	PID      int
	HostPath string // /proc/<pid>/root/<path> — crosses the mount namespace
	BuildID  string
	Library  string // "openssl" | "gnutls" | "gotls"
	Inode    uint64
	CgroupID uint64
}

type Reconciler struct {
	objs *Objects
	cfg  *config.Config
	log  *slog.Logger

	mu       sync.Mutex
	attached map[string][]link.Link // keyed by buildID+inode
	cgroups  map[uint64]bool        // cgroups already in the stage-1 approver map
}

// AttachKprobes links the socket-tracking programs.
//
// These were loaded but never attached in an earlier revision, so sock_info
// stayed empty, every event resolved to port 0, and the port approver dropped
// the lot. The sensor captured 195 events and emitted none.
func AttachKprobes(objs *Objects) ([]link.Link, error) {
	kp, err := link.Kprobe("security_socket_connect", objs.SockConnect, nil)
	if err != nil {
		return nil, fmt.Errorf("attach security_socket_connect: %w", err)
	}
	return []link.Link{kp}, nil
}

func NewReconciler(objs *Objects, cfg *config.Config, log *slog.Logger) *Reconciler {
	return &Reconciler{objs: objs, cfg: cfg, log: log,
		attached: map[string][]link.Link{}, cgroups: map[uint64]bool{}}
}

// Run diffs desired attachments against live ones every interval. New containers
// get probes; exited ones have their links closed. A silent detach is visible
// because sentry_agent_uprobes_attached is a gauge, not a counter.
func (r *Reconciler) Run(ctx interface{ Done() <-chan struct{} }) {
	t := time.NewTicker(time.Duration(r.cfg.ReconcileIntervalS) * time.Second)
	defer t.Stop()
	r.reconcile()
	for {
		select {
		case <-ctx.Done():
			r.closeAll()
			return
		case <-t.C:
			r.reconcile()
		}
	}
}

func (r *Reconciler) reconcile() {
	targets, err := r.discover()
	if err != nil {
		r.log.Error("target discovery failed", "err", err)
		return
	}

	desired := map[string]Target{}
	for _, t := range targets {
		desired[t.key()] = t
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for key, t := range desired {
		if _, ok := r.attached[key]; ok {
			continue // a second process mapping the same file is already covered
		}
		links, err := r.attachTo(t)
		if err != nil {
			// Degrade one target, never the whole capture.
			r.log.Warn("attach failed", "pid", t.PID, "lib", t.Library,
				"path", t.HostPath, "err", err)
			continue
		}
		r.attached[key] = links
		r.log.Info("attached", "pid", t.PID, "lib", t.Library, "build_id", t.BuildID)
	}

	for key, links := range r.attached {
		if _, ok := desired[key]; !ok {
			for _, l := range links {
				_ = l.Close()
			}
			delete(r.attached, key)
			r.log.Info("detached", "key", key)
		}
	}
}

// discover walks /proc, filters by cgroup, and locates TLS libraries.
//
// With --pid=host the agent sees every process in the VM. The target's libssl
// lives in another container's filesystem, so it is opened at
// /proc/<pid>/root/<path>, which crosses the mount namespace from the host PID
// namespace without entering it. This is the mechanism bpfman and Pixie use.
func (r *Reconciler) discover() ([]Target, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var out []Target
	seen := map[string]bool{}
	self := os.Getpid()

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}

		if !r.inScope(pid) {
			continue
		}

		maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(maps), "\n") {
			path := mappedPath(line)
			if path == "" {
				continue
			}
			lib := libraryKind(path)
			if lib == "" {
				continue
			}

			hostPath := fmt.Sprintf("/proc/%d/root%s", pid, path)
			fi, err := os.Stat(hostPath)
			if err != nil {
				continue
			}

			buildID, _ := readBuildID(hostPath)
			t := Target{PID: pid, HostPath: hostPath, BuildID: buildID, Library: lib,
				Inode: inodeOf(fi)}

			// Approve before the dedup below. A uprobe is attached per inode and
			// therefore covers every process mapping that library, but each of
			// those processes may live in a different container and so a
			// different cgroup. Approving only the deduplicated target left
			// sibling containers filtered out with no error anywhere.
			r.approveCgroup(pid)

			if seen[t.key()] {
				continue
			}
			seen[t.key()] = true
			out = append(out, t)
		}
	}
	return out, nil
}

// inScope decides whether a task is worth probing.
//
// The cgroup path format is not portable and cannot be matched against a fixed
// prefix. Observed forms:
//
//	/../<id>                              Docker Desktop (LinuxKit)
//	/docker/<id>                          cgroupfs driver
//	/system.slice/docker-<id>.scope       systemd driver
//	/kubepods/besteffort/pod<uid>/<id>    Kubernetes
//
// An earlier revision defaulted TARGET_CGROUP_PREFIX to "/docker" and therefore
// matched nothing on Docker Desktop — the agent attached to zero targets and
// reported no error, which is the worst way for a sensor to fail. The prefix is
// now an optional narrowing filter: empty means every task with a TLS library is
// in scope, and the approver *ports* do the real narrowing.
func (r *Reconciler) inScope(pid int) bool {
	if r.cfg.TargetCgroupPrefix == "" {
		return true
	}
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(cg), r.cfg.TargetCgroupPrefix)
}

func (t Target) key() string {
	if t.BuildID != "" {
		return t.Library + ":" + t.BuildID
	}
	return fmt.Sprintf("%s:inode:%d", t.Library, t.Inode)
}

func (r *Reconciler) attachTo(t Target) ([]link.Link, error) {
	ex, err := link.OpenExecutable(t.HostPath)
	if err != nil {
		return nil, err
	}

	var links []link.Link
	add := func(l link.Link, err error) error {
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}

	switch t.Library {
	case "openssl", "gnutls":
		symWrite, symRead := "SSL_write", "SSL_read"
		if t.Library == "gnutls" {
			symWrite, symRead = "gnutls_record_send", "gnutls_record_recv"
		}
		if err := add(ex.Uprobe(symWrite, r.objs.SslWriteEnter, nil)); err != nil {
			return closeAll(links), err
		}
		if err := add(ex.Uretprobe(symWrite, r.objs.SslWriteExit, nil)); err != nil {
			return closeAll(links), err
		}
		if err := add(ex.Uprobe(symRead, r.objs.SslReadEnter, nil)); err != nil {
			return closeAll(links), err
		}
		// SSL_read's buffer is empty at entry; only the return probe sees data.
		if err := add(ex.Uretprobe(symRead, r.objs.SslReadExit, nil)); err != nil {
			return closeAll(links), err
		}

		// The _ex entry points, where the library has them.
		//
		// Not fatal when absent: OpenSSL below 1.1.1 does not export them and
		// GnuTLS has no equivalent, and a library without them is fully covered
		// by the four probes above. Fatal when present and unattachable, because
		// that is the case where a caller using them — every CPython process in
		// the estate — would go entirely unobserved while the agent reported a
		// healthy attach.
		if t.Library == "openssl" && elfsym.Has(t.HostPath, "SSL_write_ex") {
			for _, p := range []struct {
				sym         string
				enter, exit *ebpf.Program
			}{
				{"SSL_write_ex", r.objs.SslWriteExEnter, r.objs.SslWriteExExit},
				{"SSL_read_ex", r.objs.SslReadExEnter, r.objs.SslReadExExit},
			} {
				if err := add(ex.Uprobe(p.sym, p.enter, nil)); err != nil {
					return closeAll(links), fmt.Errorf("attach %s: %w", p.sym, err)
				}
				if err := add(ex.Uretprobe(p.sym, p.exit, nil)); err != nil {
					return closeAll(links), fmt.Errorf("attach %s return: %w", p.sym, err)
				}
			}
		}

	case "gotls":
		// Go moves goroutine stacks, so a uretprobe cannot rely on the entry
		// stack pointer. Attach at each RET instruction in the function body
		// instead — the standard workaround, used by Pixie and Speedscale.
		if err := add(ex.Uprobe("crypto/tls.(*Conn).Write", r.objs.GoTlsWrite, nil)); err != nil {
			return closeAll(links), err
		}
		rets, err := findReturnOffsets(t.HostPath, "crypto/tls.(*Conn).Read")
		if err != nil {
			return closeAll(links), fmt.Errorf("locate RET instructions: %w", err)
		}
		for _, off := range rets {
			if err := add(ex.Uprobe("crypto/tls.(*Conn).Read", r.objs.GoTlsReadRet,
				&link.UprobeOptions{Address: off})); err != nil {
				return closeAll(links), err
			}
		}
	}

	return links, nil
}

func closeAll(links []link.Link) []link.Link {
	for _, l := range links {
		_ = l.Close()
	}
	return nil
}

func (r *Reconciler) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, links := range r.attached {
		for _, l := range links {
			_ = l.Close()
		}
		delete(r.attached, k)
	}
}

// AttachedCount backs the sentry_agent_uprobes_attached gauge.
func (r *Reconciler) AttachedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, links := range r.attached {
		n += len(links)
	}
	return n
}

// ── helpers ─────────────────────────────────────────────────────────────────

func mappedPath(line string) string {
	// Only executable mappings carry code worth probing. The permissions field
	// is the second column; testing the whole line for "x" matches any path
	// containing that letter, which is most of them.
	fields := strings.Fields(line)
	if len(fields) < 6 || !strings.Contains(fields[1], "x") {
		return ""
	}
	path := fields[len(fields)-1]
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	return path
}

func libraryKind(path string) string {
	base := filepath.Base(path)
	switch {
	case strings.HasPrefix(base, "libssl.so"):
		return "openssl"
	case strings.HasPrefix(base, "libgnutls.so"):
		return "gnutls"
	case isGoBinary(path):
		return "gotls"
	}
	return ""
}

func isGoBinary(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	// .go.buildinfo also carries the Go version, which selects the argument
	// register layout for the crypto/tls probes.
	return f.Section(".go.buildinfo") != nil
}

func readBuildID(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := f.Section(".note.gnu.build-id")
	if s == nil {
		return "", nil
	}
	data, err := s.Data()
	if err != nil || len(data) < 16 {
		return "", err
	}
	return fmt.Sprintf("%x", data[16:]), nil
}

// StatsSnapshot mirrors the per-CPU stats array in the BPF program.
type StatsSnapshot struct {
	Captured          uint64
	FilteredApprover  uint64
	FilteredDiscarder uint64
	Emitted           uint64
	FilteredCgroup    uint64
	RingbufLost       uint64
}

// SeedApprovers loads the static stage-1 filter. Anything outside these ports
// and the watched cgroups is rejected in kernel before a byte is copied.
func SeedApprovers(objs *Objects, ports []uint16) error {
	for _, p := range ports {
		one := uint8(1)
		if err := objs.ApproverPorts.Put(&p, &one); err != nil {
			return fmt.Errorf("seed port %d: %w", p, err)
		}
	}
	return nil
}

// AddDiscarder writes a known-noise signature so the kernel drops matching
// events without a ring-buffer write. The map is an LRU, so a signature that
// stops appearing ages out and the filter cannot permanently blind the sensor.
func AddDiscarder(objs *Objects, sig uint64) error {
	now := uint64(time.Now().UnixNano())
	return objs.Discarders.Put(&sig, &now)
}

func readPerCPU(m *ebpf.Map, key uint32) (uint64, error) {
	var vals []uint64
	if err := m.Lookup(&key, &vals); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total, nil
}
