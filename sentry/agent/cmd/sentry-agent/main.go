//go:build linux

// SENTRY kernel sensor.
//
// Startup is deliberately unforgiving. Every precondition below is checked
// before a probe is attached, and a failure exits non-zero naming the exact
// remediation. The agent never starts in a degraded mode and never silently
// falls back to a userspace tap — this deployment is kernel capture or nothing,
// because a sensor that quietly sees less than it claims is worse than one that
// refuses to run.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/sentry/agent/internal/attach"
	"github.com/sentry/agent/internal/btf"
	"github.com/sentry/agent/internal/config"
	"github.com/sentry/agent/internal/identity"
	"github.com/sentry/agent/internal/ringbuf"
	"github.com/sentry/agent/internal/ship"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		fatal("CONFIG", err.Error(), "check the environment variables listed in design/10-STAGE-01")
	}

	if err := preflight(cfg); err != nil {
		var p *preflightError
		if errors.As(err, &p) {
			fatal(p.check, p.detail, p.remedy)
		}
		fatal("PREFLIGHT", err.Error(), "")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fatal("MEMLOCK", err.Error(), "run the container privileged, or set ulimits.memlock=-1")
	}

	btfPath, err := btf.Resolve(cfg.BTFPath)
	if err != nil {
		// The LinuxKit kernel in Docker Desktop does not enable BTF by default.
		// Say so, and say exactly what to do about it.
		fatal("BTF",
			err.Error(),
			"mount /sys/kernel/btf, or supply BTF_PATH=/opt/sentry/btf/<kernel-release>.btf "+
				"(vendored blobs ship in the agent image for pinned Docker Desktop kernels)")
	}
	log.Info("btf resolved", "path", btfPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	objs, err := attach.LoadObjects(btfPath)
	if err != nil {
		fatal("BPF_LOAD", err.Error(),
			"the program failed the kernel verifier; run the agent's BPF test suite on this kernel")
	}
	defer objs.Close()

	if err := attach.SeedApprovers(objs, cfg.ApproverPorts); err != nil {
		fatal("APPROVER_SEED", err.Error(), "")
	}

	// Cgroup scoping only when the operator asked for it.
	if err := attach.SetCgroupFilter(objs, cfg.TargetCgroupPrefix != ""); err != nil {
		fatal("SETTINGS", err.Error(), "")
	}

	kprobes, err := attach.AttachKprobes(objs)
	if err != nil {
		fatal("KPROBE", err.Error(),
			"the socket-tracking probe could not attach; peer ports cannot be resolved")
	}
	defer func() {
		for _, l := range kprobes {
			_ = l.Close()
		}
	}()

	shipper, err := ship.New(ctx, cfg, version)
	if err != nil {
		fatal("INGEST", err.Error(), "check INGEST_ENDPOINT is reachable")
	}
	defer shipper.Close()

	reconciler := attach.NewReconciler(objs, cfg, log)
	ident := identity.New()
	consumer, err := ringbuf.New(objs, shipper, ident, log)
	if err != nil {
		fatal("RINGBUF", err.Error(), "")
	}

	go consumer.Run(ctx)
	go reportShipping(ctx, shipper, ident, log)
	go reconciler.Run(ctx)
	go reportStats(ctx, objs, log)

	log.Info("sentry-agent started",
		"version", version,
		"ingest", cfg.IngestEndpoint,
		"cgroup_prefix", cfg.TargetCgroupPrefix,
		"scan_bytes", cfg.ScanBytes)

	<-ctx.Done()
	log.Info("shutting down")
	time.Sleep(500 * time.Millisecond) // let the shipper drain
}

type preflightError struct {
	check  string
	detail string
	remedy string
}

func (e *preflightError) Error() string { return e.check + ": " + e.detail }

// preflight enforces the platform requirements. Each returns its own fix.
func preflight(cfg *config.Config) error {
	if runtimeGOOS() != "linux" {
		return &preflightError{
			"PLATFORM",
			"eBPF requires Linux; this binary is running on " + runtimeGOOS(),
			"run the agent inside a Linux container. On macOS that is the Docker Desktop VM, " +
				"which observes containers in that VM but not macOS host processes",
		}
	}

	maj, min, err := kernelVersion()
	if err != nil {
		return &preflightError{"KERNEL", err.Error(), "could not read the kernel release"}
	}
	if maj < 5 || (maj == 5 && min < 8) {
		return &preflightError{
			"KERNEL",
			fmt.Sprintf("ring buffer requires kernel 5.8+, found %d.%d", maj, min),
			"upgrade the host kernel",
		}
	}

	// Host PID namespace is required to reach a target's libssl through
	// /proc/<pid>/root, which is how a uprobe is attached across a mount
	// namespace boundary without entering it.
	self, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return &preflightError{"PROC", err.Error(), "mount /proc"}
	}
	init, err := os.Readlink("/proc/1/ns/pid")
	if err == nil && self != init {
		return &preflightError{
			"PID_NAMESPACE",
			"not running in the host PID namespace",
			"run with --pid=host (compose) or hostPID: true (kubernetes)",
		}
	}

	if _, err := os.Stat("/sys/kernel/debug"); err != nil {
		return &preflightError{
			"DEBUGFS",
			"/sys/kernel/debug is not present",
			"mount -t debugfs none /sys/kernel/debug, or mount it into the container",
		}
	}

	return nil
}

func fatal(check, detail, remedy string) {
	slog.Error("startup precondition failed", "check", check, "detail", detail, "remedy", remedy)
	fmt.Fprintf(os.Stderr, "\nFATAL [%s] %s\n", check, detail)
	if remedy != "" {
		fmt.Fprintf(os.Stderr, "  fix: %s\n", remedy)
	}
	os.Exit(1)
}

// reportShipping surfaces how many body writes were joined to their header and
// how many arrived too late to be. A rising orphan count means the batch window
// is shorter than the gap between a header and its body.
func reportShipping(ctx context.Context, s *ship.Shipper, ident *identity.Resolver, log *slog.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// callers_unnamed is the one to watch: a workload the resolver could
			// not name contributes no call-graph edge, so its dependants score a
			// blast radius of ZERO on missing evidence rather than on absence of
			// dependants.
			log.Info("shipping",
				"sent", s.Sent(),
				"body_merged", s.Merged(),
				"body_orphaned", s.Orphaned(),
				"queue_dropped", s.Dropped(),
				"callers_named", ident.Resolved(),
				"callers_unnamed", ident.Unresolved())
		}
	}
}

func reportStats(ctx context.Context, objs *attach.Objects, log *slog.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s, err := attach.ReadStats(objs)
			if err != nil {
				continue
			}
			// The reduction ratio is reported as a measurement, not asserted.
			log.Info("filter",
				"captured", s.Captured,
				"dropped_cgroup", s.FilteredCgroup,
				"dropped_port", s.FilteredApprover,
				"dropped_discarder", s.FilteredDiscarder,
				"emitted", s.Emitted,
				"ringbuf_lost", s.RingbufLost)
			if cg, err := attach.LastObservedCgroupID(objs); err == nil && cg != 0 {
				log.Debug("last observed cgroup id", "cgroup_id", cg)
			}
		}
	}
}
