// Package identity names the workload an observation came from.
//
// The kernel reports a pid and a cgroup id. Neither is a service name, and the
// pipeline needs a name: stage 03 keys call edges on the calling service, and
// without one the call graph has no edges at all — every endpoint scores a ZERO
// blast radius and the dependency argument the product rests on cannot be made.
//
// Resolution is deliberately lazy and keyed on the *kernel's own* cgroup id
// rather than on anything userspace computes. Deriving a cgroup id in userspace
// means reading /proc/<pid>/cgroup and stat-ing the result, which is reported
// relative to the reading task's cgroup namespace and does not agree with
// bpf_get_current_cgroup_id() when the agent has a namespace of its own. Using
// the id the kernel already put in the event sidesteps the disagreement
// entirely: the first event from a container resolves its name while the
// process is still alive, and every later event from that container is a map
// hit.
package identity

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
)

// nameVars are consulted in order. The first non-empty value wins.
//
// OTEL_SERVICE_NAME is the OpenTelemetry resource convention and is the one
// most likely to already be set in an instrumented estate. SENTRY_SERVICE
// exists so an operator can override a wrong or missing value without touching
// the workload's own configuration.
var nameVars = []string{
	"SENTRY_SERVICE",
	"OTEL_SERVICE_NAME",
	"SERVICE_NAME",
	"K8S_POD_NAME",
	"APP_NAME",
}

// maxAttempts bounds re-resolution for a cgroup that has never produced a name.
//
// Short-lived clients are the reason this is not one: a process can exit between
// the SSL_write that produced the event and the /proc read that would name it,
// so a single failure means nothing. A cgroup that has failed this many times is
// one whose processes carry no identity, and retrying it per event would put a
// /proc walk on the hot path forever.
const maxAttempts = 8

// nameLimit matches observation.peer_service in the schema. A longer value would
// be rejected at insert, which would drop the whole batch rather than the name.
const nameLimit = 128

// Resolver maps kernel cgroup ids to service names.
//
// Safe for concurrent use: the ring-buffer consumer resolves, and the health
// endpoint reads the table.
type Resolver struct {
	procRoot string

	mu       sync.RWMutex
	names    map[uint64]string
	attempts map[uint64]int
}

func New() *Resolver { return NewWithRoot("/proc") }

// NewWithRoot builds a resolver over an arbitrary proc tree, which is what makes
// the parsing testable without a Linux kernel underneath it.
func NewWithRoot(procRoot string) *Resolver {
	return &Resolver{
		procRoot: procRoot,
		names:    make(map[uint64]string),
		attempts: make(map[uint64]int),
	}
}

// Lookup names the workload that owns a cgroup, reading /proc for it the first
// time and answering from the table afterwards. An empty string means the
// workload could not be named — the caller must leave the field unset rather
// than substitute anything.
func (r *Resolver) Lookup(cgroupID uint64, pid uint32) string {
	if cgroupID == 0 && pid == 0 {
		return ""
	}

	r.mu.RLock()
	name, known := r.names[cgroupID]
	tries := r.attempts[cgroupID]
	r.mu.RUnlock()

	if known {
		return name
	}
	if tries >= maxAttempts {
		return ""
	}

	name = r.resolve(pid)

	r.mu.Lock()
	if name != "" {
		r.names[cgroupID] = name
	} else {
		r.attempts[cgroupID]++
	}
	r.mu.Unlock()

	return name
}

// resolve reads a name out of a live process.
func (r *Resolver) resolve(pid uint32) string {
	if pid == 0 {
		return ""
	}
	if n := r.fromEnviron(pid); n != "" {
		return n
	}
	if n := r.fromHostname(pid); n != "" {
		return n
	}
	return r.fromCgroupPath(pid)
}

// fromEnviron reads the process environment.
//
// This is the declared identity of the workload rather than an artefact of how
// it was scheduled, which is why it is tried first.
func (r *Resolver) fromEnviron(pid uint32) string {
	raw, err := os.ReadFile(fmt.Sprintf("%s/%d/environ", r.procRoot, pid))
	if err != nil {
		return ""
	}

	env := make(map[string]string, 32)
	for _, entry := range bytes.Split(raw, []byte{0}) {
		k, v, ok := strings.Cut(string(entry), "=")
		if ok && env[k] == "" {
			env[k] = v
		}
	}
	for _, key := range nameVars {
		if n := sanitise(env[key]); n != "" {
			return n
		}
	}
	return ""
}

// fromHostname reads /etc/hostname inside the target's mount namespace.
//
// Compose and Kubernetes both put a meaningful name here. Docker on its own
// puts the short container id, which is an identity but not a name — that case
// is caught by looksLikeContainerID and handled by fromCgroupPath instead, so
// the two paths cannot disagree about the prefix.
func (r *Resolver) fromHostname(pid uint32) string {
	raw, err := os.ReadFile(fmt.Sprintf("%s/%d/root/etc/hostname", r.procRoot, pid))
	if err != nil {
		return ""
	}
	name := sanitise(string(raw))
	if name == "" || looksLikeContainerID(name) {
		return ""
	}
	return name
}

// fromCgroupPath is the last resort: the container id itself.
//
// It is prefixed so that nothing downstream can mistake an opaque id for a
// service name an operator would recognise. A graph node labelled
// container:3f9a1c8e2b04 is a truthful statement that the workload was seen but
// not identified; a node labelled 3f9a1c8e2b04 is not.
func (r *Resolver) fromCgroupPath(pid uint32) string {
	raw, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", r.procRoot, pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, seg := range strings.Split(parts[2], "/") {
			seg = strings.TrimSuffix(strings.TrimPrefix(seg, "docker-"), ".scope")
			if looksLikeContainerID(seg) {
				return "container:" + seg[:12]
			}
		}
	}
	return ""
}

// Names returns a copy of the resolved table, for the health endpoint.
func (r *Resolver) Names() map[uint64]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[uint64]string, len(r.names))
	for k, v := range r.names {
		out[k] = v
	}
	return out
}

// Resolved reports how many workloads have been named. Zero while events are
// arriving means every call edge is being dropped.
func (r *Resolver) Resolved() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.names)
}

// Unresolved reports how many cgroups have been seen and could not be named.
func (r *Resolver) Unresolved() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.attempts)
}

func sanitise(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(rn rune) rune {
		// Control characters and quotes would survive into a database column and
		// then into the console. Dropping them here keeps the name printable.
		if rn < 0x20 || rn == 0x7f || rn == '"' || rn == '\'' {
			return -1
		}
		return rn
	}, s)
	if len(s) > nameLimit {
		s = s[:nameLimit]
	}
	return s
}

// looksLikeContainerID reports whether a string is a 64- or 12-character hex id.
func looksLikeContainerID(s string) bool {
	if len(s) != 64 && len(s) != 12 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
