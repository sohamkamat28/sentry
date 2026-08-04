//go:build linux

package attach

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// CgroupRoot is the cgroup v2 mount point.
const CgroupRoot = "/sys/fs/cgroup"

// cgroupIDFor returns the id bpf_get_current_cgroup_id() will report for a task.
//
// That helper returns the *inode number* of the task's cgroup v2 directory, so
// resolving it is a matter of reading the task's cgroup path and stat-ing the
// corresponding directory. There is no helper that maps the other way, which is
// why the agent has to do this in userspace and keep the approver map populated.
func cgroupIDFor(pid int) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, err
	}

	// cgroup v2 has a single unified entry of the form "0::/path".
	var rel string
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			rel = parts[2]
			break
		}
	}
	if rel == "" {
		return 0, fmt.Errorf("no cgroup v2 entry for pid %d", pid)
	}

	// Candidate paths, in order.
	//
	// /proc/<pid>/cgroup is reported relative to the *reading* task's cgroup
	// namespace. Without --cgroupns=host the agent has its own root and sibling
	// containers appear as "/../<id>", which resolves outside the mount and
	// cannot be stat-ed. Falling back to the bare id at the cgroup root covers
	// that case; the canonical fix is to run with --cgroupns=host, and readyz
	// reports zero approved cgroups when neither works.
	candidates := []string{
		CgroupRoot + rel,
		CgroupRoot + "/" + strings.TrimLeft(rel, "./"),
	}
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		candidates = append(candidates, CgroupRoot+"/"+rel[i+1:])
	}

	var st syscall.Stat_t
	for _, c := range candidates {
		if err := syscall.Stat(c, &st); err == nil {
			return st.Ino, nil
		}
	}
	return 0, fmt.Errorf("no cgroup directory found for pid %d (tried %v); "+
		"run the agent with --cgroupns=host", pid, candidates)
}

// approveCgroup adds a cgroup to the stage-1 filter.
//
// Without this the map stays empty, every lookup in should_emit() misses, and
// the sensor drops one hundred percent of what it captures — visible only as a
// filtered count, which is exactly the kind of silent nothing this design is
// meant to avoid.
func (r *Reconciler) approveCgroup(pid int) {
	id, err := cgroupIDFor(pid)
	if err != nil {
		r.log.Warn("cgroup id unresolved; events from this task will be filtered",
			"pid", pid, "err", err)
		return
	}

	r.mu.Lock()
	already := r.cgroups[id]
	if !already {
		r.cgroups[id] = true
	}
	r.mu.Unlock()
	if already {
		return
	}

	one := uint8(1)
	if err := r.objs.ApproverCgroups.Put(&id, &one); err != nil {
		r.log.Error("approver cgroup write failed", "cgroup_id", id, "err", err)
		return
	}
	r.log.Info("cgroup approved for capture", "pid", pid, "cgroup_id", id)
}

// ApprovedCgroups reports how many cgroups are in the stage-1 filter. Zero means
// the sensor is attached but will emit nothing.
func (r *Reconciler) ApprovedCgroups() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cgroups)
}
