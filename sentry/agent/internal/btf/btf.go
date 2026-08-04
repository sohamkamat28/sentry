// Package btf resolves BPF Type Format data for CO-RE relocation.
//
// The LinuxKit kernel shipped with Docker Desktop does not enable BTF by
// default, so resolution is a chain rather than a single path. If none of the
// steps succeed the agent exits: it does not fall back to a non-CO-RE build and
// it does not fall back to a userspace tap.
package btf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VendorDir holds .btf blobs baked into the agent image at build time, generated
// with `pahole -J` against the matching LinuxKit kernel-dev image.
const VendorDir = "/opt/sentry/btf"

// Resolve returns a path to usable BTF data, or an error naming every location
// that was tried.
func Resolve(configured string) (string, error) {
	var tried []string

	if configured != "" {
		if ok(configured) {
			return configured, nil
		}
		tried = append(tried, configured)
	}

	if configured != "/sys/kernel/btf/vmlinux" && ok("/sys/kernel/btf/vmlinux") {
		return "/sys/kernel/btf/vmlinux", nil
	}
	tried = append(tried, "/sys/kernel/btf/vmlinux")

	release, err := KernelRelease()
	if err == nil {
		vendored := filepath.Join(VendorDir, release+".btf")
		if ok(vendored) {
			return vendored, nil
		}
		tried = append(tried, vendored)
	}

	return "", fmt.Errorf("no BTF found (tried: %s)", strings.Join(tried, ", "))
}

func ok(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// KernelRelease reads the running kernel release, used to select a vendored blob.
func KernelRelease() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
