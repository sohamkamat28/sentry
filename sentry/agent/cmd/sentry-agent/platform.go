//go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func runtimeGOOS() string { return runtime.GOOS }

// kernelVersion reads the running kernel's major and minor version.
//
// The ring buffer used by the sensor requires 5.8+, and bpf_loop() — which the
// data-class scanner depends on — requires 5.17. Checking here means an
// unsupported kernel produces a named error at startup instead of a verifier
// rejection halfway through attach.
func kernelVersion() (int, int, error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return 0, 0, fmt.Errorf("read kernel release: %w", err)
	}

	release := strings.TrimSpace(string(b))
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("unrecognised kernel release %q", release)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("unrecognised kernel major in %q", release)
	}

	// The minor component can carry a suffix, as in "6.10.14-linuxkit".
	minorStr := parts[1]
	for i, r := range minorStr {
		if r < '0' || r > '9' {
			minorStr = minorStr[:i]
			break
		}
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("unrecognised kernel minor in %q", release)
	}

	return major, minor, nil
}
