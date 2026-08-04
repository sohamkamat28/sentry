package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeProc builds a proc tree the resolver can be pointed at, so the parsing is
// exercised without a Linux kernel or a running container underneath it.
type fakeProc struct{ root string }

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	return &fakeProc{root: t.TempDir()}
}

func (f *fakeProc) pid(t *testing.T, pid int, environ map[string]string, hostname, cgroup string) {
	t.Helper()
	dir := filepath.Join(f.root, itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "root", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if environ != nil {
		var buf []byte
		for k, v := range environ {
			buf = append(buf, []byte(k+"="+v)...)
			buf = append(buf, 0)
		}
		write(t, filepath.Join(dir, "environ"), string(buf))
	}
	if hostname != "" {
		write(t, filepath.Join(dir, "root", "etc", "hostname"), hostname+"\n")
	}
	if cgroup != "" {
		write(t, filepath.Join(dir, "cgroup"), cgroup+"\n")
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestEnvironNameWinsOverHostname(t *testing.T) {
	f := newFakeProc(t)
	f.pid(t, 41, map[string]string{"SERVICE_NAME": "core-accounts"}, "3f9a1c8e2b04", "")

	r := NewWithRoot(f.root)
	if got := r.Lookup(1000, 41); got != "core-accounts" {
		t.Fatalf("got %q, want core-accounts", got)
	}
}

func TestOverrideBeatsOtelBeatsServiceName(t *testing.T) {
	f := newFakeProc(t)
	f.pid(t, 42, map[string]string{
		"SERVICE_NAME":      "wrong",
		"OTEL_SERVICE_NAME": "also-wrong",
		"SENTRY_SERVICE":    "payments-upi",
	}, "", "")

	r := NewWithRoot(f.root)
	if got := r.Lookup(1001, 42); got != "payments-upi" {
		t.Fatalf("got %q, want payments-upi", got)
	}
}

func TestHostnameUsedWhenItIsNotAContainerID(t *testing.T) {
	f := newFakeProc(t)
	f.pid(t, 43, map[string]string{"PATH": "/usr/bin"}, "kyc-service", "")

	r := NewWithRoot(f.root)
	if got := r.Lookup(1002, 43); got != "kyc-service" {
		t.Fatalf("got %q, want kyc-service", got)
	}
}

// A bare container id is an identity, not a name. Reporting it unprefixed would
// let an opaque hex string sit in the console's dependency graph looking like a
// service an operator should recognise.
func TestContainerIDHostnameFallsThroughToPrefixedForm(t *testing.T) {
	f := newFakeProc(t)
	f.pid(t, 44, nil, "3f9a1c8e2b04",
		"0::/system.slice/docker-3f9a1c8e2b04aa11bb22cc33dd44ee55ff660077889900112233445566778899.scope")

	r := NewWithRoot(f.root)
	got := r.Lookup(1003, 44)
	if got != "container:3f9a1c8e2b04" {
		t.Fatalf("got %q, want container:3f9a1c8e2b04", got)
	}
}

func TestUnnameableWorkloadReturnsEmptyNotAGuess(t *testing.T) {
	f := newFakeProc(t)
	f.pid(t, 45, map[string]string{"PATH": "/usr/bin"}, "", "0::/")

	r := NewWithRoot(f.root)
	if got := r.Lookup(1004, 45); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

// The first event from a container resolves the name; the process may be gone by
// the second. Caching on the kernel's cgroup id is what keeps short-lived
// clients — a curl per request — from being named once and unnamed thereafter.
func TestNameSurvivesTheProcessThatSuppliedIt(t *testing.T) {
	f := newFakeProc(t)
	f.pid(t, 46, map[string]string{"SERVICE_NAME": "traffic"}, "", "")

	r := NewWithRoot(f.root)
	if got := r.Lookup(1005, 46); got != "traffic" {
		t.Fatalf("first lookup got %q", got)
	}
	if err := os.RemoveAll(filepath.Join(f.root, "46")); err != nil {
		t.Fatal(err)
	}
	// A different pid in the same cgroup, with no /proc entry at all.
	if got := r.Lookup(1005, 47); got != "traffic" {
		t.Fatalf("after process exit got %q, want traffic", got)
	}
}

func TestRepeatedFailureStopsReadingProc(t *testing.T) {
	r := NewWithRoot(t.TempDir())
	for i := 0; i < maxAttempts+5; i++ {
		r.Lookup(1006, 99)
	}
	if r.Unresolved() != 1 {
		t.Fatalf("unresolved=%d, want 1", r.Unresolved())
	}
	if r.Resolved() != 0 {
		t.Fatalf("resolved=%d, want 0", r.Resolved())
	}
}

func TestNameIsTruncatedToTheColumnWidth(t *testing.T) {
	long := ""
	for i := 0; i < 400; i++ {
		long += "x"
	}
	f := newFakeProc(t)
	f.pid(t, 48, map[string]string{"SERVICE_NAME": long}, "", "")

	r := NewWithRoot(f.root)
	if got := r.Lookup(1007, 48); len(got) != nameLimit {
		t.Fatalf("len=%d, want %d", len(got), nameLimit)
	}
}
