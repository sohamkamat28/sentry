package elfsym

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// A library is located by parsing it, not by assuming what a version exports.
// The assumption this replaces — that any OpenSSL exposes SSL_write — is true
// and useless: CPython calls SSL_write_ex, so the agent attached successfully to
// a library whose callers used entry points it was not watching.

func TestAMissingFileAnswersFalseRatherThanFailing(t *testing.T) {
	if Has(filepath.Join(t.TempDir(), "nope.so"), "SSL_write") {
		t.Fatal("a path that does not exist reported a symbol")
	}
}

func TestANonELFFileAnswersFalse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-elf.so")
	if err := os.WriteFile(p, []byte("this is not an ELF file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if Has(p, "SSL_write") {
		t.Fatal("a non-ELF file reported a symbol")
	}
}

// Builds a real shared library and reads its symbols back, so the parsing is
// exercised against something a linker produced rather than a fixture.
func TestExportedSymbolsAreFoundAndOthersAreNot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("needs a C toolchain")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler on this host")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "lib.c")
	if err := os.WriteFile(src, []byte(`
int SSL_write(void *s, const void *b, int n) { (void)s; (void)b; return n; }
int SSL_write_ex(void *s, const void *b, unsigned long n, unsigned long *w) {
    (void)s; (void)b; if (w) *w = n; return 1;
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// ELF specifically: the agent only ever reads Linux libraries, and a Mach-O
	// build here would test nothing about the code path that runs.
	out := filepath.Join(dir, "libfake.so")
	cmd := exec.Command(cc, "-shared", "-fPIC", "-o", out, src)
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot build a shared library here: %v", err)
	}
	if !isELF(out) {
		t.Skip("host toolchain does not produce ELF")
	}

	if !Has(out, "SSL_write_ex") {
		t.Error("SSL_write_ex is exported but was not found")
	}
	if !Has(out, "SSL_write") {
		t.Error("SSL_write is exported but was not found")
	}
	if Has(out, "SSL_read_ex") {
		t.Error("SSL_read_ex is not in this library but was reported present")
	}
}

func TestForgetDropsTheCachedTable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gone.so")
	_ = Has(p, "SSL_write")

	mu.Lock()
	_, cached := cache[p]
	mu.Unlock()
	if !cached {
		t.Fatal("expected the negative result to be cached")
	}

	Forget(p)

	mu.Lock()
	_, cached = cache[p]
	mu.Unlock()
	if cached {
		t.Fatal("Forget left the entry in place; a replaced library would never be re-read")
	}
}

func isELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return magic == [4]byte{0x7f, 'E', 'L', 'F'}
}
