// Package elfsym answers whether a shared library exports a given symbol.
//
// The agent needs this because which entry points a TLS library exposes decides
// which probes can be attached, and getting it wrong is silent: a process
// calling an unprobed entry point produces no events and no error. CPython's
// ssl module calls SSL_write_ex rather than SSL_write, so an agent that assumes
// the classic names observes nothing at all in a Python estate while reporting
// a successful attach.
//
// No build tag: this is ELF parsing, and it runs on the machine doing the build
// as readily as on the one running the kernel.
package elfsym

import (
	"debug/elf"
	"sync"
)

// cache keys on the library path. A reconcile pass revisits the same handful of
// libraries every few seconds, and the answer cannot change without the file
// changing.
var (
	mu    sync.Mutex
	cache = map[string]map[string]bool{}
)

// Has reports whether the ELF at path exports name in its dynamic symbol table.
//
// A file that cannot be opened or parsed answers false, which biases towards
// not attaching a probe that would fail anyway.
func Has(path, name string) bool {
	mu.Lock()
	syms, ok := cache[path]
	mu.Unlock()

	if !ok {
		syms = load(path)
		mu.Lock()
		cache[path] = syms
		mu.Unlock()
	}
	return syms[name]
}

func load(path string) map[string]bool {
	out := map[string]bool{}

	f, err := elf.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()

	// Dynamic symbols are the ones a uprobe can be attached by name. Static
	// symbols in .symtab are stripped from most distribution libraries and
	// would not be resolvable anyway.
	dyn, err := f.DynamicSymbols()
	if err != nil {
		return out
	}
	for _, s := range dyn {
		// A symbol with no value is undefined here — imported from elsewhere,
		// not exported. Attaching to it would fail.
		if s.Value != 0 {
			out[s.Name] = true
		}
	}
	return out
}

// Forget drops the cached table for a path, so a library replaced underneath a
// long-running agent is re-read rather than remembered.
func Forget(path string) {
	mu.Lock()
	delete(cache, path)
	mu.Unlock()
}
