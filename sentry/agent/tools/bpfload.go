// Loads the SENTRY BPF object into the running kernel and reports what the
// verifier said. This is the check that separates "clang accepted it" from
// "the kernel will run it".
// Command bpfload loads the SENTRY BPF object into the running kernel.
package main

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println("FATAL memlock:", err)
		os.Exit(1)
	}

	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		fmt.Println("FATAL parse:", err)
		os.Exit(1)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("VERIFIER REJECTED:\n%+v\n", ve)
			os.Exit(1)
		}
		fmt.Println("FATAL load:", err)
		os.Exit(1)
	}
	defer coll.Close()

	var names []string
	for n := range coll.Programs {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Println("VERIFIER ACCEPTED ALL PROGRAMS")
	for _, n := range names {
		p := coll.Programs[n]
		info, _ := p.Info()
		id, _ := info.ID()
		fmt.Printf("  %-20s loaded  type=%v  id=%v\n", n, p.Type(), id)
	}

	var maps []string
	for n := range coll.Maps {
		maps = append(maps, n)
	}
	sort.Strings(maps)
	fmt.Println("MAPS CREATED IN KERNEL:")
	for _, n := range maps {
		m := coll.Maps[n]
		info, _ := m.Info()
		id, _ := info.ID()
		fmt.Printf("  %-20s type=%-16v max=%-8d id=%v\n", n, m.Type(), m.MaxEntries(), id)
	}
}
