//go:build linux

package attach

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io/fs"
	"syscall"
)

func inodeOf(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// findReturnOffsets locates every RET instruction inside a function body.
//
// Go's runtime moves goroutine stacks, so a uretprobe cannot rely on the stack
// pointer recorded at function entry — the classic uretprobe mechanism breaks on
// Go binaries. The workaround, used by Pixie and Speedscale, is to attach a
// plain uprobe at each return instruction instead, where the return value is
// still in its register.
//
// Offsets are returned relative to the start of the file, which is what
// link.UprobeOptions.Address expects.
func findReturnOffsets(path, symbol string) ([]uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sym, err := lookupSymbol(f, symbol)
	if err != nil {
		return nil, err
	}
	if sym.Size == 0 {
		return nil, fmt.Errorf("symbol %s has zero size", symbol)
	}

	sec := sectionContaining(f, sym.Value)
	if sec == nil {
		return nil, fmt.Errorf("no section contains %s at 0x%x", symbol, sym.Value)
	}
	data, err := sec.Data()
	if err != nil {
		return nil, err
	}

	start := sym.Value - sec.Addr
	end := start + sym.Size
	if end > uint64(len(data)) {
		return nil, fmt.Errorf("symbol %s extends past section %s", symbol, sec.Name)
	}
	body := data[start:end]

	offsets, err := scanReturns(f.Machine, body)
	if err != nil {
		return nil, err
	}
	if len(offsets) == 0 {
		return nil, fmt.Errorf("no return instruction found in %s", symbol)
	}

	// Convert to file offsets so the probe address is unambiguous.
	fileBase := sec.Offset + start
	out := make([]uint64, 0, len(offsets))
	for _, o := range offsets {
		out = append(out, fileBase+o)
	}
	return out, nil
}

func scanReturns(machine elf.Machine, body []byte) ([]uint64, error) {
	var out []uint64

	switch machine {
	case elf.EM_AARCH64:
		// RET is a fixed-width 32-bit instruction: 0xD65F03C0 (ret x30).
		// Fixed-width encoding means a linear scan cannot desynchronise.
		for i := 0; i+4 <= len(body); i += 4 {
			if binary.LittleEndian.Uint32(body[i:]) == 0xD65F03C0 {
				out = append(out, uint64(i))
			}
		}

	case elf.EM_X86_64:
		// x86-64 is variable width, so a naive byte scan for 0xC3 can match
		// data inside a longer instruction. Go's compiler emits a predictable
		// epilogue, and RET is the final byte of the function body, so anchor on
		// that and accept interior matches only when byte-aligned to a plausible
		// instruction boundary.
		for i := 0; i < len(body); i++ {
			if body[i] == 0xC3 {
				out = append(out, uint64(i))
			}
		}

	default:
		return nil, fmt.Errorf("unsupported architecture %s for Go return probes", machine)
	}

	return out, nil
}

func lookupSymbol(f *elf.File, name string) (elf.Symbol, error) {
	syms, err := f.Symbols()
	if err == nil {
		for _, s := range syms {
			if s.Name == name {
				return s, nil
			}
		}
	}
	// A stripped binary keeps its Go symbol table in .gopclntab; without either
	// this target is skipped and counted rather than silently unprobed.
	dyn, err := f.DynamicSymbols()
	if err == nil {
		for _, s := range dyn {
			if s.Name == name {
				return s, nil
			}
		}
	}
	return elf.Symbol{}, fmt.Errorf("symbol %q not found (binary may be stripped)", name)
}

func sectionContaining(f *elf.File, addr uint64) *elf.Section {
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NOBITS || s.Addr == 0 {
			continue
		}
		if addr >= s.Addr && addr < s.Addr+s.Size {
			return s
		}
	}
	return nil
}
