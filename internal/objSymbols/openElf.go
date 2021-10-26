package symbols

import (
	"debug/elf"
	"io"
)

type elfFile struct {
	elf *elf.File
}

func openElf(r io.ReaderAt) (rawFile, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &elfFile{f}, nil
}

func (e *elfFile) Symbols() (map[string]uintptr, error) {
	elfSyms, err := e.elf.Symbols()
	if err != nil {
		return nil, err
	}
	return getElfOff(elfSyms)
}

func getElfOff(stab []elf.Symbol) (map[string]uintptr, error) {
	elfOff := make(map[string]uintptr, 0)
	for _, k := range stab {
		elfOff[k.Name] = uintptr(k.Value)
	}
	return elfOff, nil
}
