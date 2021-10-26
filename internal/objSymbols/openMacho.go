package symbols

import (
	"debug/macho"
	"io"
)

type machoFile struct {
	macho *macho.File
}

func openMacho(r io.ReaderAt) (rawFile, error) {
	f, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &machoFile{f}, nil
}

func (f *machoFile) Symbols() (map[string]uintptr, error) {
	if f.macho.Symtab == nil {
		return nil, nil
	}
	elfOff := make(map[string]uintptr, 0)
	for _, s := range f.macho.Symtab.Syms {
		elfOff[s.Name] = uintptr(s.Value)

	}
	return nil, nil
}
