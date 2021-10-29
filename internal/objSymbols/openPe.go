package symbols

import (
	"debug/pe"
	"io"
)

type peFile struct {
	pe *pe.File
}

func openPE(r io.ReaderAt) (rawFile, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &peFile{f}, nil
}

func (f *peFile) Symbols() (map[string]uintptr, error) {
	if f.pe.Symbols == nil {
		return nil, nil
	}
	elfOff := make(map[string]uintptr, 0)
	for _, s := range f.pe.Symbols {
		elfOff[s.Name] = uintptr(s.Value)

	}
	return elfOff, nil
}
