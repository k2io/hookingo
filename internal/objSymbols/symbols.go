package symbols

import (
	"fmt"
	"io"
	"os"
)

type rawFile interface {
	Symbols() (map[string]uintptr, error)
}

var objType = []func(io.ReaderAt) (rawFile, error){
	openElf,
	openMacho,
	openPE,
}

func ReadSymbols(name string) (map[string]uintptr, error) {
	r, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	for _, try := range objType {
		if raw, err := try(r); err == nil {
			return raw.Symbols()
		}
	}
	r.Close()
	return nil, fmt.Errorf("open %s: unrecognized object file", name)
}
