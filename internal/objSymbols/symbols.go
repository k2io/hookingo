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
	// openPE,
	// openPlan9,
	// openXcoff,
	// openElf,
}

func ReadSymbols(name string) (map[string]uintptr, error) {

	fmt.Println("ReadSymbols: ", name)

	r, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	// if f, err := openGoFile(r); err == nil {
	// 	fmt.Println(f)
	// 	return f, nil
	// }
	for _, try := range objType {
		if raw, err := try(r); err == nil {
			return raw.Symbols()
		} else {
			fmt.Println(err)
		}
	}
	r.Close()
	return nil, fmt.Errorf("open %s: unrecognized object file", name)
}
