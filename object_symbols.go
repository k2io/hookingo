package hookingo

import (
	sym "github.com/k2io/hookingo/internal/objSymbols"
)

func GetSymbols(name string) (map[string]uintptr, error) {
	return sym.ReadSymbols(name)
}
