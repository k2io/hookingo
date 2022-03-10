// Copyright (C) 2022 K2 Cyber Security Inc.
package hookingo

import (
	sym "github.com/k2io/hookingo/internal/objSymbols"
)

func GetSymbols(name string) (map[string]uintptr, error) {
	return sym.ReadSymbols(name)
}
