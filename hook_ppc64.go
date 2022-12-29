package hookingo

import (
	"errors"
	"runtime"
)

const (
	jumperSize = 0
)

func applyHook(from, to uintptr) (*hook, error) {

	return nil, errors.New("TODO " + runtime.GOARCH + "Not supported")
}
