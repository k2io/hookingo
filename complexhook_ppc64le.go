//go:build !windows

package hookingo

import (
	"errors"
	"runtime"
)

func applyWrapHook(from, to, toc uintptr) (*hook, error) {
	return nil, errors.New("TODO " + runtime.GOARCH + "Not supported")
}
