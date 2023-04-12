package hookingo

import (
	"errors"
	"sync"
)

type hook struct {
	// the modified instructions
	target []byte
	// the moved and jump back instructions
	jumper []byte
	// use to call the origin function
	origin interface{}
}

var (
	// hooks applied with target addresses as keys
	hooks map[uintptr]*hook
	// protect the hooks map
	lock sync.Mutex
)

var (
	// ErrDoubleHook means already hooked
	ErrDoubleHook = errors.New("double hook")
	// ErrHookNotFound means the hook not found
	ErrHookNotFound = errors.New("hook not found")
	// ErrDifferentType means from and to are of different types
	ErrDifferentType = errors.New("inputs are of different type")
	// ErrInputType means inputs are not func type
	ErrInputType = errors.New("inputs are not func type")
	// ErrRelativeAddr means cannot call the origin function
	ErrRelativeAddr = errors.New("relative address in instruction")
)
var (
	gomajor = -1
	gominor = -1
)
var pageSize uintptr

func init() {
	hooks = make(map[uintptr]*hook)
}

type info struct {
	length      int
	relocatable bool
}
