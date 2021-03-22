package hookingo

import (
	"fmt"
	"testing"
)

func TestHook(t *testing.T) {
	s, err := f4()
	if err != nil {
		t.Error(err)
	}
	if s != "f4f2f3f1f2f1f2f3f2f1" {
		t.Error(s)
	}
}

func f1() string {
	s := "f1"
	fmt.Print(s)
	return s
}

func f2() string {
	s := "f2"
	fmt.Print(s)
	return s + f1()
}

func f3() string {
	s := "f3"
	fmt.Print(s)
	return s
}

func f4() (string, error) {
	s := "f4"
	fmt.Print(s)
	h, err := Apply(f1, f3)
	if err != nil {
		return "", err
	}
	s += f2()
	o := h.Origin()
	if f, ok := o.(func() string); ok {
		s += f()
	} else if e, ok := o.(error); ok {
		return "", e
	}
	e := h.Disable()
	s += f2()
	e.Enable()
	s += f2()
	err = h.Restore()
	if err != nil {
		return "", err
	}
	s += f2()
	return s, nil
}
