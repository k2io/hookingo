// we drop this file in hookingo lib
package hookingo

import (
 "reflect"
 "unsafe"
)
func init () {
}
func ApplyWrapRaw(from uintptr, to,toc interface{}) (*hook,error) {

  
        vt := reflect.ValueOf(to)
        vc := reflect.ValueOf(toc) // this is typically same as vt
   
        return applyWrap(from, vt.Pointer(), vc.Pointer(),nil)
}

func ApplyWrapInterface(from,to,toc interface {}) (*hook,error) {

        vf := reflect.ValueOf(from)
        vt := reflect.ValueOf(to)
        vc := reflect.ValueOf(toc) // this is typically same as vt
        if vf.Kind() != reflect.Func {
                return nil, ErrInputType
        }
        e := (*eface)(unsafe.Pointer(&from))
        return applyWrap(vf.Pointer(), vt.Pointer(), vc.Pointer(),e.typ)
}
func ApplyWrap(from,to,toc interface {}) (*hook,error) {

	vf := reflect.ValueOf(from)
	vt := reflect.ValueOf(to)
        vc := reflect.ValueOf(toc) // this is typically same as vt
	if vf.Type() != vt.Type() {
		return nil, ErrDifferentType
	}
	if vf.Type() != vc.Type() {
		return nil, ErrDifferentType
	}
	if vf.Kind() != reflect.Func {
		return nil, ErrInputType
	}
	e := (*eface)(unsafe.Pointer(&from))
	return applyWrap(vf.Pointer(), vt.Pointer(), vc.Pointer(),e.typ)
}

func applyWrap(from, to,toc uintptr, typ unsafe.Pointer) (*hook, error) {
	lock.Lock()
	defer lock.Unlock()
	_, ok := hooks[from]
	if ok {
		return nil, ErrDoubleHook
	}
	// early object allocation
	// we may hooking runtime.mallocgc
	// or may be runtime.newobject
	f := &funcval{}
	// early bucket allocation
	hooks[from] = nil
	h, err := applyWrapHook(from, to,toc) //in assembly
	if err != nil {
		return nil, err
	}
	if h.origin == nil {
		f.fn = slicePtr(h.jumper)
		e := (*eface)(unsafe.Pointer(&h.origin))
		e.data = unsafe.Pointer(f)
		e.typ = typ
	}
	// just set value here, should not alloc memory
	hooks[from] = h
	return h, nil
}
