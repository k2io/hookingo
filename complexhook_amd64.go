//go:build !windows

// Copyright (C) 2022 K2 Cyber Security Inc.
/*
Hooking in go-lang
hooking is achieved by modifying the target function code to jump to a hook function and with the help of a substitute function, hook function called the original function. This enables the wrapping of the target function without modifying the user code.

How we done this:

ORIGINAL FUNCTION (target function)
WRAP FUNCTION (hook function)
SUBSTITUTE FUNCTION
What we are doing with all these Functions in Hooking

***Original function***
 - Adding a Jump to WRAP FUNCTION address

***Wrap function***
 - Access ORIGINAL FUNCTION argument and call SUBSTITUTE FUNCTION with same arguments


***SUBSTITUTE FUNCTION***
 *SUBSTITUTE FUNCTION has N copied Bytes from ORIGINAL FUNCTION
  - Adding a Jump to ORIGINAL FUNCTION address
  - Execute the ORIGINAL FUNCTION and return back to WRAP FUNCTION
  - WRAP FUNCTION access post function call argument and return back to caller

*/

package hookingo

import (
	"errors"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

var isDebug = false

func SetDebug(x bool) {
	isDebug = x
}

func goAfter1_16() bool {
	if gomajor == -1 {
		s := runtime.Version()
		sa := strings.Split(s, ".")
		major, _ := strconv.Atoi(strings.TrimPrefix(sa[0], "go"))
		minor, _ := strconv.Atoi(sa[1])
		gomajor = major
		gominor = minor
	}
	if (gomajor == 1) && (gominor > 16) {
		return true
	} else if gomajor > 1 {
		return true
	}
	return false
}

func isLea(i string) bool {
	return strings.HasPrefix(i, "LEA")
}
func isCmp(i string) bool {
	return strings.HasPrefix(i, "CMP")
}

func isJrel(i string) bool {
	if strings.HasPrefix(i, "JB") {
		return true
	}
	if strings.HasPrefix(i, "JZ") {
		return true
	}
	if strings.HasPrefix(i, "JN") {
		return true
	}
	if strings.HasPrefix(i, "JCX") {
		return true
	}
	return false
}

func applyWrapHook(from, to, toc uintptr) (*hook, error) {
	if goAfter1_16() {
		h, err := applyWrapHookShort(from, to, toc)
		return h, err
	} else {
		h, err := applyWrapHookLong(from, to, toc)
		return h, err
	}
}

// applyWrapHookShort
// - shorter sequence -- only covers 32bit jump --
// for go version 1.17+

func applyWrapHookShort(from, to, toc uintptr) (*hook, error) {
	fromv := from
	srcv := makeSlice(fromv, 32)
	//src := makeSlice(fromv, 32)

	maxPatchLen := uintptr(5)

	ok1, skip, fromPostStackCheck := locateAfterStackCheck(from)
	if !ok1 {
		err := errors.New("unable to locate stackcheck in hooked fn")
		if isDebug {
			println("early-exit: no-stack-check-in hooked method!")
		}
		return nil, err
	}
	ok, _, tocPostStackCheck := locateAfterStackCheck(toc)
	if !ok {
		err := errors.New("unable to locate stackcheck in _s")
		if isDebug {
			println("early-exit: no-stack-check-in _s method!")
		}
		return nil, err
	}
	if (fromPostStackCheck - skip + 1) < uintptr(maxPatchLen) {
		err := errors.New("need longer patch sequence space than 5")
		return nil, err
	}
	fromSkip := from + skip
	// fromSkip: Jrel to
	// tocPostStackCheck: JMP fromPostStackCheck
	infLen := fromPostStackCheck - fromSkip + 1
	err := protectPages(fromSkip, maxPatchLen)
	if err != nil {
		if isDebug {
			println("early-exit: CannotProtectPage - orig")
		}
		return nil, err
	}

	jmp32relLen := uintptr(5) //jrel32
	if overflowsS32(fromPostStackCheck+jmp32relLen, tocPostStackCheck) {
		if isDebug {
			println("early-exit: from,hook >32bit rel offset needed")
		}
		return nil, errors.New(">32bit rel offset - calc1")
	}
	if overflowsS32(fromSkip+jmp32relLen, to) {
		if isDebug {
			println("early-exit: to,from >32bit rel offset needed")
		}
		return nil, errors.New(">32bit rel offset - calc2")
	}
	hk := &hook{}
	// code to return to origMethod
	// this is inserted in cannibalized code.
	addrtgt := fromPostStackCheck
	myaddr := tocPostStackCheck
	addr := addrtgt - myaddr - jmp32relLen
	seq := []byte{
		0xe9,                        // JMP rel32
		byte(addr), byte(addr >> 8), // .
		byte(addr >> 16), byte(addr >> 24), // .
	}
	xlen := len(seq)
	jmpOrig := seq

	addrtgt = to
	myaddr = fromSkip
	addr = addrtgt - myaddr - jmp32relLen
	JmpTo := []byte{
		0xe9,
		byte(addr), byte(addr >> 8), // .
		byte(addr >> 16), byte(addr >> 24), // .
	}
	xlenTo := len(JmpTo)
	jmpToTo := JmpTo
	err = protectPages(tocPostStackCheck, maxPatchLen)
	if err != nil {
		err1 := reProtectPages(fromSkip, maxPatchLen)
		if isDebug {
			println("early-exit: ProtectPage  tgt failed.", err1)
		}
		return nil, err
	}

	dst := makeSlice(tocPostStackCheck, uintptr(xlen))
	src := makeSlice(fromSkip, uintptr(infLen))
	hk.jumper = dst
	hk.target = src
	if isDebug {
		println("Before-from:", hk.jumper)
		for i := range hk.jumper {
			if i > 32 {
				break
			}
			println(srcv)
		}
		println("Before-method_s:", hk.target)
		for i := range hk.jumper {
			if i > 32 {
				break
			}
			println(hk.target[i])
		}
	}

	//1. origFn first bytes copied to toc
	// no copy -- copy(dst, src)
	//2. origFn overwritten to jmp to to
	dst = makeSlice(fromSkip, uintptr(xlenTo))
	copy(dst, jmpToTo)
	//3. insert NOP/POP at end of orig code.

	//4. toc overwritten to return to POP
	dst = makeSlice(tocPostStackCheck, uintptr(xlen))
	copy(dst, jmpOrig)
	err = reProtectPages(tocPostStackCheck, maxPatchLen)
	if err != nil {
		return nil, err
	}
	err = reProtectPages(fromPostStackCheck, maxPatchLen)
	if err != nil {
		return nil, err
	}
	if isDebug {
		println("After-from:", hk.jumper)
		for i := range hk.jumper {
			if i > 32 {
				break
			}
			println(srcv)
		}
		println("After-method_s:", hk.target)
		for i := range hk.jumper {
			if i > 32 {
				break
			}
			println(hk.target[i])
		}
		println("done.")
	}
	return hk, nil
}

func overflowsS32(v1, v2 uintptr) bool {

	diff := v2 - v1
	if v1 > v2 {
		diff = v1 - v2
	}
	maxS32 := uintptr(int(^uint(0) >> 1))

	return diff > maxS32
}

// applyWrapHookLong
// long jump indirect -- requuires 13-14 bytes sequence
// for go version 1.13-1.16
func applyWrapHookLong(from, to, toc uintptr) (*hook, error) {
	fromv := from
	srcv := makeSlice(fromv, 32)
	src := makeSlice(fromv, 32)

	retseqLen := 0 //NOP
	maxpatchLen := 13
	inf, err := ensureLength(src, maxpatchLen+retseqLen) // PUSH POP was 13+1
	if err != nil {
		if isDebug {
			println("early-exit: ensureLength  - err")
		}
		return nil, err
	}
	if isDebug {
		println("Patch-region Length ..", inf.length)
	}
	A, B, stkUnmodified, skip := checkLiveAndStackUpdates(from, inf.length)
	if !A && !B {
		if isDebug {
			println("no scratch reg found.")
		}
		return nil, errors.New("no scratch reg found-cannot hook")
	} else if !stkUnmodified {
		if skip < 0 {
			if isDebug {
				println("RSP updates in header - cannot patch.")
			}
			return nil, errors.New("RSPupdates -cannot hook")
		}
		from = from + uintptr(skip)
		src = makeSlice(from, 32)
		inf, err = ensureLength(src, maxpatchLen+retseqLen) // PUSH POP was 13+1
		if err != nil {
			if isDebug {
				println("early-exit: ensureLength  - err")
			}
			return nil, err
		}
	}

	// if skip > 0 {
	// 	//checktarget(toc,skip)
	// } else {

	// }
	err = protectPages(from, uintptr(inf.length))
	if err != nil {
		if isDebug {
			println("early-exit: CannotProtectPage - orig")
		}
		return nil, err
	}
	hk := &hook{}
	if !inf.relocatable {
		hk.origin = ErrRelativeAddr
		if isDebug {
			println("early-exit: NotRelocatable")
		}
		err := reProtectPages(from, pageSize)
		if err != nil {
			return nil, err
		}
		return hk, errors.New("NotRelocatable - cannot hook")
	}
	// code to return to origMethod
	// this is inserted in cannibalized code.
	addr := from + uintptr(inf.length-retseqLen) //addr of POP
	raxseq := []byte{
		0x48, 0xb8, // MOV RAX, addr
		byte(addr), byte(addr >> 8), // .
		byte(addr >> 16), byte(addr >> 24), // .
		byte(addr >> 32), byte(addr >> 40), // .
		byte(addr >> 48), byte(addr >> 56), // .
		0xff, 0xe0, // JMP RAX
	}
	r11seq := []byte{
		0x49, 0xbb, // MOV R11, addr64
		byte(addr), byte(addr >> 8), // .
		byte(addr >> 16), byte(addr >> 24), // .
		byte(addr >> 32), byte(addr >> 40), // .
		byte(addr >> 48), byte(addr >> 56), // .
		0x41, 0xff, 0xe3, // JMP R11
	}
	if (len(r11seq) > maxpatchLen) || (len(raxseq) > maxpatchLen) {
		err = reProtectPages(from, pageSize)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("code seq larger than expected")
	}
	jmpOrig := r11seq
	if !B {
		jmpOrig = raxseq
	}
	addr = to
	raxJmpTo := []byte{
		0x48, 0xb8, // MOV RAX, addr
		byte(addr), byte(addr >> 8), // .
		byte(addr >> 16), byte(addr >> 24), // .
		byte(addr >> 32), byte(addr >> 40), // .
		byte(addr >> 48), byte(addr >> 56), // .
		0xff, 0xe0, // JMP RAX
	}
	r11JmpTo := []byte{
		0x49, 0xbb, // MOV r11, addr
		byte(addr), byte(addr >> 8), // .
		byte(addr >> 16), byte(addr >> 24), // .
		byte(addr >> 32), byte(addr >> 40), // .
		byte(addr >> 48), byte(addr >> 56), // .
		0x41, 0xff, 0xe3, // JMP R11
	}
	jmpToTo := r11JmpTo
	if !B {
		jmpToTo = raxJmpTo
	}
	err = protectPages(toc, uintptr(inf.length+len(jmpOrig)))
	if err != nil {
		err = reProtectPages(from, pageSize)
		if err != nil {
			return nil, err
		}
		if isDebug {
			println("early-exit: ProtectPage  tgt failed.")
		}
		return nil, err
	}

	dst := makeSlice(toc, uintptr(inf.length))
	src = makeSlice(from, uintptr(inf.length))
	hk.jumper = dst
	hk.target = src
	if isDebug {
		println("Before-from:", hk.jumper)
		for i := range hk.jumper {
			if i > 32 {
				break
			}
			println(srcv)
		}
		println("Before-method_s:", hk.target)
		for i := range hk.jumper {
			if i > 32 {
				break
			}
			println(hk.target[i])
		}
	}

	//1. origFn first bytes copied to toc
	copy(dst, src)
	//2. origFn overwritten to jmp to to
	dst = makeSlice(from, uintptr(inf.length))
	copy(dst, jmpToTo)
	//3. insert POP at end of orig code.

	nopAtTgt := true
	if retseqLen == 0 {
		nopAtTgt = false
	}
	if nopAtTgt {
		instAtTgt := []byte{
			0x90, //nop
		}
		dst = makeSlice(from+uintptr(inf.length-len(instAtTgt)), uintptr(len(instAtTgt)))
		copy(dst, instAtTgt)
	}
	//4. toc overwritten to return to POP
	dst = makeSlice(toc+uintptr(inf.length), uintptr(len(jmpOrig)))
	copy(dst, jmpOrig)

	err = reProtectPages(toc, pageSize)
	if err != nil {
		return nil, err
	}

	err = reProtectPages(from, pageSize)
	if err != nil {
		return nil, err
	}
	if isDebug {
		println("After-from:", hk.jumper)
		for i := range hk.jumper {
			if i > 32 {
				break
			}
			println(srcv)
		}
		println("After-method_s:", hk.target)
		for i := range hk.jumper {
			if i > 32 {
				break
			}
			println(hk.target[i])
		}
		println("done.")
	}
	return hk, nil
}

func locateAfterStackCheck(toc uintptr) (bool, uintptr, uintptr) {
	lookwindow := 32
	lenx := 0
	skip := 0
	u0 := uintptr(0)
	src := makeSlice(toc, uintptr(lookwindow))
	for x := 0; x < lookwindow; x = x + lenx {
		i, err := x86asm.Decode(src[x:], 64)
		if err != nil {
			return false, u0, u0
		}
		//println(x,":---locate stackCheck :",i.String()," skip-",skip,"x=",x)
		if (skip == x) && isCmp(i.Op.String()) {
			lenx = i.Len
			// println("---CMP -- ",i.String())
		} else if (skip == 0) && isLea(i.Op.String()) {
			skip = i.Len
			lenx = i.Len
			// println("---Lea -- ",i.String())
		} else if (x != skip) && isJrel(i.Op.String()) {
			//println("---Jrel -- ",i.String())
			//println("---return SUCCESS locate stackChehck",i.String())
			return true, uintptr(skip), toc + uintptr(+x+i.Len)
		} else {
			//println("---FAILED locate stackChehck",i.String())
			return false, u0, u0
		}

	}
	//println("---FAILED locate stackChehck")
	return false, u0, u0
}

// updates for rax r11 rsp
func checkLiveAndStackUpdates(from uintptr, lenf int) (bool, bool, bool, int) {
	okA := true
	okB := true
	stkUnModified := true
	skip := -1
	countStkUpdate := 0
	stkUpdInstr := 0

	featureHandleNoStkChk := false
	src := makeSlice(from, uintptr(lenf))
	lenx := lenf
	if isDebug {
		println(" start checkLive  ----------------------------------------------- ")
	}
	adj16 := false
	for x := 0; x < lenf; x = x + lenx {
		i, err := x86asm.Decode(src[x:], 64)
		if err != nil {
			return false, false, false, skip
		}
		if isDebug {
			println(" instr: ", x, " len:", i.Len, " opcode: ", i.String())
		}
		if strings.HasPrefix(i.Op.String(), "PUSH") {
			stkUnModified = false
			countStkUpdate++
			stkUpdInstr = -1
		} else if strings.HasPrefix(i.Op.String(), "POP") {
			stkUnModified = false
			countStkUpdate++
			stkUpdInstr = -1
		}
		if strings.HasPrefix(i.Op.String(), "CMP") {
			continue
		}
		if i.Args[0] != nil {
			s := i.Args[0].String()
			if ("RAX" == s) || ("EAX" == s) || ("AX" == s) || ("AH" == s) || ("AL" == s) {
				okA = false
			}
			if "R11" == s {
				okB = false
			}
			if "RSP" == s {
				stkUnModified = false
				countStkUpdate++
				stkUpdInstr = -1
				if strings.HasPrefix(i.Op.String(), "SUB") {
					y := i.Args[1].String()
					if y == "0x10" {
						adj16 = true
					}
					stkUpdInstr = x + i.Len
				}
			}
		}
		if strings.HasPrefix(i.Op.String(), "XCHG") {
			if i.Args[1] != nil {
				s := i.Args[1].String()
				if ("RAX" == s) || ("EAX" == s) || ("AX" == s) || ("AH" == s) || ("AL" == s) {
					okA = false
				}
				if "R11" == s {
					okB = false
				}
			}
		}
		lenx = i.Len
		if isDebug {
			println(" found ... ", i.String(), " len: ", i.Len)
		}

		for _, a := range i.Args {
			if a == nil {
				break
			}
			if isDebug {
				println(" args: ... ", a.String())
			}
		}
		if isDebug {
			println(" regAX available: ", okA)
			println(" regR11 available: ", okB)
			println(" RSP unmodified: ", stkUnModified)
		}
	}
	if !stkUnModified && (countStkUpdate == 1) && adj16 {
		if featureHandleNoStkChk {
			println("----------found header with skip ", stkUpdInstr)
			return okA, okB, stkUnModified, stkUpdInstr
		}
	}
	return okA, okB, stkUnModified, -1
}

func ensureLength(src []byte, size int) (info, error) {
	var inf info
	inf.relocatable = true
	for inf.length < size {
		i, err := analysis(src)
		if err != nil {
			return inf, err
		}
		inf.relocatable = inf.relocatable && i.relocatable
		inf.length += i.length
		src = src[i.length:]
	}
	return inf, nil
}

func analysis(src []byte) (inf info, err error) {
	inst, err := x86asm.Decode(src, 64)
	if err != nil {
		return
	}
	inf.length = inst.Len
	inf.relocatable = true
	for _, a := range inst.Args {
		if mem, ok := a.(x86asm.Mem); ok {
			if mem.Base == x86asm.RIP {
				inf.relocatable = false
				return
			}
		} else if _, ok := a.(x86asm.Rel); ok {
			inf.relocatable = false
			return
		}
	}
	return
}

func reProtectPages(addr, size uintptr) error {
	start := pageSize * (addr / pageSize)
	length := pageSize * ((addr + size + pageSize - 1 - start) / pageSize)
	for i := uintptr(0); i < length; i += pageSize {
		data := makeSlice(start+i, pageSize)
		err := unix.Mprotect(data, unix.PROT_EXEC|unix.PROT_READ)
		if err != nil {
			return err
		}
	}
	return nil
}

func protectPages(addr, size uintptr) error {
	start := pageSize * (addr / pageSize)
	length := pageSize * ((addr + size + pageSize - 1 - start) / pageSize)
	for i := uintptr(0); i < length; i += pageSize {
		data := makeSlice(start+i, pageSize)
		err := unix.Mprotect(data, unix.PROT_EXEC|unix.PROT_READ|unix.PROT_WRITE)
		if err != nil {
			return err
		}
	}
	return nil
}

func init() {
	pageSize = uintptr(unix.Getpagesize())
}
