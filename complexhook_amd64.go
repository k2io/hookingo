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
)

var isDebug = false

func SetDebug(x bool) {
	isDebug = x
}

var (
	gomajor = -1
	gominor = -1
)

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
	if strings.HasPrefix(i, "LEA") {
		return true
	}
	return false
}
func isCmp(i string) bool {
	if strings.HasPrefix(i, "CMP") {
		return true
	}
	return false
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
	src := makeSlice(fromv, 32)

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
		reProtectPages(fromSkip, maxPatchLen)
		if isDebug {
			println("early-exit: ProtectPage  tgt failed.")
		}
		return nil, err
	}

	dst := makeSlice(tocPostStackCheck, uintptr(xlen))
	src = makeSlice(fromSkip, uintptr(infLen))
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
	reProtectPages(tocPostStackCheck, maxPatchLen)
	reProtectPages(fromPostStackCheck, maxPatchLen)

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
	if diff > maxS32 {
		return true
	}
	return false
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

	if skip > 0 {
		//checktarget(toc,skip)
	} else {

	}
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
		reProtectPages(from, pageSize)
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
	if (len(r11seq) > maxpatchLen) || (len(r11seq) > maxpatchLen) {
		reProtectPages(from, pageSize)
		return nil, errors.New("code seq larger than expected")
	}
	jmpOrig := r11seq
	if B == false {
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
	if B == false {
		jmpToTo = raxJmpTo
	}
	err = protectPages(toc, uintptr(inf.length+len(jmpOrig)))
	if err != nil {
		reProtectPages(from, pageSize)
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

	reProtectPages(toc, pageSize)
	reProtectPages(from, pageSize)

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
	if (stkUnModified == false) && (countStkUpdate == 1) && (adj16 == true) {
		if featureHandleNoStkChk {
			println("----------found header with skip ", stkUpdInstr)
			return okA, okB, stkUnModified, stkUpdInstr
		}
	}
	return okA, okB, stkUnModified, -1
}
