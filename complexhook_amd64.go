
// (C) 2020,2021 K2 Cyber Security Inc. 
package hookingo
//import ( "unsafe" )
import (
        "golang.org/x/arch/x86/x86asm"
        "strings"
        "errors"
)
var hdebug=true
func SetDebug(x bool) {
	hdebug=x
}



func applyWrapHook(from, to, toc uintptr) (*hook, error) {

        fromv:=from 
	srcv := makeSlice(fromv, 32)
	src := makeSlice(fromv, 32)

        retseqLen:=0 //NOP
        maxpatchLen:=13
	inf, err := ensureLength(src, maxpatchLen+retseqLen) // PUSH POP was 13+1
	if err != nil {
		if hdebug {
			 println("early-exit: ensureLength  - err")
		}
		return nil, err
	}
	if hdebug {
		println("Patch-region Length ..",inf.length)
	}
        A,B,stkUnmodified,skip := checkLiveAndStackUpdates(from,inf.length)
        if !A && !B {
	    if hdebug {
	        println("no scratch reg found.")
	    }
           return nil,errors.New("no scratch reg found-cannot hook")
        }else if !stkUnmodified {
            if skip  < 0 {
	      if hdebug {
	          println("RSP updates in header - cannot patch.")
	      }
              return nil,errors.New("RSPupdates -cannot hook")
            }
            println("--- change hookpt by ----",skip)
	    from=from+uintptr(skip)
	    src = makeSlice(from, 32)
	    inf, err = ensureLength(src, maxpatchLen+retseqLen) // PUSH POP was 13+1
	    if err != nil {
                println("--- patchlen failed----",err.Error())
		if hdebug {
			 println("early-exit: ensureLength  - err")
		}
		return nil, err
	    }
            println("--- patchlen----",inf.length)
        }

        if skip >0 {
          //checktarget(toc,skip)
        } else {

        }
	err = protectPages(from, uintptr(inf.length))
	if err != nil {
		if hdebug {
			 println("early-exit: CannotProtectPage - orig")
		}
		return nil, err
	}
	hk := &hook{}
	if !inf.relocatable {
		hk.origin = ErrRelativeAddr
		if hdebug {
			 println("early-exit: NotRelocatable")
		}
		reProtectPages(from,pageSize)
                return hk,errors.New("NotRelocatable - cannot hook")
	}
        // code to return to origMethod
        // this is inserted in cannibalized code.
	addr := from + uintptr(inf.length-retseqLen) //addr of POP
        raxseq:= []byte {
		0x48, 0xb8,                         // MOV RAX, addr
		byte(addr), byte(addr >> 8),        // .
		byte(addr >> 16), byte(addr >> 24), // .
		byte(addr >> 32), byte(addr >> 40), // .
		byte(addr >> 48), byte(addr >> 56), // .
		0xff, 0xe0,                         // JMP RAX
        }
        r11seq:= []byte {
                0x49, 0xbb,                          // MOV R11, addr64
                byte(addr), byte(addr >> 8),        // .
                byte(addr >> 16), byte(addr >> 24), // .
                byte(addr >> 32), byte(addr >> 40), // .
                byte(addr >> 48), byte(addr >> 56), // .
                0x41,0xff, 0xe3,                         // JMP R11
        }
        if (len(r11seq) > maxpatchLen) || (len(r11seq) > maxpatchLen) {
		reProtectPages(from,pageSize)
                return nil,errors.New("code seq larger than expected")
        }
        jmpOrig:= r11seq
        if B == false  {
           jmpOrig = raxseq
        }
        addr = to
        raxJmpTo:= []byte {
                0x48, 0xb8,                         // MOV RAX, addr
                byte(addr), byte(addr >> 8),        // .
                byte(addr >> 16), byte(addr >> 24), // .
                byte(addr >> 32), byte(addr >> 40), // .
                byte(addr >> 48), byte(addr >> 56), // .
                0xff, 0xe0,                         // JMP RAX
        }
        r11JmpTo:= []byte {
                0x49, 0xbb,                         // MOV r11, addr
                byte(addr), byte(addr >> 8),        // .
                byte(addr >> 16), byte(addr >> 24), // .
                byte(addr >> 32), byte(addr >> 40), // .
                byte(addr >> 48), byte(addr >> 56), // .
                0x41,0xff, 0xe3,                         // JMP R11
        }
        jmpToTo:= r11JmpTo
        if B == false {
           jmpToTo=raxJmpTo
        }
	err = protectPages(toc, uintptr(inf.length+len(jmpOrig)))
	if err != nil {
		reProtectPages(from,pageSize)
		if hdebug {
			 println("early-exit: ProtectPage  tgt failed.")
		}
		return nil, err
	}

	dst := makeSlice(toc,uintptr(inf.length))
	src = makeSlice(from, uintptr(inf.length))
	hk.jumper = dst
	hk.target = src
	if hdebug {
          println("Before-from:",hk.jumper)
          for i:= range hk.jumper { if i> 32 {break;};println(srcv);}
          println("Before-method_s:",hk.target)
          for i:= range hk.jumper { if i> 32 {break;};println(hk.target[i]);}
        }

        //1. origFn first bytes copied to toc
	copy(dst, src)
        //2. origFn overwritten to jmp to to
	dst = makeSlice(from,uintptr(inf.length))
        copy(dst,jmpToTo)
        //3. insert POP at end of orig code.

        nopAtTgt:=true
        if retseqLen == 0 {
            nopAtTgt=false
        }
        if nopAtTgt {
           instAtTgt:= []byte {
                0x90, //nop
           }
	   dst = makeSlice(from+uintptr(inf.length-len(instAtTgt)),uintptr(len(instAtTgt)))
	   copy(dst, instAtTgt)
        }
        //4. toc overwritten to return to POP
	dst = makeSlice(toc+uintptr(inf.length),uintptr(len(jmpOrig)))
        copy(dst,jmpOrig)

        reProtectPages(toc,pageSize)
        reProtectPages(from,pageSize)

	if hdebug {
          println("After-from:",hk.jumper)
          for i:= range hk.jumper { if i> 32 {break;};println(srcv);}
          println("After-method_s:",hk.target)
          for i:= range hk.jumper { if i> 32 {break;};println(hk.target[i]);}
          println("done.")
        }
	return hk, nil
}

// updates for rax r11 rsp
func checkLiveAndStackUpdates( from uintptr,lenf int) (bool,bool,bool,int) {
      okA:=true
      okB:=true
      stkUnModified:=true
      skip:=-1
      countStkUpdate:=0
      stkUpdInstr:=0

      featureHandleNoStkChk:=false
      src := makeSlice(from,uintptr(lenf))
      lenx:=lenf
      if hdebug {
          println(" start checkLive  ----------------------------------------------- ")
      }
      adj16:=false
      for x:=0;x< lenf; x=x+lenx{
        i, err := x86asm.Decode(src[x:], 64)
        if err != nil {
           return false,false,false,skip
        }
        if hdebug {
          println(" instr: ",x," len:",i.Len," opcode: ",i.String())
        }
        if strings.HasPrefix(i.Op.String(),"PUSH")  {
             stkUnModified = false
             countStkUpdate++
             stkUpdInstr=-1
        }else if strings.HasPrefix(i.Op.String(),"POP")  {
             stkUnModified = false
             countStkUpdate++
             stkUpdInstr=-1
        }
        if  strings.HasPrefix(i.Op.String(),"CMP") {
            continue
        }
        if i.Args[0] != nil  {
          s:=i.Args[0].String()
          if    ("RAX" == s ) || ("EAX" == s ) || ( "AX" == s ) || ( "AH" == s ) || ( "AL" == s ) {
             okA=false
          }
          if    ("R11" == s ) {
             okB=false
          }
          if "RSP" == s {
             stkUnModified=false
             countStkUpdate++
             stkUpdInstr=-1
             if strings.HasPrefix(i.Op.String(),"SUB") {
                y:=i.Args[1].String()
                if y == "0x10" { 
                   adj16=true
                }
                stkUpdInstr=x+i.Len
             }
          }
        }
        if  strings.HasPrefix(i.Op.String(),"XCHG") { 
          if i.Args[1] != nil  {
          s:=i.Args[1].String()
          if    ("RAX" == s ) || ("EAX" == s ) || ( "AX" == s ) || ( "AH" == s ) || ( "AL" == s ) {
             okA=false
          }
          if    ("R11" == s ) {
             okB=false
          }
          }
        }
        lenx=i.Len
        if hdebug {
          println(" found ... ",i.String()," len: ",i.Len)
        }

        for _,a := range(i.Args) {
            if a==nil { break }
            if hdebug {
               println(" args: ... ",a.String())
            }
        }
        if hdebug {
           println(" regAX available: ",okA)
           println(" regR11 available: ",okB)
           println(" RSP unmodified: ",stkUnModified)
        }
      }
      if (stkUnModified==false) && (countStkUpdate == 1) && (adj16==true){
         if featureHandleNoStkChk  {
            println("----------found header with skip ",stkUpdInstr)
            return okA,okB,stkUnModified,stkUpdInstr
         }
      }
      return okA,okB,stkUnModified,-1
}

// --------
// --- origFoo
// ------- first ensureLength bytes taken and copied to toc
// ------- RAX <- address-of-to
// ------- JMP RAX
// ----origFooNext: NOP
// toc 
//   copied N bytes
//   R11 or RAX <- address-of-origFooNext
//   JMP R11 or RAX
// to: -- wrap hook --
//      call toc(arg...)
// 
