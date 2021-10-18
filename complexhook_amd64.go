
// (C) 2020,2021 K2 Cyber Security Inc. 
package hookingo
//import ( "unsafe" )
import (
        "golang.org/x/arch/x86/x86asm"
        "strings"
)
var hdebug=true
func SetDebug(x bool) {
	hdebug=x
}

func locateStackCheck( from uintptr ) ( uintptr ) {
        n:=64
	x := makeSlice(from, 64)
        // do do --- disassemble until first JBE or jump encountered

        for i,b := range x {
		if hdebug {
			println("DEBUG:addr:",from+uintptr(i)," ",i," ",x[i])
		}
           if b == 0x76 {
              return uintptr(i+2)
           }
           if b == 0x0f {
              if i < (n-6) {
                  if x[i+1] == 0x86 {
			  if hdebug {
				  println("DEBUG:addr:",from+uintptr(i)," ",i+1," ",x[i+1])
			  }
                     return uintptr(i+6)
                  }
              }
           }
        }
        return uintptr(0)
}

func locateStackCheckNew( from uintptr) (uintptr) {
        n:=64
        src := makeSlice(from, 64)
        lenx:=n
        lenf:=n
        for x:=0;x< lenf; x=x+lenx{
            i, err := x86asm.Decode(src[x:], 64)
            if hdebug && (err==nil) {
               println("DEBUG: decode-for-stackCheck:",i.String())
            }
            if err != nil {
               println("DEBUG: failed to decode-for-stackCheck:",err.Error())
               return  uintptr(0)
            }
            if  strings.HasPrefix(i.Op.String(),"JB") { 
               return uintptr(x+i.Len)
            }
            if  strings.HasPrefix(i.Op.String(),"JMP") { 
               return uintptr(x+i.Len)
            }
            lenx=i.Len
        }
        return uintptr(0)
}
func applyWrapHook(fromv, to, toc uintptr) (*hook, error) {

        n := locateStackCheck(fromv)
        n1 := locateStackCheckNew(fromv)
        if n1!=n {
             if hdebug {
                 println("DEBUG--- locateStackCheck using decode != adhoc method")
             }
        }
        from:= fromv+n
        //locate first jbe --> 0x76 dd or 0x0f 0x86 dd dd dd dd
	if hdebug {
		println("relocating wrap by ..",n)
	}
	src := makeSlice(from, 32)

	inf, err := ensureLength(src, 13+1) // PUSH POP was 13+1
	if err != nil {
		if hdebug {
			 println("early-exit: ensureLength  - err")
		}
		return nil, err
	}
        A,B := checkLive(fromv,inf.length)
        if !A && !B {
	    if hdebug {
	        println("no scratch reg found.")
	    }
           return nil,nil
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
                return hk,nil
	}
        // code to return to origMethod
        // this is inserted in cannibalized code.
        retseqLen:=1 //NOP
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
          for i:= range hk.jumper { if i> 32 {break;};println(hk.jumper[i]);}
          println("Before-method_s:",hk.target)
          for i:= range hk.jumper { if i> 32 {break;};println(hk.target[i]);}
        }

        //1. origFn first bytes copied to toc
	copy(dst, src)
        //2. origFn overwritten to jmp to to
	dst = makeSlice(from,uintptr(inf.length))
        copy(dst,jmpToTo)
        //3. insert POP at end of orig code.
        instAtTgt:= []byte {
                0x90, //nop
        }
	dst = makeSlice(from+uintptr(inf.length-len(instAtTgt)),uintptr(len(instAtTgt)))
	copy(dst, instAtTgt)
        //4. toc overwritten to return to POP
	dst = makeSlice(toc+uintptr(inf.length),uintptr(len(jmpOrig)))
        copy(dst,jmpOrig)

        reProtectPages(toc,pageSize)
        reProtectPages(from,pageSize)

	if hdebug {
          println("Before-from:",hk.jumper)
          for i:= range hk.jumper { if i> 32 {break;};println(hk.jumper[i]);}
          println("Before-method_s:",hk.target)
          for i:= range hk.jumper { if i> 32 {break;};println(hk.target[i]);}
        }
	return hk, nil
}

func checkLive( from uintptr,lenf int) (bool,bool) {
      okA:=true
      okB:=true
      src := makeSlice(from,uintptr(lenf))
      lenx:=lenf
      if hdebug {
          println(" start  ----------------------------------------------- ")
      }
      for x:=0;x< lenf; x=x+lenx{
        i, err := x86asm.Decode(src[x:], 64)
        if err != nil {
           return false,false
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
          println(" found ... ",i.String(),"len:",i.Len)
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
        }
      }
      return okA,okB
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
