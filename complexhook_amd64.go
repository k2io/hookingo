
// (C) 2020,2021 K2 Cyber Security Inc. 
package hookingo
//import ( "unsafe" )
var hdebug=true
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

func applyWrapHook(fromv, to, toc uintptr) (*hook, error) {

        n := locateStackCheck(fromv)
        from:= fromv+n
        //locate first jbe --> 0x76 dd or 0x0f 0x86 dd dd dd dd
	if hdebug {
		println("relocating wrap by ..",n)
	}
	src := makeSlice(from, 32)

	inf, err := ensureLength(src, 14)
	if err != nil {
		if hdebug {
			 println("early-exit: ensureLength  - err")
		}
		return nil, err
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
	addr := from + uintptr(inf.length-1) //addr of POP
        jmpOrig:= []byte {
                0x50,                               //PUSH RAX
		0x48, 0xb8,                         // MOV RAX, addr
		byte(addr), byte(addr >> 8),        // .
		byte(addr >> 16), byte(addr >> 24), // .
		byte(addr >> 32), byte(addr >> 40), // .
		byte(addr >> 48), byte(addr >> 56), // .
		0xff, 0xe0,                         // JMP RAX
        }
        addr = to 
        jmpToTo:= []byte {
                0x48, 0xb8,                         // MOV RAX, addr
                byte(addr), byte(addr >> 8),        // .
                byte(addr >> 16), byte(addr >> 24), // .
                byte(addr >> 32), byte(addr >> 40), // .
                byte(addr >> 48), byte(addr >> 56), // .
                0xff, 0xe0,                         // JMP RAX
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
	dst = makeSlice(from+uintptr(inf.length-1),uintptr(1))
        instAtTgt:= []byte {
                0x58,      //POP RAX
        }
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

// ---
// current scheme 
//     jmper saved as before
//        orig-12-code, push rax, push rax, rax<- restcode, pop rax, ret
//     orig:
//         mov rax, newaddress
//         JMP RAX -- this code returns unwinds stack
//         
// ---
// scheme 1: prefix hook
//     jmper saved as before
//        orig-12-code, push rax, push rax, rax<- restcode, pop rax, ret
//     orig:
//         mov rax, jumper !!! original code copy address
//         push rax        !!!
//         mov rax, newaddress
//         JMP RAX -- this code returns unwinds stack to jumper.
// ---
// scheme 1: suffix hook
//     jmper saved as before
//        orig-12-code, push rax, push rax, rax<- restcode, pop rax, ret
//     orig:
//         mov rax, newaddress
//         push rax        !!!
//         mov rax, jumper !!!
//         JMP RAX -- this code returns unwinds stack
//         TODO: need to restore return values from part1
// ---

