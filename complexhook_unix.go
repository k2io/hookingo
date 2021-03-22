
package hookingo

import (
        "golang.org/x/sys/unix"
)

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

