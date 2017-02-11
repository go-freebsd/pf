package main

import (
	"fmt"
	"unsafe"
)

// #cgo CFLAGS: -DPF -DPRIVATE
// #include <sys/ioctl.h>
// #include "pfvar.h"
import "C"

// var status C.struct_pf_status
//
// err = ioctl(pf.Fd(), C.DIOCGETSTATUS, uintptr(unsafe.Pointer(&status)))
// if err != nil {
// 	log.Fatalf("DIOCGETSTATUS: %s\n", err)
// }
//
// log.Printf("Status: %+v\n", status)
//
// var pi C.struct_pfioc_if
//
// // pi.ifname = [C.IFNAMSIZ]C.char{'/', 'd', 'e', 'v', '/', 'p', 'f', 'l', 'o', 'g', '0'}
//

func (pf Pf) SetStatusInterface(dev string) error {
	var pi C.struct_pfioc_if
	err := CStringCopy(unsafe.Pointer(&pi.ifname), dev, C.IFNAMSIZ)
	if err != nil {
		return err
	}
	err = pf.ioctl(C.DIOCSETSTATUSIF, uintptr(unsafe.Pointer(&pi)))
	if err != nil {
		return fmt.Errorf("DIOCSETSTATUSIF: %s\n", err)
	}
	return nil
}
