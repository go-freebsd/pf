// +build freebsd

package pf

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// Handle to the pf kernel module ioctl file
type Handle os.File

// Open pf ioctl dev
func Open() (*Handle, error) {
	file, err := os.OpenFile("/dev/pf", os.O_RDWR, 0644)
	return (*Handle)(file), err
}

// Close pf ioctl dev
func (file *Handle) Close() error {
	return (*os.File)(file).Close()
}

// Rule uses the passed ticket to return the rule at the given index
func (file Handle) Rule(ticket, index int, rule *Rule) error {
	if ticket <= 0 || index < 0 {
		return fmt.Errorf("Invalid ticket or index: ticket %d index %d",
			ticket, index)
	}
	if rule == nil {
		panic(fmt.Errorf("Can't store rule data in nil value"))
	}
	rule.wrap.nr = C.u_int32_t(index)
	rule.wrap.ticket = C.u_int32_t(ticket)
	return file.ioctl(C.DIOCGETRULE, unsafe.Pointer(&rule.wrap))
}

// Rules returns all rules using one ticket
func (file Handle) Rules() ([]Rule, error) {
	var rules C.struct_pfioc_rule
	err := file.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules))
	if err != nil {
		return nil, fmt.Errorf("DIOCGETRULES: %s", err)
	}
	ruleList := make([]Rule, rules.nr)

	for i := 0; i < int(rules.nr); i++ {
		err = file.Rule(int(rules.ticket), i, &ruleList[i])
		if err != nil {
			return nil, fmt.Errorf("DIOCGETRULE: %s\n", err)
		}
	}

	return ruleList, nil
}

// SetStatusInterface sets the status interface(s) for pf
// usually that is something like pflog0. The device needs
// to be created before using interface cloning.
func (file Handle) SetStatusInterface(dev string) error {
	var pi C.struct_pfioc_if
	err := cStringCopy(unsafe.Pointer(&pi.ifname), dev, C.IFNAMSIZ)
	if err != nil {
		return err
	}
	err = file.ioctl(C.DIOCSETSTATUSIF, unsafe.Pointer(&pi))
	if err != nil {
		return fmt.Errorf("DIOCSETSTATUSIF: %s\n", err)
	}
	return nil
}

// StatusInterface returns the currently configured status
// interface or an error.
func (file Handle) StatusInterface() (string, error) {
	var pi C.struct_pfioc_if
	err := file.ioctl(C.DIOCSETSTATUSIF, unsafe.Pointer(&pi))
	if err != nil {
		return "", fmt.Errorf("DIOCSETSTATUSIF: %s\n", err)
	}
	return C.GoString(&(pi.ifname[0])), nil
}

// ioctl helper for pf dev
func (file *Handle) ioctl(cmd uintptr, ptr unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, (*os.File)(file).Fd(), cmd, uintptr(ptr))
	if e != 0 {
		return e
	}
	return nil
}
