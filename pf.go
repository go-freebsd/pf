package pf

import (
	"fmt"
	"os"
	"syscall"
	"time"
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
			return nil, fmt.Errorf("DIOCGETRULE: %s", err)
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
		return fmt.Errorf("DIOCSETSTATUSIF: %s", err)
	}
	return nil
}

// StatusInterface returns the currently configured status
// interface or an error.
func (file Handle) StatusInterface() (string, error) {
	var pi C.struct_pfioc_if
	err := file.ioctl(C.DIOCSETSTATUSIF, unsafe.Pointer(&pi))
	if err != nil {
		return "", fmt.Errorf("DIOCSETSTATUSIF: %s", err)
	}
	return C.GoString(&(pi.ifname[0])), nil
}

// Start the packet filter.
func (file Handle) Start() error {
	err := file.ioctl(C.DIOCSTART, nil)
	if err != nil {
		return fmt.Errorf("DIOCSTART: %s", err)
	}
	return nil
}

// Stop the packet filter
func (file Handle) Stop() error {
	err := file.ioctl(C.DIOCSTOP, nil)
	if err != nil {
		return fmt.Errorf("DIOCSTOP: %s", err)
	}
	return nil
}

// Statistics of the packet filter
func (file Handle) UpdateStatistics(stats *Statistics) error {
	err := file.ioctl(C.DIOCGETSTATUS, unsafe.Pointer(stats))
	if err != nil {
		return fmt.Errorf("DIOCGETSTATUS: %s", err)
	}
	return nil
}

// SetDebugMode of the packetfilter
func (file Handle) SetDebugMode(mode DebugMode) error {
	level := C.u_int32_t(mode)
	err := file.ioctl(C.DIOCSETDEBUG, unsafe.Pointer(&level))
	if err != nil {
		return fmt.Errorf("DIOCSETDEBUG: %s", err)
	}
	return nil
}

// ClearPerRuleStats clear per-rule statistics
func (file Handle) ClearPerRuleStats() error {
	err := file.ioctl(C.DIOCCLRRULECTRS, nil)
	if err != nil {
		return fmt.Errorf("DIOCCLRRULECTRS: %s", err)
	}
	return nil
}

// ClearPFStats	clear the internal packet filter statistics
func (file Handle) ClearPFStats() error {
	err := file.ioctl(C.DIOCCLRSTATUS, nil)
	if err != nil {
		return fmt.Errorf("DIOCCLRSTATUS: %s", err)
	}
	return nil
}

// ClearSourceNodes clear the tree of source tracking nodes
func (file Handle) ClearSourceNodes() error {
	err := file.ioctl(C.DIOCCLRSRCNODES, nil)
	if err != nil {
		return fmt.Errorf("DIOCCLRSRCNODES: %s", err)
	}
	return nil
}

// SetHostID set the host ID, which is used by pfsync to identify
// which host created state table entries.
func (file Handle) SetHostID(id uint32) error {
	hostid := C.u_int32_t(id)
	err := file.ioctl(C.DIOCSETHOSTID, unsafe.Pointer(&hostid))
	if err != nil {
		return fmt.Errorf("DIOCSETHOSTID : %s", err)
	}
	return nil
}

// SetTimeout set the state timeout to specified duration
func (file Handle) SetTimeout(t Timeout, d time.Duration) error {
	var tm C.struct_pfioc_tm
	tm.timeout = C.int(t)
	tm.seconds = C.int(d / time.Second)
	err := file.ioctl(C.DIOCSETTIMEOUT, unsafe.Pointer(&tm))
	if err != nil {
		return fmt.Errorf("DIOCSETTIMEOUT: %s", err)
	}
	return nil
}

// Timeout returns the currently configured timeout duration
func (file Handle) Timeout(t Timeout) (time.Duration, error) {
	var tm C.struct_pfioc_tm
	var d time.Duration
	tm.timeout = C.int(t)
	err := file.ioctl(C.DIOCGETTIMEOUT, unsafe.Pointer(&tm))
	if err != nil {
		return d, fmt.Errorf("DIOCGETTIMEOUT: %s", err)
	}
	d = time.Duration(int(tm.seconds)) * time.Second
	return d, nil
}

// ioctl helper for pf dev
func (file *Handle) ioctl(cmd uintptr, ptr unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, (*os.File)(file).Fd(), cmd, uintptr(ptr))
	if e != 0 {
		return e
	}
	return nil
}
