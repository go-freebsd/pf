package pf

import (
	"fmt"
	"unsafe"
)

// #include <string.h>
// #include <stdlib.h>
// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// diagGetAddrs is a temporary diagnosis, removed again.
func diagGetAddrs(a Anchor, anchor string) []string {
	var out []string
	var rules C.struct_pfioc_rule
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	C.strlcpy(&rules.anchor[0], ca, C.MAXPATHLEN)
	if err := a.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules)); err != nil {
		return []string{fmt.Sprintf("GETRULES: %v", err)}
	}
	out = append(out, fmt.Sprintf("nr=%d ticket=%d", rules.nr, rules.ticket))
	for _, act := range []int{C.PF_PASS, C.PF_DROP, C.PF_NAT, C.PF_RDR, C.PF_BINAT} {
		for _, last := range []int{0, 1} {
			var pp C.struct_pfioc_pooladdr
			pp.ticket = rules.ticket
			pp.r_action = C.u_int8_t(act)
			pp.r_last = C.u_int8_t(last)
			C.strlcpy(&pp.anchor[0], ca, C.MAXPATHLEN)
			err := a.ioctl(C.DIOCGETADDRS, unsafe.Pointer(&pp))
			out = append(out, fmt.Sprintf("GETADDRS r_action=%d r_last=%d -> nr=%d err=%v", act, last, pp.nr, err))
		}
	}
	return out
}

// diagRuleKeys dumps the keys of the DIOCGETRULENV reply for rule 0.
func diagRuleKeys(a Anchor, anchor string) []string {
	var rules C.struct_pfioc_rule
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	C.strlcpy(&rules.anchor[0], ca, C.MAXPATHLEN)
	if err := a.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules)); err != nil {
		return []string{err.Error()}
	}
	req := newNV()
	defer req.destroy()
	req.addString("anchor", anchor)
	req.addNumber("ruleset", uint64(ActionPass))
	req.addNumber("ticket", uint64(rules.ticket))
	req.addNumber("nr", 0)
	reply, err := a.nvIoctl(C.DIOCGETRULENV, req)
	if err != nil {
		return []string{err.Error()}
	}
	defer reply.destroy()
	return reply.dump("")
}
