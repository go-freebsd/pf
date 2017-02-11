package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// #cgo CFLAGS: -DPF -DPRIVATE
// #include <sys/ioctl.h>
// #include "pfvar.h"
import "C"

type Rule struct {
	wrap     C.struct_pfioc_rule
	src, dst *Address
}

type PortRange struct {
	StartPort uint16
	EndPort   uint16
	Operation uint8
}

type Address struct {
	IPNet     net.IPNet
	PortRange *PortRange
	Negate    bool
}

func (r Rule) Source() *Address {
	if r.src == nil {
		r.src = NewAddress(&r.wrap.rule.src, r.wrap.rule.af)
	}
	return r.src
}

func (r Rule) Destination() *Address {
	if r.dst == nil {
		r.dst = NewAddress(&r.wrap.rule.dst, r.wrap.rule.af)
	}
	return r.dst
}

func NewPortRange(xport [8]byte) *PortRange {
	var pr PortRange
	pr.StartPort = binary.BigEndian.Uint16(xport[0:2])
	pr.EndPort = binary.BigEndian.Uint16(xport[2:4])
	pr.Operation = xport[4]
	return &pr
}

func (pr PortRange) String() string {
	switch pr.Operation {
	case C.PF_OP_NONE:
		return fmt.Sprintf("%d", pr.StartPort)
	case C.PF_OP_IRG:
		return fmt.Sprintf("%d><%d", pr.StartPort, pr.EndPort)
	case C.PF_OP_EQ:
		return fmt.Sprintf("%d", pr.StartPort)
	case C.PF_OP_NE:
		return fmt.Sprintf("!=%d", pr.StartPort)
	case C.PF_OP_LT:
		return fmt.Sprintf("<%d", pr.StartPort)
	case C.PF_OP_LE:
		return fmt.Sprintf("<=%d", pr.StartPort)
	case C.PF_OP_GT:
		return fmt.Sprintf(">%d", pr.StartPort)
	case C.PF_OP_GE:
		return fmt.Sprintf(">=%d", pr.StartPort)
	case C.PF_OP_XRG:
		return fmt.Sprintf("%d<>%d", pr.StartPort, pr.EndPort)
	default:
		return fmt.Sprintf("%d:%d", pr.StartPort, pr.EndPort)
	}
}

func NewAddress(addr *C.struct_pf_rule_addr, af C.sa_family_t) *Address {
	var address Address
	if addr.neg == 1 {
		address.Negate = true
	}

	if af == C.AF_INET {
		address.IPNet.IP = addr.addr.v[0:4]
		address.IPNet.Mask = addr.addr.v[16:20]
	} else {
		address.IPNet.IP = addr.addr.v[0:16]
		address.IPNet.Mask = addr.addr.v[16:32]
	}

	address.PortRange = NewPortRange(addr.xport)

	return &address
}

func (a Address) String() string {
	addr := a.IPNet.String()
	if a.Negate {
		addr = "!" + addr
	}

	if a.PortRange.StartPort == 0 {
		return addr
	}

	return fmt.Sprintf("%s port %s", addr, a.PortRange.String())
}

func (r Rule) String() string {
	str := fmt.Sprintf("%s %s ",
		map[C.u_int8_t]string{
			C.PF_PASS: "pass",
			C.PF_DROP: "drop",
		}[r.wrap.rule.action],
		map[C.u_int8_t]string{
			C.PF_INOUT: "inout",
			C.PF_IN:    "in",
			C.PF_OUT:   "out",
		}[r.wrap.rule.direction])
	if r.wrap.rule.log != 0 {
		str += "log "
	}
	if r.wrap.rule.quick != 0 {
		str += "quick "
	}
	if r.wrap.rule.af == C.AF_INET {
		str += "inet"
	} else {
		str += "inet6"
	}
	if r.wrap.rule.proto == C.IPPROTO_TCP {
		str += " proto tcp"
	} else if r.wrap.rule.proto == C.IPPROTO_UDP {
		str += " proto udp"
	}
	str += " from "
	str += r.Source().String()
	str += " to "
	str += r.Destination().String()
	return str
}

func (pf Pf) GetRule(ticket, i C.u_int32_t, rule *Rule) error {
	rule.wrap.nr = i
	rule.wrap.ticket = ticket
	return pf.ioctl(C.DIOCGETRULE, uintptr(unsafe.Pointer(&rule.wrap)))
}

func (pf Pf) GetRules() ([]Rule, error) {
	var rules C.struct_pfioc_rule
	err := pf.ioctl(C.DIOCGETRULES, uintptr(unsafe.Pointer(&rules)))
	if err != nil {
		return nil, fmt.Errorf("DIOCGETRULES: %s", err)
	}
	ruleList := make([]Rule, rules.nr)

	var i C.u_int32_t
	for ; i < rules.nr; i++ {
		err = pf.GetRule(rules.ticket, i, &ruleList[i])
		if err != nil {
			return nil, fmt.Errorf("DIOCGETRULE: %s\n", err)
		}
	}

	return ruleList, nil
}
