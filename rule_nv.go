package pf

import (
	"errors"
	"fmt"
	"unsafe"
)

// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void rule_set_basics(struct pf_rule *r, uint64_t action, uint64_t direction,
	uint64_t log, uint64_t quick, uint64_t keep_state, uint64_t af, uint64_t proto) {
	r->action = action;
	r->direction = direction;
	r->log = log;
	r->quick = quick;
	r->keep_state = keep_state;
	r->af = af;
	r->proto = proto;
}

static void rule_set_counters(struct pf_rule *r, uint64_t evaluations,
	uint64_t packets_in, uint64_t packets_out, uint64_t bytes_in, uint64_t bytes_out) {
	r->evaluations = evaluations;
	r->packets[0] = packets_in;
	r->packets[1] = packets_out;
	r->bytes[0] = bytes_in;
	r->bytes[1] = bytes_out;
}

static void rule_addr_set(struct pf_rule_addr *a, uint64_t type, uint64_t iflags,
	uint64_t cnt, uint64_t neg, uint64_t port_op, uint64_t port0, uint64_t port1) {
	a->addr.type = type;
	a->addr.iflags = iflags;
	a->addr.p.tblcnt = cnt;
	a->neg = neg;
	a->port_op = port_op;
	a->port[0] = port0;
	a->port[1] = port1;
}

static void rule_addr_bytes(struct pf_rule_addr *a, const void *addr, const void *mask) {
	if (addr != NULL) memcpy(&a->addr.v, addr, 16);
	if (mask != NULL) memcpy((char*)&a->addr.v + 16, mask, 16);
}

static void rule_addr_name(struct pf_rule_addr *a, const char *name) {
	strlcpy((char*)&a->addr.v, name, sizeof(a->addr.v));
}
*/
import "C"

// ruleNV reads one rule with DIOCGETRULENV. FreeBSD 15 dropped the struct
// based DIOCGETRULE; DIOCGETRULENV exists since FreeBSD 13/14. The reply
// is translated into the struct the rest of the package uses.
func (a Anchor) ruleNV(t RuleSetType, ticket, index int, rule *Rule) error {
	req := newNV()
	defer req.destroy()
	req.addString("anchor", a.Path)
	// the kernel maps this number with pf_get_ruleset_number: it is an
	// action (pass, nat, rdr, ...) that selects the rule set, not the index
	// of the rule set
	req.addNumber("ruleset", uint64(rulesetAction[t]))
	req.addNumber("ticket", uint64(ticket))
	req.addNumber("nr", uint64(index))

	reply, err := a.nvIoctl(C.DIOCGETRULENV, req)
	if err != nil {
		return err
	}
	defer reply.destroy()

	nvrule, ok := reply.child("rule")
	if !ok {
		return errors.New("DIOCGETRULENV: reply without rule")
	}
	rule.wrap.nr = C.u_int32_t(index)
	rule.wrap.ticket = C.u_int32_t(ticket)
	return rule.fromNV(nvrule)
}

func num(n *nv, name string) uint64 {
	v, _ := n.number(name)
	return v
}

func (r *Rule) fromNV(n *nv) error {
	C.rule_set_basics(&r.wrap.rule,
		C.uint64_t(num(n, "action")), C.uint64_t(num(n, "direction")),
		C.uint64_t(num(n, "log")), C.uint64_t(num(n, "quick")),
		C.uint64_t(num(n, "keep_state")), C.uint64_t(num(n, "af")),
		C.uint64_t(num(n, "proto")))

	if name, ok := n.str("ifname"); ok {
		if err := r.SetInterface(name); err != nil {
			return err
		}
	}
	r.SetInterfaceNot(num(n, "ifnot") != 0)

	r.setTCPFlagsRaw(TCPFlags(num(n, "flags")), TCPFlags(num(n, "flagset")))

	packets, _ := n.numbers("packets")
	bytes, _ := n.numbers("bytes")
	for len(packets) < 2 {
		packets = append(packets, 0)
	}
	for len(bytes) < 2 {
		bytes = append(bytes, 0)
	}
	C.rule_set_counters(&r.wrap.rule, C.uint64_t(num(n, "evaluations")),
		C.uint64_t(packets[0]), C.uint64_t(packets[1]),
		C.uint64_t(bytes[0]), C.uint64_t(bytes[1]))

	if pool, ok := n.child("rpool"); ok {
		ports, _ := pool.numbers("proxy_port")
		for len(ports) < 2 {
			ports = append(ports, 0)
		}
		r.setProxyPorts(uint(ports[0]), uint(ports[1]), uint(num(pool, "opts")))
	}
	r.setRouteRaw(RouteType(num(n, "rt")))
	r.setScrubRaw(num(n, "rule_flag"), num(n, "scrub_flags"), num(n, "min_ttl"), num(n, "max_mss"))
	r.setRTableRaw(int64(num(n, "rtableid")))
	if d, ok := n.child("divert"); ok {
		var addr []byte
		if c, ok := d.child("addr"); ok {
			addr, _ = c.binary("addr")
		} else {
			addr, _ = d.binary("addr")
		}
		r.setDivertRaw(addr, num(d, "port"))
	}

	for _, side := range []struct {
		key string
		dst *C.struct_pf_rule_addr
	}{{"src", &r.wrap.rule.src}, {"dst", &r.wrap.rule.dst}} {
		child, ok := n.child(side.key)
		if !ok {
			return fmt.Errorf("rule without %s", side.key)
		}
		if err := ruleAddrFromNV(side.dst, child); err != nil {
			return fmt.Errorf("%s: %s", side.key, err)
		}
	}
	return nil
}

func ruleAddrFromNV(dst *C.struct_pf_rule_addr, n *nv) error {
	wrap, ok := n.child("addr")
	if !ok {
		return errors.New("address without addr")
	}
	ports, _ := n.numbers("port")
	for len(ports) < 2 {
		ports = append(ports, 0)
	}
	cnt := num(wrap, "tblcnt")
	if cnt == 0 {
		cnt = num(wrap, "dyncnt")
	}
	C.rule_addr_set(dst, C.uint64_t(num(wrap, "type")), C.uint64_t(num(wrap, "iflags")),
		C.uint64_t(cnt), C.uint64_t(num(n, "neg")), C.uint64_t(num(n, "port_op")),
		C.uint64_t(ports[0]), C.uint64_t(ports[1]))

	var addr, mask []byte
	if c, ok := wrap.child("addr"); ok {
		addr, _ = c.binary("addr")
	}
	if c, ok := wrap.child("mask"); ok {
		mask, _ = c.binary("addr")
	}
	var pa, pm unsafe.Pointer
	if len(addr) >= 16 {
		pa = unsafe.Pointer(&addr[0])
	}
	if len(mask) >= 16 {
		pm = unsafe.Pointer(&mask[0])
	}
	C.rule_addr_bytes(dst, pa, pm)

	if name, ok := wrap.str("ifname"); ok && name != "" {
		cs := C.CString(name)
		C.rule_addr_name(dst, cs)
		C.free(unsafe.Pointer(cs))
	}
	if name, ok := wrap.str("tblname"); ok && name != "" {
		cs := C.CString(name)
		C.rule_addr_name(dst, cs)
		C.free(unsafe.Pointer(cs))
	}
	return nil
}
