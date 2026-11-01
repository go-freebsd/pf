package pf

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

// #include <stdlib.h>
// #include <string.h>
// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void rule_set_proxy_ports(struct pf_rule *r, unsigned int first, unsigned int last, unsigned int opts) {
	r->rpool.proxy_port[0] = first;
	r->rpool.proxy_port[1] = last;
	r->rpool.opts = opts;
}

static unsigned int rule_proxy_port(struct pf_rule *r, int i) { return r->rpool.proxy_port[i]; }

static void pool_set_ifname(struct pfioc_pooladdr *pp, const char *name) {
	strlcpy(pp->addr.ifname, name, sizeof(pp->addr.ifname));
}
static const char *pool_ifname(struct pfioc_pooladdr *pp) { return pp->addr.ifname; }
*/
import "C"

// setProxyPorts stores the port range and the options of the translation pool
func (r *Rule) setProxyPorts(first, last, opts uint) {
	C.rule_set_proxy_ports(&r.wrap.rule, C.uint(first), C.uint(last), C.uint(opts))
}

// translates reports whether the action has a translation address: nat, rdr
// and binat, but not their "no" forms.
func (a Action) translates() bool {
	return a == ActionNAT || a == ActionRDR || a == ActionBINAT
}

// SetRedirect sets the address a nat, rdr or binat rule translates to (the
// part after "->" in pf.conf) and, for nat and rdr, the port or port range
// ("40002", "40000:40010"; empty for none). The address may be a host or a
// network in CIDR notation. The action is set separately with SetAction.
func (r *Rule) SetRedirect(address, ports string) error {
	var wrap C.struct_pf_addr_wrap
	a := Address{wrap: &wrap, af: r.wrap.rule.af}
	if err := a.ParseCIDR(address); err != nil {
		return fmt.Errorf("redirect address %q: %s", address, err)
	}
	var first, last uint64
	if ports != "" {
		lo, hi, isRange := strings.Cut(ports, ":")
		var err error
		if first, err = strconv.ParseUint(lo, 10, 16); err != nil {
			return fmt.Errorf("redirect port %q: %s", ports, err)
		}
		if isRange {
			if last, err = strconv.ParseUint(hi, 10, 16); err != nil {
				return fmt.Errorf("redirect port %q: %s", ports, err)
			}
			if last < first {
				return fmt.Errorf("redirect port range %q is backwards", ports)
			}
		}
	}
	r.pool = []poolAddr{{addr: wrap}}
	r.setProxyPorts(uint(first), uint(last), 0)
	return nil
}

// Redirect returns the translation address of a nat, rdr or binat rule and
// its port range, or empty strings.
func (r Rule) Redirect() (address, ports string) {
	if len(r.pool) == 0 {
		return "", ""
	}
	address = Address{wrap: &r.pool[0].addr, af: r.wrap.rule.af}.String()
	first := uint(C.rule_proxy_port(&r.wrap.rule, 0))
	last := uint(C.rule_proxy_port(&r.wrap.rule, 1))
	switch {
	case first == 0:
	case last == 0 || last == first:
		ports = strconv.FormatUint(uint64(first), 10)
	default:
		ports = fmt.Sprintf("%d:%d", first, last)
	}
	return address, ports
}

// the dynamic port range pfctl gives a nat rule without a port clause
const (
	natPortLow  = 50001
	natPortHigh = 65535
)

// addPool hands the translation addresses of the rule to the kernel; they
// belong to the pool ticket that DIOCBEGINADDRS gave for the rule.
func (rs RuleSet) addPool(r *Rule, ticket C.u_int32_t) error {
	// A nat rule without ports translates to the dynamic range, as pfctl
	// does; with no range the kernel shows the rule as "static-port".
	if Action(r.wrap.rule.action) == ActionNAT && len(r.pool) > 0 &&
		C.rule_proxy_port(&r.wrap.rule, 0) == 0 && C.rule_proxy_port(&r.wrap.rule, 1) == 0 {
		r.setProxyPorts(natPortLow, natPortHigh, 0)
	}
	for i := range r.pool {
		var pp C.struct_pfioc_pooladdr
		pp.ticket = ticket
		pp.af = C.u_int8_t(r.wrap.rule.af)
		pp.anchor = rs.wrap.anchor
		pp.addr.addr = r.pool[i].addr
		if r.pool[i].ifname != "" {
			cs := C.CString(r.pool[i].ifname)
			C.pool_set_ifname(&pp, cs)
			C.free(unsafe.Pointer(cs))
		}
		if err := rs.tx.handle.ioctl(C.DIOCADDADDR, unsafe.Pointer(&pp)); err != nil {
			return fmt.Errorf("DIOCADDADDR: %s", err)
		}
	}
	return nil
}

// readPool reads the translation addresses of rule number index of the
// anchor's rule set, which the kernel does not return with the rule.
func (a Anchor) readPool(ticket, index int, rule *Rule) error {
	var pp C.struct_pfioc_pooladdr
	pp.ticket = C.u_int32_t(ticket)
	pp.r_num = C.u_int32_t(index)
	pp.r_action = C.u_int8_t(rule.wrap.rule.action)
	if err := cStringCopy(unsafe.Pointer(&pp.anchor), a.Path, int(C.MAXPATHLEN)); err != nil {
		return err
	}
	if err := a.ioctl(C.DIOCGETADDRS, unsafe.Pointer(&pp)); err != nil {
		return fmt.Errorf("DIOCGETADDRS: %s", err)
	}
	n := int(pp.nr)
	rule.pool = make([]poolAddr, 0, n)
	for i := 0; i < n; i++ {
		pp.nr = C.u_int32_t(i)
		if err := a.ioctl(C.DIOCGETADDR, unsafe.Pointer(&pp)); err != nil {
			return fmt.Errorf("DIOCGETADDR: %s", err)
		}
		rule.pool = append(rule.pool, poolAddr{addr: pp.addr.addr, ifname: C.GoString(C.pool_ifname(&pp))})
	}
	return nil
}
