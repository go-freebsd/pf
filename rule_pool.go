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
static unsigned int rule_pool_opts_get(struct pf_rule *r) { return r->rpool.opts; }
static void rule_pool_opts_set(struct pf_rule *r, unsigned int o) { r->rpool.opts = o; }

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

// parseRedirectPorts parses "40002" or "40000:40010" into the proxy port
// range; an empty string is no range.
func parseRedirectPorts(ports string) (first, last uint64, err error) {
	if ports == "" {
		return 0, 0, nil
	}
	lo, hi, isRange := strings.Cut(ports, ":")
	if first, err = strconv.ParseUint(lo, 10, 16); err != nil {
		return 0, 0, fmt.Errorf("redirect port %q: %s", ports, err)
	}
	if isRange {
		if last, err = strconv.ParseUint(hi, 10, 16); err != nil {
			return 0, 0, fmt.Errorf("redirect port %q: %s", ports, err)
		}
		if last < first {
			return 0, 0, fmt.Errorf("redirect port range %q is backwards", ports)
		}
	}
	return first, last, nil
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
	return r.setRedirectWrap(wrap, ports)
}

// SetRedirectInterface makes the rule translate to the address of an
// interface, "-> (em0)" of pf.conf. The flags select which addresses of the
// interface: DynamicFlagNetwork "(em0:network)", DynamicFlagBroadcast,
// DynamicFlagPeer and DynamicFlagNoAlias "(em0:0)". Without flags it is the
// primary address(es). The address follows the interface when it changes.
func (r *Rule) SetRedirectInterface(name, ports string, flags ...DynamicFlag) error {
	var wrap C.struct_pf_addr_wrap
	a := Address{wrap: &wrap, af: r.wrap.rule.af}
	if err := a.SetInterface(name); err != nil {
		return fmt.Errorf("redirect interface %q: %s", name, err)
	}
	var all DynamicFlag
	for _, f := range flags {
		all |= f
	}
	if all != 0 {
		a.SetDynamicFlag(all)
	}
	return r.setRedirectWrap(wrap, ports)
}

// SetRedirectTable makes the rule translate to the addresses of a table,
// "-> <name>" of pf.conf; use SetPoolType(PoolRoundRobin) to spread over them.
func (r *Rule) SetRedirectTable(name, ports string) error {
	var wrap C.struct_pf_addr_wrap
	a := Address{wrap: &wrap, af: r.wrap.rule.af}
	if err := a.SetTableName(name); err != nil {
		return fmt.Errorf("redirect table %q: %s", name, err)
	}
	return r.setRedirectWrap(wrap, ports)
}

func (r *Rule) setRedirectWrap(wrap C.struct_pf_addr_wrap, ports string) error {
	first, last, err := parseRedirectPorts(ports)
	if err != nil {
		return err
	}
	r.pool = []poolAddr{{addr: wrap}}
	r.setProxyPorts(uint(first), uint(last), r.poolOpts())
	r.staticPort = false
	return nil
}

// PoolType says how a pool of translation addresses is used.
type PoolType uint8

const (
	// PoolNone is the first address (or the only one).
	PoolNone PoolType = 0
	// PoolBitmask combines the network part of the address with the host part
	// of the source address ("bitmask").
	PoolBitmask PoolType = 1
	// PoolRandom picks an address of the pool at random ("random").
	PoolRandom PoolType = 2
	// PoolSourceHash picks the address by a hash of the source address
	// ("source-hash").
	PoolSourceHash PoolType = 3
	// PoolRoundRobin uses the addresses of the pool in turn ("round-robin").
	PoolRoundRobin PoolType = 4

	poolTypeMask = 0x0f
	poolSticky   = 0x20
)

func (t PoolType) String() string {
	switch t {
	case PoolNone:
		return ""
	case PoolBitmask:
		return "bitmask"
	case PoolRandom:
		return "random"
	case PoolSourceHash:
		return "source-hash"
	case PoolRoundRobin:
		return "round-robin"
	}
	return fmt.Sprintf("PoolType(%d)", uint8(t))
}

func (r *Rule) poolOpts() uint { return uint(C.rule_pool_opts_get(&r.wrap.rule)) }

func (r *Rule) setPoolOpts(o uint) { C.rule_pool_opts_set(&r.wrap.rule, C.uint(o)) }

// SetPoolType sets how a pool of translation addresses is used.
func (r *Rule) SetPoolType(t PoolType) {
	r.setPoolOpts(r.poolOpts()&^poolTypeMask | uint(t)&poolTypeMask)
}

// PoolType returns how the pool is used.
func (r Rule) PoolType() PoolType { return PoolType(r.poolOpts() & poolTypeMask) }

// SetStickyAddress makes a translated connection keep its address
// ("sticky-address").
func (r *Rule) SetStickyAddress(on bool) {
	if on {
		r.setPoolOpts(r.poolOpts() | poolSticky)
	} else {
		r.setPoolOpts(r.poolOpts() &^ poolSticky)
	}
}

// StickyAddress reports whether translated connections keep their address.
func (r Rule) StickyAddress() bool { return r.poolOpts()&poolSticky != 0 }

// SetStaticPort keeps the source port of a nat rule ("static-port"): no port
// range is used. A nat rule without it gets the dynamic range 50001:65535.
func (r *Rule) SetStaticPort(on bool) {
	r.staticPort = on
	if on {
		r.setProxyPorts(0, 0, r.poolOpts())
	}
}

// StaticPort reports whether the nat rule keeps the source port.
func (r Rule) StaticPort() bool { return r.staticPort }

// poolString is how pfctl prints the options of the pool of a translation
// rule after the address and the ports.
func (r Rule) poolString() []string {
	var out []string
	if t := r.PoolType().String(); t != "" {
		out = append(out, t)
	}
	if r.StickyAddress() {
		out = append(out, "sticky-address")
	}
	if r.staticPort && Action(r.wrap.rule.action) == ActionNAT {
		out = append(out, "static-port")
	}
	return out
}

// Redirect returns the translation address of a nat, rdr or binat rule and
// its port range, or empty strings.
func (r Rule) Redirect() (address, ports string) {
	if len(r.pool) == 0 || !Action(r.wrap.rule.action).translates() {
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
	if Action(r.wrap.rule.action) == ActionNAT && len(r.pool) > 0 && !r.staticPort &&
		C.rule_proxy_port(&r.wrap.rule, 0) == 0 && C.rule_proxy_port(&r.wrap.rule, 1) == 0 {
		r.setProxyPorts(natPortLow, natPortHigh, r.poolOpts())
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
