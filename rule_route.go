package pf

import (
	"fmt"
	"strings"
)

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void rule_set_rt(struct pf_rule *r, unsigned int rt, unsigned int opts) {
	r->rt = rt;
	r->rpool.opts = opts;
}
static unsigned int rule_rt(struct pf_rule *r) { return r->rt; }
static unsigned int rule_pool_opts(struct pf_rule *r) { return r->rpool.opts; }
*/
import "C"

// RouteType says how a rule routes the packets it matches.
type RouteType uint8

const (
	// RouteNone leaves the routing to the routing table.
	RouteNone RouteType = 0
	// RouteTo sends matching packets to the targets (route-to).
	RouteTo RouteType = C.PF_ROUTETO
	// ReplyTo sends the replies of matching packets to the targets
	// (reply-to).
	ReplyTo RouteType = C.PF_REPLYTO
	// DupTo sends a copy of matching packets to the targets (dup-to).
	DupTo RouteType = C.PF_DUPTO
)

func (t RouteType) String() string {
	switch t {
	case RouteNone:
		return ""
	case RouteTo:
		return "route-to"
	case ReplyTo:
		return "reply-to"
	case DupTo:
		return "dup-to"
	default:
		return fmt.Sprintf("RouteType(%d)", uint8(t))
	}
}

// RouteTarget is a route target: the interface the packet leaves on and the
// gateway it goes to, the "(em0 192.0.2.1)" of pf.conf.
type RouteTarget struct {
	Interface string
	// Address is the gateway, a host such as "192.0.2.1".
	Address string
}

// pool types (the low bits of the pool options)
const poolRoundRobin = C.PF_POOL_ROUNDROBIN

// SetRoute makes the rule route its packets: route-to, reply-to or dup-to
// the targets. With several targets the packets are spread over them in
// round-robin order, as pfctl does for a list. RouteNone removes the routing.
// The rule needs a direction (route-to and dup-to are meant for "out" rules,
// reply-to for "in" rules).
func (r *Rule) SetRoute(t RouteType, targets ...RouteTarget) error {
	if t == RouteNone {
		if len(targets) > 0 {
			return fmt.Errorf("RouteNone has no targets")
		}
		r.pool = nil
		C.rule_set_rt(&r.wrap.rule, 0, 0)
		return nil
	}
	if len(targets) == 0 {
		return fmt.Errorf("%s needs at least one target", t)
	}
	pool := make([]poolAddr, 0, len(targets))
	for _, tg := range targets {
		if tg.Interface == "" || tg.Address == "" {
			return fmt.Errorf("%s target (%s %s): interface and address are needed", t, tg.Interface, tg.Address)
		}
		if len(tg.Interface) >= C.IFNAMSIZ {
			return fmt.Errorf("interface name %q is too long (max %d)", tg.Interface, int(C.IFNAMSIZ)-1)
		}
		var pa poolAddr
		a := Address{wrap: &pa.addr, af: r.wrap.rule.af}
		if err := a.ParseCIDR(tg.Address); err != nil {
			return fmt.Errorf("%s target address %q: %s", t, tg.Address, err)
		}
		pa.ifname = tg.Interface
		pool = append(pool, pa)
	}
	r.pool = pool
	opts := uint(0)
	if len(pool) > 1 {
		opts = poolRoundRobin
	}
	C.rule_set_rt(&r.wrap.rule, C.uint(t), C.uint(opts))
	return nil
}

// Route returns how the rule routes its packets and the targets.
func (r Rule) Route() (RouteType, []RouteTarget) {
	t := RouteType(C.rule_rt(&r.wrap.rule))
	if t == RouteNone {
		return RouteNone, nil
	}
	targets := make([]RouteTarget, 0, len(r.pool))
	for i := range r.pool {
		targets = append(targets, RouteTarget{
			Interface: r.pool[i].ifname,
			Address:   Address{wrap: &r.pool[i].addr, af: r.wrap.rule.af}.String(),
		})
	}
	return t, targets
}

// setRouteRaw stores what the kernel reports; the targets follow with the
// pool addresses.
func (r *Rule) setRouteRaw(t RouteType) {
	C.rule_set_rt(&r.wrap.rule, C.uint(t), C.rule_pool_opts(&r.wrap.rule))
}

// routeString is how pfctl prints the routing of a rule.
func (r Rule) routeString() string {
	t, targets := r.Route()
	if t == RouteNone {
		return ""
	}
	parts := make([]string, 0, len(targets))
	for _, tg := range targets {
		parts = append(parts, fmt.Sprintf("(%s %s)", tg.Interface, tg.Address))
	}
	var b strings.Builder
	b.WriteString(t.String())
	b.WriteByte(' ')
	if len(parts) == 1 {
		b.WriteString(parts[0])
	} else {
		b.WriteString("{ " + strings.Join(parts, ", ") + " }")
	}
	if C.rule_pool_opts(&r.wrap.rule)&C.PF_POOL_TYPEMASK == poolRoundRobin {
		b.WriteString(" round-robin")
	}
	return b.String()
}
