package pf

import (
	"strings"
)

// routeSpec is the route-to, reply-to or dup-to of a rule.
type routeSpec struct {
	kind    RouteType
	targets []RouteTarget
}

// divertSpec is the divert-to of a rule.
type divertSpec struct {
	addr string
	port uint16
}

func (b *RuleBuilder) setRoute(kind RouteType, targets []RouteTarget) *RuleBuilder {
	if b.route != nil {
		return b.fail("%s after %s: a rule routes one way", kind, b.route.kind)
	}
	if len(targets) == 0 {
		return b.fail("%s needs at least one target", kind)
	}
	for _, t := range targets {
		_, af, err := parseAddrText(t.Address)
		if err != nil || t.Interface == "" || af == AddressFamilyAny {
			return b.fail("%s target (%s %s): want an interface and a host address", kind, t.Interface, t.Address)
		}
		if b.af != AddressFamilyAny && b.af != af {
			return b.fail("%s target %s is %s but the rule is %s", kind, t.Address, af, b.af)
		}
		b.af = af
	}
	b.route = &routeSpec{kind: kind, targets: append([]RouteTarget(nil), targets...)}
	return b
}

// RouteTo sends the packets of the rule to the targets, "route-to (em0
// 192.0.2.1)": the interface they leave on and the gateway. With several
// targets they are used round-robin.
func (b *RuleBuilder) RouteTo(targets ...RouteTarget) *RuleBuilder {
	return b.setRoute(RouteTo, targets)
}

// ReplyTo sends the replies of the packets the rule matches to the targets,
// "reply-to (em0 192.0.2.1)", for a host with several uplinks.
func (b *RuleBuilder) ReplyTo(targets ...RouteTarget) *RuleBuilder {
	return b.setRoute(ReplyTo, targets)
}

// DupTo sends a copy of the packets to the targets, "dup-to (em0 192.0.2.1)".
func (b *RuleBuilder) DupTo(targets ...RouteTarget) *RuleBuilder {
	return b.setRoute(DupTo, targets)
}

// DivertTo hands the packets to a divert socket listening on the address and
// port, "divert-to 127.0.0.1 port 8668".
func (b *RuleBuilder) DivertTo(addr string, port uint16) *RuleBuilder {
	spec, af, err := parseAddrText(addr)
	if err != nil || spec.kind != addrNet || af == AddressFamilyAny {
		return b.fail("divert-to %q is not a host address", addr)
	}
	if b.af != AddressFamilyAny && b.af != af {
		return b.fail("divert-to %s is %s but the rule is %s", addr, af, b.af)
	}
	b.af = af
	b.divert = &divertSpec{addr: strings.SplitN(spec.text, "/", 2)[0], port: port}
	return b
}

// RTable routes the packets of the rule with routing table n ("rtable n").
func (b *RuleBuilder) RTable(n int) *RuleBuilder {
	b.rtable, b.rtableSet = n, true
	return b
}

// Tag marks the packets the rule matches with a tag that later rules can
// match with Tagged ("tag NAME").
func (b *RuleBuilder) Tag(name string) *RuleBuilder {
	b.tag = name
	return b
}

// Tagged matches the packets that carry the tag ("tagged NAME").
func (b *RuleBuilder) Tagged(name string) *RuleBuilder {
	b.tagged, b.taggedSet, b.taggedNot = name, true, false
	return b
}

// NotTagged matches the packets that do not carry the tag ("! tagged NAME").
func (b *RuleBuilder) NotTagged(name string) *RuleBuilder {
	b.tagged, b.taggedSet, b.taggedNot = name, true, true
	return b
}

// Prio matches the packets of the priority 0 to 7 ("prio 3").
func (b *RuleBuilder) Prio(n int) *RuleBuilder {
	b.prio, b.prioSet = n, true
	return b
}

// SetPrio gives the packets the priority 0 to 7, and with a second value
// their replies another one ("set prio 3", "set prio (3, 5)").
func (b *RuleBuilder) SetPrio(n int, reply ...int) *RuleBuilder {
	b.setPrio, b.setPrioReply, b.setPrioSet = n, n, true
	if len(reply) > 0 {
		b.setPrioReply = reply[0]
	}
	return b
}

// Queue assigns the packets to an ALTQ queue and, as an option, a second
// queue for packets with a low delay or an ACK, "queue (std, ack)". The
// kernel keeps the names; they take effect where ALTQ is compiled in.
func (b *RuleBuilder) Queue(queue string, priority ...string) *RuleBuilder {
	b.queue = queue
	if len(priority) > 0 {
		b.queuePrio = priority[0]
	}
	return b
}
