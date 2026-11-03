package pf

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// addrKind says what kind of address a side (source or destination) of a
// rule is.
type addrKind uint8

const (
	// addrAny matches every address ("any").
	addrAny addrKind = iota
	// addrNet is a host or network in CIDR notation.
	addrNet
	// addrTable is a table, "<name>".
	addrTable
	// addrInterface is a dynamic interface address, "(em0)".
	addrInterface
	// addrNoRoute is any address without a route ("no-route").
	addrNoRoute
	// addrURPFFailed is any source address that fails the unicast reverse
	// path check ("urpf-failed").
	addrURPFFailed
)

// addrSpec describes the address of one side of a rule.
type addrSpec struct {
	kind  addrKind
	text  string
	flags DynamicFlag
	not   bool
}

// setSide applies the specification to one side of the rule.
func (r *Rule) setSide(side *C.struct_pf_rule_addr, s addrSpec) error {
	a := Address{wrap: &side.addr, af: r.wrap.rule.af}
	switch s.kind {
	case addrAny:
		a.SetAny()
	case addrNet:
		if err := a.ParseCIDR(s.text); err != nil {
			return err
		}
	case addrTable:
		if err := a.SetTableName(s.text); err != nil {
			return err
		}
	case addrInterface:
		if err := a.SetInterface(s.text); err != nil {
			return err
		}
		if s.flags != 0 {
			a.SetDynamicFlag(s.flags)
		}
	case addrNoRoute:
		a.SetNoRoute()
	case addrURPFFailed:
		a.SetURPFFailed()
	}
	if s.not {
		side.neg = 1
	} else {
		side.neg = 0
	}
	return nil
}

func (r *Rule) setSource(s addrSpec) error      { return r.setSide(&r.wrap.rule.src, s) }
func (r *Rule) setDestination(s addrSpec) error { return r.setSide(&r.wrap.rule.dst, s) }

func (r *Rule) setSourcePorts(ports string) error {
	return parsePort(&r.wrap.rule.src, ports)
}

func (r *Rule) setDestinationPorts(ports string) error {
	return parsePort(&r.wrap.rule.dst, ports)
}
