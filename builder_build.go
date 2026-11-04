package pf

import (
	"errors"
	"fmt"
	"strings"
)

// flagsDefaultForAnyProtocol says whether a pass rule that keeps state and
// has no protocol gets the TCP flags S/SA as well. It is what pfctl does;
// the comparison with pfctl checks it.
const flagsDefaultForAnyProtocol = true

// Rules returns the kernel rules the builder stands for. Normally that is
// one; a list of interfaces (OnAny) gives one rule for each interface, in
// order, the way pfctl expands "on { em0 em1 }".
func (b *RuleBuilder) Rules() ([]*Rule, error) {
	if len(b.errs) > 0 {
		return nil, errors.Join(b.errs...)
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	ifaces := b.ifaces
	if len(ifaces) == 0 {
		ifaces = []string{""}
	}
	rules := make([]*Rule, 0, len(ifaces))
	for _, itf := range ifaces {
		r, err := b.build(itf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.kind, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// Rule returns the one kernel rule the builder stands for; it is an error if
// that are several (use Rules).
func (b *RuleBuilder) Rule() (*Rule, error) {
	rules, err := b.Rules()
	if err != nil {
		return nil, err
	}
	if len(rules) != 1 {
		return nil, fmt.Errorf("%s: the rule stands for %d kernel rules, use Rules", b.kind, len(rules))
	}
	return rules[0], nil
}

// MustRule is Rule for examples and tests: it panics on an error.
func (b *RuleBuilder) MustRule() *Rule {
	r, err := b.Rule()
	if err != nil {
		panic(err)
	}
	return r
}

// String is the rule in the form pfctl prints it, or the reason it cannot be
// built.
func (b *RuleBuilder) String() string {
	rules, err := b.Rules()
	if err != nil {
		return "(invalid: " + strings.ReplaceAll(err.Error(), "\n", "; ") + ")"
	}
	lines := make([]string, len(rules))
	for i, r := range rules {
		lines[i] = r.String()
	}
	return strings.Join(lines, "\n")
}

// family is the address family of the rule: the one asked for, else the one
// of an address.
func (b *RuleBuilder) family() AddressFamily { return b.af }

func isPortProto(p Protocol) bool { return p == ProtocolTCP || p == ProtocolUDP }

// validate refuses what pfctl refuses.
func (b *RuleBuilder) validate() error {
	var errs []error
	bad := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: "+format, append([]any{b.kind}, args...)...))
	}
	if b.src.ports != "" || b.dst.ports != "" {
		if !isPortProto(b.proto) {
			bad("a port needs the protocol tcp or udp")
		}
	}
	if b.flagsSet && b.proto != ProtocolTCP {
		bad("flags need the protocol tcp")
	}
	if b.kind.translation() {
		if b.dirSet {
			bad("a translation rule has no direction (leave out In and Out)")
		}
		if b.quick {
			bad("a translation rule has no quick")
		}
		if b.stateSet || b.flagsSet {
			bad("a translation rule keeps no state and has no TCP flags")
		}
		if b.kind.negative() {
			if b.redirect != nil {
				bad("a \"no\" rule has no target")
			}
		} else if b.redirect == nil {
			bad("a target is needed (RedirectTo, RedirectToInterface or RedirectToTable)")
		}
		if b.kind != kindNAT && b.static {
			bad("StaticPort is for nat")
		}
		if (b.pool != PoolNone || b.sticky || b.static) && b.redirect == nil {
			bad("pool options need a target")
		}
	} else {
		if b.redirect != nil || b.pool != PoolNone || b.sticky || b.static {
			bad("only nat, rdr and binat rules have a target")
		}
	}
	if b.kind.translation() || b.kind == kindScrub {
		if b.route != nil || b.divert != nil || b.queue != "" || b.prioSet || b.setPrioSet || b.taggedSet {
			bad("route-to, divert-to, queue, prio and tagged are for pass, block and match rules")
		}
	}
	if b.kind == kindBlock && b.route != nil {
		bad("a block rule does not route")
	}
	if b.kind == kindScrub {
		if b.stateSet || b.flagsSet {
			bad("a scrub rule keeps no state and has no TCP flags")
		}
		if b.scrub.ReassembleTCP && b.dirSet {
			bad("reassemble tcp rules can not specify a direction")
		}
	} else if b.scrubSet {
		bad("NoDF, RandomID, MinTTL, MaxMSS and ReassembleTCP are for scrub rules")
	}
	if b.kind == kindBlock && b.stateSet && b.state != StateNo {
		// pf.conf takes "block ... keep state" but it has no effect
		_ = b
	}
	return errors.Join(errs...)
}

func sideSpecOf(s builderSide) addrSpec {
	if s.set {
		return s.addr
	}
	return addrSpec{kind: addrAny}
}

// build makes the kernel rule for one interface ("" for none).
func (b *RuleBuilder) build(itf string) (*Rule, error) {
	var r Rule
	r.SetAction(b.action())
	r.SetDirection(DirectionInOut)
	if b.dirSet {
		r.SetDirection(b.direction)
	}
	r.SetQuick(b.quick)
	r.SetLog(b.log)
	if itf != "" {
		if err := r.SetInterface(itf); err != nil {
			return nil, err
		}
		r.SetInterfaceNot(b.ifNot)
	}
	r.SetAddressFamily(b.family())
	r.SetProtocol(b.proto)

	if err := r.setSource(sideSpecOf(b.src)); err != nil {
		return nil, fmt.Errorf("from: %w", err)
	}
	if err := r.setDestination(sideSpecOf(b.dst)); err != nil {
		return nil, fmt.Errorf("to: %w", err)
	}
	if err := r.setSourcePorts(b.src.ports); err != nil {
		return nil, fmt.Errorf("from port %q: %w", b.src.ports, err)
	}
	if err := r.setDestinationPorts(b.dst.ports); err != nil {
		return nil, fmt.Errorf("to port %q: %w", b.dst.ports, err)
	}

	switch {
	case b.kind.translation():
		if err := b.buildRedirect(&r); err != nil {
			return nil, err
		}
	case b.kind == kindScrub:
		r.SetScrub(b.scrub)
	default:
		b.buildState(&r)
		if b.flagsSet {
			if err := r.ParseTCPFlags(b.flags); err != nil {
				return nil, fmt.Errorf("flags %q: %w", b.flags, err)
			}
		}
	}
	if err := b.buildOptions(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (b *RuleBuilder) action() Action {
	switch b.kind {
	case kindPass:
		return ActionPass
	case kindBlock:
		return ActionDrop
	case kindMatch:
		return ActionMatch
	case kindNAT:
		return ActionNAT
	case kindNoNAT:
		return ActionNoNAT
	case kindRDR:
		return ActionRDR
	case kindNoRDR:
		return ActionNoRDR
	case kindBINAT:
		return ActionBINAT
	case kindNoBINAT:
		return ActionNoBINAT
	case kindScrub:
		return ActionScrub
	}
	return ActionPass
}

// buildState applies the state and the default TCP flags of pfctl.
func (b *RuleBuilder) buildState(r *Rule) {
	state := StateNo
	switch {
	case b.stateSet:
		state = b.state
	case b.kind == kindPass:
		state = StateKeep
	}
	r.SetState(state)
	if !b.flagsSet && state != StateNo && b.kind != kindBlock {
		if b.proto == ProtocolTCP || (b.proto == ProtocolAny && flagsDefaultForAnyProtocol) {
			_ = r.ParseTCPFlags("S/SA")
		}
	}
}

func (b *RuleBuilder) buildRedirect(r *Rule) error {
	if b.redirect == nil {
		return nil
	}
	t := b.redirect
	var err error
	switch t.kind {
	case addrNet:
		err = r.SetRedirect(t.text, t.ports)
	case addrInterface:
		err = r.SetRedirectInterface(t.text, t.ports, singleFlag(t.flags)...)
	case addrTable:
		err = r.SetRedirectTable(t.text, t.ports)
	}
	if err != nil {
		return err
	}
	r.SetPoolType(b.pool)
	r.SetStickyAddress(b.sticky)
	if b.static {
		r.SetStaticPort(true)
	}
	return nil
}

// singleFlag splits a set of flags for SetRedirectInterface, which ORs them.
func singleFlag(f DynamicFlag) []DynamicFlag {
	if f == 0 {
		return nil
	}
	return []DynamicFlag{f}
}

// buildOptions applies the options of the rule that no kind forbids.
func (b *RuleBuilder) buildOptions(r *Rule) error {
	if b.route != nil {
		if err := r.SetRoute(b.route.kind, b.route.targets...); err != nil {
			return err
		}
	}
	if b.divert != nil {
		if err := r.SetDivertTo(b.divert.addr, b.divert.port); err != nil {
			return err
		}
	}
	if b.rtableSet {
		r.SetRTable(b.rtable)
	}
	if b.tag != "" {
		if err := r.SetTag(b.tag); err != nil {
			return err
		}
	}
	if b.taggedSet {
		if err := r.SetTagged(b.tagged, b.taggedNot); err != nil {
			return err
		}
	}
	if b.prioSet {
		if err := r.SetPriority(b.prio); err != nil {
			return err
		}
	}
	if b.setPrioSet {
		if err := r.SetSetPriority(b.setPrio, b.setPrioReply); err != nil {
			return err
		}
	}
	if b.queue != "" {
		if err := r.SetQueue(b.queue, b.queuePrio); err != nil {
			return err
		}
	}
	return nil
}
