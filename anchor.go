package pf

import (
	"fmt"
	"unsafe"
)

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// Anchor allows to read and manipulate rulesets without
// requiring a transaction
type Anchor struct {
	*ioctlDev
	Path string
}

// Rules returns all filter rules using one ticket
func (a Anchor) Rules() ([]Rule, error) {
	return a.RulesOf(RuleSetFilter)
}

// rulesetAction is an action that selects the rule set of the type
var rulesetAction = map[RuleSetType]Action{
	RuleSetScrub:    ActionScrub,
	RuleSetFilter:   ActionPass,
	RuleSetNAT:      ActionNAT,
	RuleSetBINAT:    ActionBINAT,
	RuleSetRedirect: ActionRDR,
}

// RulesOf returns all rules of one type (filter, scrub, nat, binat or rdr)
// using one ticket
func (a Anchor) RulesOf(t RuleSetType) ([]Rule, error) {
	action, ok := rulesetAction[t]
	if !ok {
		return nil, fmt.Errorf("rules of rule set type %d can't be read", int(t))
	}
	var rules C.struct_pfioc_rule
	rules.rule.action = C.u_int8_t(action)
	err := cStringCopy(unsafe.Pointer(&rules.anchor), a.Path, int(C.MAXPATHLEN))
	if err != nil {
		return nil, err
	}
	err = a.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules))
	if err != nil {
		return nil, fmt.Errorf("DIOCGETRULES: %s", err)
	}
	ruleList := make([]Rule, rules.nr)

	for i := 0; i < int(rules.nr); i++ {
		err = a.ruleOf(t, int(rules.ticket), i, &ruleList[i])
		if err != nil {
			return nil, fmt.Errorf("DIOCGETRULE: %s", err)
		}
	}

	return ruleList, nil
}

// Rule uses the passed ticket to return the rule at the given index
func (a Anchor) rule(ticket, index int, rule *Rule) error {
	return a.ruleOf(RuleSetFilter, ticket, index, rule)
}

// ruleOf is rule for the rule set of the given type
func (a Anchor) ruleOf(t RuleSetType, ticket, index int, rule *Rule) error {
	if ticket <= 0 || index < 0 {
		return fmt.Errorf("Invalid ticket or index: ticket %d index %d",
			ticket, index)
	}
	if rule == nil {
		panic(fmt.Errorf("Can't store rule data in nil value"))
	}
	if err := a.ruleNV(t, ticket, index, rule); err != nil {
		return err
	}
	if Action(rule.wrap.rule.action).translates() {
		return a.readPool(ticket, index, rule)
	}
	return nil
}

// Anchors returns the anchors directly below the anchor, as full paths
// (what pfctl -a path -sA shows). The pseudo device lists them in the order
// of the kernel.
func (a Anchor) Anchors() ([]string, error) {
	var rs C.struct_pfioc_ruleset
	if err := cStringCopy(unsafe.Pointer(&rs.path), a.Path, int(C.MAXPATHLEN)); err != nil {
		return nil, err
	}
	if err := a.ioctl(C.DIOCGETRULESETS, unsafe.Pointer(&rs)); err != nil {
		return nil, fmt.Errorf("DIOCGETRULESETS: %s", err)
	}
	n := int(rs.nr)
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		rs.nr = C.u_int32_t(i)
		if err := a.ioctl(C.DIOCGETRULESET, unsafe.Pointer(&rs)); err != nil {
			return nil, fmt.Errorf("DIOCGETRULESET: %s", err)
		}
		name := C.GoString(&rs.name[0])
		if a.Path != "" {
			name = a.Path + "/" + name
		}
		names = append(names, name)
	}
	return names, nil
}
