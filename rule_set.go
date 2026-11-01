package pf

import (
	"fmt"
	"unsafe"
)

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// RuleSet represents a pf rule set that is a collection of
// rules
type RuleSet struct {
	tx   Transaction
	wrap *C.struct_pfioc_trans_e
}

// RuleSetType is the type of a given rule set
type RuleSetType int

const (
	// RuleSetScrub Scrub (packet normalization) rules.
	RuleSetScrub RuleSetType = C.PF_RULESET_SCRUB
	// RuleSetFilter Filter rules.
	RuleSetFilter RuleSetType = C.PF_RULESET_FILTER
	// RuleSetNAT NAT (Network Address Translation) rules.
	RuleSetNAT RuleSetType = C.PF_RULESET_NAT
	// RuleSetBINAT Bidirectional NAT rules.
	RuleSetBINAT RuleSetType = C.PF_RULESET_BINAT
	// RuleSetRedirect Redirect rules.
	RuleSetRedirect RuleSetType = C.PF_RULESET_RDR
	// RuleSetALTQ ALTQ disciplines.
	RuleSetALTQ RuleSetType = C.PF_RULESET_ALTQ
	// RuleSetTable Address tables.
	RuleSetTable RuleSetType = C.PF_RULESET_TABLE
)

// SetType can be used to change the type of a rule set
func (rs *RuleSet) SetType(t RuleSetType) {
	rs.wrap.rs_num = C.int(t)
}

// Type returns the type of the rule set
func (rs RuleSet) Type() RuleSetType {
	return RuleSetType(rs.wrap.rs_num)
}

// SetAnchor can be used to set the anchor path for the rule set
func (rs *RuleSet) SetAnchor(path string) error {
	return cStringCopy(unsafe.Pointer(&rs.wrap.anchor), path, int(C.MAXPATHLEN))
}

// Anchor returns the anchor of the rule set
func (rs RuleSet) Anchor() string {
	return C.GoString(&rs.wrap.anchor[0])
}

// AddRule adds the given rule to the end of the rule set
func (rs RuleSet) AddRule(r *Rule) error {
	if r == nil {
		panic(fmt.Errorf("Empty/nil rules aren't permitted by pf"))
	}
	defer func() { r.wrap.ticket = 0 }()
	r.wrap.ticket = rs.wrap.ticket
	// the kernel adds the rule to the rule set named by the rule itself:
	// without the anchor the rule goes to the main rule set and fails with
	// EBUSY (its ticket belongs to the anchor's rule set)
	r.wrap.anchor = rs.wrap.anchor
	r.applyRTable()
	// every rule needs a fresh pool ticket (pfctl asks for one with
	// DIOCBEGINADDRS, too). Ticket 0 is only accepted by a kernel on which
	// nobody has loaded a rule yet.
	var pool C.struct_pfioc_pooladdr
	if err := rs.tx.handle.ioctl(C.DIOCBEGINADDRS, unsafe.Pointer(&pool)); err != nil {
		return fmt.Errorf("DIOCBEGINADDRS: %s", err)
	}
	r.wrap.pool_ticket = pool.ticket
	if err := rs.addPool(r, pool.ticket); err != nil {
		return err
	}
	err := rs.tx.handle.ioctl(C.DIOCADDRULE, unsafe.Pointer(&r.wrap))
	if err != nil {
		return fmt.Errorf("DIOCADDRULE: %s", err)
	}
	return nil
}

// AddRuleOnInterfaces adds the rule once for every interface or interface
// group, in the given order, each with its own "on <interface>": the
// expansion pfctl makes of "on { em0 em1 }". Whether the interface is negated
// is taken from the rule. The rule itself is not changed. Without interfaces
// it is AddRule.
func (rs RuleSet) AddRuleOnInterfaces(r *Rule, interfaces ...string) error {
	if r == nil {
		panic(fmt.Errorf("Empty/nil rules aren't permitted by pf"))
	}
	if len(interfaces) == 0 {
		return rs.AddRule(r)
	}
	// check every name before the first rule goes to the kernel
	rules := make([]Rule, len(interfaces))
	for i, name := range interfaces {
		if name == "" {
			return fmt.Errorf("interface %d of the list is empty", i)
		}
		rules[i] = *r
		if err := rules[i].SetInterface(name); err != nil {
			return err
		}
	}
	for i := range rules {
		if err := rs.AddRule(&rules[i]); err != nil {
			return fmt.Errorf("interface %q: %s", interfaces[i], err)
		}
	}
	return nil
}
