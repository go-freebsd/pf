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

// Rules returns all rules using one ticket
func (a Anchor) Rules() ([]Rule, error) {
	var rules C.struct_pfioc_rule
	err := a.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules))
	if err != nil {
		return nil, fmt.Errorf("DIOCGETRULES: %s", err)
	}
	ruleList := make([]Rule, rules.nr)

	for i := 0; i < int(rules.nr); i++ {
		err = a.rule(int(rules.ticket), i, &ruleList[i])
		if err != nil {
			return nil, fmt.Errorf("DIOCGETRULE: %s", err)
		}
	}

	return ruleList, nil
}

// Rule uses the passed ticket to return the rule at the given index
func (a Anchor) rule(ticket, index int, rule *Rule) error {
	if ticket <= 0 || index < 0 {
		return fmt.Errorf("Invalid ticket or index: ticket %d index %d",
			ticket, index)
	}
	if rule == nil {
		panic(fmt.Errorf("Can't store rule data in nil value"))
	}
	rule.wrap.nr = C.u_int32_t(index)
	rule.wrap.ticket = C.u_int32_t(ticket)
	return a.ioctl(C.DIOCGETRULE, unsafe.Pointer(&rule.wrap))
}
