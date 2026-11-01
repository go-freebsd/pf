package pf

import (
	"fmt"
	"unsafe"
)

// #include <stdlib.h>
// #include <string.h>
// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static int rule_set_ifname(struct pf_rule *r, const char *name) {
	if (strlen(name) >= sizeof(r->ifname)) return -1;
	strlcpy(r->ifname, name, sizeof(r->ifname));
	return 0;
}
static const char *rule_ifname(struct pf_rule *r) { return r->ifname; }
static void rule_set_ifnot(struct pf_rule *r, int v) { r->ifnot = v; }
static int rule_ifnot(struct pf_rule *r) { return r->ifnot; }
*/
import "C"

// SetInterface restricts the rule to packets on the interface or interface
// group ("em0", "lo", "egress"), the "on em0" of pf.conf. An empty name
// removes the restriction. The interface need not exist yet.
func (r *Rule) SetInterface(name string) error {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	if C.rule_set_ifname(&r.wrap.rule, cs) != 0 {
		return fmt.Errorf("interface name %q is too long (max %d)", name, int(C.IFNAMSIZ)-1)
	}
	if name == "" {
		C.rule_set_ifnot(&r.wrap.rule, 0)
	}
	return nil
}

// Interface returns the interface or interface group the rule is restricted
// to, or an empty string.
func (r Rule) Interface() string {
	return C.GoString(C.rule_ifname(&r.wrap.rule))
}

// SetInterfaceNot negates the interface restriction: "on ! em0" matches the
// packets on every interface but em0. It has no effect without an interface.
func (r *Rule) SetInterfaceNot(negate bool) {
	v := 0
	if negate {
		v = 1
	}
	C.rule_set_ifnot(&r.wrap.rule, C.int(v))
}

// InterfaceNot reports whether the interface restriction is negated.
func (r Rule) InterfaceNot() bool {
	return C.rule_ifnot(&r.wrap.rule) != 0
}
