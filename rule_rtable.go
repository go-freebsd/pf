package pf

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void rule_set_rtableid(struct pf_rule *r, int id) { r->rtableid = id; }
*/
import "C"

// SetRTable makes the rule act on routing table n: the packets it passes are
// routed with it ("rtable n" of pf.conf). A rule without it leaves the
// routing table alone, which is not the same as table 0. The number is not
// checked: the kernel refuses a table that does not exist (net.fibs).
func (r *Rule) SetRTable(n int) {
	r.rtable = int32(n) + 1
}

// ClearRTable removes the routing table of the rule.
func (r *Rule) ClearRTable() { r.rtable = 0 }

// RTable returns the routing table of the rule and whether it has one.
func (r Rule) RTable() (n int, ok bool) {
	return int(r.rtable) - 1, r.rtable != 0
}

// setRTableRaw stores the rtableid the kernel reports (-1 for none).
func (r *Rule) setRTableRaw(id int64) {
	if id < 0 {
		r.rtable = 0
		return
	}
	r.rtable = int32(id) + 1
}

// applyRTable writes the routing table to the struct the kernel gets: none is
// -1, not 0.
func (r *Rule) applyRTable() {
	id := int(r.rtable) - 1
	C.rule_set_rtableid(&r.wrap.rule, C.int(id))
}

// rtableString is the "rtable N" pfctl prints.
func (r Rule) rtableString() string {
	if n, ok := r.RTable(); ok {
		return "rtable " + itoa(n)
	}
	return ""
}
