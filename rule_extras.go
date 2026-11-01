package pf

import (
	"fmt"
	"strings"
	"unsafe"
)

// #include <stdlib.h>
// #include <string.h>
// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static int copy_name(char *dst, size_t n, const char *src) {
	if (strlen(src) >= n) return -1;
	strlcpy(dst, src, n);
	return 0;
}
static int rule_set_queue(struct pf_rule *r, const char *q, const char *p) {
	if (copy_name(r->qname, sizeof(r->qname), q) != 0) return -1;
	return copy_name(r->pqname, sizeof(r->pqname), p);
}
static const char *rule_qname(struct pf_rule *r) { return r->qname; }
static const char *rule_pqname(struct pf_rule *r) { return r->pqname; }

static int rule_set_tag(struct pf_rule *r, const char *name) { return copy_name(r->tagname, sizeof(r->tagname), name); }
static const char *rule_tagname(struct pf_rule *r) { return r->tagname; }
static int rule_set_tagged(struct pf_rule *r, const char *name, int not) {
	r->match_tag_not = not;
	return copy_name(r->match_tagname, sizeof(r->match_tagname), name);
}
static const char *rule_match_tagname(struct pf_rule *r) { return r->match_tagname; }
static int rule_match_tag_not(struct pf_rule *r) { return r->match_tag_not; }

static void rule_set_prio(struct pf_rule *r, unsigned int prio) { r->prio = prio; }
static unsigned int rule_prio(struct pf_rule *r) { return r->prio; }
static void rule_set_set_prio(struct pf_rule *r, unsigned int a, unsigned int b) {
	r->set_prio[0] = a;
	r->set_prio[1] = b;
	r->scrub_flags |= PFSTATE_SETPRIO;
}
static void rule_clear_set_prio(struct pf_rule *r) {
	r->set_prio[0] = 0;
	r->set_prio[1] = 0;
	r->scrub_flags &= ~PFSTATE_SETPRIO;
}
static void rule_set_set_prio_raw(struct pf_rule *r, unsigned int a, unsigned int b) {
	r->set_prio[0] = a;
	r->set_prio[1] = b;
}
static unsigned int rule_set_prio_at(struct pf_rule *r, int i) { return r->set_prio[i]; }
static int rule_has_set_prio(struct pf_rule *r) { return (r->scrub_flags & PFSTATE_SETPRIO) != 0; }

*/
import "C"

// SetQueue assigns the packets of the rule to an ALTQ queue and, as an
// option, a second queue for packets with a low delay (TOS) or an ACK
// ("queue (std, ack)"). The kernel keeps the names whether or not it has
// ALTQ; they only take effect with ALTQ and a queue of that name.
func (r *Rule) SetQueue(queue, priority string) error {
	cq := C.CString(queue)
	defer C.free(unsafe.Pointer(cq))
	cp := C.CString(priority)
	defer C.free(unsafe.Pointer(cp))
	if C.rule_set_queue(&r.wrap.rule, cq, cp) != 0 {
		return fmt.Errorf("queue name too long (max %d)", int(C.PF_QNAME_SIZE)-1)
	}
	return nil
}

// Queue returns the names set by SetQueue.
func (r Rule) Queue() (queue, priority string) {
	return C.GoString(C.rule_qname(&r.wrap.rule)), C.GoString(C.rule_pqname(&r.wrap.rule))
}

// SetTag marks the packets the rule matches with the tag ("tag T1").
func (r *Rule) SetTag(name string) error {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	if C.rule_set_tag(&r.wrap.rule, cs) != 0 {
		return fmt.Errorf("tag name too long (max %d)", int(C.PF_TAG_NAME_SIZE)-1)
	}
	return nil
}

// Tag returns the tag the rule sets.
func (r Rule) Tag() string { return C.GoString(C.rule_tagname(&r.wrap.rule)) }

// SetTagged makes the rule match packets that carry the tag, or with
// negate those that do not ("tagged T1", "! tagged T1").
func (r *Rule) SetTagged(name string, negate bool) error {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	n := 0
	if negate {
		n = 1
	}
	if C.rule_set_tagged(&r.wrap.rule, cs, C.int(n)) != 0 {
		return fmt.Errorf("tag name too long (max %d)", int(C.PF_TAG_NAME_SIZE)-1)
	}
	return nil
}

// Tagged returns the tag the rule matches and whether the match is negated.
func (r Rule) Tagged() (name string, negate bool) {
	return C.GoString(C.rule_match_tagname(&r.wrap.rule)), C.rule_match_tag_not(&r.wrap.rule) != 0
}

// SetPriority makes the rule match packets of the priority 0 to 7 ("prio
// 3"). ClearPriority removes the match.
func (r *Rule) SetPriority(prio int) error {
	if prio < 0 || prio > 7 {
		return fmt.Errorf("priority %d is out of range 0-7", prio)
	}
	if prio == 0 {
		// the field is 0 for no priority; "prio 0" has a value of its own
		C.rule_set_prio(&r.wrap.rule, C.PF_PRIO_ZERO)
		return nil
	}
	C.rule_set_prio(&r.wrap.rule, C.uint(prio))
	return nil
}

// ClearPriority removes the priority the rule matches.
func (r *Rule) ClearPriority() { C.rule_set_prio(&r.wrap.rule, 0) }

// Priority returns the priority the rule matches; ok is false for a rule
// that does not match one.
func (r Rule) Priority() (prio int, ok bool) {
	switch v := int(C.rule_prio(&r.wrap.rule)); {
	case v == int(C.PF_PRIO_ZERO):
		return 0, true
	case v >= 1 && v <= 7:
		return v, true
	}
	return 0, false
}

// SetSetPriority makes the rule give the packets the priority (0-7) and,
// for replies, a second one ("set prio (3, 5)"); with the same value twice it
// is "set prio 3". ClearSetPriority removes it.
func (r *Rule) SetSetPriority(prio, replyPrio int) error {
	if prio < 0 || prio > 7 || replyPrio < 0 || replyPrio > 7 {
		return fmt.Errorf("priorities %d, %d are out of range 0-7", prio, replyPrio)
	}
	C.rule_set_set_prio(&r.wrap.rule, C.uint(prio), C.uint(replyPrio))
	return nil
}

// ClearSetPriority removes the priority the rule sets.
func (r *Rule) ClearSetPriority() { C.rule_clear_set_prio(&r.wrap.rule) }

// SetPriorityOf returns the priorities the rule sets and whether it sets
// any.
func (r Rule) SetPriorityOf() (prio, replyPrio int, ok bool) {
	if C.rule_has_set_prio(&r.wrap.rule) == 0 {
		return 0, 0, false
	}
	return int(C.rule_set_prio_at(&r.wrap.rule, 0)), int(C.rule_set_prio_at(&r.wrap.rule, 1)), true
}

// setExtrasRaw stores what the kernel reports for the attributes of this
// file.
func (r *Rule) setExtrasRaw(qname, pqname, tag, matchTag string, matchNot, prio uint64, setPrio []uint64) {
	_ = r.SetQueue(qname, pqname)
	_ = r.SetTag(tag)
	_ = r.SetTagged(matchTag, matchNot != 0)
	C.rule_set_prio(&r.wrap.rule, C.uint(prio))
	for len(setPrio) < 2 {
		setPrio = append(setPrio, 0)
	}
	C.rule_set_set_prio_raw(&r.wrap.rule, C.uint(setPrio[0]), C.uint(setPrio[1]))
}

// prioString is how pfctl prints the priority a rule matches and sets.
func (r Rule) prioString() []string {
	var out []string
	if p, ok := r.Priority(); ok {
		out = append(out, fmt.Sprintf("prio %d", p))
	}
	if a, b, ok := r.SetPriorityOf(); ok {
		if a == b {
			out = append(out, fmt.Sprintf("set ( prio %d )", a))
		} else {
			out = append(out, fmt.Sprintf("set ( prio(%d, %d) )", a, b))
		}
	}
	return out
}

// extrasString is how pfctl prints the queue and the tags after
// the state.
func (r Rule) extrasString() []string {
	var out []string
	if q, p := r.Queue(); q != "" {
		if p != "" {
			out = append(out, fmt.Sprintf("queue(%s, %s)", q, p))
		} else {
			out = append(out, "queue "+q)
		}
	}
	if t := r.Tag(); t != "" {
		out = append(out, "tag "+t)
	}
	if t, neg := r.Tagged(); t != "" {
		if neg {
			out = append(out, "! tagged "+t)
		} else {
			out = append(out, "tagged "+t)
		}
	}
	return []string{strings.Join(out, " ")}
}
