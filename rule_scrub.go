package pf

import (
	"fmt"
	"strings"
)

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void rule_set_scrub(struct pf_rule *r, int nodf, int randomid, int tcp, unsigned int minttl, unsigned int maxmss) {
	// the rule describes the option twice: pfctl sets the rule flag, the kernel
	// keeps the state flag
	r->rule_flag &= ~(PFRULE_NODF | PFRULE_RANDOMID | PFRULE_REASSEMBLE_TCP);
	r->scrub_flags &= ~(PFSTATE_NODF | PFSTATE_RANDOMID | PFSTATE_SCRUB_TCP);
	if (nodf) { r->rule_flag |= PFRULE_NODF; r->scrub_flags |= PFSTATE_NODF; }
	if (randomid) { r->rule_flag |= PFRULE_RANDOMID; r->scrub_flags |= PFSTATE_RANDOMID; }
	if (tcp) { r->rule_flag |= PFRULE_REASSEMBLE_TCP; r->scrub_flags |= PFSTATE_SCRUB_TCP; }
	r->min_ttl = minttl;
	r->max_mss = maxmss;
}
static void rule_set_scrub_raw(struct pf_rule *r, unsigned int rule_flag, unsigned int scrub_flags, unsigned int minttl, unsigned int maxmss) {
	r->rule_flag = rule_flag;
	r->scrub_flags = scrub_flags;
	r->min_ttl = minttl;
	r->max_mss = maxmss;
}
static int rule_scrub_nodf(struct pf_rule *r) { return (r->rule_flag & PFRULE_NODF) || (r->scrub_flags & PFSTATE_NODF); }
static int rule_scrub_randomid(struct pf_rule *r) { return (r->rule_flag & PFRULE_RANDOMID) || (r->scrub_flags & PFSTATE_RANDOMID); }
static int rule_scrub_tcp(struct pf_rule *r) { return (r->rule_flag & PFRULE_REASSEMBLE_TCP) || (r->scrub_flags & PFSTATE_SCRUB_TCP); }
static unsigned int rule_min_ttl(struct pf_rule *r) { return r->min_ttl; }
static unsigned int rule_max_mss(struct pf_rule *r) { return r->max_mss; }
*/
import "C"

// ScrubOptions are the options of a scrub rule.
type ScrubOptions struct {
	// NoDF clears the don't-fragment bit (no-df).
	NoDF bool
	// RandomID replaces the IP identification field with random values
	// (random-id).
	RandomID bool
	// ReassembleTCP normalizes TCP connections (reassemble tcp); pf.conf
	// takes it only in a rule without a direction.
	ReassembleTCP bool
	// MinTTL raises a lower TTL to this value (min-ttl), 0 for none.
	MinTTL uint8
	// MaxMSS lowers a higher TCP maximum segment size to this value
	// (max-mss), 0 for none.
	MaxMSS uint16
}

// SetScrub sets the options of a scrub rule. Fragments are always
// reassembled, the "fragment reassemble" that pfctl prints for every scrub
// rule.
func (r *Rule) SetScrub(o ScrubOptions) {
	b := func(v bool) C.int {
		if v {
			return 1
		}
		return 0
	}
	C.rule_set_scrub(&r.wrap.rule, b(o.NoDF), b(o.RandomID), b(o.ReassembleTCP), C.uint(o.MinTTL), C.uint(o.MaxMSS))
}

// Scrub returns the options of a scrub rule.
func (r Rule) Scrub() ScrubOptions {
	return ScrubOptions{
		NoDF:          C.rule_scrub_nodf(&r.wrap.rule) != 0,
		RandomID:      C.rule_scrub_randomid(&r.wrap.rule) != 0,
		ReassembleTCP: C.rule_scrub_tcp(&r.wrap.rule) != 0,
		MinTTL:        uint8(C.rule_min_ttl(&r.wrap.rule)),
		MaxMSS:        uint16(C.rule_max_mss(&r.wrap.rule)),
	}
}

// setScrubRaw stores what the kernel reports.
func (r *Rule) setScrubRaw(ruleFlag, scrubFlags, minTTL, maxMSS uint64) {
	C.rule_set_scrub_raw(&r.wrap.rule, C.uint(ruleFlag), C.uint(scrubFlags), C.uint(minTTL), C.uint(maxMSS))
}

// scrubString is how pfctl prints the options of a scrub rule.
func (r Rule) scrubString() string {
	if r.Action() != ActionScrub {
		return ""
	}
	o := r.Scrub()
	var parts []string
	if o.NoDF {
		parts = append(parts, "no-df")
	}
	if o.RandomID {
		parts = append(parts, "random-id")
	}
	if o.MinTTL != 0 {
		parts = append(parts, fmt.Sprintf("min-ttl %d", o.MinTTL))
	}
	if o.MaxMSS != 0 {
		parts = append(parts, fmt.Sprintf("max-mss %d", o.MaxMSS))
	}
	if o.ReassembleTCP {
		parts = append(parts, "reassemble tcp")
	}
	parts = append(parts, "fragment reassemble")
	return strings.Join(parts, " ")
}
