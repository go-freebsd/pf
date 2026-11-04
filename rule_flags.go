package pf

import (
	"fmt"
	"strings"
)

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void rule_set_flags(struct pf_rule *r, unsigned int flags, unsigned int mask) {
	r->flags = flags;
	r->flagset = mask;
}
static unsigned int rule_flags(struct pf_rule *r) { return r->flags; }
static unsigned int rule_flagset(struct pf_rule *r) { return r->flagset; }
*/
import "C"

// TCPFlags is a set of TCP header flags, the letters of pf.conf.
type TCPFlags uint8

// The TCP flags with the letters pf.conf uses for them.
const (
	TCPFlagFIN TCPFlags = 0x01 // F
	TCPFlagSYN TCPFlags = 0x02 // S
	TCPFlagRST TCPFlags = 0x04 // R
	TCPFlagPSH TCPFlags = 0x08 // P
	TCPFlagACK TCPFlags = 0x10 // A
	TCPFlagURG TCPFlags = 0x20 // U
	TCPFlagECE TCPFlags = 0x40 // E
	TCPFlagCWR TCPFlags = 0x80 // W
)

// tcpFlagLetters in the order of the bits, as pfctl prints them
const tcpFlagLetters = "FSRPAUEW"

// String returns the flags as letters ("SA"), empty for none.
func (f TCPFlags) String() string {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		if f&(1<<uint(i)) != 0 {
			b.WriteByte(tcpFlagLetters[i])
		}
	}
	return b.String()
}

// ParseTCPFlags parses letters such as "SA". An empty string is no flags.
func ParseTCPFlags(s string) (TCPFlags, error) {
	var f TCPFlags
	for _, c := range s {
		i := strings.IndexRune(tcpFlagLetters, c)
		if i < 0 {
			return 0, fmt.Errorf("unknown TCP flag %q (want some of %s)", c, tcpFlagLetters)
		}
		f |= 1 << uint(i)
	}
	return f, nil
}

// SetTCPFlags makes the rule match TCP packets whose flags, looked at through
// the mask, are the given ones: flags S, mask SA is "flags S/SA" of pf.conf,
// the packets with SYN set and ACK not. With flags and mask empty the flags
// are not looked at ("flags any"). Every flag must be in the mask. The flags
// only apply to the protocol tcp.
func (r *Rule) SetTCPFlags(flags, mask TCPFlags) error {
	if flags&^mask != 0 {
		return fmt.Errorf("flags %s are not in the mask %s: the rule would never match", flags, mask)
	}
	r.setTCPFlagsRaw(flags, mask)
	return nil
}

// setTCPFlagsRaw stores flags the way the kernel reports them, unchecked.
func (r *Rule) setTCPFlagsRaw(flags, mask TCPFlags) {
	C.rule_set_flags(&r.wrap.rule, C.uint(flags), C.uint(mask))
}

// TCPFlags returns the flags and the mask of the rule, see SetTCPFlags.
func (r Rule) TCPFlags() (flags, mask TCPFlags) {
	return TCPFlags(C.rule_flags(&r.wrap.rule)), TCPFlags(C.rule_flagset(&r.wrap.rule))
}

// ParseTCPFlags sets the flags from their pf.conf spelling: "S/SA", "any".
func (r *Rule) ParseTCPFlags(s string) error {
	if s == "any" {
		return r.SetTCPFlags(0, 0)
	}
	f, m, ok := strings.Cut(s, "/")
	if !ok {
		return fmt.Errorf("TCP flags %q: want flags/mask (\"S/SA\") or \"any\"", s)
	}
	flags, err := ParseTCPFlags(f)
	if err != nil {
		return err
	}
	mask, err := ParseTCPFlags(m)
	if err != nil {
		return err
	}
	return r.SetTCPFlags(flags, mask)
}

// tcpFlagsString is how pfctl prints the flags of a rule: "flags S/SA" when
// flags or mask are set (whatever the protocol: pfctl gives a pass rule that
// keeps state and has no protocol the flags S/SA as well), "flags any" for a
// tcp rule that keeps state and does not look at the flags, nothing
// otherwise.
func (r Rule) tcpFlagsString() string {
	flags, mask := r.TCPFlags()
	if flags != 0 || mask != 0 {
		return fmt.Sprintf("flags %s/%s", flags, mask)
	}
	if r.Protocol() == ProtocolTCP && r.State() != StateNo {
		return "flags any"
	}
	return ""
}
