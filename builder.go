package pf

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// RuleBuilder builds a rule the way pf.conf writes it, with the defaults
// pfctl gives: a pass rule keeps state (with the TCP flags S/SA for tcp), a
// block rule drops, "any" is any address and no port clause is no port. The
// methods return the builder, so a rule reads like its pf.conf line:
//
//	pf.NAT().On("em0").Inet().RedirectToInterface("em0").RoundRobin()
//	// nat on em0 inet from any to any -> (em0) round-robin
//
// A bad argument does not stop the chain: the error is remembered and
// returned, with all the others, by Rule, Rules or Ruleset.Load. Nothing is
// sent to the kernel before the whole rule has been checked against what
// pfctl would refuse.
type RuleBuilder struct {
	kind builderKind
	errs []error

	direction Direction
	dirSet    bool
	quick     bool
	log       bool
	ifaces    []string
	ifNot     bool

	af    AddressFamily
	proto Protocol

	src, dst builderSide

	flags    string
	flagsSet bool

	state    State
	stateSet bool

	redirect *builderRedirect
	pool     PoolType
	sticky   bool
	static   bool

	scrub    ScrubOptions
	scrubSet bool
}

type builderKind uint8

const (
	kindPass builderKind = iota
	kindBlock
	kindMatch
	kindNAT
	kindNoNAT
	kindRDR
	kindNoRDR
	kindBINAT
	kindNoBINAT
	kindScrub
)

// builderSide is the source or the destination of a rule.
type builderSide struct {
	addr  addrSpec
	set   bool
	ports string
}

// builderRedirect is the "-> address port" of a translation rule.
type builderRedirect struct {
	kind  addrKind
	text  string
	flags DynamicFlag
	ports string
}

func newBuilder(k builderKind) *RuleBuilder {
	return &RuleBuilder{kind: k}
}

// Pass starts a rule that lets the packets it matches through. Like pfctl it
// keeps state by default (NoState opts out), and a tcp rule that keeps state
// matches the flags S/SA.
func Pass() *RuleBuilder { return newBuilder(kindPass) }

// Block starts a rule that drops the packets it matches. It keeps no state.
func Block() *RuleBuilder { return newBuilder(kindBlock) }

// Match starts a rule that only sets options for the packets it matches and
// leaves the decision to later rules.
func Match() *RuleBuilder { return newBuilder(kindMatch) }

// NAT starts a nat rule: the source addresses of the packets are translated.
// Translate to an address with RedirectTo, RedirectToInterface or
// RedirectToTable.
func NAT() *RuleBuilder { return newBuilder(kindNAT) }

// NoNAT starts a rule that exempts the packets it matches from nat.
func NoNAT() *RuleBuilder { return newBuilder(kindNoNAT) }

// RDR starts a rdr rule: the destination of the packets is redirected.
func RDR() *RuleBuilder { return newBuilder(kindRDR) }

// NoRDR starts a rule that exempts the packets it matches from rdr.
func NoRDR() *RuleBuilder { return newBuilder(kindNoRDR) }

// BINAT starts a binat rule: a one-to-one translation in both directions.
func BINAT() *RuleBuilder { return newBuilder(kindBINAT) }

// NoBINAT starts a rule that exempts the packets it matches from binat.
func NoBINAT() *RuleBuilder { return newBuilder(kindNoBINAT) }

// Scrub starts a rule that normalizes the packets it matches.
func Scrub() *RuleBuilder { return newBuilder(kindScrub) }

func (k builderKind) translation() bool {
	switch k {
	case kindNAT, kindNoNAT, kindRDR, kindNoRDR, kindBINAT, kindNoBINAT:
		return true
	}
	return false
}

// negative reports whether the kind is a "no" rule, which takes no target.
func (k builderKind) negative() bool {
	return k == kindNoNAT || k == kindNoRDR || k == kindNoBINAT
}

func (k builderKind) String() string {
	switch k {
	case kindPass:
		return "pass"
	case kindBlock:
		return "block"
	case kindMatch:
		return "match"
	case kindNAT:
		return "nat"
	case kindNoNAT:
		return "no nat"
	case kindRDR:
		return "rdr"
	case kindNoRDR:
		return "no rdr"
	case kindBINAT:
		return "binat"
	case kindNoBINAT:
		return "no binat"
	case kindScrub:
		return "scrub"
	}
	return "rule"
}

// RuleSetType is the kind of rule set the rule belongs to.
func (b *RuleBuilder) RuleSetType() RuleSetType {
	switch b.kind {
	case kindScrub:
		return RuleSetScrub
	case kindNAT, kindNoNAT:
		return RuleSetNAT
	case kindRDR, kindNoRDR:
		return RuleSetRedirect
	case kindBINAT, kindNoBINAT:
		return RuleSetBINAT
	}
	return RuleSetFilter
}

// Clone returns an independent copy, to derive several rules from a common
// start.
func (b *RuleBuilder) Clone() *RuleBuilder {
	c := *b
	c.errs = append([]error(nil), b.errs...)
	c.ifaces = append([]string(nil), b.ifaces...)
	if b.redirect != nil {
		r := *b.redirect
		c.redirect = &r
	}
	return &c
}

func (b *RuleBuilder) fail(format string, args ...any) *RuleBuilder {
	b.errs = append(b.errs, fmt.Errorf("%s: "+format, append([]any{b.kind}, args...)...))
	return b
}

// In matches packets coming in.
func (b *RuleBuilder) In() *RuleBuilder { return b.setDirection(DirectionIn) }

// Out matches packets going out.
func (b *RuleBuilder) Out() *RuleBuilder { return b.setDirection(DirectionOut) }

func (b *RuleBuilder) setDirection(d Direction) *RuleBuilder {
	if b.dirSet && b.direction != d {
		return b.fail("in and out are both set; leave the direction out to match both")
	}
	b.direction, b.dirSet = d, true
	return b
}

// Quick makes the rule the last one looked at if it matches.
func (b *RuleBuilder) Quick() *RuleBuilder { b.quick = true; return b }

// Log logs the packets that match to the log interface (pflog0).
func (b *RuleBuilder) Log() *RuleBuilder { b.log = true; return b }

// On restricts the rule to an interface or interface group ("em0", "lo",
// "egress").
func (b *RuleBuilder) On(name string) *RuleBuilder { return b.OnAny(name) }

// OnNot restricts the rule to the packets on every interface but this one
// ("on ! em0").
func (b *RuleBuilder) OnNot(name string) *RuleBuilder {
	b.ifNot = true
	return b.OnAny(name)
}

// OnAny restricts the rule to several interfaces, "on { em0 em1 }": Rules
// returns one rule for each, in this order, like pfctl does.
func (b *RuleBuilder) OnAny(names ...string) *RuleBuilder {
	for _, n := range names {
		if n == "" || strings.ContainsAny(n, " \t{}!,") {
			return b.fail("%q is not an interface name", n)
		}
		b.ifaces = append(b.ifaces, n)
	}
	return b
}

// Inet restricts the rule to IPv4.
func (b *RuleBuilder) Inet() *RuleBuilder { return b.setFamily(AddressFamilyInet) }

// Inet6 restricts the rule to IPv6.
func (b *RuleBuilder) Inet6() *RuleBuilder { return b.setFamily(AddressFamilyInet6) }

func (b *RuleBuilder) setFamily(af AddressFamily) *RuleBuilder {
	if b.af != AddressFamilyAny && b.af != af {
		return b.fail("inet and inet6 are both set")
	}
	b.af = af
	return b
}

// Proto restricts the rule to a protocol.
func (b *RuleBuilder) Proto(p Protocol) *RuleBuilder {
	b.proto = p
	return b
}

// From sets the source address: a host or network ("10.0.0.0/8", "::1"),
// "any", a table ("<name>"), the addresses of an interface ("(em0)",
// "(em0:network)", "(em0:0)"), "no-route" or "urpf-failed". A leading "!"
// negates it.
func (b *RuleBuilder) From(addr string) *RuleBuilder { return b.side(&b.src, "from", addr, false) }

// FromNot is From with the address negated.
func (b *RuleBuilder) FromNot(addr string) *RuleBuilder { return b.side(&b.src, "from", addr, true) }

// To sets the destination address, see From.
func (b *RuleBuilder) To(addr string) *RuleBuilder { return b.side(&b.dst, "to", addr, false) }

// ToNot is To with the address negated.
func (b *RuleBuilder) ToNot(addr string) *RuleBuilder { return b.side(&b.dst, "to", addr, true) }

// FromPort sets the source port: "22", "1024:65535", ">1023", "!=22",
// "1<>10" (exclusive range), "10><100" (outside the range). It needs the
// protocol tcp or udp.
func (b *RuleBuilder) FromPort(ports string) *RuleBuilder {
	b.src.ports = strings.TrimSpace(ports)
	return b
}

// ToPort sets the destination port, see FromPort.
func (b *RuleBuilder) ToPort(ports string) *RuleBuilder {
	b.dst.ports = strings.TrimSpace(ports)
	return b
}

func (b *RuleBuilder) side(s *builderSide, word, addr string, not bool) *RuleBuilder {
	spec, af, err := parseAddrText(addr)
	if err != nil {
		return b.fail("%s %q: %s", word, addr, err)
	}
	if not {
		spec.not = !spec.not
	}
	s.addr, s.set = spec, true
	if af != AddressFamilyAny {
		if b.af != AddressFamilyAny && b.af != af {
			return b.fail("%s %q is %s but the rule is %s", word, addr, af, b.af)
		}
		b.af = af
	}
	return b
}

// parseAddrText reads the address forms of pf.conf.
func parseAddrText(text string) (addrSpec, AddressFamily, error) {
	var s addrSpec
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "!") {
		s.not = true
		t = strings.TrimSpace(t[1:])
	}
	switch {
	case t == "":
		return s, 0, errors.New("empty address")
	case t == "any":
		s.kind = addrAny
		return s, 0, nil
	case t == "no-route":
		s.kind = addrNoRoute
		return s, 0, nil
	case t == "urpf-failed":
		s.kind = addrURPFFailed
		return s, 0, nil
	case strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">"):
		name := t[1 : len(t)-1]
		if name == "" || strings.ContainsAny(name, " \t<>{}") {
			return s, 0, fmt.Errorf("%q is not a table name", t)
		}
		s.kind, s.text = addrTable, name
		return s, 0, nil
	case strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")"):
		parts := strings.Split(t[1:len(t)-1], ":")
		name := strings.TrimSpace(parts[0])
		if name == "" || strings.ContainsAny(name, " \t(){}") {
			return s, 0, fmt.Errorf("%q is not an interface address", t)
		}
		for _, m := range parts[1:] {
			switch m {
			case "network":
				s.flags |= DynamicFlagNetwork
			case "broadcast":
				s.flags |= DynamicFlagBroadcast
			case "peer":
				s.flags |= DynamicFlagPeer
			case "0":
				s.flags |= DynamicFlagNoAlias
			default:
				return s, 0, fmt.Errorf("unknown modifier %q in %q (want network, broadcast, peer or 0)", m, t)
			}
		}
		s.kind, s.text = addrInterface, name
		return s, 0, nil
	}
	ip := t
	if i := strings.IndexByte(t, '/'); i >= 0 {
		ip = t[:i]
		if _, _, err := net.ParseCIDR(t); err != nil {
			return s, 0, fmt.Errorf("%q is not an address or network", t)
		}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return s, 0, fmt.Errorf("%q is not an address, a network, a table (<name>) or an interface ((name))", t)
	}
	s.kind, s.text = addrNet, t
	if parsed.To4() != nil && !strings.Contains(ip, ":") {
		return s, AddressFamilyInet, nil
	}
	return s, AddressFamilyInet6, nil
}

// Flags sets the TCP flags the rule matches: "S/SA" (SYN set, ACK not, out
// of SYN and ACK) or "any" for no check. A tcp rule that keeps state gets
// "S/SA" when this is not called, like with pfctl.
func (b *RuleBuilder) Flags(f string) *RuleBuilder {
	b.flags, b.flagsSet = f, true
	return b
}

// KeepState tracks the connections of the rule (the default of Pass).
func (b *RuleBuilder) KeepState() *RuleBuilder { b.state, b.stateSet = StateKeep, true; return b }

// NoState tracks no connections, so every packet of both directions needs a
// rule that passes it.
func (b *RuleBuilder) NoState() *RuleBuilder { b.state, b.stateSet = StateNo, true; return b }

// ModulateState keeps state and gives tcp connections random sequence
// numbers.
func (b *RuleBuilder) ModulateState() *RuleBuilder {
	b.state, b.stateSet = StateModulate, true
	return b
}

// SynproxyState keeps state and answers the tcp handshake itself before it
// lets the connection through.
func (b *RuleBuilder) SynproxyState() *RuleBuilder {
	b.state, b.stateSet = StateSynproxy, true
	return b
}

// RedirectTo translates to a host or network ("192.0.2.1"), the part after
// "->" in pf.conf. For nat and rdr an optional port or range follows:
// RedirectTo("10.0.0.5", "8080") or ("10.0.0.5", "50000:60000").
func (b *RuleBuilder) RedirectTo(addr string, ports ...string) *RuleBuilder {
	spec, af, err := parseAddrText(addr)
	if err != nil || spec.kind != addrNet {
		return b.fail("-> %q is not a host or network (use RedirectToInterface or RedirectToTable)", addr)
	}
	if af != AddressFamilyAny && b.af != AddressFamilyAny && b.af != af {
		return b.fail("-> %q is %s but the rule is %s", addr, af, b.af)
	}
	if af != AddressFamilyAny && b.af == AddressFamilyAny {
		b.af = af
	}
	return b.setRedirect(&builderRedirect{kind: addrNet, text: spec.text, ports: firstOf(ports)})
}

// RedirectToInterface translates to the address of an interface, "-> (em0)":
// the address follows the interface when it changes. The modifiers pick the
// addresses, as in pf.conf: DynamicFlagNetwork "(em0:network)",
// DynamicFlagBroadcast, DynamicFlagPeer, DynamicFlagNoAlias "(em0:0)".
func (b *RuleBuilder) RedirectToInterface(name string, flags ...DynamicFlag) *RuleBuilder {
	if name == "" || strings.ContainsAny(name, " \t(){}:") {
		return b.fail("-> (%s) is not an interface", name)
	}
	var all DynamicFlag
	for _, f := range flags {
		all |= f
	}
	return b.setRedirect(&builderRedirect{kind: addrInterface, text: name, flags: all})
}

// RedirectToTable translates to the addresses of a table, "-> <name>"; spread
// them with RoundRobin, Random, ....
func (b *RuleBuilder) RedirectToTable(name string) *RuleBuilder {
	if name == "" || strings.ContainsAny(name, " \t<>{}") {
		return b.fail("-> <%s> is not a table", name)
	}
	return b.setRedirect(&builderRedirect{kind: addrTable, text: name})
}

// RedirectPort sets the port or range the translation uses on the target: a
// rdr rule's "port 8080", a nat rule's "port 50000:60000". A nat rule
// without it uses the dynamic range 50001:65535 (StaticPort keeps the
// source port instead).
func (b *RuleBuilder) RedirectPort(ports string) *RuleBuilder {
	if b.redirect == nil {
		return b.fail("RedirectPort needs a target first (RedirectTo, RedirectToInterface or RedirectToTable)")
	}
	b.redirect.ports = strings.TrimSpace(ports)
	return b
}

func (b *RuleBuilder) setRedirect(r *builderRedirect) *RuleBuilder {
	if b.redirect != nil {
		return b.fail("two targets: only the last one of RedirectTo*, ... counts")
	}
	b.redirect = r
	return b
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.TrimSpace(s[0])
}

// RoundRobin spreads the connections over the addresses of the target in turn.
func (b *RuleBuilder) RoundRobin() *RuleBuilder { return b.setPool(PoolRoundRobin) }

// Random picks an address of the target at random.
func (b *RuleBuilder) Random() *RuleBuilder { return b.setPool(PoolRandom) }

// BitMask combines the network part of the target with the host part of the
// source address.
func (b *RuleBuilder) BitMask() *RuleBuilder { return b.setPool(PoolBitmask) }

func (b *RuleBuilder) setPool(t PoolType) *RuleBuilder {
	if b.pool != PoolNone && b.pool != t {
		return b.fail("two pool types (%s and %s)", b.pool, t)
	}
	b.pool = t
	return b
}

// StickyAddress keeps a connection's translation address for its later
// connections.
func (b *RuleBuilder) StickyAddress() *RuleBuilder { b.sticky = true; return b }

// StaticPort keeps the source port of a nat rule instead of translating it
// to the dynamic range.
func (b *RuleBuilder) StaticPort() *RuleBuilder { b.static = true; return b }

// NoDF clears the don't-fragment bit (scrub).
func (b *RuleBuilder) NoDF() *RuleBuilder { b.scrub.NoDF, b.scrubSet = true, true; return b }

// RandomID replaces the IP identification field with random values (scrub).
func (b *RuleBuilder) RandomID() *RuleBuilder { b.scrub.RandomID, b.scrubSet = true, true; return b }

// MinTTL raises a lower TTL to this value (scrub).
func (b *RuleBuilder) MinTTL(ttl uint8) *RuleBuilder {
	b.scrub.MinTTL, b.scrubSet = ttl, true
	return b
}

// MaxMSS lowers a higher TCP maximum segment size to this value (scrub).
func (b *RuleBuilder) MaxMSS(mss uint16) *RuleBuilder {
	b.scrub.MaxMSS, b.scrubSet = mss, true
	return b
}

// ReassembleTCP normalizes TCP connections (scrub); pf.conf takes it in a
// rule without a direction only.
func (b *RuleBuilder) ReassembleTCP() *RuleBuilder {
	b.scrub.ReassembleTCP, b.scrubSet = true, true
	return b
}
