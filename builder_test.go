package pf

// The builder is checked against pfctl twice. Its defaults: the minimal
// pf.conf line and the minimal builder must give the very same rules in the
// kernel, as pfctl prints them. Its refusals: whatever pfctl refuses, the
// builder must refuse too, and what pfctl accepts, the builder must build.

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func slug(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, strings.ToLower(s))
}

// pfctlAccepts reports whether pfctl would load the rules (it only parses).
func pfctlAccepts(conf string) error {
	cmd := exec.Command("pfctl", "-n", "-f", "-")
	cmd.Stdin = strings.NewReader(conf + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &pfctlError{strings.TrimSpace(string(out))}
	}
	return nil
}

type pfctlError struct{ text string }

func (e *pfctlError) Error() string { return e.text }

// shown is what pfctl prints for the translation and the filter rules of an
// anchor.
func shown(t *testing.T, anchor string) (string, string) {
	t.Helper()
	return pfctl(t, "", "-a", anchor, "-sn"), pfctl(t, "", "-a", anchor, "-sr")
}

var defaultCases = []struct {
	name string
	conf string
	rule func() *RuleBuilder
}{
	{"pass", "pass", func() *RuleBuilder { return Pass() }},
	{"pass in", "pass in", func() *RuleBuilder { return Pass().In() }},
	{"pass out quick log", "pass out log quick", func() *RuleBuilder { return Pass().Out().Quick().Log() }},
	{"pass tcp", "pass proto tcp", func() *RuleBuilder { return Pass().Proto(ProtocolTCP) }},
	{"pass udp", "pass proto udp", func() *RuleBuilder { return Pass().Proto(ProtocolUDP) }},
	{"pass icmp", "pass inet proto icmp", func() *RuleBuilder { return Pass().Inet().Proto(ProtocolICMP) }},
	{"pass inet", "pass inet", func() *RuleBuilder { return Pass().Inet() }},
	{"pass inet6", "pass inet6", func() *RuleBuilder { return Pass().Inet6() }},
	{"pass no state", "pass no state", func() *RuleBuilder { return Pass().NoState() }},
	{"pass modulate", "pass proto tcp modulate state", func() *RuleBuilder { return Pass().Proto(ProtocolTCP).ModulateState() }},
	{"pass flags any", "pass proto tcp flags any", func() *RuleBuilder { return Pass().Proto(ProtocolTCP).Flags("any") }},
	{"pass hosts and ports", "pass in on lo0 inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40001",
		func() *RuleBuilder {
			return Pass().In().On("lo0").Inet().Proto(ProtocolTCP).From("10.0.0.1").To("10.0.0.2").ToPort("40001")
		}},
	{"pass from not", "pass proto tcp from ! 10.0.0.0/8 port 40002 to any",
		func() *RuleBuilder { return Pass().Proto(ProtocolTCP).FromNot("10.0.0.0/8").FromPort("40002") }},
	{"pass table", "pass in from <t1> to any", func() *RuleBuilder { return Pass().In().From("<t1>") }},
	{"pass interface address", "pass out from (lo0) to any", func() *RuleBuilder { return Pass().Out().From("(lo0)") }},
	{"pass interface network", "pass out from (lo0:network) to any", func() *RuleBuilder { return Pass().Out().From("(lo0:network)") }},
	{"pass no-route", "pass from any to no-route", func() *RuleBuilder { return Pass().To("no-route") }},
	{"block", "block", func() *RuleBuilder { return Block() }},
	{"block in quick", "block in quick", func() *RuleBuilder { return Block().In().Quick() }},
	{"block tcp from", "block in proto tcp from 10.0.0.1 to any port 40003",
		func() *RuleBuilder { return Block().In().Proto(ProtocolTCP).From("10.0.0.1").ToPort("40003") }},
	{"match", "match", func() *RuleBuilder { return Match() }},
	{"match in on", "match in on lo0 inet proto tcp", func() *RuleBuilder { return Match().In().On("lo0").Inet().Proto(ProtocolTCP) }},
	{"nat (issue 5)", "nat on lo0 inet from any to any -> (lo0) round-robin",
		func() *RuleBuilder { return NAT().On("lo0").Inet().RedirectToInterface("lo0").RoundRobin() }},
	{"nat address", "nat on lo0 inet from 10.0.0.0/24 to any -> 192.0.2.1",
		func() *RuleBuilder { return NAT().On("lo0").From("10.0.0.0/24").RedirectTo("192.0.2.1") }},
	{"nat static port", "nat on lo0 inet from 10.0.0.0/24 to any -> 192.0.2.1 static-port",
		func() *RuleBuilder { return NAT().On("lo0").From("10.0.0.0/24").RedirectTo("192.0.2.1").StaticPort() }},
	{"nat port range", "nat on lo0 inet from 10.0.0.0/24 to any -> 192.0.2.1 port 40000:40100",
		func() *RuleBuilder {
			return NAT().On("lo0").From("10.0.0.0/24").RedirectTo("192.0.2.1").RedirectPort("40000:40100")
		}},
	{"nat table round-robin", "nat on lo0 inet from 10.0.0.0/24 to any -> <pool> round-robin",
		func() *RuleBuilder { return NAT().On("lo0").From("10.0.0.0/24").RedirectToTable("pool").RoundRobin() }},
	{"nat interface network", "nat on lo0 inet from 10.0.0.0/24 to any -> (lo0:network) round-robin",
		func() *RuleBuilder {
			return NAT().On("lo0").From("10.0.0.0/24").RedirectToInterface("lo0", DynamicFlagNetwork)
		}},
	{"no nat", "no nat on lo0 inet from 10.1.0.0/24 to any", func() *RuleBuilder { return NoNAT().On("lo0").From("10.1.0.0/24") }},
	{"rdr", "rdr on lo0 inet proto tcp from any to 192.0.2.1 port 40081 -> 10.0.0.5 port 40082",
		func() *RuleBuilder {
			return RDR().On("lo0").Proto(ProtocolTCP).To("192.0.2.1").ToPort("40081").RedirectTo("10.0.0.5", "40082")
		}},
	{"no rdr", "no rdr on lo0 inet proto tcp from any to 192.0.2.9 port 40004",
		func() *RuleBuilder { return NoRDR().On("lo0").Proto(ProtocolTCP).To("192.0.2.9").ToPort("40004") }},
	{"binat", "binat on lo0 inet from 10.0.0.9 to any -> 192.0.2.9",
		func() *RuleBuilder { return BINAT().On("lo0").From("10.0.0.9").RedirectTo("192.0.2.9") }},
	{"scrub", "scrub in on lo0 all", func() *RuleBuilder { return Scrub().In().On("lo0") }},
	{"scrub options", "scrub in on lo0 all no-df min-ttl 64 max-mss 1440 random-id",
		func() *RuleBuilder { return Scrub().In().On("lo0").NoDF().MinTTL(64).MaxMSS(1440).RandomID() }},
	{"scrub reassemble tcp", "scrub on lo0 all reassemble tcp", func() *RuleBuilder { return Scrub().On("lo0").ReassembleTCP() }},
}

// TestBuilderDefaultsLikePfctl: the same pf.conf line, minimal, loaded by
// pfctl and built by the builder must be the same rule.
func TestBuilderDefaultsLikePfctl(t *testing.T) {
	for _, tc := range defaultCases {
		t.Run(tc.name, func(t *testing.T) {
			theirs := oracleAnchor(t, "bd-theirs-"+slug(tc.name))
			mine := oracleAnchor(t, "bd-mine-"+slug(tc.name))
			pfctl(t, tc.conf+"\n", "-a", theirs, "-f", "-")

			rb := tc.rule()
			require.NoError(t, NewRuleset().Add(rb).Load(pfh, mine), "%s", rb)

			wantNat, wantFilter := shown(t, theirs)
			gotNat, gotFilter := shown(t, mine)
			assert.Equal(t, wantNat, gotNat, "translation rules, pfctl vs builder")
			assert.Equal(t, wantFilter, gotFilter, "filter rules, pfctl vs builder")

			// what the library prints for the built rule is what pfctl prints
			lines := ruleLines(wantNat + wantFilter)
			rules, err := rb.Rules()
			require.NoError(t, err)
			if len(lines) == len(rules) {
				for i := range rules {
					if want, got := normalize(lines[i]), normalize(rules[i].String()); want != got {
						t.Errorf("String of rule %d:\n pfctl:   %s\n library: %s", i, want, got)
					}
				}
			}
		})
	}
}

var rejectCases = []struct {
	name string
	conf string
	rule func() *RuleBuilder
	ok   func() *RuleBuilder // the valid sibling
	okc  string
}{
	{"port without protocol", "pass in from any port 40010 to any",
		func() *RuleBuilder { return Pass().In().FromPort("40010") },
		func() *RuleBuilder { return Pass().In().Proto(ProtocolTCP).FromPort("40010") }, "pass in proto tcp from any port 40010 to any"},
	{"flags without tcp", "pass proto udp flags S/SA keep state",
		func() *RuleBuilder { return Pass().Proto(ProtocolUDP).Flags("S/SA") },
		func() *RuleBuilder { return Pass().Proto(ProtocolTCP).Flags("S/SA") }, "pass proto tcp flags S/SA keep state"},
	{"address family mismatch", "pass from 10.0.0.1 to ::1",
		func() *RuleBuilder { return Pass().From("10.0.0.1").To("::1") },
		func() *RuleBuilder { return Pass().From("10.0.0.1").To("10.0.0.2") }, "pass from 10.0.0.1 to 10.0.0.2"},
	{"inet with an inet6 address", "pass inet from ::1 to any",
		func() *RuleBuilder { return Pass().Inet().From("::1") },
		func() *RuleBuilder { return Pass().Inet6().From("::1") }, "pass inet6 from ::1 to any"},
	{"nat without a target", "nat on lo0 inet from any to any",
		func() *RuleBuilder { return NAT().On("lo0").Inet() },
		func() *RuleBuilder { return NAT().On("lo0").Inet().RedirectTo("192.0.2.1") }, "nat on lo0 inet from any to any -> 192.0.2.1"},
	{"no nat with a target", "no nat on lo0 inet from any to any -> 192.0.2.1",
		func() *RuleBuilder { return NoNAT().On("lo0").Inet().RedirectTo("192.0.2.1") },
		func() *RuleBuilder { return NoNAT().On("lo0").Inet() }, "no nat on lo0 inet from any to any"},
	{"nat with a direction", "nat out on lo0 inet from any to any -> 192.0.2.1",
		func() *RuleBuilder { return NAT().Out().On("lo0").Inet().RedirectTo("192.0.2.1") },
		func() *RuleBuilder { return NAT().On("lo0").Inet().RedirectTo("192.0.2.1") }, "nat on lo0 inet from any to any -> 192.0.2.1"},
	{"scrub reassemble tcp with a direction", "scrub in on lo0 all reassemble tcp",
		func() *RuleBuilder { return Scrub().In().On("lo0").ReassembleTCP() },
		func() *RuleBuilder { return Scrub().On("lo0").ReassembleTCP() }, "scrub on lo0 all reassemble tcp"},
}

// TestBuilderRejectsLikePfctl: what pfctl refuses the builder refuses, and the
// valid sibling of each case is accepted by both.
func TestBuilderRejectsLikePfctl(t *testing.T) {
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := pfctlAccepts(tc.conf); err == nil {
				t.Fatalf("pfctl accepts %q, the case is wrong", tc.conf)
			}
			_, err := tc.rule().Rules()
			assert.Error(t, err, "the builder builds what pfctl refuses (%q): %s", tc.conf, tc.rule())

			require.NoError(t, pfctlAccepts(tc.okc), "pfctl refuses the valid sibling %q", tc.okc)
			_, err = tc.ok().Rules()
			assert.NoError(t, err, "the builder refuses what pfctl accepts (%q)", tc.okc)
		})
	}
}

func TestBuilderErrorsAreCollected(t *testing.T) {
	_, err := Pass().From("nonsense").To("also nonsense").Inet().Inet6().Rules()
	require.Error(t, err)
	for _, want := range []string{"nonsense", "also nonsense", "inet and inet6"} {
		assert.Contains(t, err.Error(), want)
	}
	assert.Contains(t, Pass().From("nonsense").String(), "invalid")
}

func TestBuilderInterfaceList(t *testing.T) {
	rules, err := Pass().In().OnAny("lo0", "egress").Rules()
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, "lo0", rules[0].Interface())
	assert.Equal(t, "egress", rules[1].Interface())
	_, err = Pass().OnAny("lo0", "egress").Rule()
	assert.Error(t, err, "Rule is one rule")
}

func TestBuilderCloneIsIndependent(t *testing.T) {
	base := Pass().In().On("lo0")
	a := base.Clone().Proto(ProtocolTCP)
	b := base.Clone().Proto(ProtocolUDP)
	assert.Contains(t, a.String(), "tcp")
	assert.Contains(t, b.String(), "udp")
	assert.NotContains(t, base.String(), "proto")
}

// A transaction with several rule sets used to fail: esize has to be the size
// of one element, not of all of them.
func TestTransactionWithSeveralRuleSets(t *testing.T) {
	anchor := oracleAnchor(t, "multi")
	err := NewRuleset().
		Add(Scrub().In().On("lo0")).
		Add(NAT().On("lo0").From("10.0.0.0/24").RedirectTo("192.0.2.1")).
		Add(RDR().On("lo0").Proto(ProtocolTCP).To("192.0.2.1").ToPort("40081").RedirectTo("10.0.0.5", "40082")).
		Add(BINAT().On("lo0").From("10.0.0.9").RedirectTo("192.0.2.9")).
		Add(Pass().In().On("lo0")).
		Add(Block().Out()).
		Load(pfh, anchor)
	require.NoError(t, err)
	nat, filter := shown(t, anchor)
	assert.Len(t, ruleLines(nat), 3, nat)
	assert.Len(t, ruleLines(filter), 3, filter)

	// loading again replaces everything, and an empty set empties every rule set
	require.NoError(t, NewRuleset().Load(pfh, anchor))
	nat, filter = shown(t, anchor)
	assert.Empty(t, ruleLines(nat))
	assert.Empty(t, ruleLines(filter))
}
