package pf

// These tests compare the library with pfctl(8), the reference
// implementation of the packet filter's user interface. Rules written by the
// library must be shown by pfctl as the library describes them, rules loaded
// by pfctl must be read back by the library, and the status, limits and
// timeouts set through the library must be the ones pfctl reports.
//
// Everything happens in an anchor of its own, so the main ruleset of the
// machine is never touched.

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pfctl runs pfctl(8) and returns its standard output. The ALTQ notices pfctl
// prints on kernels without ALTQ go to standard error and are ignored.
func pfctl(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("pfctl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("pfctl %s: %v\n%s%s", strings.Join(args, " "), err, out.String(), errOut.String())
	}
	return out.String()
}

// oracleAnchor returns the path of a scratch anchor and empties it again when
// the test is over.
func oracleAnchor(t *testing.T, name string) string {
	t.Helper()
	path := "go-pf-oracle-" + name
	flush := func() { exec.Command("pfctl", "-a", path, "-F", "all").Run() }
	flush()
	t.Cleanup(flush)
	return path
}

func anchorOf(path string) Anchor {
	return Anchor{ioctlDev: pfh.ioctlDev, Path: path}
}

// commitRules replaces the filter rules of the anchor with the given rules.
func commitRules(t *testing.T, anchor string, rules ...*Rule) {
	t.Helper()
	commitRulesOf(t, anchor, RuleSetFilter, rules...)
}

// commitRulesOf replaces the rules of one type of the anchor.
func commitRulesOf(t *testing.T, anchor string, typ RuleSetType, rules ...*Rule) {
	t.Helper()
	commitRulesOn(t, anchor, typ, nil, rules...)
}

// commitRulesOn is commitRulesOf with every rule added once per interface.
func commitRulesOn(t *testing.T, anchor string, typ RuleSetType, interfaces []string, rules ...*Rule) {
	t.Helper()
	tx := pfh.NewTransaction(1)
	rs := tx.RuleSet(0)
	rs.SetType(typ)
	require.NoError(t, rs.SetAnchor(anchor))
	require.NoError(t, tx.Begin())
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	for _, r := range rules {
		require.NoError(t, rs.AddRuleOnInterfaces(r, interfaces...))
	}
	require.NoError(t, tx.Commit())
	committed = true
}

var (
	reSpaces    = regexp.MustCompile(`\s+`)
	reHost      = regexp.MustCompile(`/(32|128)\b`)
	reTable     = regexp.MustCompile(`<([^>:]+):[0-9*]+>`)
	rePortOp    = regexp.MustCompile(`port (=|!=|<=|>=|<|>) ?`)
	rePortRange = regexp.MustCompile(`(\d+) ?(<>|><) ?(\d+)`)
)

// normalize maps the output of pfctl and the output of the library onto one
// spelling. It only removes differences of notation that carry no meaning
// (spaces, the implicit host prefix, pfctl's default flags S/SA, "all"); it
// must not hide a different rule.
func normalize(s string) string {
	s = reSpaces.ReplaceAllString(strings.TrimSpace(s), " ")
	s = reHost.ReplaceAllString(s, "")
	// pfctl shows the number of addresses of a table: <name:3>
	s = reTable.ReplaceAllString(s, "<$1>")
	s = strings.ReplaceAll(s, " inout", "")
	// the routing table is not modelled
	s = strings.ReplaceAll(s, " rtable 0", "")
	// the way a scrub rule without options is described
	s = strings.ReplaceAll(s, " fragment reassemble", "")
	s = strings.Replace(s, "block drop", "drop", 1)
	s = strings.Replace(s, "block", "drop", 1)
	s = strings.ReplaceAll(s, " all", " from any to any")
	s = rePortOp.ReplaceAllStringFunc(s, func(m string) string {
		sub := rePortOp.FindStringSubmatch(m)
		if sub[1] == "=" {
			return "port "
		}
		return "port " + sub[1]
	})
	s = rePortRange.ReplaceAllString(s, "$1$2$3")
	return s
}

func ruleLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

type ruleCase struct {
	name  string
	build func(r *Rule) error
}

func oracleRuleCases() []ruleCase {
	tcp := func(r *Rule) {
		r.SetAction(ActionPass)
		r.SetProtocol(ProtocolTCP)
	}
	return []ruleCase{
		{"pass in quick log tcp", func(r *Rule) error {
			tcp(r)
			r.SetDirection(DirectionIn)
			r.SetQuick(true)
			r.SetLog(true)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.ParseSource("10.0.0.1", "40001", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40002", false)
		}},
		{"drop out udp network", func(r *Rule) error {
			r.SetAction(ActionDrop)
			r.SetProtocol(ProtocolUDP)
			r.SetDirection(DirectionOut)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("192.168.1.0/24", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.1.0.0/16", "40003", false)
		}},
		{"inet6", func(r *Rule) error {
			tcp(r)
			r.SetDirection(DirectionIn)
			r.SetAddressFamily(AddressFamilyInet6)
			if err := r.ParseSource("2001:db8::/32", "", false); err != nil {
				return err
			}
			return r.ParseDestination("::1", "40004", false)
		}},
		{"negated addresses", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.1.1", "40005", true); err != nil {
				return err
			}
			return r.ParseDestination("10.0.2.0/24", "40006", true)
		}},
		{"port not equal", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.0.1", "!=40007", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", ">40008", false)
		}},
		{"port less equal greater equal", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.0.1", "<=40009", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", ">=40010", false)
		}},
		{"port less greater", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.0.1", "<40011", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", ">40012", false)
		}},
		{"port ranges", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.0.1", "40013:40020", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40030:40040", false)
		}},
		{"exclusive range", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.0.1", "40050<>40060", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40070><40080", false)
		}},
		{"tcp flags S/SA", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.ParseTCPFlags("S/SA"); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40701", false)
		}},
		{"tcp flags SA/SA and FSRPAUEW mask", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.ParseTCPFlags("SA/FSRPAUEW"); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40702", false)
		}},
		{"tcp flags any", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.ParseTCPFlags("any"); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40703", false)
		}},
		{"tcp flags without state", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseTCPFlags("S/SAFR"); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40704", false)
		}},
		{"route-to", func(r *Rule) error {
			tcp(r)
			r.SetDirection(DirectionOut)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.SetRoute(RouteTo, RouteTarget{Interface: "lo0", Address: "127.0.0.1"}); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40801", false)
		}},
		{"reply-to", func(r *Rule) error {
			tcp(r)
			r.SetDirection(DirectionIn)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.SetRoute(ReplyTo, RouteTarget{Interface: "lo0", Address: "127.0.0.1"}); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40802", false)
		}},
		{"dup-to", func(r *Rule) error {
			tcp(r)
			r.SetDirection(DirectionOut)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.SetRoute(DupTo, RouteTarget{Interface: "lo0", Address: "127.0.0.1"}); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40803", false)
		}},
		{"route-to a list", func(r *Rule) error {
			tcp(r)
			r.SetDirection(DirectionOut)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.SetRoute(RouteTo, RouteTarget{Interface: "lo0", Address: "127.0.0.1"}, RouteTarget{Interface: "lo0", Address: "127.0.0.2"}); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40804", false)
		}},
		{"modulate state", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateModulate)
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40090", false)
		}},
		{"synproxy state", func(r *Rule) error {
			tcp(r)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateSynproxy)
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40091", false)
		}},
		{"icmp", func(r *Rule) error {
			r.SetAction(ActionPass)
			r.SetProtocol(ProtocolICMP)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "", false)
		}},
		{"on interface", func(r *Rule) error {
			tcp(r)
			r.SetDirection(DirectionIn)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.SetInterface("lo0"); err != nil {
				return err
			}
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40501", false)
		}},
		{"not on interface", func(r *Rule) error {
			tcp(r)
			r.SetDirection(DirectionOut)
			r.SetQuick(true)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetState(StateKeep)
			if err := r.SetInterface("lo0"); err != nil {
				return err
			}
			r.SetInterfaceNot(true)
			if err := r.ParseSource("10.0.0.1", "", false); err != nil {
				return err
			}
			return r.ParseDestination("10.0.0.2", "40502", false)
		}},
		{"on interface group", func(r *Rule) error {
			r.SetAction(ActionDrop)
			r.SetAddressFamily(AddressFamilyInet6)
			return r.SetInterface("egress")
		}},
		{"any to any", func(r *Rule) error {
			r.SetAction(ActionPass)
			r.SetDirection(DirectionOut)
			return nil
		}},
	}
}

// TestRulesLikePfctl writes every case with the library and expects pfctl to
// show the rule the way the library describes it.
func TestRulesLikePfctl(t *testing.T) {
	anchor := oracleAnchor(t, "write")
	for _, tc := range oracleRuleCases() {
		t.Run(tc.name, func(t *testing.T) {
			var r Rule
			require.NoError(t, tc.build(&r))
			commitRules(t, anchor, &r)

			shown := ruleLines(pfctl(t, "", "-a", anchor, "-sr"))
			require.Len(t, shown, 1, "pfctl output: %v", shown)

			back, err := anchorOf(anchor).Rules()
			require.NoError(t, err)
			require.Len(t, back, 1)

			t.Logf("library:  %s", r.String())
			t.Logf("readback: %s", back[0].String())
			t.Logf("pfctl:    %s", shown[0])
			assert.Equal(t, normalize(shown[0]), normalize(r.String()), "pfctl vs rule written")
			assert.Equal(t, r.String(), back[0].String(), "rule written vs rule read back")
		})
	}
}

// TestRulesLoadedByPfctl loads rules with pfctl and reads them with the
// library, in order.
func TestRulesLoadedByPfctl(t *testing.T) {
	anchor := oracleAnchor(t, "read")
	ruleset := strings.Join([]string{
		"pass in quick log inet proto tcp from 10.0.0.1 port 40001 to 10.0.0.2 port 40002 keep state",
		"block drop out inet proto udp from 192.168.1.0/24 to 10.1.0.0/16 port 40003",
		"pass in inet6 proto tcp from 2001:db8::/32 to ::1 port 40004 no state",
		"pass out inet proto tcp from 10.0.0.1 port 40013:40020 to ! 10.0.2.0/24 port != 40021 keep state",
		"pass inet proto icmp from 10.0.0.1 to 10.0.0.2",
		"pass in on lo0 inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40501 keep state",
		"pass out quick on ! lo0 inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40502 keep state",
		"block drop on egress inet6 all",
		"pass in inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40701 flags SA/FSRPAUEW keep state",
		"pass in inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40702 flags any keep state",
		"pass in inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40703 flags S/SAFR no state",
		"pass out route-to (lo0 127.0.0.1) inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40801 keep state",
		"pass in reply-to (lo0 127.0.0.1) inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40802 keep state",
		"pass out route-to { (lo0 127.0.0.1) (lo0 127.0.0.2) } inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40804 keep state",
	}, "\n") + "\n"
	pfctl(t, ruleset, "-a", anchor, "-f", "-")

	shown := ruleLines(pfctl(t, "", "-a", anchor, "-sr"))
	read, err := anchorOf(anchor).Rules()
	require.NoError(t, err)
	require.Len(t, read, len(shown), "number of rules")
	require.Len(t, read, 14)

	for i := range read {
		t.Logf("pfctl:   %s", shown[i])
		t.Logf("library: %s", read[i].String())
		assert.Equal(t, normalize(shown[i]), normalize(read[i].String()), "rule %d", i)
	}
}

// TestRuleTransactionsLikePfctl checks commit and rollback against what pfctl
// reports.
func TestRuleTransactionsLikePfctl(t *testing.T) {
	anchor := oracleAnchor(t, "tx")
	mk := func(port string) *Rule {
		var r Rule
		r.SetAction(ActionPass)
		r.SetProtocol(ProtocolTCP)
		r.SetAddressFamily(AddressFamilyInet)
		require.NoError(t, r.ParseSource("10.0.0.1", "", false))
		require.NoError(t, r.ParseDestination("10.0.0.2", port, false))
		return &r
	}

	commitRules(t, anchor, mk("40101"), mk("40102"))
	assert.Len(t, ruleLines(pfctl(t, "", "-a", anchor, "-sr")), 2)

	// a rolled back transaction leaves the committed rules in place
	tx := pfh.NewTransaction(1)
	rs := tx.RuleSet(0)
	rs.SetType(RuleSetFilter)
	require.NoError(t, rs.SetAnchor(anchor))
	require.NoError(t, tx.Begin())
	require.NoError(t, rs.AddRule(mk("40103")))
	require.NoError(t, tx.Rollback())
	shown := ruleLines(pfctl(t, "", "-a", anchor, "-sr"))
	assert.Len(t, shown, 2)
	assert.Contains(t, shown[0], "40101")
	assert.Contains(t, shown[1], "40102")

	// a commit replaces them
	commitRules(t, anchor, mk("40104"))
	shown = ruleLines(pfctl(t, "", "-a", anchor, "-sr"))
	require.Len(t, shown, 1)
	assert.Contains(t, shown[0], "40104")

	// an empty commit empties the anchor
	commitRules(t, anchor)
	assert.Empty(t, ruleLines(pfctl(t, "", "-a", anchor, "-sr")))
}

// kv parses lines like "states        hard limit   100000" into a map from
// the first word to the last word.
func kv(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			m[f[0]] = f[len(f)-1]
		}
	}
	return m
}

func TestStatusLikePfctl(t *testing.T) {
	var stats Statistics

	require.NoError(t, pfh.Start())
	defer pfh.Stop()
	require.NoError(t, pfh.UpdateStatistics(&stats))
	assert.True(t, stats.Running())
	assert.Contains(t, pfctl(t, "", "-si", "-v"), "Status: Enabled")

	require.NoError(t, pfh.Stop())
	require.NoError(t, pfh.UpdateStatistics(&stats))
	assert.False(t, stats.Running())
	assert.Contains(t, pfctl(t, "", "-si", "-v"), "Status: Disabled")

	// debug level; pfctl calls "noisy" loud
	names := map[DebugMode]string{
		DebugModeNone: "None", DebugModeUrgent: "Urgent",
		DebugModeMisc: "Misc", DebugModeNoisy: "Loud",
	}
	defer pfh.SetDebugMode(DebugModeUrgent)
	for mode, name := range names {
		require.NoError(t, pfh.SetDebugMode(mode))
		require.NoError(t, pfh.UpdateStatistics(&stats))
		assert.Equal(t, mode, stats.Debug())
		assert.Contains(t, pfctl(t, "", "-si", "-v"), "Debug: "+name, "mode %s", mode)
	}

	// host id
	require.NoError(t, pfh.UpdateStatistics(&stats))
	old := stats.HostID()
	defer pfh.SetHostID(old)
	require.NoError(t, pfh.SetHostID(0x1badcafe))
	assert.Contains(t, pfctl(t, "", "-si", "-v"), "Hostid:   0x1badcafe")
	require.NoError(t, pfh.UpdateStatistics(&stats))
	assert.Equal(t, uint32(0x1badcafe), stats.HostID())

	// state table
	out := pfctl(t, "", "-si", "-v")
	require.NoError(t, pfh.UpdateStatistics(&stats))
	re := regexp.MustCompile(`(?m)^\s+current entries\s+(\d+)`)
	m := re.FindStringSubmatch(out)
	require.NotNil(t, m, out)
	n, _ := strconv.Atoi(m[1])
	assert.Equal(t, n, stats.States())
}

func TestLimitsLikePfctl(t *testing.T) {
	limits := map[Limit]string{
		LimitStates:       "states",
		LimitSourceNodes:  "src-nodes",
		LimitFragments:    "frags",
		LimitTableEntries: "table-entries",
	}
	keys := make([]int, 0, len(limits))
	for l := range limits {
		keys = append(keys, int(l))
	}
	sort.Ints(keys)
	for _, k := range keys {
		l := Limit(k)
		name := limits[l]
		t.Run(name, func(t *testing.T) {
			old, err := pfh.Limit(l)
			require.NoError(t, err)
			defer pfh.SetLimit(l, old)

			assert.Equal(t, fmt.Sprint(old), kv(pfctl(t, "", "-sm"))[name], "initial")

			require.NoError(t, pfh.SetLimit(l, old+1000))
			assert.Equal(t, fmt.Sprint(old+1000), kv(pfctl(t, "", "-sm"))[name], "after SetLimit")
		})
	}
}

func TestTimeoutsLikePfctl(t *testing.T) {
	timeouts := []struct {
		t    Timeout
		name string
	}{
		{TimeoutTCPFirstPacket, "tcp.first"},
		{TimeoutTCPOpening, "tcp.opening"},
		{TimeoutTCPEstablished, "tcp.established"},
		{TimeoutTCPClosing, "tcp.closing"},
		{TimeoutTCPFinWait, "tcp.finwait"},
		{TimeoutTCPClosed, "tcp.closed"},
		{TimeoutUDPFirstPacket, "udp.first"},
		{TimeoutUDPSingle, "udp.single"},
		{TimeoutUDPMultiple, "udp.multiple"},
		{TimeoutICMPFirstPacket, "icmp.first"},
		{TimeoutICMPErrorReply, "icmp.error"},
		{TimeoutOtherFirstPacket, "other.first"},
		{TimeoutOtherSingle, "other.single"},
		{TimeoutOtherMultiple, "other.multiple"},
		{TimeoutFragment, "frag"},
		{TimeoutInterval, "interval"},
		{TimeoutSourceNode, "src.track"},
	}
	for _, tc := range timeouts {
		t.Run(tc.name, func(t *testing.T) {
			old, err := pfh.Timeout(tc.t)
			require.NoError(t, err)
			defer pfh.SetTimeout(tc.t, old)

			assert.Equal(t, fmt.Sprintf("%ds", int(old/time.Second)), kv(pfctl(t, "", "-st"))[tc.name], "initial")

			require.NoError(t, pfh.SetTimeout(tc.t, 91*time.Second))
			assert.Equal(t, "91s", kv(pfctl(t, "", "-st"))[tc.name], "after SetTimeout")
			got, err := pfh.Timeout(tc.t)
			require.NoError(t, err)
			assert.Equal(t, 91*time.Second, got)
		})
	}
}

// TestRuleStatsLikePfctl: a fresh rule has no evaluations, pfctl agrees.
func TestRuleStatsLikePfctl(t *testing.T) {
	anchor := oracleAnchor(t, "stats")
	pfctl(t, "pass in inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40201 keep state\n", "-a", anchor, "-f", "-")

	read, err := anchorOf(anchor).Rules()
	require.NoError(t, err)
	require.Len(t, read, 1)

	var s RuleStats
	read[0].Stats(&s)
	assert.Equal(t, RuleStats{}, s)
	assert.Regexp(t, `Evaluations: 0\s+Packets: 0\s+Bytes: 0`, pfctl(t, "", "-a", anchor, "-vsr"))
}

// translationCases are the rules with a translation address: nat, rdr and
// binat, and the "no" forms that exempt traffic from them.
func translationCases() []struct {
	name  string
	typ   RuleSetType
	build func(r *Rule) error
} {
	return []struct {
		name  string
		typ   RuleSetType
		build func(r *Rule) error
	}{
		{"nat", RuleSetNAT, func(r *Rule) error {
			r.SetAction(ActionNAT)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.0.0/24", "", false); err != nil {
				return err
			}
			if err := r.ParseDestination("0.0.0.0/0", "", false); err != nil {
				return err
			}
			return r.SetRedirect("192.0.2.1", "")
		}},
		{"nat on interface", RuleSetNAT, func(r *Rule) error {
			r.SetAction(ActionNAT)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.SetInterface("lo0"); err != nil {
				return err
			}
			if err := r.ParseSource("10.2.0.0/24", "", false); err != nil {
				return err
			}
			if err := r.ParseDestination("0.0.0.0/0", "", false); err != nil {
				return err
			}
			return r.SetRedirect("192.0.2.2", "")
		}},
		{"rdr not on interface", RuleSetRedirect, func(r *Rule) error {
			r.SetAction(ActionRDR)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetProtocol(ProtocolTCP)
			if err := r.SetInterface("lo0"); err != nil {
				return err
			}
			r.SetInterfaceNot(true)
			if err := r.ParseSource("0.0.0.0/0", "", false); err != nil {
				return err
			}
			if err := r.ParseDestination("192.0.2.3", "40503", false); err != nil {
				return err
			}
			return r.SetRedirect("10.0.0.6", "40504")
		}},
		{"no nat", RuleSetNAT, func(r *Rule) error {
			r.SetAction(ActionNoNAT)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.1.0.0/24", "", false); err != nil {
				return err
			}
			return r.ParseDestination("0.0.0.0/0", "", false)
		}},
		{"rdr", RuleSetRedirect, func(r *Rule) error {
			r.SetAction(ActionRDR)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetProtocol(ProtocolTCP)
			if err := r.ParseSource("0.0.0.0/0", "", false); err != nil {
				return err
			}
			if err := r.ParseDestination("192.0.2.1", "40001", false); err != nil {
				return err
			}
			return r.SetRedirect("10.0.0.5", "40002")
		}},
		{"rdr port range", RuleSetRedirect, func(r *Rule) error {
			r.SetAction(ActionRDR)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetProtocol(ProtocolTCP)
			if err := r.ParseSource("0.0.0.0/0", "", false); err != nil {
				return err
			}
			if err := r.ParseDestination("192.0.2.1", "40010:40019", false); err != nil {
				return err
			}
			return r.SetRedirect("10.0.0.5", "40100:40109")
		}},
		{"no rdr", RuleSetRedirect, func(r *Rule) error {
			r.SetAction(ActionNoRDR)
			r.SetAddressFamily(AddressFamilyInet)
			r.SetProtocol(ProtocolTCP)
			if err := r.ParseSource("0.0.0.0/0", "", false); err != nil {
				return err
			}
			return r.ParseDestination("192.0.2.9", "40003", false)
		}},
		{"binat", RuleSetBINAT, func(r *Rule) error {
			r.SetAction(ActionBINAT)
			r.SetAddressFamily(AddressFamilyInet)
			if err := r.ParseSource("10.0.0.9", "", false); err != nil {
				return err
			}
			if err := r.ParseDestination("0.0.0.0/0", "", false); err != nil {
				return err
			}
			return r.SetRedirect("192.0.2.9", "")
		}},
	}
}

// TestTranslationRulesLikePfctl writes nat, rdr and binat rules with the
// library; pfctl -sn must show them as the library describes them, and the
// library reads them back unchanged, translation address included.
func TestTranslationRulesLikePfctl(t *testing.T) {
	for _, tc := range translationCases() {
		t.Run(tc.name, func(t *testing.T) {
			anchor := oracleAnchor(t, "tr-"+strings.ReplaceAll(tc.name, " ", "-"))
			var r Rule
			require.NoError(t, tc.build(&r))
			commitRulesOf(t, anchor, tc.typ, &r)

			shown := ruleLines(pfctl(t, "", "-a", anchor, "-sn"))
			require.Len(t, shown, 1, "pfctl output: %v", shown)
			back, err := anchorOf(anchor).RulesOf(tc.typ)
			require.NoError(t, err)
			require.Len(t, back, 1)

			t.Logf("library:  %s", r.String())
			t.Logf("readback: %s", back[0].String())
			t.Logf("pfctl:    %s", shown[0])
			assert.Equal(t, normalize(shown[0]), normalize(r.String()), "pfctl vs rule written")
			assert.Equal(t, r.String(), back[0].String(), "rule written vs rule read back")
		})
	}
}

// TestTranslationRulesLoadedByPfctl loads the rules with pfctl and reads
// them with the library, type by type.
func TestTranslationRulesLoadedByPfctl(t *testing.T) {
	anchor := oracleAnchor(t, "tr-read")
	pfctl(t, strings.Join([]string{
		"nat inet from 10.0.0.0/24 to any -> 192.0.2.1",
		"no nat inet from 10.1.0.0/24 to any",
		"rdr inet proto tcp from any to 192.0.2.1 port 40001 -> 10.0.0.5 port 40002",
		"no rdr inet proto tcp from any to 192.0.2.9 port 40003",
		"binat inet from 10.0.0.9 to any -> 192.0.2.9",
		"nat on lo0 inet from 10.2.0.0/24 to any -> 192.0.2.2",
		"rdr on ! lo0 inet proto tcp from any to 192.0.2.3 port 40503 -> 10.0.0.6 port 40504",
	}, "\n")+"\n", "-a", anchor, "-f", "-")

	shown := ruleLines(pfctl(t, "", "-a", anchor, "-sn"))
	var read []Rule
	for _, typ := range []RuleSetType{RuleSetNAT, RuleSetRedirect, RuleSetBINAT} {
		rules, err := anchorOf(anchor).RulesOf(typ)
		require.NoError(t, err)
		read = append(read, rules...)
	}
	require.Len(t, read, len(shown), "number of rules")
	for i := range read {
		t.Logf("pfctl:   %s", shown[i])
		t.Logf("library: %s", read[i].String())
		assert.Equal(t, normalize(shown[i]), normalize(read[i].String()), "rule %d", i)
	}
}

func netStrings(nets []*net.IPNet) []string {
	var out []string
	for _, n := range nets {
		ones, bits := n.Mask.Size()
		if ones == bits {
			out = append(out, n.IP.String())
		} else {
			out = append(out, n.String())
		}
	}
	sort.Strings(out)
	return out
}

func trimmedLines(out string) []string {
	var lines []string
	for _, l := range ruleLines(out) {
		lines = append(lines, strings.TrimSpace(l))
	}
	sort.Strings(lines)
	return lines
}

func mustNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var nets []*net.IPNet
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		_, n, err := net.ParseCIDR(c)
		require.NoError(t, err)
		nets = append(nets, n)
	}
	return nets
}

// TestTablesLikePfctl: tables made by the library are the ones pfctl shows
// with their addresses, tables made by pfctl are read by the library, and a
// rule that refers to a table is described the same way.
func TestTablesLikePfctl(t *testing.T) {
	anchor := oracleAnchor(t, "tables")

	require.NoError(t, pfh.CreateTable(anchor, "t1"))
	added, err := pfh.AddTableAddresses(anchor, "t1", mustNets(t, "10.9.9.1", "10.8.0.0/16", "2001:db8::/32"))
	require.NoError(t, err)
	assert.Equal(t, 3, added)
	added, err = pfh.AddTableAddresses(anchor, "t1", mustNets(t, "10.9.9.1"))
	require.NoError(t, err)
	assert.Equal(t, 0, added, "an address that is there is not added again")

	assert.Equal(t, []string{"t1"}, trimmedLines(pfctl(t, "", "-a", anchor, "-sT")))
	assert.Equal(t, []string{"10.8.0.0/16", "10.9.9.1", "2001:db8::/32"},
		trimmedLines(pfctl(t, "", "-a", anchor, "-t", "t1", "-T", "show")))

	// made by pfctl, read by the library
	pfctl(t, "", "-a", anchor, "-t", "t2", "-T", "add", "10.7.7.7", "10.6.0.0/24", "2001:db8:1::1")
	tables, err := pfh.Tables(anchor)
	require.NoError(t, err)
	var names []string
	for _, tb := range tables {
		names = append(names, tb.Name)
	}
	sort.Strings(names)
	assert.Equal(t, []string{"t1", "t2"}, names)
	nets, err := pfh.TableAddresses(anchor, "t2")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.6.0.0/24", "10.7.7.7", "2001:db8:1::1"}, netStrings(nets))
	nets, err = pfh.TableAddresses(anchor, "t1")
	require.NoError(t, err)
	assert.Equal(t, trimmedLines(pfctl(t, "", "-a", anchor, "-t", "t1", "-T", "show")), netStrings(nets))

	// a rule that refers to the table
	var r Rule
	r.SetAction(ActionPass)
	r.SetProtocol(ProtocolTCP)
	r.SetAddressFamily(AddressFamilyInet)
	r.SetState(StateKeep)
	require.NoError(t, r.ParseSource("10.0.0.1", "", false))
	dst := Address{wrap: &r.wrap.rule.dst.addr}
	require.NoError(t, dst.SetTableName("t1"))
	commitRules(t, anchor, &r)
	shown := ruleLines(pfctl(t, "", "-a", anchor, "-sr"))
	require.Len(t, shown, 1)
	t.Logf("library: %s", r.String())
	t.Logf("pfctl:   %s", shown[0])
	assert.Equal(t, normalize(shown[0]), normalize(r.String()))
	back, err := anchorOf(anchor).Rules()
	require.NoError(t, err)
	require.Len(t, back, 1)
	assert.Equal(t, normalize(shown[0]), normalize(back[0].String()))

	// deleting
	require.NoError(t, pfh.DeleteTable(anchor, "t2"))
	assert.NotContains(t, trimmedLines(pfctl(t, "", "-a", anchor, "-sT")), "t2")
}

// TestAnchorsLikePfctl: nested anchors as pfctl -sA lists them.
func TestAnchorsLikePfctl(t *testing.T) {
	parent := oracleAnchor(t, "nest")
	for _, child := range []string{"b", "a"} {
		pfctl(t, "pass in inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40401 keep state\n",
			"-a", parent+"/"+child, "-f", "-")
	}
	t.Cleanup(func() {
		for _, child := range []string{"a", "b"} {
			exec.Command("pfctl", "-a", parent+"/"+child, "-F", "all").Run()
		}
	})

	got, err := anchorOf(parent).Anchors()
	require.NoError(t, err)
	shown := trimmedLines(pfctl(t, "", "-a", parent, "-sA"))
	sort.Strings(got)
	t.Logf("library: %v", got)
	t.Logf("pfctl:   %v", shown)
	assert.Equal(t, []string{parent + "/a", parent + "/b"}, got)
	assert.Equal(t, shown, got)
}

// TestScrubLikePfctl: a scrub rule is a rule of its own rule set.
func TestScrubLikePfctl(t *testing.T) {
	anchor := oracleAnchor(t, "scrub")
	var r Rule
	r.SetAction(ActionScrub)
	r.SetDirection(DirectionIn)
	r.SetAddressFamily(AddressFamilyInet)
	require.NoError(t, r.ParseSource("10.0.0.0/8", "", false))
	require.NoError(t, r.ParseDestination("0.0.0.0/0", "", false))
	commitRulesOf(t, anchor, RuleSetScrub, &r)

	back, err := anchorOf(anchor).RulesOf(RuleSetScrub)
	require.NoError(t, err)
	require.Len(t, back, 1)
	shown := ruleLines(pfctl(t, "", "-a", anchor, "-sr"))
	t.Logf("library:  %s", r.String())
	t.Logf("readback: %s", back[0].String())
	t.Logf("pfctl:    %v", shown)
	assert.Equal(t, r.String(), back[0].String())
	require.Len(t, shown, 1)
	assert.Equal(t, normalize(shown[0]), normalize(r.String()))
}

// TestInterfaceListLikePfctl: "on { lo0 egress }" is one rule per interface
// in the order of the list, for pfctl as for AddRuleOnInterfaces.
func TestInterfaceListLikePfctl(t *testing.T) {
	list := []string{"lo0", "egress"}

	t.Run("filter", func(t *testing.T) {
		theirs := oracleAnchor(t, "iflist-pfctl")
		mine := oracleAnchor(t, "iflist-mine")
		pfctl(t, "pass in quick on { lo0 egress } inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40601 keep state\n",
			"-a", theirs, "-f", "-")

		var r Rule
		r.SetAction(ActionPass)
		r.SetDirection(DirectionIn)
		r.SetQuick(true)
		r.SetProtocol(ProtocolTCP)
		r.SetAddressFamily(AddressFamilyInet)
		r.SetState(StateKeep)
		// what pfctl makes of a tcp rule that keeps state and has no flags
		require.NoError(t, r.ParseTCPFlags("S/SA"))
		require.NoError(t, r.ParseSource("10.0.0.1", "", false))
		require.NoError(t, r.ParseDestination("10.0.0.2", "40601", false))
		commitRulesOn(t, mine, RuleSetFilter, list, &r)
		assert.Equal(t, "", r.Interface(), "the rule given is not changed")

		want := ruleLines(pfctl(t, "", "-a", theirs, "-sr"))
		got := ruleLines(pfctl(t, "", "-a", mine, "-sr"))
		require.Len(t, want, 2)
		require.Len(t, got, 2)
		for i := range want {
			t.Logf("pfctl loaded: %s", want[i])
			t.Logf("library:      %s", got[i])
			assert.Equal(t, normalize(want[i]), normalize(got[i]), "rule %d", i)
		}
		back, err := anchorOf(mine).Rules()
		require.NoError(t, err)
		require.Len(t, back, 2)
		assert.Equal(t, "lo0", back[0].Interface())
		assert.Equal(t, "egress", back[1].Interface())
	})

	t.Run("nat", func(t *testing.T) {
		theirs := oracleAnchor(t, "iflist-nat-pfctl")
		mine := oracleAnchor(t, "iflist-nat-mine")
		pfctl(t, "nat on { lo0 egress } inet from 10.3.0.0/24 to any -> 192.0.2.4\n", "-a", theirs, "-f", "-")

		var r Rule
		r.SetAction(ActionNAT)
		r.SetAddressFamily(AddressFamilyInet)
		require.NoError(t, r.ParseSource("10.3.0.0/24", "", false))
		require.NoError(t, r.ParseDestination("0.0.0.0/0", "", false))
		require.NoError(t, r.SetRedirect("192.0.2.4", ""))
		commitRulesOn(t, mine, RuleSetNAT, list, &r)

		want := ruleLines(pfctl(t, "", "-a", theirs, "-sn"))
		got := ruleLines(pfctl(t, "", "-a", mine, "-sn"))
		require.Len(t, want, 2)
		require.Len(t, got, 2)
		for i := range want {
			assert.Equal(t, normalize(want[i]), normalize(got[i]), "rule %d", i)
		}
	})

	t.Run("a bad name adds nothing", func(t *testing.T) {
		anchor := oracleAnchor(t, "iflist-bad")
		tx := pfh.NewTransaction(1)
		rs := tx.RuleSet(0)
		rs.SetType(RuleSetFilter)
		require.NoError(t, rs.SetAnchor(anchor))
		require.NoError(t, tx.Begin())
		defer tx.Rollback()
		var r Rule
		r.SetAction(ActionPass)
		assert.Error(t, rs.AddRuleOnInterfaces(&r, "lo0", "this-interface-name-is-too-long"))
		assert.Error(t, rs.AddRuleOnInterfaces(&r, "lo0", ""))
		require.NoError(t, tx.Rollback())
		assert.Empty(t, ruleLines(pfctl(t, "", "-a", anchor, "-sr")))
	})
}

func TestTCPFlags(t *testing.T) {
	var r Rule
	assert.NoError(t, r.ParseTCPFlags("S/SA"))
	f, m := r.TCPFlags()
	assert.Equal(t, TCPFlagSYN, f)
	assert.Equal(t, TCPFlagSYN|TCPFlagACK, m)
	assert.Equal(t, "SA", m.String())
	assert.Equal(t, "FSRPAUEW", TCPFlags(0xff).String())

	assert.NoError(t, r.ParseTCPFlags("any"))
	f, m = r.TCPFlags()
	assert.Zero(t, f)
	assert.Zero(t, m)

	for _, bad := range []string{"S", "S/", "X/SA", "SA/S", "S/SAX", ""} {
		assert.Error(t, r.ParseTCPFlags(bad), bad)
	}
	assert.Error(t, r.SetTCPFlags(TCPFlagSYN, TCPFlagACK), "flags that are not in the mask")
	for in, want := range map[string]TCPFlags{"": 0, "F": 1, "FSRPAUEW": 0xff, "W": 0x80} {
		got, err := ParseTCPFlags(in)
		assert.NoError(t, err)
		assert.Equal(t, want, got, in)
	}
}

func TestRouteTargets(t *testing.T) {
	var r Rule
	r.SetAddressFamily(AddressFamilyInet)
	assert.Error(t, r.SetRoute(RouteTo), "no target")
	assert.Error(t, r.SetRoute(RouteTo, RouteTarget{Interface: "lo0"}), "no address")
	assert.Error(t, r.SetRoute(RouteTo, RouteTarget{Address: "10.0.0.1"}), "no interface")
	assert.Error(t, r.SetRoute(RouteTo, RouteTarget{Interface: "lo0", Address: "nonsense"}))
	assert.Error(t, r.SetRoute(RouteNone, RouteTarget{Interface: "lo0", Address: "10.0.0.1"}))

	assert.NoError(t, r.SetRoute(DupTo, RouteTarget{Interface: "lo0", Address: "127.0.0.1"}))
	kind, targets := r.Route()
	assert.Equal(t, DupTo, kind)
	assert.Equal(t, []RouteTarget{{Interface: "lo0", Address: "127.0.0.1/32"}}, targets)

	assert.NoError(t, r.SetRoute(RouteNone))
	kind, targets = r.Route()
	assert.Equal(t, RouteNone, kind)
	assert.Empty(t, targets)
}

func TestParseCIDRRefusesNonsense(t *testing.T) {
	var r Rule
	for _, bad := range []string{"nonsense", "10.0.0", "10.0.0.256", "", "1.2.3.4/33", "::g"} {
		assert.Error(t, r.ParseSource(bad, "", false), bad)
		assert.Error(t, r.ParseDestination(bad, "", false), bad)
	}
	assert.NoError(t, r.ParseSource("10.0.0.1", "", false))
	assert.NoError(t, r.ParseSource("10.0.0.0/8", "", false))
	assert.NoError(t, r.ParseSource("2001:db8::1", "", false))
}
