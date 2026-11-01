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
	tx := pfh.NewTransaction(1)
	rs := tx.RuleSet(0)
	rs.SetType(RuleSetFilter)
	require.NoError(t, rs.SetAnchor(anchor))
	require.NoError(t, tx.Begin())
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	for _, r := range rules {
		require.NoError(t, rs.AddRule(r))
	}
	require.NoError(t, tx.Commit())
	committed = true
}

var (
	reSpaces    = regexp.MustCompile(`\s+`)
	reHost      = regexp.MustCompile(`/(32|128)\b`)
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
	s = strings.ReplaceAll(s, " flags S/SA", "")
	s = strings.ReplaceAll(s, " inout", "")
	// the library prints nothing for a rule without state, pfctl "no state"
	s = strings.ReplaceAll(s, " no state", "")
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
	}, "\n") + "\n"
	pfctl(t, ruleset, "-a", anchor, "-f", "-")

	shown := ruleLines(pfctl(t, "", "-a", anchor, "-sr"))
	read, err := anchorOf(anchor).Rules()
	require.NoError(t, err)
	require.Len(t, read, len(shown), "number of rules")
	require.Len(t, read, 5)

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
