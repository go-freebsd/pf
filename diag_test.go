package pf

import "testing"

func TestRouteDiag(t *testing.T) {
	probe := func(label, anchor string) {
		for _, l := range diagGetAddrs(anchorOf(anchor), anchor) {
			t.Logf("%s: %s", label, l)
		}
	}
	theirs := oracleAnchor(t, "diag-theirs")
	pfctl(t, "pass out route-to (lo0 127.0.0.1) inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40801 keep state\n", "-a", theirs, "-f", "-")
	t.Logf("pfctl -sr -vv:\n%s", pfctl(t, "", "-a", theirs, "-sr", "-vv"))
	probe("pfctl-loaded", theirs)
	for _, l := range diagRuleKeys(anchorOf(theirs), theirs) {
		t.Logf("keys: %s", l)
	}

	mine := oracleAnchor(t, "diag-mine")
	var r Rule
	r.SetAction(ActionPass)
	r.SetDirection(DirectionOut)
	r.SetProtocol(ProtocolTCP)
	r.SetAddressFamily(AddressFamilyInet)
	r.SetState(StateKeep)
	if err := r.SetRoute(RouteTo, RouteTarget{Interface: "lo0", Address: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	commitRules(t, mine, &r)
	t.Logf("pfctl -sr -vv of the library's rule:\n%s", pfctl(t, "", "-a", mine, "-sr", "-vv"))
	probe("library-written", mine)
}
