package pf

import (
	"testing"
	"unsafe"
)

// #include <string.h>
// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

func TestRouteDiag(t *testing.T) {
	probe := func(label, anchor string) {
		var rules C.struct_pfioc_rule
		C.strlcpy(&rules.anchor[0], C.CString(anchor), C.MAXPATHLEN)
		if err := pfh.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules)); err != nil {
			t.Logf("%s: GETRULES: %v", label, err)
			return
		}
		t.Logf("%s: nr=%d ticket=%d", label, rules.nr, rules.ticket)
		for _, act := range []int{C.PF_PASS, C.PF_DROP, C.PF_NAT, C.PF_RDR, C.PF_BINAT} {
			for _, last := range []int{0, 1} {
				var pp C.struct_pfioc_pooladdr
				pp.ticket = rules.ticket
				pp.r_num = 0
				pp.r_action = C.u_int8_t(act)
				pp.r_last = C.u_int8_t(last)
				C.strlcpy(&pp.anchor[0], C.CString(anchor), C.MAXPATHLEN)
				err := pfh.ioctl(C.DIOCGETADDRS, unsafe.Pointer(&pp))
				t.Logf("%s: GETADDRS r_action=%d r_last=%d -> nr=%d err=%v", label, act, last, pp.nr, err)
			}
		}
	}
	theirs := oracleAnchor(t, "diag-theirs")
	pfctl(t, "pass out route-to (lo0 127.0.0.1) inet proto tcp from 10.0.0.1 to 10.0.0.2 port 40801 keep state\n", "-a", theirs, "-f", "-")
	t.Logf("pfctl -sr -vv:\n%s", pfctl(t, "", "-a", theirs, "-sr", "-vv"))
	probe("pfctl-loaded", theirs)

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
