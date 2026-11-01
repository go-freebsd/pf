package pf

import (
	"fmt"
	"os"
	"unsafe"
)

// #cgo LDFLAGS: -lpfctl
// #include <string.h>
// #include <stdlib.h>
// #include <errno.h>
// #include <sys/param.h>
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <sys/ioctl.h>
// #include <netinet/in.h>
// #include <net/if.h>
// #include <net/pfvar.h>
// #include <libpfctl.h>
/*
static int diag_route(int dev, const char *anchor, unsigned ruleset, unsigned ticket, unsigned nr, char *out, int outlen) {
#if __FreeBSD_version >= 1500000
	struct pfctl_rule rule;
	char anchor_call[MAXPATHLEN];
	memset(&rule, 0, sizeof(rule));
	int err = pfctl_get_rule(dev, nr, ticket, anchor, ruleset, &rule, anchor_call);
	if (err) { snprintf(out, outlen, "pfctl_get_rule: %d", err); return -1; }
	int n = 0;
	struct pfctl_pooladdr *pa;
	int off = 0;
	TAILQ_FOREACH(pa, &rule.route.list, entries) {
		off += snprintf(out + off, outlen - off, "[%s type=%d] ", pa->ifname, pa->addr.type);
		n++;
	}
	snprintf(out + off, outlen - off, "rt=%d", rule.rt);
	return n;
#else
	snprintf(out, outlen, "not 15");
	return -2;
#endif
}
*/
import "C"

type os_File = os.File

// diagGetAddrs is a temporary diagnosis, removed again.
func diagGetAddrs(a Anchor, anchor string) []string {
	var out []string
	var rules C.struct_pfioc_rule
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	C.strlcpy(&rules.anchor[0], ca, C.MAXPATHLEN)
	if err := a.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules)); err != nil {
		return []string{fmt.Sprintf("GETRULES: %v", err)}
	}
	out = append(out, fmt.Sprintf("nr=%d ticket=%d", rules.nr, rules.ticket))
	for _, act := range []int{C.PF_PASS, C.PF_DROP, C.PF_NAT, C.PF_RDR, C.PF_BINAT} {
		for _, last := range []int{0, 1} {
			var pp C.struct_pfioc_pooladdr
			pp.ticket = rules.ticket
			pp.r_action = C.u_int8_t(act)
			pp.r_last = C.u_int8_t(last)
			C.strlcpy(&pp.anchor[0], ca, C.MAXPATHLEN)
			err := a.ioctl(C.DIOCGETADDRS, unsafe.Pointer(&pp))
			out = append(out, fmt.Sprintf("GETADDRS r_action=%d r_last=%d -> nr=%d err=%v", act, last, pp.nr, err))
		}
	}
	return out
}

// diagRuleKeys dumps the keys of the DIOCGETRULENV reply for rule 0.
func diagRuleKeys(a Anchor, anchor string) []string {
	var rules C.struct_pfioc_rule
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	C.strlcpy(&rules.anchor[0], ca, C.MAXPATHLEN)
	if err := a.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules)); err != nil {
		return []string{err.Error()}
	}
	req := newNV()
	defer req.destroy()
	req.addString("anchor", anchor)
	req.addNumber("ruleset", uint64(ActionPass))
	req.addNumber("ticket", uint64(rules.ticket))
	req.addNumber("nr", 0)
	reply, err := a.nvIoctl(C.DIOCGETRULENV, req)
	if err != nil {
		return []string{err.Error()}
	}
	defer reply.destroy()
	return reply.dump("")
}

func diagLibpfctl(a Anchor, anchor string) []string {
	var rules C.struct_pfioc_rule
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	C.strlcpy(&rules.anchor[0], ca, C.MAXPATHLEN)
	if err := a.ioctl(C.DIOCGETRULES, unsafe.Pointer(&rules)); err != nil {
		return []string{err.Error()}
	}
	var out []string
	for _, rs := range []uint{0, 1, 4} { // pass action, rule set index filter, drop?
		buf := (*C.char)(C.malloc(512))
		n := C.diag_route(C.int((*os_File)(a.ioctlDev).Fd()), ca, C.uint(rs), C.uint(rules.ticket), 0, buf, 512)
		out = append(out, fmt.Sprintf("pfctl_get_rule ruleset=%d -> %d %s", rs, int(n), C.GoString(buf)))
		C.free(unsafe.Pointer(buf))
	}
	return out
}
