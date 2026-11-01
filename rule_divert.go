package pf

import (
	"fmt"
	"net"
	"unsafe"
)

// #include <string.h>
// #include <sys/ioctl.h>
// #include <netinet/in.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void rule_set_divert(struct pf_rule *r, const void *addr, size_t n, unsigned int port) {
	memset(&r->divert.addr, 0, sizeof(r->divert.addr));
	if (addr != NULL) memcpy(&r->divert.addr, addr, n);
	r->divert.port = htons(port);
}
static void rule_set_divert_raw(struct pf_rule *r, const void *addr, size_t n, unsigned int port) {
	memset(&r->divert.addr, 0, sizeof(r->divert.addr));
	if (addr != NULL && n <= sizeof(r->divert.addr)) memcpy(&r->divert.addr, addr, n);
	r->divert.port = port;
}
static unsigned int rule_divert_port(struct pf_rule *r) { return ntohs(r->divert.port); }
static const void *rule_divert_addr(struct pf_rule *r) { return &r->divert.addr; }
*/
import "C"

// SetDivertTo makes the rule divert the packets it matches to a divert
// socket listening on the address and port ("divert-to 127.0.0.1 port
// 8668"). The rule has to be an "in" rule with a protocol. pf.conf has no
// divert-reply and divert-packet on FreeBSD.
func (r *Rule) SetDivertTo(address string, port uint16) error {
	if port == 0 {
		return fmt.Errorf("divert-to needs a port")
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return fmt.Errorf("divert-to address %q is not an IP address", address)
	}
	b := ip.To4()
	if b == nil {
		b = ip.To16()
	}
	C.rule_set_divert(&r.wrap.rule, unsafe.Pointer(&b[0]), C.size_t(len(b)), C.uint(port))
	r.divertV6 = ip.To4() == nil
	return nil
}

// ClearDivertTo removes the diversion.
func (r *Rule) ClearDivertTo() {
	C.rule_set_divert(&r.wrap.rule, nil, 0, 0)
	r.divertV6 = false
}

// DivertTo returns the address and port the rule diverts to; ok is false for
// a rule that does not divert.
func (r Rule) DivertTo() (address string, port uint16, ok bool) {
	port = uint16(C.rule_divert_port(&r.wrap.rule))
	if port == 0 {
		return "", 0, false
	}
	raw := C.GoBytes(C.rule_divert_addr(&r.wrap.rule), 16)
	if r.divertV6 || r.wrap.rule.af == C.AF_INET6 {
		return net.IP(raw).String(), port, true
	}
	return net.IP(raw[:4]).String(), port, true
}

// setDivertRaw stores what the kernel reports; the port is in network order.
func (r *Rule) setDivertRaw(addr []byte, port uint64) {
	var p unsafe.Pointer
	if len(addr) > 0 {
		p = unsafe.Pointer(&addr[0])
	}
	C.rule_set_divert_raw(&r.wrap.rule, p, C.size_t(len(addr)), C.uint(port))
}

// divertString is how pfctl prints the diversion: the port only.
func (r Rule) divertString() string {
	if _, port, ok := r.DivertTo(); ok {
		return fmt.Sprintf("divert-to %d", port)
	}
	return ""
}
