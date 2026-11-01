package pf

import (
	"fmt"
	"net"
	"unsafe"
)

// #include <stdlib.h>
// #include <string.h>
// #include <sys/ioctl.h>
// #include <netinet/in.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void table_io(struct pfioc_table *io, const char *anchor, const char *name,
	void *buffer, int esize, int size) {
	memset(io, 0, sizeof(*io));
	strlcpy(io->pfrio_table.pfrt_anchor, anchor, sizeof(io->pfrio_table.pfrt_anchor));
	strlcpy(io->pfrio_table.pfrt_name, name, sizeof(io->pfrio_table.pfrt_name));
	io->pfrio_buffer = buffer;
	io->pfrio_esize = esize;
	io->pfrio_size = size;
}

static int table_io_size(struct pfioc_table *io) { return io->pfrio_size; }
static int table_io_added(struct pfioc_table *io) { return io->pfrio_nadd; }

static size_t pfr_table_size(void) { return sizeof(struct pfr_table); }
static size_t pfr_addr_size(void) { return sizeof(struct pfr_addr); }

static void pfr_table_set(struct pfr_table *t, const char *anchor, const char *name, int persist) {
	memset(t, 0, sizeof(*t));
	strlcpy(t->pfrt_anchor, anchor, sizeof(t->pfrt_anchor));
	strlcpy(t->pfrt_name, name, sizeof(t->pfrt_name));
	t->pfrt_flags = persist ? PFR_TFLAG_PERSIST : 0;
}

static const char *pfr_table_name(struct pfr_table *t) { return t->pfrt_name; }

static void pfr_addr_set(struct pfr_addr *a, int af, int net, const void *ip, size_t n, int not) {
	memset(a, 0, sizeof(*a));
	a->pfra_af = af;
	a->pfra_net = net;
	a->pfra_not = not;
	memcpy(&a->pfra_u, ip, n);
}

static int pfr_addr_af(struct pfr_addr *a) { return a->pfra_af; }
static int pfr_addr_net(struct pfr_addr *a) { return a->pfra_net; }
static int pfr_addr_not(struct pfr_addr *a) { return a->pfra_not; }
static const void *pfr_addr_ip(struct pfr_addr *a) { return &a->pfra_u; }
*/
import "C"

// Table is a pf address table, a set of networks that rules refer to as
// <name>. A table belongs to an anchor ("" for the main ruleset).
type Table struct {
	Anchor, Name string
}

func (h Handle) tableOp(cmd uintptr, op string, anchor, name string, buf unsafe.Pointer, esize, n int) (C.struct_pfioc_table, error) {
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	cn := C.CString(name)
	defer C.free(unsafe.Pointer(cn))
	var io C.struct_pfioc_table
	C.table_io(&io, ca, cn, buf, C.int(esize), C.int(n))
	if err := h.ioctl(cmd, unsafe.Pointer(&io)); err != nil {
		return io, fmt.Errorf("%s: %s", op, err)
	}
	return io, nil
}

// CreateTable creates a persistent table, one that stays when no rule
// refers to it (pfctl -T add does the same).
func (h Handle) CreateTable(anchor, name string) error {
	buf := C.calloc(1, C.pfr_table_size())
	defer C.free(buf)
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	cn := C.CString(name)
	defer C.free(unsafe.Pointer(cn))
	C.pfr_table_set((*C.struct_pfr_table)(buf), ca, cn, 1)
	_, err := h.tableOp(C.DIOCRADDTABLES, "DIOCRADDTABLES", "", "", buf, int(C.pfr_table_size()), 1)
	return err
}

// DeleteTable deletes the table and its addresses.
func (h Handle) DeleteTable(anchor, name string) error {
	buf := C.calloc(1, C.pfr_table_size())
	defer C.free(buf)
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	cn := C.CString(name)
	defer C.free(unsafe.Pointer(cn))
	C.pfr_table_set((*C.struct_pfr_table)(buf), ca, cn, 0)
	_, err := h.tableOp(C.DIOCRDELTABLES, "DIOCRDELTABLES", "", "", buf, int(C.pfr_table_size()), 1)
	return err
}

// Tables returns the tables of the anchor.
func (h Handle) Tables(anchor string) ([]Table, error) {
	io, err := h.tableOp(C.DIOCRGETTABLES, "DIOCRGETTABLES", anchor, "", nil, int(C.pfr_table_size()), 0)
	if err != nil {
		return nil, err
	}
	n := int(C.table_io_size(&io))
	if n == 0 {
		return nil, nil
	}
	buf := C.calloc(C.size_t(n), C.pfr_table_size())
	defer C.free(buf)
	io, err = h.tableOp(C.DIOCRGETTABLES, "DIOCRGETTABLES", anchor, "", buf, int(C.pfr_table_size()), n)
	if err != nil {
		return nil, err
	}
	n = int(C.table_io_size(&io))
	tables := make([]Table, 0, n)
	size := uintptr(C.pfr_table_size())
	for i := 0; i < n; i++ {
		t := (*C.struct_pfr_table)(unsafe.Add(buf, uintptr(i)*size))
		tables = append(tables, Table{Anchor: anchor, Name: C.GoString(C.pfr_table_name(t))})
	}
	return tables, nil
}

// AddTableAddresses adds networks (a host is a /32 or /128) to the table and
// returns how many were new. The table must exist.
func (h Handle) AddTableAddresses(anchor, name string, nets []*net.IPNet) (int, error) {
	if len(nets) == 0 {
		return 0, nil
	}
	size := uintptr(C.pfr_addr_size())
	buf := C.calloc(C.size_t(len(nets)), C.pfr_addr_size())
	defer C.free(buf)
	for i, n := range nets {
		ip, af := n.IP.To4(), C.AF_INET
		if ip == nil {
			ip, af = n.IP.To16(), C.AF_INET6
		}
		if ip == nil {
			return 0, fmt.Errorf("invalid address %v", n)
		}
		ones, _ := n.Mask.Size()
		C.pfr_addr_set((*C.struct_pfr_addr)(unsafe.Add(buf, uintptr(i)*size)), C.int(af), C.int(ones),
			unsafe.Pointer(&ip[0]), C.size_t(len(ip)), 0)
	}
	io, err := h.tableOp(C.DIOCRADDADDRS, "DIOCRADDADDRS", anchor, name, buf, int(size), len(nets))
	if err != nil {
		return 0, err
	}
	return int(C.table_io_added(&io)), nil
}

// TableAddresses returns the networks of the table.
func (h Handle) TableAddresses(anchor, name string) ([]*net.IPNet, error) {
	io, err := h.tableOp(C.DIOCRGETADDRS, "DIOCRGETADDRS", anchor, name, nil, int(C.pfr_addr_size()), 0)
	if err != nil {
		return nil, err
	}
	n := int(C.table_io_size(&io))
	if n == 0 {
		return nil, nil
	}
	buf := C.calloc(C.size_t(n), C.pfr_addr_size())
	defer C.free(buf)
	io, err = h.tableOp(C.DIOCRGETADDRS, "DIOCRGETADDRS", anchor, name, buf, int(C.pfr_addr_size()), n)
	if err != nil {
		return nil, err
	}
	n = int(C.table_io_size(&io))
	size := uintptr(C.pfr_addr_size())
	nets := make([]*net.IPNet, 0, n)
	for i := 0; i < n; i++ {
		a := (*C.struct_pfr_addr)(unsafe.Add(buf, uintptr(i)*size))
		var ip net.IP
		bits := 32
		switch C.pfr_addr_af(a) {
		case C.AF_INET:
			ip = net.IP(C.GoBytes(C.pfr_addr_ip(a), 4))
		case C.AF_INET6:
			ip = net.IP(C.GoBytes(C.pfr_addr_ip(a), 16))
			bits = 128
		default:
			continue
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(int(C.pfr_addr_net(a)), bits)})
	}
	return nets, nil
}
