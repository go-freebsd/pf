package pf

import (
	"errors"
	"unsafe"
)

// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
/*
static void status_scalars(struct pf_status *s, uint64_t running, uint64_t since,
	uint64_t debug, uint64_t hostid, uint64_t states, uint64_t src_nodes) {
	s->running = running;
	s->since = since;
	s->debug = debug;
	s->hostid = hostid;
	s->states = states;
	s->src_nodes = src_nodes;
}

// kind: 0 counters, 1 lcounters, 2 fcounters, 3 scounters
static void status_counter(struct pf_status *s, int kind, int i, uint64_t v) {
	switch (kind) {
	case 0: if (i < (int)(sizeof(s->counters)/sizeof(s->counters[0]))) s->counters[i] = v; break;
	case 1: if (i < (int)(sizeof(s->lcounters)/sizeof(s->lcounters[0]))) s->lcounters[i] = v; break;
	case 2: if (i < (int)(sizeof(s->fcounters)/sizeof(s->fcounters[0]))) s->fcounters[i] = v; break;
	case 3: if (i < (int)(sizeof(s->scounters)/sizeof(s->scounters[0]))) s->scounters[i] = v; break;
	}
}

static void status_pcounter(struct pf_status *s, int i, int j, int k, uint64_t v) {
	s->pcounters[i][j][k] = v;
}

static void status_bcounter(struct pf_status *s, int i, int j, uint64_t v) {
	s->bcounters[i][j] = v;
}

static void status_ifname(struct pf_status *s, const char *name) {
	strlcpy(s->ifname, name, sizeof(s->ifname));
}

static void status_chksum(struct pf_status *s, const void *sum, size_t n) {
	if (n > sizeof(s->pf_chksum)) n = sizeof(s->pf_chksum);
	memcpy(s->pf_chksum, sum, n);
}
*/
import "C"

// status reads the packet filter status with DIOCGETSTATUSNV and stores
// it in the struct based representation the Statistics accessors use.
// FreeBSD 15 removed the struct based DIOCGETSTATUS.
func (dev *ioctlDev) status(stats *Statistics) error {
	reply, err := dev.nvIoctl(C.DIOCGETSTATUSNV, nil)
	if err != nil {
		return err
	}
	defer reply.destroy()

	var s C.struct_pf_status
	running, _ := reply.boolean("running")
	var r uint64
	if running {
		r = 1
	}
	C.status_scalars(&s, C.uint64_t(r), C.uint64_t(num(reply, "since")),
		C.uint64_t(num(reply, "debug")), C.uint64_t(num(reply, "hostid")),
		C.uint64_t(num(reply, "states")), C.uint64_t(num(reply, "src_nodes")))

	for kind, key := range []string{"counters", "lcounters", "fcounters", "scounters"} {
		child, ok := reply.child(key)
		if !ok {
			continue
		}
		values, _ := child.numbers("counters")
		for i, v := range values {
			C.status_counter(&s, C.int(kind), C.int(i), C.uint64_t(v))
		}
	}

	if p, ok := reply.numbers("pcounters"); ok {
		if len(p) < 8 {
			return errors.New("short pcounters")
		}
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				for k := 0; k < 2; k++ {
					C.status_pcounter(&s, C.int(i), C.int(j), C.int(k), C.uint64_t(p[i*4+j*2+k]))
				}
			}
		}
	}
	if b, ok := reply.numbers("bcounters"); ok {
		if len(b) < 4 {
			return errors.New("short bcounters")
		}
		for i := 0; i < 2; i++ {
			for j := 0; j < 2; j++ {
				C.status_bcounter(&s, C.int(i), C.int(j), C.uint64_t(b[i*2+j]))
			}
		}
	}

	if name, ok := reply.str("ifname"); ok {
		cs := C.CString(name)
		C.status_ifname(&s, cs)
		C.free(unsafe.Pointer(cs))
	}
	if sum, ok := reply.binary("chksum"); ok && len(sum) > 0 {
		C.status_chksum(&s, unsafe.Pointer(&sum[0]), C.size_t(len(sum)))
	}
	stats.wrap = s
	return nil
}
