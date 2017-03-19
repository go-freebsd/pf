package pf

/*
TODO:
struct pf_status {
	uint64_t	pcounters[2][2][3];
	uint64_t	bcounters[2][2];
	uint32_t	running;
	uint32_t	states;
	uint32_t	src_nodes;
	uint32_t	since;
	uint32_t	debug;
	uint32_t	hostid;
	char		ifname[IFNAMSIZ];
	uint8_t		pf_chksum[PF_MD5_DIGEST_LENGTH];
};
*/

import (
	"fmt"
	"strings"
)

// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// Statistics about the internal packet filter
type Statistics struct {
	wrap C.struct_pf_status
}

/* Reasons code for passing/dropping a packet */

// ReasonMatch num of explicit match of a rule
func (s Statistics) ReasonMatch() uint64 {
	return uint64(s.wrap.counters[C.PFRES_MATCH])
}

// ReasonBadOffset num of bad offset for pull_hdr
func (s Statistics) ReasonBadOffset() uint64 {
	return uint64(s.wrap.counters[C.PFRES_BADOFF])
}

// ReasonFragment num dropping following fragment
func (s Statistics) ReasonFragment() uint64 {
	return uint64(s.wrap.counters[C.PFRES_FRAG])
}

// ReasonShort num dropping short packet
func (s Statistics) ReasonShort() uint64 {
	return uint64(s.wrap.counters[C.PFRES_SHORT])
}

// ReasonNormalizer num dropping by normalizer
func (s Statistics) ReasonNormalizer() uint64 {
	return uint64(s.wrap.counters[C.PFRES_NORM])
}

// ReasonMemory num dropped die to lacking mem
func (s Statistics) ReasonMemory() uint64 {
	return uint64(s.wrap.counters[C.PFRES_MEMORY])
}

// ReasonBadTimestamp num of bad TCP Timestamp (RFC1323)
func (s Statistics) ReasonBadTimestamp() uint64 {
	return uint64(s.wrap.counters[C.PFRES_TS])
}

// ReasonCongestion num of congestion of ipintrq
func (s Statistics) ReasonCongestion() uint64 {
	return uint64(s.wrap.counters[C.PFRES_CONGEST])
}

// ReasonIPOption num IP option
func (s Statistics) ReasonIPOption() uint64 {
	return uint64(s.wrap.counters[C.PFRES_IPOPTIONS])
}

// ReasonProtocolChecksum num protocol checksum invalid
func (s Statistics) ReasonProtocolChecksum() uint64 {
	return uint64(s.wrap.counters[C.PFRES_PROTCKSUM])
}

// ReasonBadState num of state mismatch
func (s Statistics) ReasonBadState() uint64 {
	return uint64(s.wrap.counters[C.PFRES_BADSTATE])
}

// ReasonStateInsertion num of state insertion failure
func (s Statistics) ReasonStateInsertion() uint64 {
	return uint64(s.wrap.counters[C.PFRES_STATEINS])
}

// ReasonMaxStates num of state limit
func (s Statistics) ReasonMaxStates() uint64 {
	return uint64(s.wrap.counters[C.PFRES_MAXSTATES])
}

// ReasonSourceLimit num of source node/conn limit
func (s Statistics) ReasonSourceLimit() uint64 {
	return uint64(s.wrap.counters[C.PFRES_SRCLIMIT])
}

// ReasonSynProxy num SYN proxy
func (s Statistics) ReasonSynProxy() uint64 {
	return uint64(s.wrap.counters[C.PFRES_SYNPROXY])
}

// ReasonMapFailed num pf_map_addr() failed
func (s Statistics) ReasonMapFailed() uint64 {
	return uint64(s.wrap.counters[C.PFRES_MAPFAILED])
}

/* Counters for other things we want to keep track of */

// CounterStates num states
func (s Statistics) CounterStates() uint64 {
	return uint64(s.wrap.lcounters[C.LCNT_STATES])
}

// CounterSrcStates max src states
func (s Statistics) CounterSrcStates() uint64 {
	return uint64(s.wrap.lcounters[C.LCNT_SRCSTATES])
}

// CounterSrcNodes max src nodes
func (s Statistics) CounterSrcNodes() uint64 {
	return uint64(s.wrap.lcounters[C.LCNT_SRCNODES])
}

// CounterSrcConn max src conn
func (s Statistics) CounterSrcConn() uint64 {
	return uint64(s.wrap.lcounters[C.LCNT_SRCCONN])
}

// CounterSrcConnRate max src conn rate
func (s Statistics) CounterSrcConnRate() uint64 {
	return uint64(s.wrap.lcounters[C.LCNT_SRCCONNRATE])
}

// CounterOverloadTable entry added to overload table
func (s Statistics) CounterOverloadTable() uint64 {
	return uint64(s.wrap.lcounters[C.LCNT_OVERLOAD_TABLE])
}

// CounterOverloadFlush state entries flushed
func (s Statistics) CounterOverloadFlush() uint64 {
	return uint64(s.wrap.lcounters[C.LCNT_OVERLOAD_FLUSH])
}

/* state operation counters */

// CounterStateSearch num state search
func (s Statistics) CounterStateSearch() uint64 {
	return uint64(s.wrap.fcounters[C.FCNT_STATE_SEARCH])
}

// CounterStateInsert num state insert
func (s Statistics) CounterStateInsert() uint64 {
	return uint64(s.wrap.fcounters[C.FCNT_STATE_INSERT])
}

// CounterStateRemovals num state insert
func (s Statistics) CounterStateRemovals() uint64 {
	return uint64(s.wrap.fcounters[C.FCNT_STATE_REMOVALS])
}

/* src_node operation counters */

// CounterNodeSearch num state search
func (s Statistics) CounterNodeSearch() uint64 {
	return uint64(s.wrap.scounters[C.SCNT_SRC_NODE_SEARCH])
}

// CounterNodeInsert num state insert
func (s Statistics) CounterNodeInsert() uint64 {
	return uint64(s.wrap.scounters[C.SCNT_SRC_NODE_INSERT])
}

// CounterNodeRemovals num state insert
func (s Statistics) CounterNodeRemovals() uint64 {
	return uint64(s.wrap.scounters[C.SCNT_SRC_NODE_REMOVALS])
}

func (s Statistics) String() string {
	dump := []struct {
		name  string
		value uint64
	}{
		{"match", s.ReasonMatch()},
		{"bad-offset", s.ReasonBadOffset()},
		{"fragment", s.ReasonFragment()},
		{"short", s.ReasonShort()},
		{"normalize", s.ReasonNormalizer()},
		{"memory", s.ReasonMemory()},
		{"bad-timestamp", s.ReasonBadTimestamp()},
		{"congestion", s.ReasonCongestion()},
		{"ip-option", s.ReasonIPOption()},
		{"proto-cksum", s.ReasonProtocolChecksum()},
		{"state-mismatch", s.ReasonBadState()},
		{"state-insert", s.ReasonStateInsertion()},
		{"state-limit", s.ReasonMaxStates()},
		{"src-limit", s.ReasonSourceLimit()},
		{"synproxy", s.ReasonSynProxy()},
		{"map-failed", s.ReasonMapFailed()},

		{"max-states-per-rule", s.CounterStates()},
		{"max-src-states", s.CounterSrcStates()},
		{"max-src-nodes", s.CounterSrcNodes()},
		{"max-src-conn", s.CounterSrcConn()},
		{"max-src-conn-rate", s.CounterSrcConnRate()},
		{"overload-table-insertion", s.CounterOverloadTable()},
		{"overload-flush-states", s.CounterOverloadFlush()},

		{"counter-state-search", s.CounterStateSearch()},
		{"counter-state-insert", s.CounterStateInsert()},
		{"counter-state-removals", s.CounterStateRemovals()},

		{"counter-node-search", s.CounterNodeSearch()},
		{"counter-node-insert", s.CounterNodeInsert()},
		{"counter-node-removals", s.CounterNodeRemovals()},
	}
	list := make([]string, 0, len(dump))

	for _, line := range dump {
		list = append(list, fmt.Sprintf("%s: %d", line.name, line.value))
	}

	return strings.Join(list, " ")
}
