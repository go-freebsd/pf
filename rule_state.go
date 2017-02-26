package pf

import (
	"fmt"
)

// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// State wether the packet filter should keep
// track of the packet flows (stateful packet filter)
// or not (stateless packet filter).
type State uint8

const (
	StateNo       State = 0
	StateKeep     State = C.PF_STATE_NORMAL
	StateModulate State = C.PF_STATE_MODULATE
	StateSynproxy State = C.PF_STATE_SYNPROXY
)

func (s State) String() string {
	switch s {
	case StateNo:
		return ""
	case StateKeep:
		return "keep state"
	case StateModulate:
		return "modulate state"
	case StateSynproxy:
		return "synproxy state"
	default:
		return fmt.Sprintf("State(%d)", s)
	}
}
