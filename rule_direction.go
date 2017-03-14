// +build freebsd

package pf

import (
	"fmt"
)

// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// Direction in which the traffic flows
type Direction uint8

const (
	// In incoming (ingress) traffic
	DirectionIn Direction = C.PF_IN
	// Out outgoing (egress) traffic
	DirectionOut Direction = C.PF_OUT
	// InOut any direction (ingress/egress) traffic
	DirectionInOut Direction = C.PF_INOUT
	// Forward
	DirectionFwd Direction = C.PF_FWD
)

func (d Direction) String() string {
	switch d {
	case DirectionIn:
		return "in"
	case DirectionOut:
		return "out"
	case DirectionInOut:
		return "inout"
	case DirectionFwd:
		return "fwd"
	default:
		return fmt.Sprintf("Direction(%d)", d)
	}
}
