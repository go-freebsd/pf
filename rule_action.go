package pf

import (
	"fmt"
)

// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// Action that should be performed by pf
type Action uint8

const (
	ActionPass         Action = C.PF_PASS
	ActionDrop         Action = C.PF_DROP
	ActionScrub        Action = C.PF_SCRUB
	ActionNoScrub      Action = C.PF_NOSCRUB
	ActionNAT          Action = C.PF_NAT
	ActionNoNAT        Action = C.PF_NONAT
	ActionBINAT        Action = C.PF_BINAT
	ActionNoBINAT      Action = C.PF_NOBINAT
	ActionRDR          Action = C.PF_RDR
	ActionNoRDR        Action = C.PF_NORDR
	ActionSynProxyDrop Action = C.PF_SYNPROXY_DROP
	ActionDefer        Action = C.PF_DEFER
)

func (a Action) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionDrop:
		return "drop"
	case ActionScrub:
		return "scrub"
	case ActionNoScrub:
		return "no scrub"
	case ActionNAT:
		return "nat"
	case ActionNoNAT:
		return "no nat"
	case ActionBINAT:
		return "binat"
	case ActionNoBINAT:
		return "no binat"
	case ActionRDR:
		return "rdr"
	case ActionNoRDR:
		return "no rdr"
	case ActionSynProxyDrop:
		return "synproxy drop"
	case ActionDefer:
		return "defer"
	default:
		return fmt.Sprintf("Action(%d)", a)
	}
}
