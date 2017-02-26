package pf

import (
	"fmt"
)

// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// Protocol that should be filtered by pf
type Protocol uint8

const (
	// Any matches any protocol
	ProtocolAny Protocol = 0
	// TCP
	ProtocolTCP Protocol = C.IPPROTO_TCP
	// UDP
	ProtocolUDP Protocol = C.IPPROTO_UDP
	// ICMP
	ProtocolICMP Protocol = C.IPPROTO_ICMP
)

func (p Protocol) String() string {
	switch p {
	case ProtocolAny:
		return "any"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolICMP:
		return "icmp"
	default:
		return fmt.Sprintf("Protocol(%d)", p)
	}
}
