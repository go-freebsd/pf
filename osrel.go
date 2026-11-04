package pf

import (
	"sync"
	"syscall"
)

var (
	osReleaseOnce sync.Once
	osRelease     uint32
)

// osreldate is kern.osreldate, 0 if it cannot be read: 1403000 is FreeBSD
// 14.3, 1500068 is 15.0-RELEASE-p13.
func osreldate() uint32 {
	osReleaseOnce.Do(func() {
		osRelease, _ = syscall.SysctlUint32("kern.osreldate")
	})
	return osRelease
}

// routePoolOptionsWork is false where the pool type of a route-to list
// cannot be written: FreeBSD 15 keeps the route pool apart from the pool the
// ioctl interface of this package sets the type of.
func routePoolOptionsWork() bool { return osreldate() < 1500000 }
