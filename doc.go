// PF (Packet Filter)
//
// This go module enables easy access to the packet filter inside the
// kernel. The pf packet filter originally based on openbsd was imported
// to freebsd a while ago and can be found in other operating systems
// like macOS too.
//
// Since the kernel interface is different between the operating systems
// this version currently only works with freebsd.
//
// Packet filtering is handled in the kernel to avoid copying. To change
// the configuration of pf a pseudo-device, /dev/pf, can be used,
// it allows userland processes to control the behavior of the packet filter
// through an ioctl(2) interface.  There are commands to enable and disable
// the filter, load rulesets, add and remove individual rules or state table
// entries, and retrieve statistics.  The most commonly used functions are
// covered by this library.
//
// Manipulations like loading a ruleset that involve more than a single
// ioctl(2) call require a so-called ticket, which prevents the occurrence
// of multiple concurrent manipulations. Tickets are modeled as transaction
// objects inside the library.
//
// Working with pf directly on a remote connection can cause you to loose
// the connection in case of a programming error. Make sure you have a
// second way to access the system e.g. a serial console.
package pf
