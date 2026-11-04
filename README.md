# PF (Packet Filter)

[![GoDoc](https://godoc.org/github.com/go-freebsd/pf?status.svg)](https://godoc.org/github.com/go-freebsd/pf)
[![Coverage 84.7%](https://img.shields.io/badge/coverage-84.7%25-green.svg)]()
[![FreeBSD 14.3](https://img.shields.io/badge/freebsd-14.3-green.svg)](https://www.freebsd.org/releases/14.3R/announce/)
[![FreeBSD 15.0](https://img.shields.io/badge/freebsd-15.0-green.svg)](https://www.freebsd.org/releases/15.0R/announce/)

## Quick start

Rules are built the way `pf.conf` writes them, with the defaults `pfctl`
gives, and loaded in one transaction (you need to be root, and `pf.ko`
loaded):

```go
pfh, err := pf.Open()
if err != nil {
	log.Fatal(err)
}
defer pfh.Close()

// nat on em0 inet from any to any -> (em0) round-robin
//   (the rule asked for in issue #5)
nat := pf.NAT().On("em0").Inet().RedirectToInterface("em0").RoundRobin()

err = pf.NewRuleset().
	Add(pf.Scrub().In().On("em0")).                                      // scrub in on em0 all
	Add(nat).
	Add(pf.Block().In().Quick().From("10.0.0.0/8")).                     // block in quick from 10.0.0.0/8 to any
	Add(pf.Pass().Out().On("em0")).                                      // pass out on em0 flags S/SA keep state
	Add(pf.Pass().In().On("em0").Proto(pf.ProtocolTCP).ToPort("22")).    // pass in on em0 proto tcp ... port 22 flags S/SA keep state
	Load(pfh, "") // replaces the rules of the main rule set, atomically
```

* Every method is the word you know from `pf.conf`: `In`, `Out`, `Quick`,
  `Log`, `On`, `OnNot`, `OnAny("em0", "em1")`, `Inet`, `Inet6`, `Proto`,
  `From`, `To`, `FromPort`, `ToPort`, `Flags`, `KeepState`, `NoState`,
  `RedirectTo`, `RedirectToInterface`, `RedirectToTable`, `RoundRobin`,
  `StaticPort`, `RouteTo`, `DivertTo`, `Tag`, `Tagged`, `Prio`, `Queue`,
  `NoDF`, `MinTTL`, ... Addresses are written as in `pf.conf` too: `"any"`,
  `"10.0.0.0/8"`, `"<table>"`, `"(em0)"`, `"(em0:network)"`, `"no-route"`.
* **Defaults are pfctl's**, and the tests check them against `pfctl` on
  FreeBSD 14.3 and 15.0: the minimal builder and the minimal `pf.conf` line
  give the same rule in the kernel. A `Pass` keeps state (`NoState` opts
  out) and matches the TCP flags `S/SA`; a `Block` drops; `any` is any
  address and no port is no port; a `nat` rule without ports uses the dynamic
  range 50001:65535 (`StaticPort` keeps the source port); a direction is both.
* **Errors are collected**, not panicked: a wrong argument is remembered, the
  chain goes on, and `Rule()`, `Rules()` or `Load` return all of them. The
  builder refuses what pfctl refuses (a port without `tcp` or `udp`, `flags`
  without `tcp`, a `nat` rule without a target or with a direction, `reassemble
  tcp` with a direction, mixed address families, ...) before anything is sent to
  the kernel.
* `Rules()` returns what pfctl expands: `OnAny("em0", "em1")` is one kernel
  rule per interface. `String()` is the rule as pfctl prints it.
* The low-level `Rule` API below is unchanged and still there for everything
  the builder does not cover yet; `docs/coverage.md` lists what is covered.

The FreeBSD operating system has multiple packet filter build-in. One of
the packet filters was ported from OpenBSD and is called pf (packetfilter).

Packet filtering restricts the types of packets that pass through network
interfaces entering or leaving the host based on filter rules as
described in. The packet filter can also replace addresses
and ports of packets. Replacing source addresses and ports of outgoing
packets is called NAT (Network Address Translation) and is used to
connect an internal network (usually reserved address space) to an
external one (the Internet) by making all connections to external hosts
appear to come from the gateway. Replacing destination addresses and
ports of incoming packets is used to redirect connections to different
hosts and/or ports. A combination of both translations, bidirectional
NAT, is also supported.

This go module enables easy access to the packet filter inside the
kernel. The FreeBSD kernel module responsible for implementing pf is
called pf.ko.

Since the kernel interface is different between the operating
systems this version currently only works with FreeBSD.

The packet filter creates the pseudo-device node /dev/pf,
it allows userland processes to control the behavior of the packet filter
through an ioctl(2) interface. There are commands to enable and disable
the filter, load rulesets, add and remove individual rules or state table
entries, and retrieve statistics. The most commonly used functions are
covered by this library.

Manipulations like loading a ruleset that involve more than a single
ioctl(2) call require a so-called ticket, which prevents the occurrence
of multiple concurrent manipulations. Tickets are modeled as transaction
objects inside the library.

Working with pf directly on a remote connection can cause you to loose
the connection in case of a programming error. Make sure you have a
second way to access the system e.g. a serial console.

# Supported releases

The library is tested on FreeBSD 14.3 and 15.0 (amd64). FreeBSD 15 removed
the struct based `DIOCGETRULE` and `DIOCGETSTATUS` ioctls; the rules and the
status are therefore read with their nvlist variants (`DIOCGETRULENV`,
`DIOCGETSTATUSNV`, through libnv), which exist on 14 and 15. Older releases
(10 and 11 were the first targets of this package) are not exercised any more
and are not supported; FreeBSD 14.3 and 15.0 are tested in CI on every push
(amd64, and 14.3 on an emulated aarch64 VM).

# Testing

You need to be root to execute the tests.

	make test

The tests do not only check the library against itself: `oracle_test.go`
compares it with `pfctl(8)`. Rules written by the library must be shown by
`pfctl -sr` as the library describes them and are read back unchanged. Rules
loaded with `pfctl -f` must be read in order by the library. The status, the
debug level, the host id, the limits and the timeouts set through the library
must be the values `pfctl -si/-sm/-st` report. Everything happens in scratch
anchors (`go-pf-oracle-*`), so the main ruleset is not touched.

The comparison ignores differences of notation that carry no meaning: spaces,
the implicit host prefix (`/32`, `/128`), `port = 22` versus `port 22`, `block
drop` versus `drop`, and the address count pfctl adds to a table (`<t1:3>`).
Everything else, `flags`, `rtable`, `fragment reassemble` included, has to be
the same. Continuous integration runs the tests in FreeBSD 14.3 and 15.0
virtual machines.

# FreeBSD 15 and the targets of route-to

FreeBSD 15 keeps the targets of `route-to`, `reply-to` and `dup-to` in a pool
of their own that the kernel only hands out through netlink. The ioctl
interface this package uses can write them (`SetRoute` works, and pfctl shows
the targets), but not read them: a rule read on FreeBSD 15 reports its kind of
routing from `Route()` and no targets, and `String()` prints the keyword
without them. On FreeBSD 14 the targets are read as well. The comparison with
pfctl accounts for that.

# What the library covers

* Filter rules (`pass`, `block`/`drop`): action, direction, `log`, `quick`,
  interface or interface group (`on em0`, `on ! em0`: `SetInterface`,
  `SetInterfaceNot`; also for the translation rules; `RuleSet.AddRuleOnInterfaces`
  adds a rule once per interface, the `on { em0 em1 }` list), routing (`route-to`, `reply-to`, `dup-to` with one or more
  `(interface address)` targets: `SetRoute`), address family, protocol, TCP flags (`flags S/SA`, `flags any`:
  `SetTCPFlags`, `ParseTCPFlags`; a rule written with flags 0/0 is `flags any`, pfctl
  itself defaults to `S/SA` for tcp rules that keep state), source and destination address (host, network,
  range, `!`, tables, dynamic interface addresses) with ports and all port
  operators, and the state option. `String()` writes `no state` for a pass rule
  that keeps no state, as pfctl does.
* Translation rules: `nat`, `rdr` and `binat` with their `no` forms.
  `Rule.SetRedirect(address, ports)` sets the address after `->` and the port
  range; a nat rule without ports gets the dynamic range 50001:65535, as with
  pfctl. `Anchor.RulesOf(type)` reads the rules of one rule set type; `Rules()`
  reads the filter rules.
* Scrub rules with `no-df`, `min-ttl`, `max-mss`, `random-id` and `reassemble tcp` (`SetScrub`); fragments are reassembled, the `fragment reassemble` pfctl prints.
* `queue`/`queue (std, ack)` names (`SetQueue`), `tag`/`tagged` (`SetTag`, `SetTagged`), `prio` and `set prio` (`SetPriority`, `SetSetPriority`). The kernels the CI runs on have no ALTQ, so the queue names are only compared with pfctl as names: the rule is accepted and shown, but whether a queue of that name does anything is not tested.
* `divert-to` (`SetDivertTo`; pfctl prints the port only, the library keeps the address as well).
* The routing table of a rule (`SetRTable`, `rtable N`). A rule without it leaves the routing table alone (the kernel is told -1, as pfctl does); this is not the same as `rtable 0`.
* Tables: `CreateTable`, `DeleteTable`, `Tables`, `AddTableAddresses` and
  `TableAddresses` on a `Handle`, and `Address.SetTableName` to refer to one.
* Anchors: rule sets and rules in an anchor (`Anchor{Path: ...}`), nested
  anchors with `Anchor.Anchors()`.
* Transactions, status, debug level, host id (in network byte order, as
  pfctl shows it), limits and timeouts.

Not modelled: dummynet pipes (`dnpipe`, `dnqueue`: the struct that `DIOCADDRULE` takes has no field for them, only the nvlist `DIOCADDRULENV` does), `divert-reply` and `divert-packet` (FreeBSD's pf.conf has neither), and pool options other than the port range and round-robin.
