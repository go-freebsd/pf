package pf_test

import (
	"fmt"
	"log"

	"github.com/go-freebsd/pf"
)

func ExampleRule_Stats() {
	pfh, err := pf.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer pfh.Close()

	rules, err := pfh.Rules()
	if err != nil {
		log.Fatalf("GetRules: %s\n", err)
	}
	var stats pf.RuleStats

	for i, rule := range rules {
		rule.Stats(&stats)
		fmt.Printf("Rule (%d): %s\t%d\t%d\t%d\t%d\t%d\n", i, rule,
			stats.Evaluations,
			stats.PacketIn,
			stats.PacketOut,
			stats.BytesIn,
			stats.BytesOut)
	}
}

// The rule of issue 5: a nat rule that translates to the address of an
// interface and spreads over its addresses.
func ExampleNAT() {
	nat := pf.NAT().On("em0").Inet().RedirectToInterface("em0").RoundRobin()
	// nat on em0 inet from any to any -> (em0) round-robin

	rule, err := nat.Rule()
	if err != nil {
		log.Fatal(err)
	}
	_ = rule
}

// A ruleset loads scrub, nat, rdr, binat and filter rules in one transaction,
// the way pfctl -f does: the rules of the anchor are replaced as a whole.
func ExampleRuleset() {
	pfh, err := pf.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer pfh.Close()

	err = pf.NewRuleset().
		Add(pf.NAT().On("em0").From("10.0.0.0/24").RedirectToInterface("em0")).
		Add(pf.Block().In().Quick().From("<bruteforce>")).
		Add(pf.Pass().Out().On("em0")).
		Add(pf.Pass().In().On("em0").Proto(pf.ProtocolTCP).ToPort("22")).
		Load(pfh, "")
	if err != nil {
		log.Fatal(err)
	}
}

// Errors are collected: nothing is sent unless every rule is valid.
func ExampleRuleBuilder_Rules() {
	_, err := pf.Pass().Proto(pf.ProtocolUDP).Flags("S/SA").From("nonsense").Rules()
	fmt.Println(err != nil)
	// Output: true
}
