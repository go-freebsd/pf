package pf_test

import (
	"fmt"
	"log"

	"github.com/go-freebsd/pf"
)

func ExampleStats() {
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
