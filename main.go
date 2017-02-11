package main

import (
	"fmt"
	"log"
	"time"
)

func main() {
	pf, err := Open()
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Printf("Status interface: %s\n", pf.SetStatusInterface("pflog0"))

	for {
		ClearScreen()
		fmt.Printf("Rules as of %s\n", time.Now())

		rules, err := pf.GetRules()
		if err != nil {
			log.Fatalf("GetRules: %s\n", err)
		}
		for i, rule := range rules {
			fmt.Printf("Rule (%d): %s\t%d\t%d\t%d\t%d\t%d\n", i, rule,
				uint64(rule.wrap.rule.evaluations),
				uint64(rule.wrap.rule.packets[0]),
				uint64(rule.wrap.rule.packets[1]),
				uint64(rule.wrap.rule.bytes[0]),
				uint64(rule.wrap.rule.bytes[1]))
		}
		time.Sleep(time.Millisecond * 500)
	}
}

func ClearScreen() {
	// tput clear | xxd -i
	fmt.Printf("%s", string([]byte{0x1b, 0x5b, 0x48, 0x1b, 0x5b, 0x32, 0x4a}))
}
