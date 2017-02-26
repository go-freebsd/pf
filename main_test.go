package pf

import (
	"flag"
	"log"
	"os"
	"testing"
)

var pfh *Handle

func TestMain(m *testing.M) {
	var err error
	pfh, err = Open()
	if err != nil {
		log.Fatalf("Failed to run tests (are you root?): %s", err)
	}
	flag.Parse()
	code := m.Run()
	err = pfh.Close()
	if err != nil {
		log.Println("Failed to close pf handle!")
	}
	os.Exit(code)
}
