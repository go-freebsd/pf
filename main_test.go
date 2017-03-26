package pf

import (
	"flag"
	"log"
	"os"
	"testing"

	"github.com/go-freebsd/kld"
)

var pfh *Handle

func TestMain(m *testing.M) {
	var err error

	// Load kernel module if not already loaded
	if ok, _ := kld.Loaded("pf"); !ok {
		err := kld.Load("pf")
		if err != nil {
			log.Fatalf("Unable to load pf kernel module", err)
		}
	}

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
