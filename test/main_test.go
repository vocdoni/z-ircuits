package test

import (
	"flag"
	"testing"
)

var (
	testID  string
	persist bool
)

func TestMain(m *testing.M) {
	flag.StringVar(&testID, "testID", "", "Test ID")
	flag.BoolVar(&persist, "persist", false, "Persist the test data")
	flag.Parse()

	m.Run()
}
