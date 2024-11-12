package test

import (
	"crypto/rand"
	"flag"
	"math/big"
	"testing"
)

var (
	testID  string
	persist bool
	path    string
)

func TestMain(m *testing.M) {
	flag.StringVar(&testID, "testID", "", "Test ID")
	flag.BoolVar(&persist, "persist", false, "Persist the test data")
	flag.StringVar(&path, "path", "./testdata", "Path to store the test data")
	flag.Parse()

	m.Run()
}

func ballotFieldsGenerator(n, min, max int) []*big.Int {
	var fields []*big.Int
	for i := 0; i < n; i++ {
		randValue, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
		if err != nil {
			panic(err)
		}
		fields = append(fields, randValue.Add(randValue, big.NewInt(int64(min))))
	}
	return fields
}
