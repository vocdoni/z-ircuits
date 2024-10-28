package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

func BigIntArrayToStringArray(arr []*big.Int, n int) []string {
	strArr := make([]string, n)
	for i := 0; i < n; i++ {
		if i < len(arr) {
			strArr[i] = arr[i].String()
		} else {
			strArr[i] = "0"
		}
	}
	return strArr
}

func RandomK() (*big.Int, error) {
	// Generate random scalar k
	kBytes := make([]byte, 32)
	_, err := rand.Read(kBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random k: %v", err)
	}

	k := new(big.Int).SetBytes(kBytes)
	k.Mod(k, babyjub.SubOrder)
	return k, nil
}
