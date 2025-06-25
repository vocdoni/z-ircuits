package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.vocdoni.io/dvote/util"
)

func BigIntArrayToN(arr []*big.Int, n int) []*big.Int {
	bigArr := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		if i < len(arr) {
			bigArr[i] = arr[i]
		} else {
			bigArr[i] = big.NewInt(0)
		}
	}
	return bigArr
}

func BigIntArrayToStringArray(arr []*big.Int, n int) []string {
	strArr := []string{}
	for _, b := range BigIntArrayToN(arr, n) {
		strArr = append(strArr, b.String())
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

func MultiPoseidon(inputs ...*big.Int) (*big.Int, error) {
	if len(inputs) > 256 {
		return nil, fmt.Errorf("too many inputs")
	} else if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs provided")
	}
	// calculate chunk hashes
	hashes := []*big.Int{}
	chunk := []*big.Int{}
	for _, input := range inputs {
		if len(chunk) == 16 {
			hash, err := poseidon.Hash(chunk)
			if err != nil {
				return nil, err
			}
			hashes = append(hashes, hash)
			chunk = []*big.Int{}
		}
		chunk = append(chunk, input)
	}
	// if the final chunk is not empty, hash it to get the last chunk hash
	if len(chunk) > 0 {
		hash, err := poseidon.Hash(chunk)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	// if there is only one chunk hash, return it
	if len(hashes) == 1 {
		return hashes[0], nil
	}
	// return the hash of all chunk hashes
	return poseidon.Hash(hashes)
}

func VoteID(bigPID, bigAddr, k *big.Int) (*big.Int, error) {
	hash, err := mimc7.Hash([]*big.Int{
		util.BigToFF(bigPID),
		util.BigToFF(bigAddr),
		util.BigToFF(k),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vote ID: %v", err)
	}
	return TruncateTo160Bits(hash), nil
}

func TruncateTo160Bits(input *big.Int) *big.Int {
	mask := new(big.Int).Lsh(big.NewInt(1), 160) // 1 << 160
	mask.Sub(mask, big.NewInt(1))                // (1 << 160) - 1
	return new(big.Int).And(input, mask)         // input & ((1<<160)-1)
}
