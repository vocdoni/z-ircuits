package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.vocdoni.io/dvote/util"
)

// State Namespaces

const (
	ConfigMax uint64 = 0x0000000000000010
	BallotMin uint64 = 0x0000000000000011 // = ConfigMax + 1
	VoteIDMin uint64 = 0x8000000000000000 // = 1<<63 = 0b1000...000 (64 bits)
)

func BigIntArrayToN(arr []*big.Int, n int) []*big.Int {
	bigArr := make([]*big.Int, n)
	for i := range n {
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
	hash, err := poseidon.Hash([]*big.Int{
		util.BigToFF(bigPID),
		util.BigToFF(bigAddr),
		util.BigToFF(k),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate vote ID: %v", err)
	}
	return MapHashToVoteID(hash), nil
}

func MapHashToVoteID(hash *big.Int) *big.Int {
	voteIDMin := new(big.Int).SetUint64(VoteIDMin)
	return new(big.Int).Add(voteIDMin, new(big.Int).Mod(hash, voteIDMin))
}
