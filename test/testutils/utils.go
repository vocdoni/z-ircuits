package testutils

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/vocdoni/davinci-node/crypto/elgamal"
	"github.com/vocdoni/poseidon377"
)

// RandomK returns randomness in the BLS12-377 Edwards scalar field (used by circom ElGamal).
func RandomK() (*big.Int, error) {
	return elgamal.RandK()
}

// ToFr converts supported numeric types to an fr.Element.
func ToFr(i interface{}) fr.Element {
	var e fr.Element
	switch v := i.(type) {
	case int:
		e.SetUint64(uint64(v))
	case *big.Int:
		e.SetBigInt(v)
	case fr.Element:
		return v
	default:
		panic("unsupported type for ToFr")
	}
	return e
}

func MiMCHash(inputs ...*big.Int) (*big.Int, error) {
	h := mimc.NewFieldHasher()
	for _, input := range inputs {
		var e fr.Element
		e.SetBigInt(input)
		h.WriteElement(e)
	}
	res := h.SumElement()
	return res.BigInt(new(big.Int)), nil
}

func VoteID(bigPID, bigAddr, k *big.Int) (*big.Int, error) {
	hash, err := MiMCHash(bigPID, bigAddr, k)
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

// DerivePoseidonChain derives n+1 values where out[0]=seed and out[i+1]=Hash(domain,out[i]).
func DerivePoseidonChain(domain fr.Element, seed *big.Int, n int) ([]*big.Int, error) {
	out := make([]*big.Int, n+1)
	out[0] = new(big.Int).Set(seed)
	for i := 0; i < n; i++ {
		h, err := poseidon377.Hash(domain, ToFr(out[i]))
		if err != nil {
			return nil, err
		}
		out[i+1] = new(big.Int)
		h.BigInt(out[i+1])
	}
	return out, nil
}
