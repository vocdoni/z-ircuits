package utils

import (
	"crypto/rand"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.vocdoni.io/dvote/util"
)

func GenerateBallotFields(n, max, min int, unique bool) []*big.Int {
	fields := []*big.Int{}
	stored := map[string]bool{}
	for i := 0; i < n; i++ {
		for {
			// generate random field
			field, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
			if err != nil {
				panic(err)
			}
			field.Add(field, big.NewInt(int64(min)))
			// if it should be unique and it's already stored, skip it,
			// otherwise add it to the list of fields and continue
			if !unique || !stored[field.String()] {
				fields = append(fields, field)
				stored[field.String()] = true
				break
			}
		}
	}
	return fields
}

func CipherBallotFields(fields []*big.Int, n int, pk *babyjub.PublicKey, k *big.Int) ([][][]string, []*big.Int) {
	cipherfields := make([][][]string, n)
	plainCipherfields := []*big.Int{}

	lastK, err := mimc7.Hash([]*big.Int{k}, nil)
	if err != nil {
		panic(err)
	}
	for i := range n {
		if i < len(fields) {
			c1, c2 := Encrypt(fields[i], pk, lastK)
			cipherfields[i] = [][]string{
				{c1.X.String(), c1.Y.String()},
				{c2.X.String(), c2.Y.String()},
			}
			plainCipherfields = append(plainCipherfields, c1.X, c1.Y, c2.X, c2.Y)
		} else {
			cipherfields[i] = [][]string{
				{"0", "0"},
				{"0", "0"},
			}
			plainCipherfields = append(plainCipherfields, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0))
		}
		lastK, err = mimc7.Hash([]*big.Int{lastK}, nil)
		if err != nil {
			panic(err)
		}
	}
	return cipherfields, plainCipherfields
}

func MockedCommitmentAndNullifier(address, processID, secret []byte) (*big.Int, *big.Int, error) {
	commitment, err := poseidon.Hash([]*big.Int{
		util.BigToFF(new(big.Int).SetBytes(address)),
		util.BigToFF(new(big.Int).SetBytes(processID)),
		util.BigToFF(new(big.Int).SetBytes(secret)),
	})
	if err != nil {
		return nil, nil, err
	}
	nullifier, err := poseidon.Hash([]*big.Int{
		commitment,
		util.BigToFF(new(big.Int).SetBytes(secret)),
	})
	if err != nil {
		return nil, nil, err
	}
	return commitment, nullifier, nil
}
