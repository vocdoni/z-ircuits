package testutils

import (
	"crypto/rand"
	"encoding/json"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/vocdoni/davinci-node/crypto/ecc/bls12377te"
	"github.com/vocdoni/davinci-node/crypto/ecc/curves"
	"github.com/vocdoni/poseidon377"
)

// BallotVectors holds a reproducible set of inputs for the ballot circuits.
type BallotVectors struct {
	Fields         []int
	Weight         int
	PubKeyX        *big.Int
	PubKeyY        *big.Int
	Cipherfields   [][2][2]*big.Int
	ProcessID      *big.Int
	Address        *big.Int
	K              *big.Int
	VoteID         *big.Int
	InputsHash     fr.Element
	NumFields      int
	UniqueValues   int
	MaxValue       int
	MinValue       int
	MaxValueSum    int
	MinValueSum    int
	CostExponent   int
	CostFromWeight int
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// BuildBallotVectors creates fresh valid inputs matching the circom ballot circuits.
func BuildBallotVectors() (*BallotVectors, error) {
	nFields := 8
	maxValue := 16
	maxValueSum := 1125
	minValue := 0
	minValueSum := 5
	uniqueValues := 1
	costExponent := 2
	costFromWeight := 0
	numFields := 5

	fields := make([]int, nFields)
	for i := 0; i < numFields; i++ {
		fields[i] = i + 1
	}
	weight := 1

	_, pub := GenerateKeyPair()
	pubX, pubY := AffineCoords(pub)

	k, err := RandomK()
	if err != nil {
		return nil, err
	}

	var domain fr.Element
	ks, err := DerivePoseidonChain(domain, k, nFields)
	if err != nil {
		return nil, err
	}

	cipherfields := make([][2][2]*big.Int, nFields)
	for i := 0; i < nFields; i++ {
		c1, c2 := Encrypt(big.NewInt(int64(fields[i])), pub, ks[i+1])
		cipherfields[i] = [2][2]*big.Int{
			{new(big.Int).Set(&c1[0]), new(big.Int).Set(&c1[1])},
			{new(big.Int).Set(&c2[0]), new(big.Int).Set(&c2[1])},
		}
	}

	processID := new(big.Int).SetBytes(randomBytes(20))
	address := new(big.Int).SetBytes(randomBytes(20))

	voteIDRes, err := poseidon377.Hash(domain, ToFr(processID), ToFr(address), ToFr(k))
	if err != nil {
		return nil, err
	}
	voteID := TruncateTo160Bits(voteIDRes.BigInt(new(big.Int)))

	var inputsList []fr.Element
	for i := 0; i < nFields; i++ {
		inputsList = append(inputsList, ToFr(fields[i]))
	}
	inputsList = append(inputsList, ToFr(weight))
	inputsList = append(inputsList, ToFr(pubX))
	inputsList = append(inputsList, ToFr(pubY))
	for i := 0; i < nFields; i++ {
		inputsList = append(inputsList, ToFr(cipherfields[i][0][0]))
		inputsList = append(inputsList, ToFr(cipherfields[i][0][1]))
		inputsList = append(inputsList, ToFr(cipherfields[i][1][0]))
		inputsList = append(inputsList, ToFr(cipherfields[i][1][1]))
	}
	inputsList = append(inputsList, ToFr(processID))
	inputsList = append(inputsList, ToFr(address))
	inputsList = append(inputsList, ToFr(k))
	inputsList = append(inputsList, ToFr(voteID))
	inputsList = append(inputsList, ToFr(numFields))
	inputsList = append(inputsList, ToFr(uniqueValues))
	inputsList = append(inputsList, ToFr(maxValue))
	inputsList = append(inputsList, ToFr(minValue))
	inputsList = append(inputsList, ToFr(maxValueSum))
	inputsList = append(inputsList, ToFr(minValueSum))
	inputsList = append(inputsList, ToFr(costExponent))
	inputsList = append(inputsList, ToFr(costFromWeight))

	inputsHash, err := poseidon377.MultiHash(domain, inputsList...)
	if err != nil {
		return nil, err
	}

	return &BallotVectors{
		Fields:         fields,
		Weight:         weight,
		PubKeyX:        pubX,
		PubKeyY:        pubY,
		Cipherfields:   cipherfields,
		ProcessID:      processID,
		Address:        address,
		K:              k,
		VoteID:         voteID,
		InputsHash:     inputsHash,
		NumFields:      numFields,
		UniqueValues:   uniqueValues,
		MaxValue:       maxValue,
		MinValue:       minValue,
		MaxValueSum:    maxValueSum,
		MinValueSum:    minValueSum,
		CostExponent:   costExponent,
		CostFromWeight: costFromWeight,
	}, nil
}

// InputsMap returns the JSON-friendly map expected by snarkjs/ballot circuits.
func (b *BallotVectors) InputsMap() map[string]any {
	return map[string]any{
		"fields":            b.Fields,
		"weight":            b.Weight,
		"encryption_pubkey": []string{b.PubKeyX.String(), b.PubKeyY.String()},
		"cipherfields":      StringifyCipherfields(b.Cipherfields),
		"process_id":        b.ProcessID.String(),
		"address":           b.Address.String(),
		"k":                 b.K.String(),
		"vote_id":           b.VoteID.String(),
		"inputs_hash":       b.InputsHash.String(),
		"num_fields":        b.NumFields,
		"unique_values":     b.UniqueValues,
		"max_value":         b.MaxValue,
		"min_value":         b.MinValue,
		"max_value_sum":     b.MaxValueSum,
		"min_value_sum":     b.MinValueSum,
		"cost_exponent":     b.CostExponent,
		"cost_from_weight":  b.CostFromWeight,
	}
}

// MarshalInputs returns the circom input JSON bytes.
func (b *BallotVectors) MarshalInputs() ([]byte, error) {
	return json.Marshal(b.InputsMap())
}

// StringifyCipherfields converts big.Int cipherfields to strings for circom input.
func StringifyCipherfields(cf [][2][2]*big.Int) [][2][2]string {
	out := make([][2][2]string, len(cf))
	for i := range cf {
		for j := 0; j < 2; j++ {
			for k := 0; k < 2; k++ {
				out[i][j][k] = cf[i][j][k].String()
			}
		}
	}
	return out
}

// NewBLS12377Curve returns a fresh BLS12-377 Edwards point implementation.
func NewBLS12377Curve() *bls12377te.Point {
	return curves.New(bls12377te.CurveType).(*bls12377te.Point)
}
