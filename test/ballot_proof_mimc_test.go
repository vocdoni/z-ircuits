package test

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"testing"

	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/vocdoni/z-ircuits/utils"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/util"
)

func TestBallotProofMiMC(t *testing.T) {
	if persist && testID == "" {
		t.Error("Test ID is required when persisting")
		return
	}

	acc := ethereum.NewSignKeys()
	if err := acc.Generate(); err != nil {
		t.Error(err)
		return
	}
	var (
		// ballot inputs
		fields = []*big.Int{
			big.NewInt(3),
			big.NewInt(5),
			big.NewInt(2),
			big.NewInt(4),
			big.NewInt(1),
		}
		n_fields        = 8
		maxCount        = 5
		forceUniqueness = 1
		maxValue        = 16 + 1
		minValue        = 0
		costExp         = 2
		costFromWeight  = 0
		weight          = 0
		// nullifier inputs
		address   = acc.Address().Bytes()
		processID = util.RandomBytes(20)
		secret    = util.RandomBytes(16)
		// circuit assets
		wasmFile = "../artifacts/ballot_proof_mimc_test.wasm"
		zkeyFile = "../artifacts/ballot_proof_mimc_test_pkey.zkey"
		vkeyFile = "../artifacts/ballot_proof_mimc_test_vkey.json"
	)
	// encrypt ballot
	_, pubKey := utils.GenerateKeyPair()
	k, err := utils.RandomK()
	if err != nil {
		t.Errorf("Error generating random k: %v\n", err)
		return
	}
	cipherfields := make([][][]string, n_fields)
	plainCipherfields := []*big.Int{}
	for i := 0; i < n_fields; i++ {
		if i < len(fields) {
			c1, c2 := utils.Encrypt(fields[i], pubKey, k)
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
	}
	// generate the nullifier
	commitment, err := poseidon.Hash([]*big.Int{
		util.BigToFF(new(big.Int).SetBytes(address)),
		util.BigToFF(new(big.Int).SetBytes(processID)),
		util.BigToFF(new(big.Int).SetBytes(secret)),
	})
	if err != nil {
		log.Fatalf("Error hashing: %v\n", err)
		return
	}
	nullifier, err := poseidon.Hash([]*big.Int{
		commitment,
		util.BigToFF(new(big.Int).SetBytes(secret)),
	})
	if err != nil {
		log.Fatalf("Error hashing: %v\n", err)
		return
	}
	bigInputs := []*big.Int{
		big.NewInt(int64(maxCount)),
		big.NewInt(int64(forceUniqueness)),
		big.NewInt(int64(maxValue)),
		big.NewInt(int64(minValue)),
		big.NewInt(int64(math.Pow(float64(maxValue-1), float64(costExp))) * int64(maxCount)),
		big.NewInt(int64(maxCount)),
		big.NewInt(int64(costExp)),
		big.NewInt(int64(costFromWeight)),
		big.NewInt(int64(weight)),
		pubKey.X,
		pubKey.Y,
		k,
		nullifier,
		commitment,
		util.BigToFF(new(big.Int).SetBytes(secret)),
	}
	bigInputs = append(bigInputs, utils.BigIntArrayToN(fields, n_fields)...)
	bigInputs = append(bigInputs, plainCipherfields...)
	inputsHash, err := mimc7.Hash(bigInputs, nil)
	if err != nil {
		log.Fatalf("Error hashing: %v\n", err)
		return
	}

	// circuit inputs
	inputs := map[string]any{
		"fields":           utils.BigIntArrayToStringArray(fields, n_fields),
		"max_count":        fmt.Sprint(maxCount),
		"force_uniqueness": fmt.Sprint(forceUniqueness),
		"max_value":        fmt.Sprint(maxValue),
		"min_value":        fmt.Sprint(minValue),
		"max_total_cost":   fmt.Sprint(int(math.Pow(float64(maxValue-1), float64(costExp))) * maxCount), // (maxValue-1)^costExp * maxCount
		"min_total_cost":   fmt.Sprint(maxCount),
		"cost_exp":         fmt.Sprint(costExp),
		"cost_from_weight": fmt.Sprint(costFromWeight),
		"weight":           fmt.Sprint(weight),
		"pk":               []string{pubKey.X.String(), pubKey.Y.String()},
		"k":                k.String(),
		"cipherfields":     cipherfields,
		"nullifier":        nullifier.String(),
		"commitment":       commitment.String(),
		"secret":           util.BigToFF(new(big.Int).SetBytes(secret)).String(),
		"inputs_hash":      inputsHash.String(),
	}
	bInputs, _ := json.MarshalIndent(inputs, "  ", "  ")
	t.Log("Inputs:", string(bInputs))
	proofData, pubSignals, err := utils.CompileAndGenerateProof(bInputs, wasmFile, zkeyFile)
	if err != nil {
		t.Errorf("Error compiling and generating proof: %v\n", err)
		return
	}
	t.Log("Proof:", proofData)
	t.Log("Public signals:", pubSignals)
	// read zkey file
	vkey, err := os.ReadFile(vkeyFile)
	if err != nil {
		t.Errorf("Error reading zkey file: %v\n", err)
		return
	}
	if err := utils.VerifyProof(proofData, pubSignals, vkey); err != nil {
		t.Errorf("Error verifying proof: %v\n", err)
		return
	}
	log.Println("Proof verified")
	if persist {
		if err := os.WriteFile(fmt.Sprintf("./%s_proof.json", testID), []byte(proofData), 0644); err != nil {
			t.Errorf("Error writing proof file: %v\n", err)
			return
		}
		if err := os.WriteFile(fmt.Sprintf("./%s_pub_signals.json", testID), []byte(pubSignals), 0644); err != nil {
			t.Errorf("Error writing public signals file: %v\n", err)
			return
		}
	}
}
