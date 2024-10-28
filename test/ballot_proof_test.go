package test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/vocdoni/z-ircuits/utils"
	"go.vocdoni.io/dvote/util"
)

func TestBallotProof(t *testing.T) {
	var (
		fields = []*big.Int{
			big.NewInt(3),
			big.NewInt(5),
			big.NewInt(2),
			big.NewInt(4),
			big.NewInt(1),
		}
		n_fields     = 16
		maxCount     = 5
		maxValue     = 16 + 1
		minValue     = 0
		costExp      = 2
		address, _   = hex.DecodeString("0x6Db989fbe7b1308cc59A27f021e2E3de9422CF0A")
		processID, _ = hex.DecodeString("0xf16236a51F11c0Bf97180eB16694e3A345E42506")
		secret, _    = hex.DecodeString("super-secret-mnemonic-phrase")
		// circuit assets
		wasmFile = "../circuits/artifacts/ballot_proof_test.wasm"
		zkeyFile = "../circuits/artifacts/ballot_proof_test_pkey.zkey"
		vkeyFile = "../circuits/artifacts/ballot_proof_test_vkey.json"
	)
	// encrypt ballot
	_, pubKey := utils.GenerateKeyPair()
	k, err := utils.RandomK()
	if err != nil {
		t.Errorf("Error generating random k: %v\n", err)
		return
	}
	cipherfields := make([][][]string, n_fields)
	for i := 0; i < n_fields; i++ {
		if i < len(fields) {
			c1, c2 := utils.Encrypt(fields[i], pubKey, k)
			cipherfields[i] = [][]string{
				{c1.X.String(), c1.Y.String()},
				{c2.X.String(), c2.Y.String()},
			}
		} else {
			cipherfields[i] = [][]string{
				{"0", "0"},
				{"0", "0"},
			}
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
	// circuit inputs
	inputs := map[string]any{
		"fields":           utils.BigIntArrayToStringArray(fields, n_fields),
		"max_count":        fmt.Sprint(maxCount),
		"force_uniqueness": "0",
		"max_value":        fmt.Sprint(maxValue),
		"min_value":        fmt.Sprint(minValue),
		"cost_exp":         fmt.Sprint(costExp),
		"max_total_cost":   fmt.Sprint(int(math.Pow(float64(maxValue-1), float64(costExp))) * maxCount), // (maxValue-1)^costExp * maxCount
		"min_total_cost":   fmt.Sprint(maxCount),
		"cost_from_weight": "0",
		"weight":           "1",
		"pk":               []string{pubKey.X.String(), pubKey.Y.String()},
		"k":                k.String(),
		"cipherfields":     cipherfields,
		"nullifier":        nullifier.String(),
		"commitment":       commitment.String(),
		"secret":           util.BigToFF(new(big.Int).SetBytes(secret)).String(),
	}
	bInputs, _ := json.MarshalIndent(inputs, "  ", "  ")
	t.Log("Inputs:", string(bInputs))
	proofData, pubSignals, err := utils.CompileAndGenerateProof(bInputs, wasmFile, zkeyFile)
	if err != nil {
		t.Errorf("Error compiling and generating proof: %v\n", err)
		return
	}
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
}
