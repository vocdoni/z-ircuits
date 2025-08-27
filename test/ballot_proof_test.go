package test

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"testing"

	"github.com/vocdoni/z-ircuits/utils"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/util"
)

func TestBallotProof(t *testing.T) {
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
		numFields       = 5
		maxValue        = 16
		minValue        = 0
		costExp         = 2
		forceUniqueness = 1
		weight          = 1
		costFromWeight  = 0
		// nullifier inputs
		address   = acc.Address().Bytes()
		processID = util.RandomBytes(20)
		// circuit assets
		wasmFile = "../artifacts/ballot_proof_test.wasm"
		zkeyFile = "../artifacts/ballot_proof_test_pkey.zkey"
		vkeyFile = "../artifacts/ballot_proof_test_vkey.json"
	)
	// encrypt ballot
	_, pubKey := utils.GenerateKeyPair()
	k, err := utils.RandomK()
	if err != nil {
		t.Errorf("Error generating random k: %v\n", err)
		return
	}
	cipherfields, _ := utils.CipherBallotFields(fields, n_fields, pubKey, k)
	bigPID := util.BigToFF(new(big.Int).SetBytes(processID))
	bigAddr := util.BigToFF(new(big.Int).SetBytes(address))
	voteID, err := utils.VoteID(bigPID, bigAddr, k)
	if err != nil {
		t.Errorf("Error generating vote ID: %v\n", err)
		return
	}
	// circuit inputs
	inputs := map[string]any{
		"fields":            utils.BigIntArrayToStringArray(fields, n_fields),
		"num_fields":        fmt.Sprint(numFields),
		"unique_values":     fmt.Sprint(forceUniqueness),
		"max_value":         fmt.Sprint(maxValue),
		"min_value":         fmt.Sprint(minValue),
		"cost_exponent":     fmt.Sprint(costExp),
		"max_value_sum":     fmt.Sprint(int(math.Pow(float64(maxValue-1), float64(costExp))) * numFields), // (maxValue-1)^costExp * maxCount
		"min_value_sum":     fmt.Sprint(numFields),
		"cost_from_weight":  fmt.Sprint(costFromWeight),
		"weight":            fmt.Sprint(weight),
		"encryption_pubkey": []string{pubKey.X.String(), pubKey.Y.String()},
		"k":                 k.String(),
		"cipherfields":      cipherfields,
		"address":           bigAddr.String(),
		"process_id":        bigPID.String(),
		"vote_id":           voteID.String(),
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
		if err := os.WriteFile(fmt.Sprintf("./%s_proof.json", testID), []byte(proofData), 0o644); err != nil {
			t.Errorf("Error writing proof file: %v\n", err)
			return
		}
		if err := os.WriteFile(fmt.Sprintf("./%s_pub_signals.json", testID), []byte(pubSignals), 0o644); err != nil {
			t.Errorf("Error writing public signals file: %v\n", err)
			return
		}
	}
}
