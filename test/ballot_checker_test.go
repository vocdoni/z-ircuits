package test

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/vocdoni/z-ircuits/utils"
)

func TestBallotChecker(t *testing.T) {
	// circuit files
	var (
		wasmFile = "../artifacts/ballot_checker_test.wasm"
		zkeyFile = "../artifacts/ballot_checker_test_pkey.zkey"
		vkeyFile = "../artifacts/ballot_checker_test_vkey.json"
	)
	// init inputs
	inputs := map[string]any{
		"fields":           []string{"1", "2", "3", "0", "0"}, // total_cost = 1^2 + 2^2 + 3^2 = 14
		"max_count":        "3",                               // number of valid values in fields
		"force_uniqueness": "1",                               // no boolean type in circom
		"max_value":        "4",
		"min_value":        "0",
		"max_total_cost":   "15",
		"min_total_cost":   "13",
		"cost_exp":         "2",
		"weight":           "0",
		"cost_from_weight": "0",
	}
	// compile and generate proof
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
