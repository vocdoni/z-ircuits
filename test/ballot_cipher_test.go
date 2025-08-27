package test

import (
	"encoding/json"
	"log"
	"math/big"
	"os"
	"testing"

	"github.com/vocdoni/z-ircuits/utils"
)

func TestBallotCipher(t *testing.T) {
	var (
		// circuit assets
		wasmFile = "../artifacts/ballot_cipher_test.wasm"
		zkeyFile = "../artifacts/ballot_cipher_test_pkey.zkey"
		vkeyFile = "../artifacts/ballot_cipher_test_vkey.json"
	)

	// encrypt ballot
	_, pubKey := utils.GenerateKeyPair()
	k, err := utils.RandomK()
	if err != nil {
		t.Errorf("Error generating random k: %v\n", err)
		return
	}
	msg := big.NewInt(3)
	c1, c2 := utils.Encrypt(msg, pubKey, k)
	inputs := map[string]any{
		"encryption_pubkey": []string{pubKey.X.String(), pubKey.Y.String()},
		"k":                 k.String(),
		"msg":               msg.String(),
		"c1":                []string{c1.X.String(), c1.Y.String()},
		"c2":                []string{c2.X.String(), c2.Y.String()},
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
