package test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
	leanimt "github.com/vocdoni/lean-imt-go"
	"github.com/vocdoni/z-ircuits/utils"
)

const (
	imtDepth       = 27
	censusWasmFile = "../artifacts/census_proof_test.wasm"
	censusZkeyFile = "../artifacts/census_proof_test_pkey.zkey"
	censusVkeyFile = "../artifacts/census_proof_test_vkey.json"
)

func TestCensusProofWithLeanIMT(t *testing.T) {
	c := qt.New(t)
	// Create a Lean IMT tree with some test data
	tree, err := leanimt.New(leanimt.PoseidonHasher, leanimt.BigIntEqual, nil, nil, nil)
	c.Assert(err, qt.IsNil)

	// Generate random ethereum-like address (20 bytes)
	testAddr := randomBytes(20)
	c.Assert(testAddr, qt.IsNotNil)

	numEntries := 1000
	entries := []*big.Int{testAddr}
	for range numEntries {
		addr := randomBytes(20)
		c.Assert(addr, qt.IsNotNil)
		entries = append(entries, addr)
	}
	// Insert entries into the tree
	err = tree.InsertMany(entries)
	c.Assert(err, qt.IsNil)

	// Get the proof for the test address
	testAddrIndex := tree.IndexOf(testAddr)
	proof, err := tree.GenerateProof(testAddrIndex)
	c.Assert(err, qt.IsNil)

	circomInputs := map[string]any{
		"root":     proof.Root.String(),
		"index":    fmt.Sprint(testAddrIndex),
		"leaf":     proof.Leaf.String(),
		"siblings": utils.BigIntArrayToStringArray(proof.Siblings, imtDepth),
	}
	bInputs, err := json.MarshalIndent(circomInputs, "  ", "  ")
	c.Assert(err, qt.IsNil)

	proofData, pubSignals, err := utils.CompileAndGenerateProof(bInputs, censusWasmFile, censusZkeyFile)
	c.Assert(err, qt.IsNil)

	// Load verification key
	vkeyBytes, err := os.ReadFile(censusVkeyFile)
	c.Assert(err, qt.IsNil)

	// Verify proof
	err = utils.VerifyProof(proofData, pubSignals, vkeyBytes)
	c.Assert(err, qt.IsNil)
}

func randomBytes(n int) *big.Int {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil
	}
	return new(big.Int).SetBytes(b)
}
