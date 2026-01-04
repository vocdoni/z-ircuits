package test

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/davinci-circom-circuits/test/testutils"
)

func TestBallotCipher(t *testing.T) {
	c := qt.New(t)
	// Get artifact paths
	wasmPath, err := testutils.GetArtifactPath(testutils.BallotCipherWasm)
	c.Assert(err, qt.IsNil)
	zkeyPath, err := testutils.GetArtifactPath(testutils.BallotCipherZkey)
	c.Assert(err, qt.IsNil)
	vkeyPath, err := testutils.GetArtifactPath(testutils.BallotCipherVkey)
	c.Assert(err, qt.IsNil)

	// encrypt ballot
	_, pubKey := testutils.GenerateKeyPair()
	pubX, pubY := testutils.AffineCoords(pubKey)
	k, err := testutils.RandomK()
	c.Assert(err, qt.IsNil, qt.Commentf("Error generating random k"))

	// Circuit derives k_i = Poseidon(k_{i-1}) per field; we only have one field.
	domain := testutils.ToFr(0)
	ks, err := testutils.DerivePoseidonChain(domain, k, 1)
	c.Assert(err, qt.IsNil, qt.Commentf("derive ks"))

	msg := big.NewInt(3)
	c1, c2 := testutils.Encrypt(msg, pubKey, ks[1])
	inputs := map[string]any{
		"encryption_pubkey": []string{pubX.String(), pubY.String()},
		"k":                 k.String(),
		"msg":               msg.String(),
		"c1":                []string{c1[0].String(), c1[1].String()},
		"c2":                []string{c2[0].String(), c2[1].String()},
	}
	bInputs, _ := json.MarshalIndent(inputs, "  ", "  ")
	c.Log("Inputs:", string(bInputs))
	proofData, pubSignals, err := testutils.CompileAndGenerateProof(bInputs, wasmPath, zkeyPath)
	c.Assert(err, qt.IsNil, qt.Commentf("Error compiling and generating proof"))

	// read vkey file
	vkey, err := os.ReadFile(vkeyPath)
	c.Assert(err, qt.IsNil, qt.Commentf("Error reading vkey file"))

	err = testutils.VerifyProof(proofData, pubSignals, vkey)
	c.Assert(err, qt.IsNil, qt.Commentf("Error verifying proof"))
	c.Log("Proof verified")
}
