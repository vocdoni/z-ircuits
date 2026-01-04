package test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"

	"github.com/vocdoni/davinci-circom-circuits/circom2gnark"
	"github.com/vocdoni/davinci-circom-circuits/test/testutils"
)

const (
	numProofs = 5
)

// aggregationCircuit verifies numProofs BLS12-377 Groth16 proofs inside BW6-761.
type aggregationCircuit struct {
	Proofs       [numProofs]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	PublicInputs [numProofs]emulated.Element[sw_bls12377.ScalarField]                                `gnark:",public"`
	VerifyingKey stdgroth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

func (c *aggregationCircuit) Define(api frontend.API) error {
	for i := range numProofs {
		verifier, err := stdgroth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
		if err != nil {
			return err
		}
		witness := stdgroth16.Witness[sw_bls12377.ScalarField]{
			Public: []emulated.Element[sw_bls12377.ScalarField]{c.PublicInputs[i]},
		}
		isValid, err := verifier.IsValidProof(c.VerifyingKey, c.Proofs[i], witness, stdgroth16.WithCompleteArithmetic())
		if err != nil {
			return fmt.Errorf("proof %d: %w", i, err)
		}
		api.AssertIsEqual(isValid, 1)
	}
	return nil
}

func buildBallotInputs() ([]byte, error) {
	vectors, err := testutils.BuildBallotVectors()
	if err != nil {
		return nil, err
	}
	return json.Marshal(vectors.InputsMap())
}

func generateCircomProof(wasmPath, zkeyPath string) (proof string, pubSignals []string, err error) {
	inputBytes, err := buildBallotInputs()
	if err != nil {
		return "", nil, err
	}
	proofJSON, pubJSON, err := testutils.CompileAndGenerateProof(inputBytes, wasmPath, zkeyPath)
	if err != nil {
		return "", nil, err
	}
	pubSignals, err = circom2gnark.UnmarshalCircomPublicSignalsJSON([]byte(pubJSON))
	return proofJSON, pubSignals, err
}

func TestCircomAggregation(t *testing.T) {
	c := qt.New(t)
	err := testutils.EnsureArtifacts(testutils.BallotProofWasm, testutils.BallotProofZkey, testutils.BallotProofVkey, testutils.BallotProofR1CS)
	c.Assert(err, qt.IsNil, qt.Commentf("artifacts check failed"))

	wasmPath, err := testutils.GetArtifactPath(testutils.BallotProofWasm)
	c.Assert(err, qt.IsNil)
	zkeyPath, err := testutils.GetArtifactPath(testutils.BallotProofZkey)
	c.Assert(err, qt.IsNil)
	vkeyPath, err := testutils.GetArtifactPath(testutils.BallotProofVkey)
	c.Assert(err, qt.IsNil)

	vkeyBytes, err := os.ReadFile(vkeyPath)
	c.Assert(err, qt.IsNil, qt.Commentf("read vkey"))

	firstProofJSON, firstPubSignals, err := generateCircomProof(wasmPath, zkeyPath)
	c.Assert(err, qt.IsNil, qt.Commentf("generate proof"))

	ok, err := circom2gnark.VerifyCircomProofBLS(vkeyBytes, firstProofJSON, firstPubSignals)
	c.Assert(err, qt.IsNil)
	c.Assert(ok, qt.IsTrue, qt.Commentf("native verify failed"))
	c.Logf("native verify passed: ok=%v", ok)

	placeholder, err := circom2gnark.Circom2GnarkPlaceholderBLSWithVK(vkeyBytes, len(firstPubSignals), true)
	c.Assert(err, qt.IsNil, qt.Commentf("placeholders"))

	var recProofs [numProofs]*circom2gnark.GnarkRecursionProofBLS
	pubJSONBytes, _ := json.Marshal(firstPubSignals)
	recProofs[0], err = circom2gnark.Circom2GnarkProofForRecursionBLSWithVK(vkeyBytes, firstProofJSON, string(pubJSONBytes), true)
	c.Assert(err, qt.IsNil, qt.Commentf("convert proof 0"))

	for i := 1; i < numProofs; i++ {
		proofJSON, pubSignals, err := generateCircomProof(wasmPath, zkeyPath)
		c.Assert(err, qt.IsNil, qt.Commentf("generate proof %d", i))

		ok, err := circom2gnark.VerifyCircomProofBLS(vkeyBytes, proofJSON, pubSignals)
		c.Assert(err, qt.IsNil)
		c.Assert(ok, qt.IsTrue, qt.Commentf("native verify proof %d failed", i))

		pubJSON, _ := json.Marshal(pubSignals)
		recProofs[i], err = circom2gnark.Circom2GnarkProofForRecursionBLSWithVK(vkeyBytes, proofJSON, string(pubJSON), true)
		c.Assert(err, qt.IsNil, qt.Commentf("convert proof %d", i))
	}

	placeholderCircuit := &aggregationCircuit{VerifyingKey: placeholder.Vk}
	for i := 0; i < numProofs; i++ {
		placeholderCircuit.Proofs[i] = placeholder.Proof
		if len(placeholder.Witness.Public) > 0 {
			placeholderCircuit.PublicInputs[i] = placeholder.Witness.Public[0]
		}
	}

	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, placeholderCircuit)
	c.Assert(err, qt.IsNil, qt.Commentf("compile aggregation circuit"))

	internalVars, secretVars, publicVars := ccs.GetNbVariables()
	c.Logf("aggregation ccs: internal=%d secret=%d public=%d", internalVars, secretVars, publicVars)

	assignment := &aggregationCircuit{VerifyingKey: placeholder.Vk}
	for i := 0; i < numProofs; i++ {
		assignment.Proofs[i] = recProofs[i].Proof
		if len(recProofs[i].PublicInputs.Public) > 0 {
			assignment.PublicInputs[i] = recProofs[i].PublicInputs.Public[0]
		}
	}
	err = test.IsSolved(placeholderCircuit, assignment, ecc.BW6_761.ScalarField())
	c.Assert(err, qt.IsNil, qt.Commentf("assignment not satisfied"))

	pk, vk, err := groth16.Setup(ccs)
	c.Assert(err, qt.IsNil, qt.Commentf("setup aggregation"))

	wit, err := frontend.NewWitness(assignment, ecc.BW6_761.ScalarField())
	c.Assert(err, qt.IsNil, qt.Commentf("create witness"))

	proofAgg, err := groth16.Prove(ccs, pk, wit, stdgroth16.GetNativeProverOptions(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField()))
	c.Assert(err, qt.IsNil, qt.Commentf("prove aggregation"))

	pubWit, err := wit.Public()
	c.Assert(err, qt.IsNil, qt.Commentf("public witness"))

	err = groth16.Verify(proofAgg, vk, pubWit, stdgroth16.GetNativeVerifierOptions(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField()))
	c.Assert(err, qt.IsNil, qt.Commentf("verify aggregation"))

	c.Logf("BW6-761 aggregation circuit constraints for %d proofs: %d", numProofs, ccs.GetNbConstraints())
}
