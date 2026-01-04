package circom2gnark

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
	recursion "github.com/consensys/gnark/std/recursion/groth16"

	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

// ToGnarkRecursionBLS converts a Circom proof (BLS12-377) to the Gnark recursion proof format.
func (circomProof *CircomProof) ToGnarkRecursionBLS(circomVk *CircomVerificationKey,
	circomPublicSignals []string, fixedVk bool,
) (*GnarkRecursionProofBLS, error) {
	publicInputs, err := ConvertPublicInputsBLS(circomPublicSignals)
	if err != nil {
		return nil, err
	}
	gnarkProof, err := circomProof.ToGnarkBLS()
	if err != nil {
		return nil, err
	}
	recursionProof, err := recursion.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](gnarkProof)
	if err != nil {
		return nil, fmt.Errorf("failed to convert proof to recursion proof: %w", err)
	}

	gnarkVk, err := circomVk.ToGnarkBLS()
	if err != nil {
		return nil, err
	}
	publicInputElementsEmulated := make([]emulated.Element[sw_bls12377.ScalarField], len(publicInputs))
	for i, input := range publicInputs {
		bigIntValue := input.BigInt(new(big.Int))
		publicInputElementsEmulated[i] = emulated.ValueOf[sw_bls12377.ScalarField](bigIntValue)
	}
	assignments := &GnarkRecursionProofBLS{
		Proof: recursionProof,
		PublicInputs: recursion.Witness[sw_bls12377.ScalarField]{
			Public: publicInputElementsEmulated,
		},
	}
	if !fixedVk {
		recursionVk, err := recursion.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](gnarkVk)
		if err != nil {
			return nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
		}
		assignments.Vk = recursionVk
	}
	return assignments, nil
}

// PlaceholdersForRecursionBLS creates placeholders for BLS12-377 recursion circuits.
func PlaceholdersForRecursionBLS(circomVk *CircomVerificationKey,
	nPublicInputs int, fixedVk bool,
) (*GnarkRecursionPlaceholdersBLS, error) {
	gnarkVk, err := circomVk.ToGnarkBLS()
	if err != nil {
		return nil, err
	}
	return createPlaceholdersForRecursionBLS(gnarkVk, nPublicInputs, fixedVk)
}

func createPlaceholdersForRecursionBLS(gnarkVk *groth16_bls12377.VerifyingKey,
	nPublicInputs int, fixedVk bool,
) (*GnarkRecursionPlaceholdersBLS, error) {
	if gnarkVk == nil || nPublicInputs < 0 {
		return nil, fmt.Errorf("invalid inputs to create placeholders for recursion")
	}
	placeholderVk, err := recursion.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](gnarkVk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert verification key to recursion verification key: %w", err)
	}
	placeholderWitness := recursion.Witness[sw_bls12377.ScalarField]{
		Public: make([]emulated.Element[sw_bls12377.ScalarField], nPublicInputs),
	}
	placeholderProof := recursion.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{}

	placeholders := &GnarkRecursionPlaceholdersBLS{
		Vk:      placeholderVk,
		Witness: placeholderWitness,
		Proof:   placeholderProof,
	}
	if !fixedVk {
		placeholders.Vk.G1.K = make([]sw_bls12377.G1Affine, len(placeholders.Vk.G1.K))
	}
	return placeholders, nil
}

// ToGnarkProofBLS converts to non-recursive Gnark proof over BLS12-377.
func (circomProof *CircomProof) ToGnarkProofBLS(circomVk *CircomVerificationKey,
	circomPublicSignals []string,
) (*GnarkProofBLS, error) {
	publicInputs, err := ConvertPublicInputsBLS(circomPublicSignals)
	if err != nil {
		return nil, err
	}
	proof, err := circomProof.ToGnarkBLS()
	if err != nil {
		return nil, err
	}
	vk, err := circomVk.ToGnarkBLS()
	if err != nil {
		return nil, err
	}
	return &GnarkProofBLS{
		Proof:        proof,
		VerifyingKey: vk,
		PublicInputs: publicInputs,
	}, nil
}

// ToGnarkRecursionProofBLS is a helper to convert to recursion proof with fixed vk.
func (circomProof *CircomProof) ToGnarkRecursionProofBLS(circomVk *CircomVerificationKey,
	circomPublicSignals []string,
) (*GnarkRecursionProofBLS, error) {
	return circomProof.ToGnarkRecursionBLS(circomVk, circomPublicSignals, true)
}
