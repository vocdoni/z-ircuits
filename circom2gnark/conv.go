package circom2gnark

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
)

// ConvertPublicInputsBLS parses public inputs into BLS12-377 field elements.
func ConvertPublicInputsBLS(publicSignals []string) ([]bls12377fr.Element, error) {
	publicInputs := make([]bls12377fr.Element, len(publicSignals))
	for i, s := range publicSignals {
		bi, err := stringToBigInt(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public input %d: %v", i, err)
		}
		publicInputs[i].SetBigInt(bi)
	}
	return publicInputs, nil
}

// ToGnarkBLS converts a CircomProof into a Gnark-compatible Proof structure over BLS12-377.
func (circomProof *CircomProof) ToGnarkBLS() (*groth16_bls12377.Proof, error) {
	arG1, err := stringToG1BLS(circomProof.PiA)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiA: %v", err)
	}
	krsG1, err := stringToG1BLS(circomProof.PiC)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiC: %v", err)
	}
	bsG2, err := stringToG2BLS(circomProof.PiB)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiB: %v", err)
	}
	return &groth16_bls12377.Proof{
		Ar:  *arG1,
		Krs: *krsG1,
		Bs:  *bsG2,
	}, nil
}

// ToGnarkBLS converts a CircomVerificationKey into a Gnark-compatible verification key over BLS12-377.
func (circomVerificationKey *CircomVerificationKey) ToGnarkBLS() (*groth16_bls12377.VerifyingKey, error) {
	alphaG1, err := stringToG1BLS(circomVerificationKey.VkAlpha1)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkAlpha1: %v", err)
	}
	betaG2, err := stringToG2BLS(circomVerificationKey.VkBeta2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkBeta2: %v", err)
	}
	gammaG2, err := stringToG2BLS(circomVerificationKey.VkGamma2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkGamma2: %v", err)
	}
	deltaG2, err := stringToG2BLS(circomVerificationKey.VkDelta2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkDelta2: %v", err)
	}

	numIC := len(circomVerificationKey.IC)
	G1K := make([]bls12377.G1Affine, numIC)
	for i, icPoint := range circomVerificationKey.IC {
		icG1, err := stringToG1BLS(icPoint)
		if err != nil {
			return nil, fmt.Errorf("failed to convert IC[%d]: %v", i, err)
		}
		G1K[i] = *icG1
	}

	vk := &groth16_bls12377.VerifyingKey{}
	vk.G1.Alpha = *alphaG1
	vk.G1.K = G1K
	vk.G2.Beta = *betaG2
	vk.G2.Gamma = *gammaG2
	vk.G2.Delta = *deltaG2

	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("failed to precompute verification key: %v", err)
	}
	return vk, nil
}

// Verify verifies the Gnark proof using the provided verification key and public inputs over BLS12-377.
func (proof *GnarkProofBLS) Verify() (bool, error) {
	err := groth16_bls12377.Verify(proof.Proof, proof.VerifyingKey, proof.PublicInputs)
	if err != nil {
		return false, fmt.Errorf("proof verification failed: %v", err)
	}
	return true, nil
}
