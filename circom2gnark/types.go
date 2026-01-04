package circom2gnark

import (
	bls12377fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	recursion "github.com/consensys/gnark/std/recursion/groth16"
)

// CircomProof represents the proof structure output by SnarkJS.
type CircomProof struct {
	PiA      []string   `json:"pi_a"`
	PiB      [][]string `json:"pi_b"`
	PiC      []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

// CircomVerificationKey represents the verification key structure output by SnarkJS.
type CircomVerificationKey struct {
	Protocol      string       `json:"protocol"`
	Curve         string       `json:"curve"`
	NPublic       int          `json:"nPublic"`
	VkAlpha1      []string     `json:"vk_alpha_1"`
	VkBeta2       [][]string   `json:"vk_beta_2"`
	VkGamma2      [][]string   `json:"vk_gamma_2"`
	VkDelta2      [][]string   `json:"vk_delta_2"`
	IC            [][]string   `json:"IC"`
	VkAlphabeta12 [][][]string `json:"vk_alphabeta_12"` // Not used in verification
}

// GnarkRecursionPlaceholdersBLS holds placeholders for recursion over BLS12-377.
type GnarkRecursionPlaceholdersBLS struct {
	Vk      recursion.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
	Witness recursion.Witness[sw_bls12377.ScalarField]
	Proof   recursion.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
}

// GnarkRecursionProofBLS carries a BLS12-377 proof formatted for recursion.
type GnarkRecursionProofBLS struct {
	Proof        recursion.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	Vk           recursion.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
	PublicInputs recursion.Witness[sw_bls12377.ScalarField]
}

// GnarkProofBLS is a non-recursive proof over BLS12-377.
type GnarkProofBLS struct {
	Proof        *groth16_bls12377.Proof
	VerifyingKey *groth16_bls12377.VerifyingKey
	PublicInputs []bls12377fr.Element
}
