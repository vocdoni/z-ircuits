// circomgnark package provides utilities to convert between Circom and Gnark
// proof formats, allowing for verification of zkSNARK proofs created with
// Circom and SnarkJS to be used within the Gnark framework.
// It includes functions to convert Circom proofs and verification keys to
// Gnark over the BLS12-377 curve, and to verify these proofs using Gnark's
// verification functions. It also provides a way to handle recursive proofs
// and placeholders for recursive circuits.
package circom2gnark

// Circom2GnarkProofForRecursionBLS converts a Circom BLS12-377 proof into a Gnark recursion proof with fixed VK.
func Circom2GnarkProofForRecursionBLS(vkey []byte, rawCircomProof, rawPubSignals string) (*GnarkRecursionProofBLS, error) {
	return Circom2GnarkProofForRecursionBLSWithVK(vkey, rawCircomProof, rawPubSignals, true)
}

// Circom2GnarkProofForRecursionBLSWithVK converts a Circom BLS12-377 proof into a Gnark recursion proof,
// allowing the caller to decide whether the verifying key is fixed in-circuit.
func Circom2GnarkProofForRecursionBLSWithVK(vkey []byte, rawCircomProof, rawPubSignals string, fixedVk bool) (*GnarkRecursionProofBLS, error) {
	circomProof, circomPubSignals, err := UnmarshalCircom(rawCircomProof, rawPubSignals)
	if err != nil {
		return nil, err
	}
	circomVerificationKey, err := UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	return circomProof.ToGnarkRecursionBLS(circomVerificationKey, circomPubSignals, fixedVk)
}

// Circom2GnarkPlaceholderBLS creates placeholders for BLS12-377 recursion circuits with fixed VK.
func Circom2GnarkPlaceholderBLS(vkey []byte, nInputs int) (*GnarkRecursionPlaceholdersBLS, error) {
	return Circom2GnarkPlaceholderBLSWithVK(vkey, nInputs, true)
}

// Circom2GnarkPlaceholderBLSWithVK creates placeholders for BLS12-377 recursion circuits and lets caller choose fixed VK.
func Circom2GnarkPlaceholderBLSWithVK(vkey []byte, nInputs int, fixedVk bool) (*GnarkRecursionPlaceholdersBLS, error) {
	gnarkVKeyData, err := UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	return PlaceholdersForRecursionBLS(gnarkVKeyData, nInputs, fixedVk)
}

// VerifyCircomProofBLS verifies a Circom BLS12-377 proof natively using gnark-crypto.
func VerifyCircomProofBLS(vkey []byte, rawProof string, pubSignals []string) (bool, error) {
	circomProof, circomPubSignals, err := UnmarshalCircom(rawProof, stringMustJSON(pubSignals))
	if err != nil {
		return false, err
	}
	circomVerificationKey, err := UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return false, err
	}
	gnarkProof, err := circomProof.ToGnarkProofBLS(circomVerificationKey, circomPubSignals)
	if err != nil {
		return false, err
	}
	return gnarkProof.Verify()
}
