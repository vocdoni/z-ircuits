package circom2gnark

import (
	"encoding/json"
	"fmt"
)

// stringMustJSON marshals a string slice into JSON string (panic on error).
func stringMustJSON(s []string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// UnmarshalCircomProofJSON unmarshals a Circom proof JSON string.
func UnmarshalCircomProofJSON(rawProof []byte) (*CircomProof, error) {
	var proof CircomProof
	if err := json.Unmarshal(rawProof, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

// UnmarshalCircomPublicSignalsJSON unmarshals a Circom public signals JSON string.
func UnmarshalCircomPublicSignalsJSON(rawPubSignals []byte) ([]string, error) {
	var pubSignals []string
	if err := json.Unmarshal(rawPubSignals, &pubSignals); err != nil {
		return nil, err
	}
	return pubSignals, nil
}

// UnmarshalCircomVerificationKeyJSON unmarshals a Circom verification key JSON string.
func UnmarshalCircomVerificationKeyJSON(rawVerificationKey []byte) (*CircomVerificationKey, error) {
	var verificationKey CircomVerificationKey
	if err := json.Unmarshal(rawVerificationKey, &verificationKey); err != nil {
		return nil, err
	}
	return &verificationKey, nil
}

// UnmarshalCircom returns circom proof and pub signals.
func UnmarshalCircom(rawCircomProof, rawPubSignals string) (*CircomProof, []string, error) {
	circomProof, err := UnmarshalCircomProofJSON([]byte(rawCircomProof))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal circom proof: %v", err)
	}
	circomPubSignals, err := UnmarshalCircomPublicSignalsJSON([]byte(rawPubSignals))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal circom public signals: %v", err)
	}

	return circomProof, circomPubSignals, nil
}
