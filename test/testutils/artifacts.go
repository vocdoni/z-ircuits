package testutils

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	ArtifactsDir = "artifacts"

	// Ballot Proof
	BallotProofWasm = "ballot_proof.wasm"
	BallotProofZkey = "ballot_proof_pkey.zkey"
	BallotProofVkey = "ballot_proof_vkey.json"
	BallotProofR1CS = "ballot_proof.r1cs"

	// Ballot Checker
	BallotCheckerWasm = "ballot_checker_test.wasm"
	BallotCheckerZkey = "ballot_checker_test_pkey.zkey"
	BallotCheckerVkey = "ballot_checker_test_vkey.json"

	// Ballot Cipher
	BallotCipherWasm = "ballot_cipher_test.wasm"
	BallotCipherZkey = "ballot_cipher_test_pkey.zkey"
	BallotCipherVkey = "ballot_cipher_test_vkey.json"
)

// FindRepoRoot attempts to find the repository root by looking for the artifacts directory.
func FindRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := filepath.Clean(cwd)
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, ArtifactsDir)); err == nil {
			return dir, nil
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return "", fmt.Errorf("artifacts directory not found from %s", cwd)
}

// GetArtifactPath returns the absolute path for an artifact.
func GetArtifactPath(filename string) (string, error) {
	root, err := FindRepoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, ArtifactsDir, filename), nil
}

// EnsureArtifacts checks if the specified artifacts exist.
func EnsureArtifacts(filenames ...string) error {
	for _, f := range filenames {
		path, err := GetArtifactPath(f)
		if err != nil {
			return err
		}
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("missing artifact %s (run prepare-circuit.sh first)", path)
		}
	}
	return nil
}
