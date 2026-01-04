#!/bin/bash

# Check if an argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <n_proofs> <path*>\n"
    echo "  - n_proofs: the number of proofs to generate"
    echo "  - path (optional): the path to store the proofs, by default ./test/testdata"
    exit 1
fi

# Set the upper limit based on the argument
n_proofs=$1

# Check if a second argument (path) is provided, and convert to absolute if necessary
if [ -n "$2" ]; then
    if [[ "$2" = /* ]]; then
        abs_path="$2"
    else
        abs_path="$(
            cd "$(dirname "$2")"
            pwd
        )/$(basename "$2")"
    fi
fi

for idx in $(seq 1 "$n_proofs"); do
    echo "Generating $((idx)) of $((n_proofs))..."
    # Construct the command with or without the -path flag
    if [ -n "$abs_path" ]; then
        go test -timeout 30s -run ^TestBallotProofPoseidon$ github.com/vocdoni/davinci-circom-circuits/test -v -count=1 -args -testID=$idx -persist -path="$abs_path" >/dev/null 2>&1
    else
        go test -timeout 30s -run ^TestBallotProofPoseidon$ github.com/vocdoni/davinci-circom-circuits/test -v -count=1 -args -testID=$idx -persist >/dev/null 2>&1
    fi
done

echo "All tests completed."
