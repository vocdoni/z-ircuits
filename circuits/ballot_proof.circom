pragma circom 2.1.0;

include "poseidon.circom";
include "./ballot_checker.circom";
include "./ballot_cipher.circom";

// BallotProof is the circuit to prove a valid vote in the Vocdoni scheme. The 
// vote is valid if it meets the Ballot Protocol requirements, but also if the
// encrypted vote provided matches with the raw vote encrypted in this circuit.
// The circuit checks the the vote over the params provided using the 
// BallotProtocol template, encodes the vote using the BallotEncoder template
// and compares the result with the encrypted vote.
template BallotProof(n_fields) {
    // Ballot inputs
    signal input fields[n_fields];  // private
    signal input max_count;         // public
    signal input force_uniqueness;  // public
    signal input max_value;         // public
    signal input min_value;         // public
    signal input max_total_cost;    // public
    signal input min_total_cost;    // public
    signal input cost_exp;          // public
    signal input cost_from_weight;  // public
    signal input weight;            // public
    // ElGamal inputs
    signal input pk[2];                         // public
    signal input k;                             // private
    signal input cipherfields[n_fields][2][2];  // public
    // Nullifier inputs
    signal input nullifier;  // public
    signal input commitment; // private
    signal input secret;     // private
    // 1. Check the vote meets the ballot requirements
    component ballotProtocol = BallotChecker(n_fields);
    ballotProtocol.fields <== fields;
    ballotProtocol.max_count <== max_count;
    ballotProtocol.force_uniqueness <== force_uniqueness;
    ballotProtocol.max_value <== max_value;
    ballotProtocol.min_value <== min_value;
    ballotProtocol.max_total_cost <== max_total_cost;
    ballotProtocol.min_total_cost <== min_total_cost;
    ballotProtocol.cost_exp <== cost_exp;
    ballotProtocol.cost_from_weight <== cost_from_weight;
    ballotProtocol.weight <== weight;
    // 2.  Check the encrypted vote
    component ballotCipher = BallotCipher(n_fields);
    ballotCipher.pk <== pk;
    ballotCipher.k <== k;
    ballotCipher.fields <== fields;
    ballotCipher.mask <== ballotProtocol.mask;
    ballotCipher.cipherfields <== cipherfields;
    ballotCipher.valid_fields === max_count;
    // 3. Check the nullifier
    component hash = Poseidon(2);
    hash.inputs[0] <== commitment;
    hash.inputs[1] <== secret;
    hash.out === nullifier;
}