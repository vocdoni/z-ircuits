pragma circom 2.1.0;

include "poseidon.circom";
include "./ballot_checker.circom";
include "./ballot_cipher.circom";
include "./lib/vote_id.circom";

// BallotProof is the circuit to prove a valid vote in the Vocdoni scheme. The 
// vote is valid if it meets the Ballot Protocol requirements, but also if the
// encrypted vote provided matches with the raw vote encrypted in this circuit.
// The circuit checks the the vote over the params provided using the 
// BallotProtocol template, encodes the vote using the BallotEncoder template
// and compares the result with the encrypted vote.
template BallotProof(n_fields) {
    // Ballot inputs
    signal input fields[n_fields];  // private
    signal input num_fields;        // public
    signal input unique_values;      // public
    signal input max_value;         // public
    signal input min_value;         // public
    signal input max_value_sum;     // public
    signal input min_value_sum;     // public
    signal input cost_exponent;     // public
    signal input cost_from_weight;  // public
    signal input address;           // public
    signal input weight;            // public
    signal input process_id;        // public
    signal input vote_id;           // public
    // ElGamal inputs
    signal input encryption_pubkey[2];          // public
    signal input k;                             // private
    signal input cipherfields[n_fields][2][2];  // public
    // 1. Check the vote meets the ballot requirements
    component ballotProtocol = BallotChecker(n_fields);
    ballotProtocol.fields <== fields;
    ballotProtocol.num_fields <== num_fields;
    ballotProtocol.unique_values <== unique_values;
    ballotProtocol.max_value <== max_value;
    ballotProtocol.min_value <== min_value;
    ballotProtocol.max_value_sum <== max_value_sum;
    ballotProtocol.min_value_sum <== min_value_sum;
    ballotProtocol.cost_exponent <== cost_exponent;
    ballotProtocol.cost_from_weight <== cost_from_weight;
    ballotProtocol.weight <== weight;
    // 2.  Check the encrypted vote
    component ballotCipher = BallotCipher(n_fields);
    ballotCipher.encryption_pubkey <== encryption_pubkey;
    ballotCipher.k <== k;
    ballotCipher.fields <== fields;
    ballotCipher.mask <== ballotProtocol.mask;
    ballotCipher.cipherfields <== cipherfields;
    ballotCipher.valid_fields === num_fields;
    // 3. Check the vote ID
    component voteIDChecker = VoteIDChecker();
    voteIDChecker.process_id <== process_id;
    voteIDChecker.address <== address;
    voteIDChecker.k <== k;
    voteIDChecker.vote_id <== vote_id;

}