pragma circom 2.1.0;

include "poseidon.circom";
include "mimc.circom";
include "./ballot_checker.circom";
include "./ballot_cipher.circom";
include "./lib/multiposeidon.circom";

// BallotProof is the circuit to prove a valid vote in the Vocdoni scheme. The 
// vote is valid if it meets the Ballot Protocol requirements, but also if the
// encrypted vote provided matches with the raw vote encrypted in this circuit.
// The circuit checks the the vote over the params provided using the 
// BallotProtocol template, encodes the vote using the BallotEncoder template
// and compares the result with the encrypted vote.
template BallotProof(n_fields) {
    // Ballot inputs
    signal input fields[n_fields];
    signal input max_count;
    signal input force_uniqueness;
    signal input max_value;
    signal input min_value;
    signal input max_total_cost;
    signal input min_total_cost;
    signal input cost_exp;
    signal input cost_from_weight;
    signal input weight;
    // ElGamal inputs
    signal input pk[2];
    signal input k;
    signal input cipherfields[n_fields][2][2];
    // Nullifier inputs
    signal input nullifier;
    signal input commitment;
    signal input secret;
    // Inputs hash
    signal input inputs_hash;
    // 0. Check the hash of the inputs (all privates except the hash)
    //  a. Fixed inputs (including pk)
    //  b. Fields
    //  c. Cipherfields
    var static_inputs = 15; // including 2 of the pk
    var cipherfields_inputs = 4 * n_fields;
    var n_inputs = n_fields + cipherfields_inputs + static_inputs;
    component inputs_hasher = MultiPoseidon(n_inputs);
    inputs_hasher.in[0] <== max_count;
    inputs_hasher.in[1] <== force_uniqueness;
    inputs_hasher.in[2] <== max_value;
    inputs_hasher.in[3] <== min_value;
    inputs_hasher.in[4] <== max_total_cost;
    inputs_hasher.in[5] <== min_total_cost;
    inputs_hasher.in[6] <== cost_exp;
    inputs_hasher.in[7] <== cost_from_weight;
    inputs_hasher.in[8] <== weight;
    inputs_hasher.in[9] <== pk[0];
    inputs_hasher.in[10] <== pk[1];
    inputs_hasher.in[11] <== k;
    inputs_hasher.in[12] <== nullifier;
    inputs_hasher.in[13] <== commitment;
    inputs_hasher.in[14] <== secret;
    for (var i = 0; i < n_fields; i++) {
        inputs_hasher.in[static_inputs + i] <== fields[i];
    }
    var offset = static_inputs + n_fields;
    for (var i = 0; i < n_fields; i++) {
        inputs_hasher.in[offset] <== cipherfields[i][0][0];
        inputs_hasher.in[offset + 1] <== cipherfields[i][0][1];
        inputs_hasher.in[offset + 2] <== cipherfields[i][1][0];
        inputs_hasher.in[offset + 3] <== cipherfields[i][1][1];
        offset += 4;
    }
    inputs_hasher.out === inputs_hash;
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