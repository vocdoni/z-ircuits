pragma circom 2.0.0;

include "ballot_checker.circom";
include "ballot_cipher.circom";
include "./lib/bls12377/poseidon377.circom";
include "bitify.circom";

// VoteIDChecker computes the VoteID from process_id, address, and k.
// VoteID = Hash(process_id, address, k) & ((1 << 160) - 1)
template VoteIDChecker() {
    signal input process_id;
    signal input address;
    signal input k;
    signal input vote_id;

    component hasher = Poseidon377Chunk(3);
    hasher.domain <== 0;
    hasher.in[0] <== process_id;
    hasher.in[1] <== address;
    hasher.in[2] <== k;

    // Truncate hash to 160 bits to get VoteID
    component n2b = Num2Bits(254);
    n2b.in <== hasher.out;

    component b2n = Bits2Num(160);
    for (var i = 0; i < 160; i++) {
        b2n.in[i] <== n2b.out[i];
    }

    vote_id === b2n.out;
}

// BallotProof verifies the validity of a vote and its encryption.
// It also checks that the hash of all public/private inputs matches the provided one.
template BallotProof(n_fields) {
    // Public inputs
    signal input inputs_hash;

    // Private inputs
    signal input fields[n_fields];
    signal input weight;
    signal input encryption_pubkey[2];
    signal input cipherfields[n_fields][2][2];
    signal input process_id;
    signal input address;
    signal input k;
    signal input vote_id;

    // Validation parameters (passed as signals)
    signal input num_fields;
    signal input unique_values;
    signal input max_value;
    signal input min_value;
    signal input max_value_sum;
    signal input min_value_sum;
    signal input cost_exponent;
    signal input cost_from_weight;

    // 1. Check Ballot Validity
    component checker = BallotChecker(n_fields);
    for (var i = 0; i < n_fields; i++) {
        checker.fields[i] <== fields[i];
    }
    checker.weight <== weight;
    checker.num_fields <== num_fields;
    checker.unique_values <== unique_values;
    checker.max_value <== max_value;
    checker.min_value <== min_value;
    checker.max_value_sum <== max_value_sum;
    checker.min_value_sum <== min_value_sum;
    checker.cost_exponent <== cost_exponent;
    checker.cost_from_weight <== cost_from_weight;

    // 2. Check Ballot Encryption
    component cipher = BallotCipher(n_fields);
    for (var i = 0; i < n_fields; i++) {
        cipher.fields[i] <== fields[i];
        cipher.mask[i] <== checker.mask[i];
        cipher.cipherfields[i] <== cipherfields[i];
    }
    cipher.encryption_pubkey <== encryption_pubkey;
    cipher.k <== k;
    
    // num_fields must match successfully encrypted and valid fields
    cipher.valid_fields === num_fields;

    // 3. Check Vote ID
    component voteIDChecker = VoteIDChecker();
    voteIDChecker.process_id <== process_id;
    voteIDChecker.address <== address;
    voteIDChecker.k <== k;
    voteIDChecker.vote_id <== vote_id;

    // 4. Verify inputs_hash
    var n_inputs = n_fields + 1 + 2 + n_fields * 4 + 1 + 1 + 1 + 1 + 8;
    component inputs_hasher = Poseidon377MultiHash(n_inputs);
    inputs_hasher.domain <== 0;
    
    var idx = 0;
    for (var i = 0; i < n_fields; i++) {
        inputs_hasher.in[idx] <== fields[i];
        idx++;
    }
    inputs_hasher.in[idx] <== weight;
    idx++;
    inputs_hasher.in[idx] <== encryption_pubkey[0];
    idx++;
    inputs_hasher.in[idx] <== encryption_pubkey[1];
    idx++;
    for (var i = 0; i < n_fields; i++) {
        inputs_hasher.in[idx] <== cipherfields[i][0][0];
        idx++;
        inputs_hasher.in[idx] <== cipherfields[i][0][1];
        idx++;
        inputs_hasher.in[idx] <== cipherfields[i][1][0];
        idx++;
        inputs_hasher.in[idx] <== cipherfields[i][1][1];
        idx++;
    }
    inputs_hasher.in[idx] <== process_id;
    idx++;
    inputs_hasher.in[idx] <== address;
    idx++;
    inputs_hasher.in[idx] <== k;
    idx++;
    inputs_hasher.in[idx] <== vote_id;
    idx++;
    
    // Validation params
    inputs_hasher.in[idx] <== num_fields; idx++;
    inputs_hasher.in[idx] <== unique_values; idx++;
    inputs_hasher.in[idx] <== max_value; idx++;
    inputs_hasher.in[idx] <== min_value; idx++;
    inputs_hasher.in[idx] <== max_value_sum; idx++;
    inputs_hasher.in[idx] <== min_value_sum; idx++;
    inputs_hasher.in[idx] <== cost_exponent; idx++;
    inputs_hasher.in[idx] <== cost_from_weight; idx++;

    inputs_hash === inputs_hasher.out;
}

component main {public [inputs_hash]} = BallotProof(8);
