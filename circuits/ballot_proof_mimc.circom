pragma circom 2.1.0;

include "poseidon.circom";
include "mimc.circom";
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
    signal input fields[n_fields];
    signal input num_fields;
    signal input unique_values;
    signal input max_value;
    signal input min_value;
    signal input max_value_sum;
    signal input min_value_sum;
    signal input cost_exponent;
    signal input cost_from_weight;
    signal input address;
    signal input weight;
    signal input process_id;
    signal input vote_id;
    // ElGamal inputs
    signal input encryption_pubkey[2];
    signal input k;
    signal input cipherfields[n_fields][2][2];
    // Inputs hash
    signal input inputs_hash;
    // 0. Check the hash of the inputs (all pubprivate inputs)
    //  a. ProcessID
    //  b. Ballot metadata:
    //      - num_fields
    //      - unique_values
    //      - max_value
    //      - min_value
    //      - max_value_sum
    //      - min_value_sum
    //      - cost_exponent
    //      - cost_from_weight
    //  c. Public encryption key (encryption_pubkey[2])
    //  d. Address
    //  e. VoteID
    //  f. Cipherfields[n_fields][2][2]
    //  g. Weight
    var static_inputs = 14; // including 2 of the encryption_pubkey
    var cipherfields_inputs = 4 * n_fields;
    var n_inputs = cipherfields_inputs + static_inputs;
    component inputs_hasher = MultiMiMC7(n_inputs, 91);
    inputs_hasher.k <== 0;
    var i = 0;
    inputs_hasher.in[i] <== process_id; i++;        // Process.ID
    inputs_hasher.in[i] <== num_fields; i++;         // Process.BallotMode
    inputs_hasher.in[i] <== unique_values; i++;  // Process.BallotMode
    inputs_hasher.in[i] <== max_value; i++;         // Process.BallotMode
    inputs_hasher.in[i] <== min_value; i++;         // Process.BallotMode
    inputs_hasher.in[i] <== max_value_sum; i++;    // Process.BallotMode
    inputs_hasher.in[i] <== min_value_sum; i++;    // Process.BallotMode
    inputs_hasher.in[i] <== cost_exponent; i++;          // Process.BallotMode
    inputs_hasher.in[i] <== cost_from_weight; i++;  // Process.BallotMode
    inputs_hasher.in[i] <== encryption_pubkey[0]; i++;             // Process.EncryptionKey
    inputs_hasher.in[i] <== encryption_pubkey[1]; i++;             // Process.EncryptionKey
    inputs_hasher.in[i] <== address; i++;           // Vote.Address
    inputs_hasher.in[i] <== vote_id; i++;           // Vote.ID
    for (var f = 0; f < n_fields; f++) {
        inputs_hasher.in[i] <== cipherfields[f][0][0]; i++; // Vote.Ballot
        inputs_hasher.in[i] <== cipherfields[f][0][1]; i++; // Vote.Ballot
        inputs_hasher.in[i] <== cipherfields[f][1][0]; i++; // Vote.Ballot
        inputs_hasher.in[i] <== cipherfields[f][1][1]; i++; // Vote.Ballot
    }
    inputs_hasher.in[i] <== weight; i++; // UserWeight
    inputs_hasher.out === inputs_hash;
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