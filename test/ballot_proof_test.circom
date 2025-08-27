pragma circom 2.1.0;

include "../circuits/ballot_proof.circom";

component main{public [num_fields, unique_values, max_value, min_value, max_value_sum, min_value_sum, cost_exponent, cost_from_weight, address, process_id, vote_id, weight, cipherfields]} = BallotProof(8);