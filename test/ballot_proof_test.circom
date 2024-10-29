pragma circom 2.1.0;

include "../circuits/ballot_proof.circom";

component main{public [max_count, force_uniqueness, max_value, min_value, max_total_cost, min_total_cost, cost_exp, cost_from_weight, weight, cipherfields, nullifier]} = BallotProof(8);