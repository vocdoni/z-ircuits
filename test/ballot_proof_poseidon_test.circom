pragma circom 2.1.0;

include "../circuits/ballot_proof_poseidon.circom";

component main{public [inputs_hash]} = BallotProof(8);