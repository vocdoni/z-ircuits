pragma circom 2.1.0;

include "../circuits/census_proof.circom";

component main{public [root, index, leaf, siblings]} = CensusProof(24);