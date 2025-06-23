pragma circom 2.1.0;

include "mimc.circom";

// VoteIDChecker is a circuit to check the validity of a vote ID. A valid vote 
// ID is the mimc7 hash of the process ID, the address and the secret k of the 
// voter.
template VoteIDChecker() {
    signal input process_id;  // public
    signal input address;     // public
    signal input k;           // private
    signal input vote_id;    // public
    // calculate the vote ID using mimc7 hash
    component hasher = MultiMiMC7(3, 91);
    hasher.k <== 0;
    hasher.in[0] <== process_id;
    hasher.in[1] <== address;
    hasher.in[2] <== k;
    // ensure that the output is the expected vote ID
    hasher.out === vote_id;
}