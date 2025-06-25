pragma circom 2.1.0;

include "bitify.circom";
include "mimc.circom";

// VoteIDChecker is a circuit to check the validity of a vote ID. A valid vote 
// ID is the mimc7 hash of the process ID, the address and the secret k of the 
// voter, truncated to 160 bits (20 bytes).
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
    // bit decomposition of the hash output
    component bits = Num2Bits(254);
    bits.in <== hasher.out;
    // reconstruct the lowest 160 bits as the truncated hash
    signal res[161];
    res[0] <== 0;  // accumulator starts at 0
    // signal partials[160];
    for (var i = 0; i < 160; i++) {
        res[i+1] <== res[i] + (bits.out[i] * (1 << i));
    }
    // ensure that the output is the expected vote ID
    res[160] === vote_id;
}