pragma circom 2.1.0;

include "./lib/lean_imt.circom";

/**
 * The LeanIMT verifier needs to set the max depth of the tree:
 *   - For 100k entries, maxDepth = 17, 
 *   - For 1M entries, maxDepth = 20
 *   - For 10M entries, maxDepth = 24, constrains = 5.9k
 *   - For 100M entries, maxDepth = 27, constrains = 5.9k
 *   - ...
 * That means that the census proof provided will have as many siblings as the 
 * maxDepth.
 * In that way, the final census proof should have:
 *  - leaf: the voter's census entry
 *  - leafIndex: the index of the voter's census entry
 *  - siblings: an array of size maxDepth with the siblings along the path to the root
 *  - root: the expected root of the tree
*/

template CensusProof(imt_max_depth) {
    signal input root;                  // The expected root of the tree
    signal input index;                 // The index of the leaf in the tree
    signal input leaf;                  // The leaf value to prove inclusion for
    signal input siblings[imt_max_depth]; // The siblings along the path to the root


    component inclusionProof = LeanIMTInclusionProof(imt_max_depth);
    inclusionProof.leaf <== leaf;
    inclusionProof.index <== index;
    inclusionProof.siblings <== siblings;

    signal calculatedRoot <== inclusionProof.out;
    calculatedRoot === root;
}

