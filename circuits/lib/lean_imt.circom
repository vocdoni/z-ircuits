pragma circom 2.1.0;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";

/**
 * @title LeanIMTInclusionProof template
 * @dev Template for generating and verifying inclusion proofs in a Lean Incremental Merkle Tree
 * @notice This circuit follows the LeanIMT design where:
 *   1. Every node with two children is the hash of its left and right nodes
 *   2. Every node with one child has the same value as its child node
 *   3. Tree is always built from leaves to root
 *   4. Tree is always balanced by construction
 *   5. Tree depth is dynamic and can increase with insertion of new leaves
 * @param max_depth The maximum depth of the Merkle tree
 */
template LeanIMTInclusionProof(max_depth) {

    //////////////////////// SIGNALS ////////////////////////

    signal input leaf;                // The leaf value to prove inclusion for
    signal input index;               // The index of the leaf in the tree
    signal input siblings[max_depth]; // The sibling values along the path to the root
    signal output out;                // The computed root value

    /////////////////// INTERNAL SIGNALS ///////////////////

    signal nodes[max_depth + 1];      // Array to store computed node values at each level
    signal indices[max_depth];        // Array to store path indices for each level

    ////////////////// COMPONENT SIGNALS //////////////////

    component sibling_is_empty[max_depth];        // Checks if sibling node is empty (zero)
    component hash_in_correct_order[max_depth];   // Orders node pairs for hashing
    component poseidons[max_depth];               // Poseidon hash components for each level

    /////////////////////// LOGIC ///////////////////////

    // Convert leaf index to binary path
    component indexToPath = Num2Bits(max_depth);
    indexToPath.in <== index;
    indices <== indexToPath.out;

    // Initialize with leaf value
    nodes[0] <== leaf;

    // For each level up to max_depth
    for (var i = 0; i < max_depth; i++) {
        // Prepare node pairs for both possible orderings (left/right)
        var children_to_sort[2][2] = [ [nodes[i], siblings[i]], [siblings[i], nodes[i]] ];
        hash_in_correct_order[i] = MultiMux1(2);
        hash_in_correct_order[i].c <== children_to_sort;
        hash_in_correct_order[i].s <== indices[i];

        // Hash the nodes
        poseidons[i] = Poseidon(2);
        poseidons[i].inputs <== hash_in_correct_order[i].out;

        // Check if sibling is empty (zero)
        sibling_is_empty[i] = IsZero();
        sibling_is_empty[i].in <== siblings[i];

        // Either keep the previous hash (no more siblings) or the new one
        nodes[i + 1] <== (nodes[i] - poseidons[i].out) * sibling_is_empty[i].out + poseidons[i].out;
    }

    // Output final computed root
    out <== nodes[max_depth];
}