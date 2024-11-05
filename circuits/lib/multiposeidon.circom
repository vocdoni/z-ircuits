pragma circom 2.1.0;

include "poseidon.circom";

// MultiPoseidon is a circuit to hash multiple inputs using the Poseidon hash.
// It split the inputs in groups of 16 and hashes them using the Poseidon hash.
// Then it hashes the hashes of the groups to calculate the final hash. This
// circuit works with a limit of 256 inputs.
template MultiPoseidon(n_inputs) {
    assert(n_inputs <= 256);
    // inputs and output
    signal input in[n_inputs];
    signal output out;
    // calculate the required number of chunks
    var n_chunks = 0;
    for (var n = n_inputs; n > 16; n -= 16) {
        n_chunks++;
    }
    n_chunks++;
    // calculate the size of every chunk, including the last one
    var chunks_sizes[n_chunks];
    if (n_chunks == 1) {
        chunks_sizes[0] = n_inputs;
    } else {
        var total_size = n_inputs;
        for (var i = 0; i < n_chunks - 1; i++) {
            chunks_sizes[i] = 16;
            total_size -= 16;
        }
        chunks_sizes[n_chunks - 1] = total_size;
    }
    // hash every chunk
    component intermediate_hashes[n_chunks];
    var offset = 0;
    for (var i = 0; i < n_chunks; i++) {
        intermediate_hashes[i] = Poseidon(chunks_sizes[i]);
        for (var j = 0; j < chunks_sizes[i]; j++) {
            intermediate_hashes[i].inputs[j] <== in[offset + j];
        }
        offset += chunks_sizes[i];
    }
    // hash the every chunk hash
    component final_hash = Poseidon(n_chunks);
    for (var i = 0; i < n_chunks; i++) {
        final_hash.inputs[i] <== intermediate_hashes[i].out;
    }
    out <== final_hash.out;
}