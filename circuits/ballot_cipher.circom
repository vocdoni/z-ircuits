pragma circom 2.1.0;

include "comparators.circom";
include "mimc.circom";
include "./lib/elgamal.circom";

template FieldComparator() {
    signal input expected[2][2];
    signal input computed[2][2];
    signal output equal;
    // compare the x and y coordinates of the expected and computed points
    component iseqC1X = IsEqual();
    iseqC1X.in[0] <== expected[0][0];
    iseqC1X.in[1] <== computed[0][0];
    component iseqC1Y = IsEqual();
    iseqC1Y.in[0] <== expected[0][1];
    iseqC1Y.in[1] <== computed[0][1];
    component iseqC2X = IsEqual();
    iseqC2X.in[0] <== expected[1][0];
    iseqC2X.in[1] <== computed[1][0];
    component iseqC2Y = IsEqual();
    iseqC2Y.in[0] <== expected[1][1];
    iseqC2Y.in[1] <== computed[1][1];
    // return the result of the comparison
    signal iseqC1 <== iseqC1X.out * iseqC1Y.out;
    signal iseqC2 <== iseqC2X.out * iseqC2Y.out;
    equal <== iseqC1 * iseqC2;
}

template BallotCipher(n_fields) {
    signal input encryption_pubkey[2];
    signal input k;
    signal input fields[n_fields];
    signal input mask[n_fields];
    signal input cipherfields[n_fields][2][2];
    
    signal output valid_fields;
    // create components to encrypt the fields and compare the results
    component ciphers[n_fields];
    component fieldComparator[n_fields];
    // create signals to count the number of valid fields
    signal sum[n_fields + 1];
    sum[0] <== 0;
    // calculate the different k's derived from the provided one using recursive
    // mimc7 hashing
    signal ks[n_fields + 1];
    ks[0] <== k;
    component k_hasher[n_fields];
    for (var i = 0; i < n_fields; i++) {
        k_hasher[i] = MultiMiMC7(1, 91);
        k_hasher[i].k <== 0;
        k_hasher[i].in[0] <== ks[i];
        ks[i+1] <== k_hasher[i].out;
    }
    // encrypt the fields using ElGamal and compare the results with the 
    // provided ciphertexts. The result of the comparison is used to count the 
    // number of valid fields.
    for (var i = 0; i < n_fields; i++) {
        ciphers[i] = ElGamal();
        ciphers[i].encryption_pubkey <== encryption_pubkey;
        ciphers[i].msg <== fields[i];
        ciphers[i].k <== ks[i+1];
        // compare the encrypted fields
        fieldComparator[i] = FieldComparator();
        fieldComparator[i].expected <== cipherfields[i];
        fieldComparator[i].computed[0] <== ciphers[i].c1;
        fieldComparator[i].computed[1] <== ciphers[i].c2;
        // aggregate the results to count the number of fields successfully encrypted
        sum[i+1] <== sum[i] + (fieldComparator[i].equal * mask[i]);
    }
    // return the number of valid fields
    valid_fields <== sum[n_fields];
}