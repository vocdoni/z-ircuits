pragma circom 2.1.0;

include "../circuits/ballot_cipher.circom";

template BallotCipherTest() {
    signal input encryption_pubkey[2]; // public key
    signal input msg;   // message to encrypt
    signal input k;     // random number
    signal input c1[2]; // first part of the ciphertext
    signal input c2[2]; // second part of the ciphertext
    // encode the inputs
    signal fields[1];
    fields[0] <== msg;
    signal cipherfields[1][2][2];
    cipherfields[0][0] <== c1;
    cipherfields[0][1] <== c2;
    signal mask[1];
    mask[0] <== 1;
    // encrypt the message
    component cipher = BallotCipher(1);
    cipher.encryption_pubkey <== encryption_pubkey;
    cipher.k <== k;
    cipher.fields <== fields;
    cipher.mask <== mask;
    cipher.cipherfields <== cipherfields;
}

component main{public [encryption_pubkey, msg, k, c1, c2]} = BallotCipherTest();