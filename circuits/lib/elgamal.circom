pragma circom 2.1.0;

include "bitify.circom";
include "twisted_edwards.circom";
include "comparators.circom";
include "escalarmulany.circom";
include "escalarmulfix.circom";

template ElGamal() {
    signal input encryption_pubkey[2]; // [pub] public key
    signal input msg;   // [priv] message to encrypt
    signal input k;     // [priv] random number

    signal output c1[2]; // first point of the ciphertext
    signal output c2[2]; // second point of the ciphertext

    // ensure that public key is on the curve
    component encryptionPubkeyCheck = PointOnCurve();
    encryptionPubkeyCheck.x <== encryption_pubkey[0];
    encryptionPubkeyCheck.y <== encryption_pubkey[1];
    // ensure that the public key is not the identity point (0, 1)
    component isz = IsZero();
    isz.in <== encryption_pubkey[0];
    component ise = IsEqual();
    ise.in[0] <== encryption_pubkey[1];
    ise.in[1] <== 1;
    isz.out + ise.out === 0;

    // encode the message as a point on the curve (fixed generator table)
    var msg_bits = 32;
    component messageBits = Num2Bits(msg_bits);
    messageBits.in <== msg;
    component messagePoint = EscalarMulFix(msg_bits);
    for (var i=0; i<msg_bits; i++) {
        messageBits.out[i] ==> messagePoint.e[i];
    }
    var k_bits = 253;
    // c1 = k * base (escalarMulFix)
    component c1Point = EscalarMulFix(k_bits);
    component kBits = Num2Bits(k_bits);
    kBits.in <== k;
    for (var i=0; i<k_bits; i++) {
        kBits.out[i] ==> c1Point.e[i];
    }
    // s = k * encryption_pubkey (escalarMulAny)
    component sPoint = EscalarMulAny(k_bits);
    sPoint.p[0] <== encryption_pubkey[0];
    sPoint.p[1] <== encryption_pubkey[1];
    for (var i=0; i<k_bits; i++) {
        kBits.out[i] ==> sPoint.e[i];
    }
    // c2 = msg + s (PointAdd)
    component c2Point = PointAdd();
    c2Point.x1 <== messagePoint.out[0];
    c2Point.y1 <== messagePoint.out[1];
    c2Point.x2 <== sPoint.out[0];
    c2Point.y2 <== sPoint.out[1];
    // return the results
    c1[0] <== c1Point.out[0];
    c1[1] <== c1Point.out[1];
    c2[0] <== c2Point.xout;
    c2[1] <== c2Point.yout;
}
